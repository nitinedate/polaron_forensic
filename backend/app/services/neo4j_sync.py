"""Neo4j GraphRAG sync — encyclopedia + job evidence + parsed artifact edges."""

from __future__ import annotations

import json
import logging
from typing import Any

from app.config import get_settings
from app.db.sql_helpers import execute, fetchall, fetchone

log = logging.getLogger("neo4j_sync")

_driver = None
_driver_failed = False


def _get_driver():
    global _driver, _driver_failed
    if _driver_failed:
        return None
    if _driver is not None:
        return _driver
    settings = get_settings()
    try:
        from neo4j import GraphDatabase

        _driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password))
        _driver.verify_connectivity()
        return _driver
    except Exception as exc:
        log.warning("Neo4j unavailable: %s", exc)
        _driver_failed = True
        return None


def neo4j_available() -> bool:
    return _get_driver() is not None


def _sync_parsed_edges(session, job_id: str, parsed_rows: list[dict], *, max_records: int | None = 20) -> int:
    """Create evidence-derived graph edges from parse results."""
    edges = 0
    for row in parsed_rows:
        norm = row.get("normalized")
        if isinstance(norm, str):
            try:
                norm = json.loads(norm)
            except json.JSONDecodeError:
                norm = [{"text": norm}]
        if not isinstance(norm, list):
            norm = [norm] if norm else []

        path = row.get("file_path", "")
        aid = row.get("encyclopedia_artifact_id")
        parser_name = row.get("parser_name", "")

        session.run(
            """
            MERGE (e:EvidenceFile {path: $path, job_id: $jid})
            SET e.parser = $parser
            """,
            path=path,
            jid=job_id,
            parser=parser_name,
        )

        for rec in norm if max_records is None else norm[:max_records]:
            if not isinstance(rec, dict):
                continue
            if rec.get("executable") or rec.get("format") == "prefetch_scca":
                exe = rec.get("executable", "")
                session.run(
                    """
                    MERGE (p:Process {name: $name, job_id: $jid})
                    MERGE (e:EvidenceFile {path: $path, job_id: $jid})
                    MERGE (e)-[:PROVES_EXECUTION]->(p)
                    """,
                    name=exe,
                    jid=job_id,
                    path=path,
                )
                edges += 1
            if rec.get("target") or rec.get("target_paths"):
                target = rec.get("target") or (rec.get("target_paths") or [""])[0]
                session.run(
                    """
                    MERGE (f:File {path: $target})
                    MERGE (e:EvidenceFile {path: $path, job_id: $jid})
                    MERGE (e)-[:LINKS_TO]->(f)
                    """,
                    target=target[:500],
                    path=path,
                    jid=job_id,
                )
                edges += 1
            if rec.get("event_id"):
                session.run(
                    """
                    MERGE (ev:TimelineEvent {event_id: $eid, job_id: $jid})
                    MERGE (e:EvidenceFile {path: $path, job_id: $jid})
                    MERGE (e)-[:CONTAINS_EVENT]->(ev)
                    """,
                    eid=str(rec["event_id"]),
                    jid=job_id,
                    path=path,
                )
                edges += 1
            if rec.get("registry_key"):
                session.run(
                    """
                    MERGE (rk:RegistryKey {path: $rkey})
                    MERGE (e:EvidenceFile {path: $path, job_id: $jid})
                    MERGE (e)-[:STORES_KEY]->(rk)
                    """,
                    rkey=rec["registry_key"][:500],
                    path=path,
                    jid=job_id,
                )
                edges += 1
            if rec.get("user_profile"):
                session.run(
                    """
                    MERGE (u:UserAccount {name: $uname, job_id: $jid})
                    MERGE (e:EvidenceFile {path: $path, job_id: $jid})
                    MERGE (e)-[:BELONGS_TO_USER]->(u)
                    """,
                    uname=rec["user_profile"],
                    jid=job_id,
                    path=path,
                )
                edges += 1
            if rec.get("table"):
                session.run(
                    """
                    MERGE (db:Database {table: $tbl, job_id: $jid})
                    MERGE (e:EvidenceFile {path: $path, job_id: $jid})
                    MERGE (e)-[:HAS_TABLE]->(db)
                    """,
                    tbl=rec["table"],
                    jid=job_id,
                    path=path,
                )
                edges += 1

        if aid:
            session.run(
                """
                MERGE (a:Artifact {id: $aid})
                MERGE (e:EvidenceFile {path: $path, job_id: $jid})
                MERGE (e)-[:MAPS_TO_ENCYCLOPEDIA]->(a)
                """,
                aid=aid,
                path=path,
                jid=job_id,
            )
            edges += 1

    return edges


def sync_job_graph(db, job_id: str, *, schema_name: str) -> dict:
    driver = _get_driver()
    if driver is None:
        execute(
            db,
            """INSERT INTO graph_sync_state (job_id, status, error)
               VALUES (:jid, 'skipped', 'Neo4j unavailable')
               ON CONFLICT (job_id) DO UPDATE SET status='skipped', error='Neo4j unavailable'""",
            {"jid": job_id},
        )
        db.commit()
        return {"status": "skipped", "nodes": 0, "edges": 0}

    arts = fetchall(
        db,
        """SELECT encyclopedia_artifact_id, file_path, sha256 FROM job_artifacts
           WHERE job_id=:jid AND encyclopedia_artifact_id IS NOT NULL LIMIT 5000""",
        {"jid": job_id},
    )
    parsed_rows = fetchall(
        db,
        """SELECT ja.file_path, ja.encyclopedia_artifact_id, apr.parser_name, apr.normalized
           FROM job_artifacts ja
           JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
           WHERE ja.job_id=:jid LIMIT 5000""",
        {"jid": job_id},
    )
    enc_rels = db.execute(
        __import__("sqlalchemy").text(
            "SELECT from_artifact_id, to_artifact_id, relationship_type FROM public.encyclopedia_relationships LIMIT 5000"
        )
    ).mappings().all()

    nodes = 0
    edges = 0

    def _mark_syncing() -> None:
        execute(
            db,
            """INSERT INTO graph_sync_state (job_id, nodes_synced, edges_synced, status, error)
               VALUES (:jid, :n, :e, 'syncing', NULL)
               ON CONFLICT (job_id) DO UPDATE SET
                 nodes_synced=EXCLUDED.nodes_synced, edges_synced=EXCLUDED.edges_synced,
                 status='syncing', error=NULL""",
            {"jid": job_id, "n": nodes, "e": edges},
        )
        db.commit()

    _mark_syncing()
    try:
        with driver.session() as session:
            session.run("MERGE (j:Job {id: $jid}) SET j.updated_at = datetime()", jid=job_id)
            nodes += 1

            for i, a in enumerate(arts):
                session.run(
                    """
                    MERGE (e:EvidenceFile {path: $path, job_id: $jid})
                    SET e.sha256 = $sha, e.artifact_id = $aid
                    WITH e
                    MERGE (a:Artifact {id: $aid})
                    MERGE (e)-[:MAPS_TO_ENCYCLOPEDIA]->(a)
                    MERGE (j:Job {id: $jid})-[:CONTAINS]->(e)
                    """,
                    path=a["file_path"],
                    jid=job_id,
                    sha=a.get("sha256"),
                    aid=a["encyclopedia_artifact_id"],
                )
                nodes += 2
                edges += 2
                if (i + 1) % 200 == 0:
                    _mark_syncing()

            for r in enc_rels:
                session.run(
                    """
                    MERGE (a:Artifact {id: $from})
                    MERGE (b:Artifact {id: $to})
                    MERGE (a)-[:RELATED_TO {type: $typ}]->(b)
                    """,
                    **{"from": r["from_artifact_id"], "to": r["to_artifact_id"], "typ": r["relationship_type"]},
                )
                edges += 1

            edges += _sync_parsed_edges(session, job_id, [dict(r) for r in parsed_rows])
    except Exception as exc:
        msg = str(exc).lower()
        if any(tok in msg for tok in ("unavailable", "refused", "connection", "timeout", "auth")):
            execute(
                db,
                """INSERT INTO graph_sync_state (job_id, status, error)
                   VALUES (:jid, 'skipped', :err)
                   ON CONFLICT (job_id) DO UPDATE SET status='skipped', error=:err""",
                {"jid": job_id, "err": f"Neo4j unavailable: {exc}"[:400]},
            )
            db.commit()
            return {"status": "skipped", "nodes": nodes, "edges": edges}
        raise

    execute(
        db,
        """INSERT INTO graph_sync_state (job_id, nodes_synced, edges_synced, last_sync_at, status, error)
           VALUES (:jid, :n, :e, NOW(), 'ok', NULL)
           ON CONFLICT (job_id) DO UPDATE SET
             nodes_synced=EXCLUDED.nodes_synced, edges_synced=EXCLUDED.edges_synced,
             last_sync_at=NOW(), status='ok', error=NULL""",
        {"jid": job_id, "n": nodes, "e": edges},
    )
    db.commit()
    from app.services.forensic_serial_policy import current_stage

    if current_stage() is not None:
        return {"status": "ok", "nodes": nodes, "edges": edges}
    # Kick entity/annotation/ontology immediately — do not wait for full corpus RAG.
    try:
        from app.services.pipeline_orchestrator import _rag_enrich_status

        enrich_done, enrich_busy = _rag_enrich_status(db, job_id)
        if not enrich_done and not enrich_busy:
            from app.tasks import rag_enrich_task

            rag_enrich_task.delay(schema_name, job_id)
    except Exception:
        pass
    return {"status": "ok", "nodes": nodes, "edges": edges}


def sync_job_graph_serial(db, job_id: str, *, schema_name: str, mobile: bool = False) -> dict:
    """Keyset graph construction after enrichment, with no 5,000-file/20-record cap."""
    from app.services.forensic_serial_pipeline import StageWaiting
    from app.services.forensic_serial_stages import report_progress
    from app.services.job_control import pipeline_should_stop

    global _driver_failed
    _driver_failed = False  # Allow the watchdog to recover after a transient outage.
    driver = _get_driver()
    if driver is None:
        raise StageWaiting("Neo4j unavailable; graph synchronization remains pending")
    total = int(fetchone(db, "SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid", {"jid": job_id})["c"])
    nodes = edges = scanned = 0
    with driver.session() as session:
        session.run("MERGE (j:Job {id:$jid}) SET j.updated_at=datetime()", jid=job_id).consume()
        last = "00000000-0000-0000-0000-000000000000"
        while True:
            rows = fetchall(db, """SELECT id,file_path,sha256,encyclopedia_artifact_id FROM job_artifacts
                WHERE job_id=:jid AND id>:last ORDER BY id LIMIT 500""", {"jid": job_id, "last": last})
            db.commit()
            if not rows:
                break
            if pipeline_should_stop(db, job_id):
                raise StageWaiting("Graph synchronization paused by user")
            payload = [{"path": r["file_path"], "sha": r["sha256"], "aid": r["encyclopedia_artifact_id"]} for r in rows]
            session.run("""UNWIND $rows AS r
                MERGE (e:EvidenceFile {path:r.path,job_id:$jid}) SET e.sha256=r.sha,e.artifact_id=r.aid
                WITH e,r MERGE (j:Job {id:$jid}) MERGE (j)-[:CONTAINS]->(e)
                FOREACH (aid IN CASE WHEN r.aid IS NULL THEN [] ELSE [r.aid] END |
                    MERGE (a:Artifact {id:aid}) MERGE (e)-[:MAPS_TO_ENCYCLOPEDIA]->(a))""",
                rows=payload, jid=job_id).consume()
            scanned += len(rows)
            nodes += len(rows)
            edges += len(rows)
            last = str(rows[-1]["id"])
            report_progress(db, job_id, "graph", total=total, completed=scanned, label="Graph synchronization of extracted evidence")
        last = "00000000-0000-0000-0000-000000000000"
        while True:
            rows = fetchall(db, """SELECT apr.id,ja.file_path,ja.encyclopedia_artifact_id,apr.parser_name,apr.normalized
                FROM artifact_parse_results apr JOIN job_artifacts ja ON ja.id=apr.job_artifact_id
                WHERE ja.job_id=:jid AND apr.id>:last ORDER BY apr.id LIMIT 100""", {"jid": job_id, "last": last})
            db.commit()
            if not rows:
                break
            if pipeline_should_stop(db, job_id):
                raise StageWaiting("Graph synchronization paused by user")
            edges += _sync_parsed_edges(session, job_id, rows, max_records=None)
            session.run("RETURN 1").consume()  # Flush the last implicit write before the SQL checkpoint.
            last = str(rows[-1]["id"])
        last = "00000000-0000-0000-0000-000000000000"
        while True:
            rows = fetchall(db, """SELECT id,from_artifact_id,to_artifact_id,relationship_type
                FROM public.encyclopedia_relationships WHERE id>:last ORDER BY id LIMIT 500""", {"last": last})
            db.commit()
            if not rows:
                break
            if pipeline_should_stop(db, job_id):
                raise StageWaiting("Graph synchronization paused by user")
            session.run("""UNWIND $rows AS r MERGE (a:Artifact {id:r.from_artifact_id})
                MERGE (b:Artifact {id:r.to_artifact_id})
                MERGE (a)-[:RELATED_TO {type:r.relationship_type}]->(b)""", rows=[dict(r) for r in rows]).consume()
            edges += len(rows)
            last = str(rows[-1]["id"])
        table = "mobile_normalized_artifacts" if mobile else "forensic_priority_records"
        if fetchone(db,"SELECT to_regclass(:name) AS name",{"name":table}).get("name"):
            last = ""
            while True:
                rows = fetchall(db, f"""SELECT artifact_id,artifact_type,state,forensic FROM {table}
                    WHERE job_id=:jid AND artifact_id>:last ORDER BY artifact_id LIMIT 500""", {"jid": job_id, "last": last})
                db.commit()
                if not rows:
                    break
                if pipeline_should_stop(db, job_id):
                    raise StageWaiting("Graph synchronization paused by user")
                payload = [{"id": r["artifact_id"], "type": r["artifact_type"], "state": r["state"],
                            "path": (r["forensic"] or {}).get("source_path") or ""} for r in rows]
                session.run("""UNWIND $rows AS r MERGE (m:EvidenceRecord {id:r.id,job_id:$jid})
                    SET m.artifact_type=r.type,m.evidence_state=r.state
                    FOREACH (_ IN CASE WHEN $mobile THEN [1] ELSE [] END | SET m:MobileArtifact)
                    WITH m,r MERGE (e:EvidenceFile {path:r.path,job_id:$jid}) MERGE (m)-[:DERIVED_FROM]->(e)
                    MERGE (j:Job {id:$jid}) MERGE (j)-[:CONTAINS]->(m)""", rows=payload, jid=job_id,mobile=mobile).consume()
                nodes += len(rows)
                edges += 2 * len(rows)
                last = str(rows[-1]["artifact_id"])
        if mobile:
            last_id = 0
            while True:
                rows = fetchall(db, """SELECT id,from_artifact_id,to_artifact_id,rel_type,confidence,reasons
                    FROM mobile_artifact_relationships WHERE job_id=:jid AND id>:last ORDER BY id LIMIT 500""",
                    {"jid": job_id, "last": last_id})
                db.commit()
                if not rows:
                    break
                if pipeline_should_stop(db, job_id):
                    raise StageWaiting("Graph synchronization paused by user")
                payload = [{"from": r["from_artifact_id"], "to": r["to_artifact_id"], "type": r["rel_type"],
                            "confidence": json.dumps(r["confidence"]), "reasons": json.dumps(r["reasons"])} for r in rows]
                session.run("""UNWIND $rows AS r MERGE (a:MobileArtifact {id:r.from,job_id:$jid})
                    MERGE (b:MobileArtifact {id:r.to,job_id:$jid})
                    MERGE (a)-[rel:CORRELATED_WITH {type:r.type}]->(b)
                    SET rel.confidence=r.confidence,rel.reasons=r.reasons""", rows=payload, jid=job_id).consume()
                edges += len(rows)
                last_id = rows[-1]["id"]
    execute(db, """INSERT INTO graph_sync_state(job_id,nodes_synced,edges_synced,last_sync_at,status,error)
        VALUES (:jid,:nodes,:edges,NOW(),'ok',NULL) ON CONFLICT(job_id) DO UPDATE
        SET nodes_synced=:nodes,edges_synced=:edges,last_sync_at=NOW(),status='ok',error=NULL""",
        {"jid": job_id, "nodes": nodes, "edges": edges})
    db.commit()
    return {"status": "ok", "nodes": nodes, "edges": edges, "total": total, "completed": scanned}


def graph_expand(driver, artifact_ids: list[str], *, hops: int = 2) -> list[dict[str, Any]]:
    if not driver or not artifact_ids:
        return []
    hops = max(1, min(int(hops), 3))
    with driver.session() as session:
        result = session.run(
            f"""
            UNWIND $ids AS aid
            MATCH (a:Artifact {{id: aid}})
            OPTIONAL MATCH path = (a)-[*1..{hops}]-(related)
            RETURN DISTINCT related.id AS id, labels(related) AS labels
            LIMIT 50
            """,
            ids=artifact_ids,
        )
        return [{"id": r["id"], "labels": r["labels"]} for r in result if r.get("id")]
