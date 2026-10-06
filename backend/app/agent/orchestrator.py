"""Agentic orchestrator — plan → tool loop → persist (no extract/vuln mutation)."""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from sqlalchemy.orm import Session

from app.agent.registry import get_agent_definition
from app.agent.tools import run_tool, tools_prompt_block
from app.config import get_settings
from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.model_router import generate_text

log = logging.getLogger("agent.orchestrator")


def _model() -> str:
    settings = get_settings()
    return settings.agent_model or settings.llm_fast_model


def _parse_llm_json(text: str) -> dict[str, Any] | None:
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}", text)
        if not m:
            return None
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None


def create_thread(
    db: Session,
    *,
    job_id: str,
    user_id: str | None,
    agent_id: str = "investigator",
    title: str | None = None,
) -> dict[str, Any]:
    row = fetchone(
        db,
        """INSERT INTO agent_threads (job_id, user_id, title, agent_id)
           VALUES (CAST(:jid AS uuid),
                   CASE WHEN :uid IS NULL THEN NULL ELSE CAST(:uid AS uuid) END,
                   :title, :aid)
           RETURNING *""",
        {
            "jid": job_id,
            "uid": user_id,
            "title": title or f"{agent_id} thread",
            "aid": agent_id,
        },
    )
    return {
        "id": str(row["id"]),
        "job_id": str(row["job_id"]),
        "agent_id": row["agent_id"],
        "title": row.get("title"),
        "status": row["status"],
    }


def append_message(
    db: Session,
    *,
    thread_id: str,
    role: str,
    content: str,
    metadata: dict | None = None,
) -> None:
    execute(
        db,
        """INSERT INTO agent_messages (thread_id, role, content, metadata_json)
           VALUES (CAST(:tid AS uuid), :role, :content, CAST(:meta AS jsonb))""",
        {
            "tid": thread_id,
            "role": role,
            "content": content,
            "meta": json.dumps(metadata or {}),
        },
    )
    execute(
        db,
        "UPDATE agent_threads SET updated_at = NOW() WHERE id = CAST(:tid AS uuid)",
        {"tid": thread_id},
    )


def list_runs_for_job(db: Session, job_id: str) -> list[dict[str, Any]]:
    rows = fetchall(
        db,
        """SELECT * FROM agent_runs
           WHERE job_id = CAST(:jid AS uuid)
           ORDER BY created_at DESC LIMIT 100""",
        {"jid": job_id},
    )
    return [
        {
            "id": str(r["id"]),
            "agent_id": r["agent_id"],
            "parent_run_id": str(r["parent_run_id"]) if r.get("parent_run_id") else None,
            "status": r["status"],
            "message": r.get("message"),
            "started_at": r["started_at"].isoformat() if r.get("started_at") else None,
            "finished_at": r["finished_at"].isoformat() if r.get("finished_at") else None,
            "latency_ms": r.get("latency_ms"),
        }
        for r in rows
    ]


def _start_run(db: Session, *, job_id: str, agent_id: str, thread_id: str | None, message: str) -> str:
    row = fetchone(
        db,
        """INSERT INTO agent_runs (thread_id, job_id, agent_id, status, message, started_at)
           VALUES (
             CASE WHEN :tid IS NULL THEN NULL ELSE CAST(:tid AS uuid) END,
             CAST(:jid AS uuid), :aid, 'running', :msg, NOW()
           )
           RETURNING id""",
        {"tid": thread_id, "jid": job_id, "aid": agent_id, "msg": message},
    )
    return str(row["id"])


def _finish_run(db: Session, run_id: str, *, status: str, message: str, latency_ms: int, plan: dict | None = None) -> None:
    execute(
        db,
        """UPDATE agent_runs
           SET status = :st, message = :msg, finished_at = NOW(), latency_ms = :lat,
               plan_json = CAST(:plan AS jsonb)
           WHERE id = CAST(:id AS uuid)""",
        {
            "st": status,
            "msg": message[:4000],
            "lat": latency_ms,
            "plan": json.dumps(plan or {}),
            "id": run_id,
        },
    )


def _record_tool(
    db: Session,
    *,
    run_id: str,
    step: int,
    tool_name: str,
    input_data: dict,
    output_data: dict,
    status: str,
    latency_ms: int,
) -> None:
    # Keep jsonb valid — never slice mid-JSON
    raw = json.dumps(output_data, default=str)
    if len(raw) > 48000:
        safe_out: dict[str, Any] = {
            "truncated": True,
            "preview": raw[:40000],
            "keys": list(output_data.keys()) if isinstance(output_data, dict) else [],
        }
    else:
        safe_out = output_data
    execute(
        db,
        """INSERT INTO agent_tool_calls
           (run_id, step_index, tool_name, input_json, output_json, status, latency_ms)
           VALUES (CAST(:rid AS uuid), :step, :name, CAST(:inp AS jsonb), CAST(:out AS jsonb), :st, :lat)""",
        {
            "rid": run_id,
            "step": step,
            "name": tool_name,
            "inp": json.dumps(input_data, default=str),
            "out": json.dumps(safe_out, default=str),
            "st": status,
            "lat": latency_ms,
        },
    )


def run_specialized_agent(db: Session, *, job_id: str, agent_id: str, user_id: str | None = None) -> dict[str, Any]:
    """One-shot agents matching existing frontend contracts (intake/scope/report)."""
    if not get_agent_definition(agent_id) and agent_id not in (
        "intake_validator",
        "scope_advisor",
        "report_qa",
    ):
        return {"agent_id": agent_id, "run_id": None, "status": "error", "message": "Unknown agent", "output": {}}

    t0 = time.time()
    run_id = _start_run(db, job_id=job_id, agent_id=agent_id, thread_id=None, message=f"Invoke {agent_id}")
    tool_map = {
        "intake_validator": "intake_validate",
        "scope_advisor": "scope_advise",
        "report_qa": "report_qa",
    }
    tool_name = tool_map.get(agent_id, agent_id)
    out = run_tool(db, tool_name, job_id=job_id)
    # Optional LLM summary
    summary = ""
    try:
        summary = generate_text(
            f"Summarize this forensic agent tool result for an examiner in 3-5 bullets:\n{json.dumps(out)[:4000]}",
            model=_model(),
            system="You are a forensic investigation assistant. Be concise and factual.",
            temperature=0.1,
        )
    except Exception:
        summary = ""
    latency = int((time.time() - t0) * 1000)
    _record_tool(
        db,
        run_id=run_id,
        step=0,
        tool_name=tool_name,
        input_data={"job_id": job_id},
        output_data=out,
        status="ok" if "error" not in out else "error",
        latency_ms=latency,
    )
    message = summary or out.get("message") or json.dumps(out.get("advice") or out.get("issues") or out)[:1000]
    # Persist completed/failed; API status also maps to frontend contracts (success/incomplete).
    persist_status = "completed" if "error" not in out else "failed"
    if agent_id == "intake_validator":
        api_status = "success" if out.get("ready") else "incomplete"
        if "suggestions" not in out and out.get("missing"):
            out = {
                **out,
                "suggestions": [f"Complete required intake field: {m}" for m in out["missing"]],
            }
    elif persist_status == "failed":
        api_status = "error"
    else:
        api_status = "success"
    _finish_run(
        db, run_id, status=persist_status, message=message, latency_ms=latency, plan={"tools": [tool_name]}
    )
    db.commit()
    return {
        "agent_id": agent_id,
        "run_id": run_id,
        "status": api_status,
        "message": message,
        "output": out,
    }


def run_investigator(
    db: Session,
    *,
    job_id: str,
    query: str,
    user_id: str | None = None,
    thread_id: str | None = None,
) -> dict[str, Any]:
    """Multi-step investigator agent with tool loop."""
    settings = get_settings()
    max_steps = max(1, min(int(settings.agent_max_steps or 6), 12))
    t0 = time.time()

    if not thread_id:
        thread = create_thread(db, job_id=job_id, user_id=user_id, agent_id="investigator", title=query[:80])
        thread_id = thread["id"]
    append_message(db, thread_id=thread_id, role="user", content=query)

    run_id = _start_run(
        db,
        job_id=job_id,
        agent_id="investigator",
        thread_id=thread_id,
        message=query[:500],
    )

    # Short-circuit OS / Users — structured hive answers, no multi-step LLM tool loop.
    try:
        from app.retrieval.answer import _OS_ARTIFACTS_INTENT, _OS_INTENT, _USER_INTENT

        if _USER_INTENT.search(query or "") or (
            _OS_INTENT.search(query or "") and not _OS_ARTIFACTS_INTENT.search(query or "")
        ):
            out_a = run_tool(db, "answer_question", job_id=job_id, query=query)
            final_answer = out_a.get("answer") or "Insufficient evidence."
            latency = int((time.time() - t0) * 1000)
            _record_tool(
                db,
                run_id=run_id,
                step=0,
                tool_name="answer_question",
                input_data={"query": query},
                output_data=out_a,
                status="ok",
                latency_ms=latency,
            )
            append_message(
                db,
                thread_id=thread_id,
                role="assistant",
                content=final_answer,
                metadata={"run_id": run_id, "steps": 1, "short_circuit": "identity"},
            )
            _finish_run(
                db,
                run_id,
                status="completed",
                message=final_answer[:2000],
                latency_ms=latency,
                plan={"observations": [{"answer": out_a}], "short_circuit": "identity"},
            )
            db.commit()
            return {
                "agent_id": "investigator",
                "run_id": run_id,
                "thread_id": thread_id,
                "status": "completed",
                "message": final_answer,
                "output": {"observations": [{"answer": out_a}], "answer": final_answer},
                "latency_ms": latency,
            }
    except Exception as exc:
        log.warning("Investigator identity short-circuit failed: %s", exc)
        try:
            db.rollback()
        except Exception:
            pass

    history = fetchall(
        db,
        """SELECT role, content FROM agent_messages
           WHERE thread_id = CAST(:tid AS uuid)
           ORDER BY created_at DESC LIMIT 12""",
        {"tid": thread_id},
    )
    history = list(reversed(history))
    transcript = "\n".join(f"{m['role']}: {m['content'][:800]}" for m in history)

    observations: list[dict[str, Any]] = []
    final_answer = ""
    system = (
        "You are an agentic forensic investigator. Use tools to gather evidence before answering. "
        "Never invent file paths or facts. If evidence is insufficient, say so.\n"
        + tools_prompt_block()
    )

    for step in range(max_steps):
        prompt = (
            f"Job ID: {job_id}\n"
            f"Conversation:\n{transcript}\n\n"
            f"Observations so far:\n{json.dumps(observations)[:6000]}\n\n"
            "Decide next tools or produce the final answer as JSON."
        )
        raw = generate_text(prompt, model=_model(), system=system, temperature=0.1)
        parsed = _parse_llm_json(raw) or {}

        if parsed.get("final") is True or (parsed.get("answer") and not parsed.get("tools")):
            final_answer = str(parsed.get("answer") or raw)
            break

        tools = parsed.get("tools") or []
        if not tools:
            # Fallback: single retrieve + answer path without requiring LLM tool JSON
            out_u = run_tool(db, "understand_query", job_id=job_id, query=query)
            _record_tool(
                db,
                run_id=run_id,
                step=step,
                tool_name="understand_query",
                input_data={"query": query},
                output_data=out_u,
                status="ok",
                latency_ms=0,
            )
            out_a = run_tool(db, "answer_question", job_id=job_id, query=query)
            _record_tool(
                db,
                run_id=run_id,
                step=step,
                tool_name="answer_question",
                input_data={"query": query},
                output_data=out_a,
                status="ok",
                latency_ms=0,
            )
            final_answer = out_a.get("answer") or raw or "Insufficient evidence."
            observations.append({"understand": out_u, "answer": out_a})
            break

        for call in tools[:4]:
            name = (call or {}).get("name") or ""
            args = dict((call or {}).get("args") or {})
            args.setdefault("job_id", job_id)
            if "query" not in args and name in ("retrieve_evidence", "answer_question", "understand_query"):
                args["query"] = query
            ts = time.time()
            out = run_tool(db, name, **args)
            lat = int((time.time() - ts) * 1000)
            _record_tool(
                db,
                run_id=run_id,
                step=step,
                tool_name=name,
                input_data=args,
                output_data=out,
                status="error" if out.get("error") else "ok",
                latency_ms=lat,
            )
            observations.append({"tool": name, "output": out})

    if not final_answer:
        # Last resort grounded answer
        out_a = run_tool(db, "answer_question", job_id=job_id, query=query)
        final_answer = out_a.get("answer") or "Unable to complete investigation with available tools."
        observations.append({"fallback_answer": out_a})

    latency = int((time.time() - t0) * 1000)
    append_message(
        db,
        thread_id=thread_id,
        role="assistant",
        content=final_answer,
        metadata={"run_id": run_id, "steps": len(observations)},
    )
    _finish_run(
        db,
        run_id,
        status="completed",
        message=final_answer[:2000],
        latency_ms=latency,
        plan={"observations": observations[-10:]},
    )
    db.commit()
    return {
        "agent_id": "investigator",
        "run_id": run_id,
        "thread_id": thread_id,
        "status": "completed",
        "message": final_answer,
        "output": {"observations": observations, "answer": final_answer},
        "latency_ms": latency,
    }
