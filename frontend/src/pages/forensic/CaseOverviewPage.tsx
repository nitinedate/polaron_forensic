import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Briefcase, FileText, Shield, Users } from "lucide-react";
import { Badge, Button, Card, PageHeader, Spinner } from "../../components/ui";
import { forensicApi } from "../../lib/forensicApi";
import { useToast } from "../../lib/toast";
import type { AuditEvent, Case, CaseMember, ChainOfCustodyEntry } from "../../lib/types/forensic";

export function CaseOverviewPage() {
  const { caseId } = useParams<{ caseId: string }>();
  const toast = useToast();

  const [caseData, setCaseData] = useState<Case | null>(null);
  const [members, setMembers] = useState<CaseMember[]>([]);
  const [chain, setChain] = useState<ChainOfCustodyEntry[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!caseId) return;
    setLoading(true);
    try {
      const [c, m, ch, a] = await Promise.all([
        forensicApi.getCase(caseId),
        forensicApi.listCaseMembers(caseId),
        forensicApi.listChainOfCustody(caseId),
        forensicApi.listAudit(caseId, { page: 1, page_size: 20 }),
      ]);
      setCaseData(c);
      setMembers(m);
      setChain(ch);
      setAudit(a.items);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load case");
    } finally {
      setLoading(false);
    }
  }, [caseId, toast]);

  useEffect(() => {
    load();
  }, [load]);

  if (loading) return <Spinner />;
  if (!caseData) return <p className="text-sm text-ink-400">Case not found.</p>;

  return (
    <div>
      <PageHeader
        title={caseData.title || `Case ${caseData.number || caseData.id.slice(0, 8)}`}
        subtitle={`Status: ${caseData.status} · ${caseData.classification || "unclassified"}`}
        actions={
          caseData.job_id && (
            <Link to={`/forensic/jobs/${caseData.job_id}`}>
              <Button variant="brand">
                <FileText className="h-4 w-4" /> Open job
              </Button>
            </Link>
          )
        }
      />

      <div className="mb-6 grid gap-4 sm:grid-cols-3">
        <Card className="p-4">
          <div className="flex items-center gap-2 text-ink-400">
            <Briefcase className="h-4 w-4" />
            <span className="text-xs font-semibold uppercase">Case number</span>
          </div>
          <p className="mt-2 font-mono text-sm text-ink-800">{caseData.number || "—"}</p>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-2 text-ink-400">
            <Shield className="h-4 w-4" />
            <span className="text-xs font-semibold uppercase">Status</span>
          </div>
          <Badge tone={caseData.status === "open" ? "green" : "neutral"}>
            {caseData.status}
          </Badge>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-2 text-ink-400">
            <Users className="h-4 w-4" />
            <span className="text-xs font-semibold uppercase">Members</span>
          </div>
          <p className="mt-2 text-2xl font-bold text-ink-900">{members.length}</p>
        </Card>
      </div>

      {caseData.authorization_notes && (
        <Card className="mb-6 p-4">
          <p className="text-xs font-semibold uppercase text-ink-400">Authorization notes</p>
          <p className="mt-2 text-sm text-ink-700">{caseData.authorization_notes}</p>
        </Card>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <div className="border-b border-ink-100 px-5 py-3">
            <h3 className="text-sm font-bold text-ink-800">Team members</h3>
          </div>
          {members.length === 0 ? (
            <p className="px-5 py-8 text-center text-sm text-ink-400">No members assigned.</p>
          ) : (
            <ul className="divide-y divide-ink-100">
              {members.map((m) => (
                <li key={m.user_id} className="flex items-center justify-between px-5 py-3 text-sm">
                  <span className="font-mono text-xs text-ink-600">{m.user_id.slice(0, 8)}…</span>
                  <Badge tone="indigo">{m.role}</Badge>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <div className="border-b border-ink-100 px-5 py-3">
            <h3 className="text-sm font-bold text-ink-800">Chain of custody</h3>
          </div>
          {chain.length === 0 ? (
            <p className="px-5 py-8 text-center text-sm text-ink-400">No custody entries.</p>
          ) : (
            <ul className="max-h-64 divide-y divide-ink-100 overflow-y-auto">
              {chain.map((e) => (
                <li key={e.id} className="px-5 py-3 text-sm">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-ink-800">{e.action}</span>
                    <span className="text-xs text-ink-400">
                      {new Date(e.timestamp).toLocaleString()}
                    </span>
                  </div>
                  {e.handler && <p className="text-xs text-ink-500">Handler: {e.handler}</p>}
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card className="overflow-hidden lg:col-span-2">
          <div className="border-b border-ink-100 px-5 py-3">
            <h3 className="text-sm font-bold text-ink-800">Recent audit events</h3>
          </div>
          {audit.length === 0 ? (
            <p className="px-5 py-8 text-center text-sm text-ink-400">No audit events.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="table-head border-b border-brand-300/70 text-xs uppercase tracking-wider text-ink-700">
                    <th className="px-5 py-2">Time</th>
                    <th className="px-5 py-2">Action</th>
                    <th className="px-5 py-2">Object</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-ink-100">
                  {audit.map((e) => (
                    <tr key={e.id}>
                      <td className="px-5 py-2 text-ink-500">
                        {new Date(e.timestamp).toLocaleString()}
                      </td>
                      <td className="px-5 py-2 font-medium text-ink-700">{e.action}</td>
                      <td className="px-5 py-2 text-ink-500">
                        {e.object_type ? `${e.object_type}:${e.object_id?.slice(0, 8)}` : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
