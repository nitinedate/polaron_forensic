import { useCallback, useEffect, useState } from "react";
import { CheckCircle2, Clock, Kanban, Plus } from "lucide-react";
import { Badge, Button, Card, Field, Input, Modal, PageHeader, Select, Spinner } from "../../components/ui";
import { InsightCharts } from "../../components/charts";
import { countBy } from "../../lib/chartCounts";
import { vulnApi } from "../../lib/vulnApi";
import { useToast } from "../../lib/toast";
import { useAuth } from "../../lib/auth";
import type { RemediationTask, RemediationTaskUpdate } from "../../lib/types/vuln";

const COLUMNS = [
  { key: "open", label: "Open", icon: Clock, tone: "amber" as const },
  { key: "in_progress", label: "In progress", icon: Kanban, tone: "indigo" as const },
  { key: "resolved", label: "Resolved", icon: CheckCircle2, tone: "green" as const },
  { key: "accepted_risk", label: "Accepted risk", icon: CheckCircle2, tone: "neutral" as const },
];

export function RemediationBoardPage() {
  const toast = useToast();
  const { hasPermission } = useAuth();
  const canRemediate = hasPermission("vuln:remediate");

  const [tasks, setTasks] = useState<RemediationTask[]>([]);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await vulnApi.listRemediationTasks({ page: 1, page_size: 100 });
      setTasks(res.items);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load tasks");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  async function moveTask(task: RemediationTask, status: string) {
    try {
      await vulnApi.updateRemediationTask(task.id, {
        status: status as RemediationTaskUpdate["status"],
      });
      load();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Update failed");
    }
  }

  const grouped = COLUMNS.map((col) => ({
    ...col,
    tasks: tasks.filter((t) => t.status === col.key),
  }));

  return (
    <div>
      <PageHeader
        title="Remediation board"
        subtitle="Track vulnerability remediation tasks across the workflow."
        actions={
          canRemediate && (
            <Button variant="brand" onClick={() => setCreateOpen(true)}>
              <Plus className="h-4 w-4" /> New task
            </Button>
          )
        }
      />

      {!loading && tasks.length > 0 && (
        <InsightCharts
          left={{
            title: "Remediation workflow",
            subtitle: "From remediation-tasks API",
            data: countBy(tasks, (t) => t.status),
            kind: "bar",
          }}
        />
      )}

      {loading ? (
        <Spinner />
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {grouped.map((col) => (
            <Card key={col.key} className="flex flex-col">
              <div className="flex items-center gap-2 border-b border-ink-100 px-4 py-3">
                <col.icon className="h-4 w-4 text-ink-400" />
                <span className="text-sm font-bold text-ink-800">{col.label}</span>
                <Badge tone={col.tone}>{col.tasks.length}</Badge>
              </div>
              <div className="flex-1 space-y-2 p-3">
                {col.tasks.length === 0 ? (
                  <p className="py-6 text-center text-xs text-ink-400">Empty</p>
                ) : (
                  col.tasks.map((task) => (
                    <div
                      key={task.id}
                      className="rounded-lg border border-ink-100 bg-ink-50/50 p-3 text-sm"
                    >
                      <p className="font-mono text-xs text-ink-500">
                        Finding: {task.finding_id.slice(0, 8)}…
                      </p>
                      {task.sla_due && (
                        <p className="mt-1 text-xs text-ink-400">
                          SLA: {new Date(task.sla_due).toLocaleDateString()}
                        </p>
                      )}
                      {canRemediate && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {COLUMNS.filter((c) => c.key !== task.status).map((c) => (
                            <button
                              key={c.key}
                              onClick={() => moveTask(task, c.key)}
                              className="rounded px-2 py-0.5 text-[10px] font-semibold uppercase text-brand-600 hover:bg-brand-50"
                            >
                              → {c.label}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            </Card>
          ))}
        </div>
      )}

      {createOpen && (
        <CreateTaskModal
          onClose={() => setCreateOpen(false)}
          onSaved={() => {
            setCreateOpen(false);
            load();
          }}
        />
      )}
    </div>
  );
}

function CreateTaskModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const [loading, setLoading] = useState(false);
  const [form, setForm] = useState({ finding_id: "", status: "open" });

  async function submit() {
    setLoading(true);
    try {
      await vulnApi.createRemediationTask({
        finding_id: form.finding_id,
        status: form.status as "open" | "in_progress" | "resolved" | "accepted_risk",
      });
      toast.success("Task created");
      onSaved();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Create failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="New remediation task"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="brand" loading={loading} onClick={submit}>
            Create
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Finding ID">
          <Input
            value={form.finding_id}
            onChange={(e) => setForm({ ...form, finding_id: e.target.value })}
            placeholder="UUID"
          />
        </Field>
        <Field label="Initial status">
          <Select value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value })}>
            <option value="open">open</option>
            <option value="in_progress">in_progress</option>
          </Select>
        </Field>
      </div>
    </Modal>
  );
}
