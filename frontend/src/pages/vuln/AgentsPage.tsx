import { useCallback, useEffect, useState } from "react";
import { Badge, Button, Card, Field, Input, Modal, PageHeader, Select, Spinner } from "../../components/ui";
import { InsightCharts } from "../../components/charts";
import { countBy } from "../../lib/chartCounts";
import { vulnApi } from "../../lib/vulnApi";
import { useAuth } from "../../lib/auth";
import { useToast } from "../../lib/toast";

type Agent = {
  id: string;
  agent_uuid: string;
  name: string | null;
  hostname: string | null;
  platform: string | null;
  version: string | null;
  lifecycle_state: string;
  last_checkin_at: string | null;
  asset_id: string | null;
};

const NEXT: Record<string, string[]> = {
  planned: ["installed", "retired"],
  installed: ["linked", "uninstalled", "retired"],
  linked: ["healthy", "stale", "unlinked", "retired"],
  healthy: ["stale", "unlinked", "retired"],
  stale: ["healthy", "unlinked", "retired"],
  unlinked: ["linked", "uninstalled", "retired"],
  uninstalled: ["retired", "planned"],
  retired: [],
};

export function AgentsPage() {
  const { hasPermission } = useAuth();
  const canManage = hasPermission("agent:manage");
  const toast = useToast();
  const [items, setItems] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ agent_uuid: "", name: "", hostname: "", platform: "" });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setItems((await vulnApi.listAgents()) as Agent[]);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load agents");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  const create = async () => {
    if (!form.agent_uuid.trim()) {
      toast.error("Agent UUID required");
      return;
    }
    try {
      await vulnApi.createAgent({
        agent_uuid: form.agent_uuid.trim(),
        name: form.name || null,
        hostname: form.hostname || null,
        platform: form.platform || null,
        lifecycle_state: "planned",
      });
      toast.success("Agent registered");
      setOpen(false);
      setForm({ agent_uuid: "", name: "", hostname: "", platform: "" });
      load();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Create failed");
    }
  };

  const transition = async (id: string, lifecycle_state: string) => {
    try {
      await vulnApi.transitionAgent(id, { lifecycle_state });
      toast.success(`Transitioned to ${lifecycle_state}`);
      load();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Transition failed");
    }
  };

  const markStale = async () => {
    try {
      const res = await vulnApi.markAgentsStale(72);
      toast.success(`Stale agents: ${res.stale_count}`);
      load();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Mark stale failed");
    }
  };

  return (
    <div>
      <PageHeader
        title="Nessus agents"
        subtitle="BRD §8.3 agent lifecycle — Planned → Installed → Linked → Healthy / Stale → Retired. Separate from forensic job agents."
        actions={
          canManage ? (
            <div className="flex gap-2">
              <Button variant="outline" onClick={markStale}>
                Mark stale (72h)
              </Button>
              <Button variant="brand" onClick={() => setOpen(true)}>
                Register agent
              </Button>
            </div>
          ) : null
        }
      />

      {!loading && items.length > 0 && (
        <InsightCharts
          left={{
            title: "Agent lifecycle",
            subtitle: "From agents API",
            data: countBy(items, (a) => a.lifecycle_state || "planned"),
            kind: "bar",
          }}
          right={{
            title: "Platform",
            subtitle: "Host OS mix",
            data: countBy(items, (a) => a.platform || "unknown"),
            kind: "donut",
            centerLabel: "Agents",
          }}
        />
      )}

      {loading ? (
        <div className="flex justify-center py-12">
          <Spinner />
        </div>
      ) : (
        <Card className="overflow-hidden p-0">
          <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead>
              <tr className="table-head border-b border-brand-300/70 text-ink-700">
                <th className="px-4 py-3">UUID</th>
                <th className="px-4 py-3">Name / Host</th>
                <th className="px-4 py-3">Platform</th>
                <th className="px-4 py-3">State</th>
                <th className="px-4 py-3">Last check-in</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((a) => (
                <tr key={a.id} className="border-b border-ink-50">
                  <td className="px-4 py-3 font-mono text-xs">{a.agent_uuid.slice(0, 12)}…</td>
                  <td className="px-4 py-3">
                    {a.name || "—"}
                    <div className="text-xs text-ink-400">{a.hostname || ""}</div>
                  </td>
                  <td className="px-4 py-3">{a.platform || "—"}</td>
                  <td className="px-4 py-3">
                    <Badge>{a.lifecycle_state}</Badge>
                  </td>
                  <td className="px-4 py-3 text-xs">{a.last_checkin_at || "—"}</td>
                  <td className="px-4 py-3">
                    {canManage ? (
                      <Select
                        className="max-w-[140px]"
                        value=""
                        onChange={(e) => {
                          if (e.target.value) transition(a.id, e.target.value);
                        }}
                      >
                        <option value="">Transition…</option>
                        {(NEXT[a.lifecycle_state] || []).map((s) => (
                          <option key={s} value={s}>
                            {s}
                          </option>
                        ))}
                      </Select>
                    ) : (
                      "—"
                    )}
                  </td>
                </tr>
              ))}
              {items.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-ink-400">
                    No agents registered.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
          </div>
        </Card>
      )}

      {open && (
        <Modal
          open
          onClose={() => setOpen(false)}
          title="Register agent"
          footer={
            <>
              <Button variant="ghost" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button variant="brand" onClick={create}>
                Save
              </Button>
            </>
          }
        >
          <div className="space-y-3">
            <Field label="Agent UUID">
              <Input value={form.agent_uuid} onChange={(e) => setForm({ ...form, agent_uuid: e.target.value })} />
            </Field>
            <Field label="Name">
              <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </Field>
            <Field label="Hostname">
              <Input value={form.hostname} onChange={(e) => setForm({ ...form, hostname: e.target.value })} />
            </Field>
            <Field label="Platform">
              <Input value={form.platform} onChange={(e) => setForm({ ...form, platform: e.target.value })} />
            </Field>
          </div>
        </Modal>
      )}
    </div>
  );
}
