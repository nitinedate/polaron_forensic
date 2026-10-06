import { useEffect, useState } from "react";
import { KeyRound, Plus } from "lucide-react";
import { Badge, Button, Card, Field, Input, LoadPanel, Modal, PageHeader } from "../components/ui";
import { InsightCharts } from "../components/charts";
import { countBy } from "../lib/chartCounts";
import { api } from "../lib/api";
import { useToast } from "../lib/toast";
import { useAuth } from "../lib/auth";
import type { Permission } from "../lib/types";

export function Permissions() {
  const { hasPermission } = useAuth();
  const [items, setItems] = useState<Permission[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);

  async function load() {
    setLoading(true);
    setLoadError(null);
    try {
      setItems(await api.get<Permission[]>("/api/permissions", undefined, { timeoutMs: 8_000 }));
    } catch (e: any) {
      setLoadError(e?.message || "Failed to load permissions");
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    load();
  }, []);

  // group by resource
  const grouped = items.reduce<Record<string, Permission[]>>((acc, p) => {
    (acc[p.resource] ||= []).push(p);
    return acc;
  }, {});

  return (
    <div>
      <PageHeader
        title="Permissions"
        subtitle="The catalog of fine-grained capabilities that roles are built from."
        actions={
          hasPermission("role:manage") && (
            <Button variant="brand" onClick={() => setOpen(true)}>
              <Plus className="h-4 w-4" /> New permission
            </Button>
          )
        }
      />
      {!loading && items.length > 0 && (
        <InsightCharts
          left={{
            title: "Permissions by resource",
            subtitle: "From /api/permissions",
            data: countBy(items, (p) => p.resource),
            kind: "bar",
          }}
          right={{
            title: "By action",
            subtitle: "Catalog mix",
            data: countBy(items, (p) => p.action),
            kind: "donut",
            centerLabel: "Perms",
          }}
        />
      )}
      <LoadPanel
        loading={loading}
        error={loadError}
        hasData={items.length > 0}
        onRetry={() => void load()}
        empty={<p className="px-5 py-16 text-center text-sm text-ink-400">No permissions found.</p>}
      >
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Object.entries(grouped).map(([resource, perms]) => (
            <Card key={resource}>
              <div className="flex items-center gap-2 border-b border-ink-100 px-5 py-3">
                <KeyRound className="h-4 w-4 text-brand-600" />
                <h3 className="font-bold capitalize text-ink-900">{resource}</h3>
                <span className="ml-auto text-xs text-ink-400">{perms.length}</span>
              </div>
              <ul className="divide-y divide-ink-100">
                {perms.map((p) => (
                  <li key={p.id} className="px-5 py-3">
                    <div className="flex items-center justify-between">
                      <code className="rounded bg-ink-100 px-1.5 py-0.5 text-xs font-semibold text-ink-700">
                        {p.code}
                      </code>
                      <Badge tone="neutral">{p.action}</Badge>
                    </div>
                    {p.description && <p className="mt-1 text-xs text-ink-400">{p.description}</p>}
                  </li>
                ))}
              </ul>
            </Card>
          ))}
        </div>
      </LoadPanel>
      {open && <CreatePermissionModal onClose={() => setOpen(false)} onCreated={() => { setOpen(false); load(); }} />}
    </div>
  );
}

function CreatePermissionModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const toast = useToast();
  const [resource, setResource] = useState("");
  const [action, setAction] = useState("");
  const [description, setDescription] = useState("");
  const [loading, setLoading] = useState(false);
  const code = resource && action ? `${resource}:${action}` : "";

  async function submit() {
    setLoading(true);
    try {
      await api.post("/api/permissions", { code, resource, action, description });
      toast.success("Permission created");
      onCreated();
    } catch (e: any) {
      toast.error(e?.message || "Create failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="Create permission"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button variant="brand" loading={loading} disabled={!code} onClick={submit}>Create</Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Resource" hint="e.g. report">
            <Input value={resource} onChange={(e) => setResource(e.target.value.toLowerCase())} />
          </Field>
          <Field label="Action" hint="e.g. export">
            <Input value={action} onChange={(e) => setAction(e.target.value.toLowerCase())} />
          </Field>
        </div>
        <Field label="Resulting code">
          <Input value={code} readOnly className="bg-ink-50 font-mono" />
        </Field>
        <Field label="Description">
          <Input value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
      </div>
    </Modal>
  );
}
