import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { Building2, Eye, Mail, Pause, Pencil, Play, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { Badge, Button, Card, Field, Input, Modal, PageHeader, Select, Spinner } from "../components/ui";
import { InsightCharts } from "../components/charts";
import { countBy } from "../lib/chartCounts";
import { api } from "../lib/api";
import { useConfirm } from "../lib/confirm";
import { useToast } from "../lib/toast";
import type { Tenant, TenantDetail } from "../lib/types";

export function Tenants() {
  const toast = useToast();
  const { confirm } = useConfirm();
  const [items, setItems] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [viewId, setViewId] = useState<string | null>(null);
  const [editId, setEditId] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    try {
      setItems(await api.get<Tenant[]>("/api/tenants"));
    } catch (e: any) {
      toast.error(e?.message || "Failed to load tenants");
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    load();
  }, []);

  async function toggleStatus(t: Tenant) {
    const action = t.status === "active" ? "suspend" : "activate";
    try {
      await api.post(`/api/tenants/${t.id}/${action}`);
      toast.success(`Firm ${action}d`);
      load();
    } catch (e: any) {
      toast.error(e?.message || "Action failed");
    }
  }

  async function onDelete(t: Tenant) {
    const ok = await confirm({
      title: "Delete firm permanently",
      message: `Delete "${t.name}" (${t.slug})? This drops schema ${t.schema_name} and all firm users. This cannot be undone.`,
      confirmLabel: "Delete permanently",
      variant: "danger",
    });
    if (!ok) return;
    try {
      await api.del(`/api/tenants/${t.id}`);
      toast.success("Firm deleted");
      load();
    } catch (e: any) {
      toast.error(e?.message || "Delete failed");
    }
  }

  return (
    <div>
      <PageHeader
        title="Firms"
        subtitle="Provision isolated firms. Each firm gets its own schema. Firm administrators are invited by email."
        actions={
          <Button variant="brand" onClick={() => setCreating(true)}>
            <Plus className="h-4 w-4" /> New firm
          </Button>
        }
      />

      {!loading && items.length > 0 && (
        <InsightCharts
          left={{ title: "Firm status", subtitle: "From /api/tenants", data: countBy(items, (t) => t.status), kind: "bar" }}
          right={{
            title: "Plans",
            subtitle: "Tenant plan mix",
            data: countBy(items, (t) => t.plan || "standard"),
            kind: "donut",
            centerLabel: "Firms",
          }}
        />
      )}

      <Card className="overflow-hidden">
        {loading ? (
          <Spinner />
        ) : items.length === 0 ? (
          <p className="px-5 py-16 text-center text-sm text-ink-400">No firms yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="table-head border-b border-brand-300/70 text-xs uppercase tracking-wider text-ink-700">
                  <th className="px-5 py-3 font-semibold">Tenant</th>
                  <th className="px-5 py-3 font-semibold">Schema</th>
                  <th className="px-5 py-3 font-semibold">Plan</th>
                  <th className="px-5 py-3 font-semibold">Status</th>
                  <th className="px-5 py-3 font-semibold">Created</th>
                  <th className="px-5 py-3 text-right font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-100">
                {items.map((t) => (
                  <tr key={t.id} className="hover:bg-ink-50/60">
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-3">
                        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-brand-50 text-brand-600 ring-1 ring-brand-100">
                          <Building2 className="h-4 w-4" />
                        </div>
                        <div>
                          <p className="font-semibold text-ink-800">{t.name}</p>
                          <p className="text-xs text-ink-400">{t.slug}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-5 py-3">
                      <code className="rounded bg-ink-100 px-1.5 py-0.5 text-xs text-ink-600">{t.schema_name}</code>
                    </td>
                    <td className="px-5 py-3 capitalize text-ink-600">{t.plan}</td>
                    <td className="px-5 py-3">
                      <Badge tone={t.status === "active" ? "green" : "red"}>{t.status}</Badge>
                    </td>
                    <td className="px-5 py-3 text-ink-500">{new Date(t.created_at).toLocaleDateString()}</td>
                    <td className="px-5 py-3">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          title="View firm"
                          onClick={() => setViewId(t.id)}
                          className="rounded-lg p-2 text-ink-400 hover:bg-ink-100 hover:text-ink-700"
                        >
                          <Eye className="h-4 w-4" />
                        </button>
                        <Link
                          to={`/tenants/${t.id}/iam`}
                          title="Manage users, roles & permissions"
                          className="rounded-lg p-2 text-ink-400 hover:bg-brand-50 hover:text-brand-700"
                        >
                          <ShieldCheck className="h-4 w-4" />
                        </Link>
                        <button
                          title="Edit firm"
                          onClick={() => setEditId(t.id)}
                          className="rounded-lg p-2 text-ink-400 hover:bg-ink-100 hover:text-ink-700"
                        >
                          <Pencil className="h-4 w-4" />
                        </button>
                        <button
                          title="Delete firm"
                          onClick={() => onDelete(t)}
                          className="rounded-lg p-2 text-ink-400 hover:bg-red-50 hover:text-red-600"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                        <Button variant="outline" onClick={() => toggleStatus(t)}>
                          {t.status === "active" ? (
                            <>
                              <Pause className="h-4 w-4" /> Suspend
                            </>
                          ) : (
                            <>
                              <Play className="h-4 w-4" /> Activate
                            </>
                          )}
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {creating && (
        <CreateTenantModal
          onClose={() => setCreating(false)}
          onCreated={() => {
            setCreating(false);
            load();
          }}
        />
      )}
      {viewId && (
        <ViewTenantModal
          firmId={viewId}
          onClose={() => setViewId(null)}
          onEdit={() => {
            setEditId(viewId);
            setViewId(null);
          }}
          onChanged={load}
        />
      )}
      {editId && (
        <EditTenantModal
          firmId={editId}
          onClose={() => setEditId(null)}
          onSaved={() => {
            setEditId(null);
            load();
          }}
        />
      )}
    </div>
  );
}

function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-ink-100 py-3 last:border-0">
      <span className="text-sm text-ink-500">{label}</span>
      <span className="text-right text-sm font-medium text-ink-800">{children}</span>
    </div>
  );
}

function ViewTenantModal({
  firmId,
  onClose,
  onEdit,
  onChanged,
}: {
  firmId: string;
  onClose: () => void;
  onEdit: () => void;
  onChanged: () => void;
}) {
  const toast = useToast();
  const [firm, setFirm] = useState<TenantDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [resending, setResending] = useState(false);

  async function loadFirm() {
    setLoading(true);
    try {
      setFirm(await api.get<TenantDetail>(`/api/tenants/${firmId}`));
    } catch (e: any) {
      toast.error(e?.message || "Failed to load firm");
      onClose();
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadFirm();
  }, [firmId]);

  async function resendInvite() {
    setResending(true);
    try {
      await api.post(`/api/tenants/${firmId}/resend-admin-invite`);
      toast.success("Admin invite email sent");
      onChanged();
      await loadFirm();
    } catch (e: any) {
      toast.error(e?.message || "Failed to resend invite");
    } finally {
      setResending(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="Firm details"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
          <Link to={`/tenants/${firmId}/iam`}>
            <Button variant="outline">
              <ShieldCheck className="h-4 w-4" /> Manage IAM
            </Button>
          </Link>
          {firm?.admin_status === "pending" && (
            <Button variant="outline" loading={resending} onClick={resendInvite}>
              <Mail className="h-4 w-4" /> Resend admin invite
            </Button>
          )}
          <Button variant="brand" onClick={onEdit} disabled={!firm}>
            Edit firm
          </Button>
        </>
      }
    >
      {loading || !firm ? (
        <Spinner />
      ) : (
        <div className="px-1">
          <DetailRow label="Organization">{firm.name}</DetailRow>
          <DetailRow label="Slug">
            <code className="rounded bg-ink-100 px-1.5 py-0.5 text-xs">{firm.slug}</code>
          </DetailRow>
          <DetailRow label="Schema">
            <code className="rounded bg-ink-100 px-1.5 py-0.5 text-xs">{firm.schema_name}</code>
          </DetailRow>
          <DetailRow label="Plan">
            <span className="capitalize">{firm.plan}</span>
          </DetailRow>
          <DetailRow label="Status">
            <Badge tone={firm.status === "active" ? "green" : "red"}>{firm.status}</Badge>
          </DetailRow>
          <DetailRow label="Primary host">{firm.primary_host || "—"}</DetailRow>
          <DetailRow label="Created">{new Date(firm.created_at).toLocaleString()}</DetailRow>
          <div className="mt-4 rounded-lg bg-ink-50 p-4">
            <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-ink-400">
              Firm administrator
            </p>
            <DetailRow label="Email">{firm.admin_email || "—"}</DetailRow>
            <DetailRow label="Account status">
              {firm.admin_status ? (
                <Badge tone={firm.admin_status === "active" ? "green" : "amber"}>{firm.admin_status}</Badge>
              ) : (
                "—"
              )}
            </DetailRow>
            {firm.admin_status === "pending" && (
              <p className="mt-3 text-xs text-ink-500">
                Pending admins must open the activation email and set their password at /activate.
                Use &quot;Resend admin invite&quot; to send a new Gmail message.
              </p>
            )}
          </div>
        </div>
      )}
    </Modal>
  );
}

function EditTenantModal({
  firmId,
  onClose,
  onSaved,
}: {
  firmId: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  const toast = useToast();
  const [form, setForm] = useState({ name: "", plan: "standard", primary_host: "" });
  const [meta, setMeta] = useState<{ slug: string; schema_name: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const firm = await api.get<TenantDetail>(`/api/tenants/${firmId}`);
        setForm({
          name: firm.name,
          plan: firm.plan,
          primary_host: firm.primary_host || "",
        });
        setMeta({ slug: firm.slug, schema_name: firm.schema_name });
      } catch (e: any) {
        toast.error(e?.message || "Failed to load firm");
        onClose();
      } finally {
        setLoading(false);
      }
    })();
  }, [firmId, onClose, toast]);

  async function submit() {
    setSaving(true);
    try {
      await api.patch(`/api/tenants/${firmId}`, {
        name: form.name,
        plan: form.plan,
        primary_host: form.primary_host || null,
      });
      toast.success("Firm updated");
      onSaved();
    } catch (e: any) {
      toast.error(e?.message || "Update failed");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="Edit firm"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="brand" loading={saving} disabled={!form.name} onClick={submit}>
            Save changes
          </Button>
        </>
      }
    >
      {loading ? (
        <Spinner />
      ) : (
        <div className="space-y-4">
          <Field label="Organization name">
            <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Slug" hint="Cannot be changed after provisioning">
              <Input value={meta?.slug || ""} readOnly className="bg-ink-50" />
            </Field>
            <Field label="Schema" hint="Read-only">
              <Input value={meta?.schema_name || ""} readOnly className="bg-ink-50 font-mono text-xs" />
            </Field>
          </div>
          <Field label="Plan">
            <Select value={form.plan} onChange={(e) => setForm({ ...form, plan: e.target.value })}>
              <option value="standard">standard</option>
              <option value="pro">pro</option>
              <option value="enterprise">enterprise</option>
            </Select>
          </Field>
          <Field label="Primary host" hint="optional, e.g. acme.iam-platform.local">
            <Input
              value={form.primary_host}
              onChange={(e) => setForm({ ...form, primary_host: e.target.value })}
            />
          </Field>
        </div>
      )}
    </Modal>
  );
}

function CreateTenantModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const toast = useToast();
  const [form, setForm] = useState({
    name: "",
    slug: "",
    plan: "standard",
    primary_host: "",
    admin_email: "",
  });
  const [loading, setLoading] = useState(false);

  function setSlugFromName(name: string) {
    const slug = name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
    setForm((f) => ({ ...f, name, slug: f.slug || slug }));
  }

  async function submit() {
    setLoading(true);
    try {
      const payload = {
        name: form.name,
        slug: form.slug,
        plan: form.plan,
        primary_host: form.primary_host || null,
        admin_email: form.admin_email || null,
      };
      await api.post("/api/tenants", payload, { service: "forensic" });
      for (const service of ["mobile-extract", "vuln"] as const) {
        try {
          await api.post("/api/tenants", { ...payload, send_invite: false }, { service });
        } catch {
          /* backend may be down or the firm already exists there */
        }
      }
      toast.success("Firm provisioned — admin invite sent via email");
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
      title="Provision firm"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button
            variant="brand"
            loading={loading}
            disabled={!form.name || !form.slug || !form.admin_email}
            onClick={submit}
          >
            Provision
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Organization name">
          <Input value={form.name} onChange={(e) => setSlugFromName(e.target.value)} placeholder="Acme Corp" />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Slug" hint="lowercase, used in URLs">
            <Input value={form.slug} onChange={(e) => setForm({ ...form, slug: e.target.value })} placeholder="acme" />
          </Field>
          <Field label="Plan">
            <Select value={form.plan} onChange={(e) => setForm({ ...form, plan: e.target.value })}>
              <option value="standard">standard</option>
              <option value="pro">pro</option>
              <option value="enterprise">enterprise</option>
            </Select>
          </Field>
        </div>
        <Field label="Primary host" hint="optional, e.g. acme.iam-platform.local">
          <Input value={form.primary_host} onChange={(e) => setForm({ ...form, primary_host: e.target.value })} />
        </Field>
        <div className="rounded-lg bg-ink-50 p-3">
          <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-ink-400">
            Firm administrator
          </p>
          <Field label="Admin email" hint="Invite email is sent via Gmail SMTP.">
            <Input
              type="email"
              value={form.admin_email}
              onChange={(e) => setForm({ ...form, admin_email: e.target.value })}
              required
            />
          </Field>
        </div>
      </div>
    </Modal>
  );
}
