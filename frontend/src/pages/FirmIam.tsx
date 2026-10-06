import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  KeyRound,
  Lock,
  Mail,
  Pencil,
  Plus,
  ShieldCheck,
  Trash2,
  Users,
} from "lucide-react";
import clsx from "clsx";
import { Badge, Button, Card, Field, Input, Modal, PageHeader, Spinner } from "../components/ui";
import { api } from "../lib/api";
import { useConfirm } from "../lib/confirm";
import { useToast } from "../lib/toast";
import type { Permission, Role, TenantDetail, TenantUser } from "../lib/types";

type Tab = "users" | "roles" | "permissions";

export function FirmIam() {
  const { firmId = "" } = useParams();
  const toast = useToast();
  const [firm, setFirm] = useState<TenantDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<Tab>("users");

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        setFirm(await api.get<TenantDetail>(`/api/tenants/${firmId}`));
      } catch (e: any) {
        toast.error(e?.message || "Failed to load firm");
      } finally {
        setLoading(false);
      }
    })();
  }, [firmId, toast]);

  if (loading || !firm) {
    return (
      <div className="flex min-h-[40vh] items-center justify-center">
        <Spinner />
      </div>
    );
  }

  const tabs: { id: Tab; label: string; icon: typeof Users }[] = [
    { id: "users", label: "Users", icon: Users },
    { id: "roles", label: "Roles", icon: ShieldCheck },
    { id: "permissions", label: "Permissions", icon: KeyRound },
  ];

  return (
    <div>
      <div className="mb-4">
        <Link
          to="/tenants"
          className="inline-flex items-center gap-1.5 text-sm font-semibold text-brand-700 hover:text-brand-800"
        >
          <ArrowLeft className="h-4 w-4" /> Back to firms
        </Link>
      </div>

      <PageHeader
        title={`${firm.name} — Identity & Access`}
        subtitle={`Manage users, roles, and permissions for firm slug "${firm.slug}". Superadmin invites admin users only; firm admins manage day-to-day IAM after activation.`}
      />

      <div className="mb-6 flex flex-wrap gap-2 border-b border-ink-200 pb-1">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={clsx(
              "inline-flex items-center gap-2 rounded-t-lg px-4 py-2.5 text-sm font-semibold transition",
              tab === t.id
                ? "border border-b-white border-ink-200 bg-white text-ink-900 shadow-sm"
                : "text-ink-500 hover:bg-ink-50 hover:text-ink-800"
            )}
          >
            <t.icon className="h-4 w-4" />
            {t.label}
          </button>
        ))}
      </div>

      {tab === "users" && <FirmUsersTab firmId={firm.id} firmSlug={firm.slug} />}
      {tab === "roles" && <FirmRolesTab firmId={firm.id} />}
      {tab === "permissions" && <FirmPermissionsTab firmId={firm.id} />}
    </div>
  );
}

function FirmUsersTab({ firmId, firmSlug }: { firmId: string; firmSlug: string }) {
  const toast = useToast();
  const { confirm } = useConfirm();
  const [users, setUsers] = useState<TenantUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState({ email: "", mfa_enabled: true });

  async function loadUsers() {
    setLoading(true);
    try {
      setUsers(await api.get<TenantUser[]>(`/api/tenants/${firmId}/users`));
    } catch (e: any) {
      toast.error(e?.message || "Failed to load users");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadUsers();
  }, [firmId]);

  async function inviteAdmin() {
    if (!form.email.trim()) return;
    setAdding(true);
    try {
      await api.post(`/api/tenants/${firmId}/users`, {
        email: form.email.trim(),
        mfa_enabled: form.mfa_enabled,
      });
      toast.success("Firm admin invite sent");
      setForm({ email: "", mfa_enabled: true });
      await loadUsers();
    } catch (e: any) {
      toast.error(e?.message || "Invite failed");
    } finally {
      setAdding(false);
    }
  }

  async function toggleMfa(u: TenantUser) {
    try {
      await api.patch(`/api/tenants/${firmId}/users/${u.id}`, { mfa_enabled: !u.mfa_enabled });
      toast.success(u.mfa_enabled ? "MFA disabled" : "MFA enabled");
      await loadUsers();
    } catch (e: any) {
      toast.error(e?.message || "Update failed");
    }
  }

  async function suspendUser(u: TenantUser) {
    const ok = await confirm({
      title: "Suspend user",
      message: `Suspend ${u.email}?`,
      confirmLabel: "Suspend",
      variant: "danger",
    });
    if (!ok) return;
    try {
      await api.patch(`/api/tenants/${firmId}/users/${u.id}`, { status: "disabled" });
      toast.success("User suspended");
      await loadUsers();
    } catch (e: any) {
      toast.error(e?.message || "Suspend failed");
    }
  }

  async function deleteUser(u: TenantUser) {
    const ok = await confirm({
      title: "Delete user",
      message: `Deactivate ${u.email}?`,
      confirmLabel: "Delete",
      variant: "danger",
    });
    if (!ok) return;
    try {
      await api.del(`/api/tenants/${firmId}/users/${u.id}`);
      toast.success("User deleted");
      await loadUsers();
    } catch (e: any) {
      toast.error(e?.message || "Delete failed");
    }
  }

  async function resendInvite(u: TenantUser) {
    try {
      await api.post(`/api/tenants/${firmId}/users/${u.id}/invite`);
      toast.success("Invite resent");
    } catch (e: any) {
      toast.error(e?.message || "Resend failed");
    }
  }

  return (
    <Card className="overflow-hidden">
      <div className="border-b border-ink-100 px-5 py-4">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 className="font-bold text-ink-900">Firm administrators</h2>
            <p className="text-sm text-ink-500">
              Invite <strong>admin</strong> users for <code className="rounded bg-ink-100 px-1">{firmSlug}</code>.
              MFA is on by default.
            </p>
          </div>
          <div className="flex flex-wrap items-end gap-2">
            <div className="min-w-[200px]">
              <Field label="Admin email">
                <Input
                  type="email"
                  value={form.email}
                  onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))}
                  placeholder="admin@company.com"
                />
              </Field>
            </div>
            <label className="flex items-center gap-2 pb-2 text-sm text-ink-700">
              <input
                type="checkbox"
                checked={form.mfa_enabled}
                onChange={(e) => setForm((f) => ({ ...f, mfa_enabled: e.target.checked }))}
                className="h-4 w-4 rounded border-ink-300 text-brand-600"
              />
              MFA on
            </label>
            <Button variant="brand" loading={adding} disabled={!form.email.trim()} onClick={inviteAdmin}>
              <Plus className="h-4 w-4" /> Invite admin
            </Button>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="p-8">
          <Spinner />
        </div>
      ) : users.length === 0 ? (
        <p className="px-5 py-12 text-center text-sm text-ink-400">No users yet. Invite a firm administrator.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="table-head border-b border-brand-300/70 text-xs uppercase tracking-wider text-ink-700">
                <th className="px-5 py-3 font-semibold">Email</th>
                <th className="px-5 py-3 font-semibold">Roles</th>
                <th className="px-5 py-3 font-semibold">Status</th>
                <th className="px-5 py-3 font-semibold">MFA</th>
                <th className="px-5 py-3 text-right font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-100">
              {users.map((u) => (
                <tr key={u.id} className="hover:bg-ink-50/60">
                  <td className="px-5 py-3 font-medium text-ink-800">{u.email}</td>
                  <td className="px-5 py-3 text-ink-600">{u.roles.join(", ") || "—"}</td>
                  <td className="px-5 py-3">
                    <Badge tone={u.status === "active" ? "green" : u.status === "pending" ? "amber" : "red"}>
                      {u.status}
                    </Badge>
                  </td>
                  <td className="px-5 py-3">
                    <button
                      type="button"
                      onClick={() => toggleMfa(u)}
                      className="text-xs font-semibold text-brand-700 hover:underline"
                    >
                      {u.mfa_enabled ? "on" : "off"}
                    </button>
                  </td>
                  <td className="px-5 py-3">
                    <div className="flex justify-end gap-1">
                      {u.status === "pending" && (
                        <Button variant="ghost" className="!px-2 !py-1 text-xs" onClick={() => resendInvite(u)}>
                          <Mail className="h-3.5 w-3.5" /> Resend
                        </Button>
                      )}
                      {u.status !== "disabled" && (
                        <Button variant="ghost" className="!px-2 !py-1 text-xs text-red-600" onClick={() => suspendUser(u)}>
                          Suspend
                        </Button>
                      )}
                      <Button variant="ghost" className="!px-2 !py-1 text-xs text-red-600" onClick={() => deleteUser(u)}>
                        <Trash2 className="h-3.5 w-3.5" />
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
  );
}

function FirmRolesTab({ firmId }: { firmId: string }) {
  const toast = useToast();
  const { confirm } = useConfirm();
  const [roles, setRoles] = useState<Role[]>([]);
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<Role | null>(null);
  const base = `/api/tenants/${firmId}`;

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [r, p] = await Promise.all([
        api.get<Role[]>(`${base}/roles`),
        api.get<Permission[]>(`${base}/permissions`),
      ]);
      setRoles(r);
      setPermissions(p);
    } catch (e: any) {
      toast.error(e?.message || "Failed to load roles");
    } finally {
      setLoading(false);
    }
  }, [base, toast]);

  useEffect(() => {
    void load();
  }, [load]);

  async function onDelete(r: Role) {
    const ok = await confirm({
      title: "Delete role",
      message: `Delete role "${r.name}"?`,
      confirmLabel: "Delete",
      variant: "danger",
    });
    if (!ok) return;
    try {
      await api.del(`${base}/roles/${r.id}`);
      toast.success("Role deleted");
      load();
    } catch (e: any) {
      toast.error(e?.message || "Delete failed");
    }
  }

  return (
    <div>
      <div className="mb-4 flex justify-end">
        <Button variant="brand" onClick={() => setCreating(true)}>
          <Plus className="h-4 w-4" /> New role
        </Button>
      </div>
      {loading ? (
        <Spinner />
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {roles.map((r) => (
            <Card key={r.id} className="flex flex-col">
              <div className="flex items-start justify-between border-b border-ink-100 px-5 py-4">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="h-5 w-5 text-brand-600" />
                  <div>
                    <h3 className="font-bold text-ink-900">{r.name}</h3>
                    {r.is_system && (
                      <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-ink-400">
                        <Lock className="h-3 w-3" /> system role
                      </span>
                    )}
                  </div>
                </div>
                {!r.is_system && (
                  <div className="flex gap-1">
                    <button
                      type="button"
                      onClick={() => setEditing(r)}
                      className="rounded-lg p-1.5 text-ink-400 hover:bg-ink-100 hover:text-ink-700"
                    >
                      <Pencil className="h-4 w-4" />
                    </button>
                    <button
                      type="button"
                      onClick={() => onDelete(r)}
                      className="rounded-lg p-1.5 text-ink-400 hover:bg-red-50 hover:text-red-600"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                )}
                {r.is_system && (
                  <button
                    type="button"
                    onClick={() => setEditing(r)}
                    className="rounded-lg p-1.5 text-ink-400 hover:bg-ink-100 hover:text-ink-700"
                  >
                    <Pencil className="h-4 w-4" />
                  </button>
                )}
              </div>
              <div className="flex-1 px-5 py-4">
                <p className="mb-3 text-sm text-ink-500">{r.description || "No description"}</p>
                <div className="flex flex-wrap gap-1.5">
                  {r.permissions.includes("*") ? (
                    <Badge tone="indigo">all permissions</Badge>
                  ) : r.permissions.length === 0 ? (
                    <span className="text-xs text-ink-400">No permissions</span>
                  ) : (
                    r.permissions.slice(0, 6).map((p) => (
                      <code key={p} className="rounded bg-ink-100 px-1.5 py-0.5 text-[11px] text-ink-600">
                        {p}
                      </code>
                    ))
                  )}
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
      {creating && (
        <FirmRoleModal
          firmId={firmId}
          permissions={permissions}
          onClose={() => setCreating(false)}
          onSaved={() => {
            setCreating(false);
            load();
          }}
        />
      )}
      {editing && (
        <FirmRoleModal
          firmId={firmId}
          role={editing}
          permissions={permissions}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            load();
          }}
        />
      )}
    </div>
  );
}

function FirmRoleModal({
  firmId,
  role,
  permissions,
  onClose,
  onSaved,
}: {
  firmId: string;
  role?: Role;
  permissions: Permission[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const toast = useToast();
  const isEdit = !!role;
  const isSystem = role?.is_system;
  const [name, setName] = useState(role?.name || "");
  const [description, setDescription] = useState(role?.description || "");
  const [selected, setSelected] = useState<string[]>(
    role && !role.permissions.includes("*") ? role.permissions : []
  );
  const [loading, setLoading] = useState(false);
  const base = `/api/tenants/${firmId}/roles`;

  function toggle(code: string) {
    setSelected((s) => (s.includes(code) ? s.filter((c) => c !== code) : [...s, code]));
  }

  async function submit() {
    setLoading(true);
    try {
      if (isEdit) {
        await api.patch(`${base}/${role!.id}`, {
          description,
          permission_codes: isSystem ? undefined : selected,
        });
        toast.success("Role updated");
      } else {
        await api.post(base, { name, description, permission_codes: selected });
        toast.success("Role created");
      }
      onSaved();
    } catch (e: any) {
      toast.error(e?.message || "Save failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={isEdit ? `Edit role · ${role!.name}` : "Create role"}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="brand" loading={loading} onClick={submit}>
            {isEdit ? "Save changes" : "Create role"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        {!isEdit && (
          <Field label="Role name">
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. analyst" />
          </Field>
        )}
        <Field label="Description">
          <Input value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
        <Field label="Permissions">
          {isSystem && role?.name === "admin" ? (
            <p className="rounded-lg bg-indigo-50 px-3 py-2 text-sm text-indigo-800">
              Admin role receives all permissions automatically.
            </p>
          ) : isSystem ? (
            <p className="rounded-lg bg-ink-50 px-3 py-2 text-sm text-ink-500">System role permissions cannot be modified.</p>
          ) : (
            <div className="max-h-64 space-y-1 overflow-y-auto rounded-lg border border-ink-200 p-2">
              {permissions.map((p) => (
                <label
                  key={p.id}
                  className="flex cursor-pointer items-center gap-3 rounded-md px-2 py-1.5 hover:bg-ink-50"
                >
                  <input
                    type="checkbox"
                    checked={selected.includes(p.code)}
                    onChange={() => toggle(p.code)}
                    className="h-4 w-4 rounded border-ink-300 text-brand-600"
                  />
                  <code className="text-xs font-semibold text-ink-700">{p.code}</code>
                  <span className="truncate text-xs text-ink-400">{p.description}</span>
                </label>
              ))}
            </div>
          )}
        </Field>
      </div>
    </Modal>
  );
}

function FirmPermissionsTab({ firmId }: { firmId: string }) {
  const toast = useToast();
  const [items, setItems] = useState<Permission[]>([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const base = `/api/tenants/${firmId}/permissions`;

  async function load() {
    setLoading(true);
    try {
      setItems(await api.get<Permission[]>(base));
    } catch (e: any) {
      toast.error(e?.message || "Failed to load permissions");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, [firmId]);

  const grouped = items.reduce<Record<string, Permission[]>>((acc, p) => {
    (acc[p.resource] ||= []).push(p);
    return acc;
  }, {});

  return (
    <div>
      <div className="mb-4 flex justify-end">
        <Button variant="brand" onClick={() => setOpen(true)}>
          <Plus className="h-4 w-4" /> New permission
        </Button>
      </div>
      {loading ? (
        <Spinner />
      ) : (
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
                      <code className="rounded bg-ink-100 px-1.5 py-0.5 text-xs font-semibold text-ink-700">{p.code}</code>
                      <Badge tone="neutral">{p.action}</Badge>
                    </div>
                    {p.description && <p className="mt-1 text-xs text-ink-400">{p.description}</p>}
                  </li>
                ))}
              </ul>
            </Card>
          ))}
        </div>
      )}
      {open && (
        <CreateFirmPermissionModal
          base={base}
          onClose={() => setOpen(false)}
          onCreated={() => {
            setOpen(false);
            load();
          }}
        />
      )}
    </div>
  );
}

function CreateFirmPermissionModal({
  base,
  onClose,
  onCreated,
}: {
  base: string;
  onClose: () => void;
  onCreated: () => void;
}) {
  const toast = useToast();
  const [resource, setResource] = useState("");
  const [action, setAction] = useState("");
  const [description, setDescription] = useState("");
  const [loading, setLoading] = useState(false);
  const code = resource && action ? `${resource}:${action}` : "";

  async function submit() {
    setLoading(true);
    try {
      await api.post(base, { code, resource, action, description });
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
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="brand" loading={loading} disabled={!code} onClick={submit}>
            Create
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Resource">
            <Input value={resource} onChange={(e) => setResource(e.target.value.toLowerCase())} />
          </Field>
          <Field label="Action">
            <Input value={action} onChange={(e) => setAction(e.target.value.toLowerCase())} />
          </Field>
        </div>
        <Field label="Code">
          <Input value={code} readOnly className="bg-ink-50 font-mono text-sm" />
        </Field>
        <Field label="Description">
          <Input value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
      </div>
    </Modal>
  );
}
