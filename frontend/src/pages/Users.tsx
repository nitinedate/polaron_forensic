import { useCallback, useEffect, useMemo, useState } from "react";
import { ChevronLeft, ChevronRight, Mail, Pencil, Plus, Search, Shield, Trash2 } from "lucide-react";
import { Badge, Button, Card, Field, Input, LoadPanel, Modal, PageHeader, Select, Spinner } from "../components/ui";
import { RoleMultiSelect, filterSelectableRoles } from "../components/RoleMultiSelect";
import { InsightCharts } from "../components/charts";
import { countBy } from "../lib/chartCounts";
import { api } from "../lib/api";
import { useConfirm } from "../lib/confirm";
import { useToast } from "../lib/toast";
import { useAuth } from "../lib/auth";
import type { Role, User, UserList } from "../lib/types";

const PAGE_SIZE = 10;

export function Users() {
  const toast = useToast();
  const { confirm } = useConfirm();
  const { hasPermission } = useAuth();
  const canCreate = hasPermission("user:create");
  const canUpdate = hasPermission("user:update");
  const canReadRoles = hasPermission("role:read");

  const [data, setData] = useState<UserList | null>(null);
  const [chartUsers, setChartUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [roles, setRoles] = useState<Role[]>([]);

  const [createOpen, setCreateOpen] = useState(false);
  const [editUser, setEditUser] = useState<User | null>(null);
  const [rolesUser, setRolesUser] = useState<User | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const res = await api.get<UserList>("/api/users", { page, page_size: PAGE_SIZE, search }, { timeoutMs: 8_000 });
      setData(res);
    } catch (e: any) {
      setLoadError(e?.message || "Failed to load users");
    } finally {
      setLoading(false);
    }
  }, [page, search]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    api
      .get<UserList>("/api/users", { page: 1, page_size: 100 })
      .then((res) => setChartUsers(res.items))
      .catch(() => setChartUsers([]));
  }, []);

  useEffect(() => {
    if (!canReadRoles) return;
    api
      .get<Role[]>("/api/roles")
      .then((list) => setRoles(filterSelectableRoles(list)))
      .catch((e: { message?: string }) => toast.error(e?.message || "Failed to load roles"));
  }, [canReadRoles, toast]);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  const selectableRoles = roles;
  const statusSeries = useMemo(() => countBy(chartUsers, (u) => u.status), [chartUsers]);
  const mfaSeries = useMemo(
    () => countBy(chartUsers, (u) => (u.mfa_enabled ? "MFA on" : "MFA off")),
    [chartUsers],
  );

  async function onResendInvite(u: User) {
    try {
      await api.post(`/api/users/${u.id}/invite`);
      toast.success("Invitation resent");
    } catch (e: any) {
      toast.error(e?.message || "Resend failed");
    }
  }

  async function onDelete(u: User) {
    const ok = await confirm({
      title: "Deactivate user",
      message: `Deactivate ${u.email}? The account will be soft-deleted and can no longer sign in.`,
      confirmLabel: "Deactivate",
      variant: "danger",
    });
    if (!ok) return;
    try {
      await api.del(`/api/users/${u.id}`);
      toast.success("User deactivated");
      load();
    } catch (e: any) {
      toast.error(e?.message || "Delete failed");
    }
  }

  return (
    <div>
      <PageHeader
        title="Users"
        subtitle="Create, update, and manage user accounts and their access."
        actions={
          canCreate && (
            <Button variant="brand" onClick={() => setCreateOpen(true)}>
              <Plus className="h-4 w-4" /> New user
            </Button>
          )
        }
      />

      {chartUsers.length > 0 && (
        <InsightCharts
          left={{ title: "Account status", subtitle: "From /api/users", data: statusSeries, kind: "bar" }}
          right={{ title: "MFA coverage", subtitle: "Live user mix", data: mfaSeries, kind: "donut", centerLabel: "Users" }}
        />
      )}

      <Card className="overflow-hidden">
        <div className="flex items-center gap-3 border-b border-ink-100 p-4">
          <div className="relative flex-1 max-w-sm">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-400" />
            <Input
              className="pl-9"
              placeholder="Search by email or username"
              value={search}
              onChange={(e) => {
                setPage(1);
                setSearch(e.target.value);
              }}
            />
          </div>
          {data && <span className="text-sm text-ink-400">{data.total} total</span>}
        </div>

        <LoadPanel
          loading={loading}
          error={loadError}
          hasData={Boolean(data?.items.length)}
          onRetry={() => void load()}
          empty={<p className="px-5 py-16 text-center text-sm text-ink-400">No users found.</p>}
        >
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="table-head border-b border-brand-300/70 text-xs uppercase tracking-wider text-ink-700">
                  <th className="px-5 py-3 font-semibold">User</th>
                  <th className="px-5 py-3 font-semibold">Status</th>
                  <th className="px-5 py-3 font-semibold">MFA</th>
                  <th className="px-5 py-3 font-semibold">Verified</th>
                  <th className="px-5 py-3 font-semibold">Created</th>
                  <th className="px-5 py-3 text-right font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-100">
                {(data?.items ?? []).map((u) => (
                  <tr key={u.id} className="hover:bg-ink-50/60">
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-3">
                        <div className="flex h-9 w-9 items-center justify-center rounded-full bg-ink-900 text-xs font-bold text-white">
                          {u.email.slice(0, 1).toUpperCase()}
                        </div>
                        <div className="min-w-0">
                          <p className="truncate font-semibold text-ink-800">
                            {u.profile?.first_name
                              ? `${u.profile.first_name} ${u.profile.last_name ?? ""}`
                              : u.username || "—"}
                          </p>
                          <p className="truncate text-xs text-ink-400">{u.email}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-5 py-3">
                      <Badge tone={u.status === "active" ? "green" : u.status === "locked" ? "red" : "amber"}>
                        {u.status}
                      </Badge>
                    </td>
                    <td className="px-5 py-3">
                      {u.mfa_enabled ? <Badge tone="indigo">on</Badge> : <span className="text-ink-400">off</span>}
                    </td>
                    <td className="px-5 py-3">
                      {u.is_email_verified ? (
                        <Badge tone="green">yes</Badge>
                      ) : (
                        <Badge tone="amber">no</Badge>
                      )}
                    </td>
                    <td className="px-5 py-3 text-ink-500">
                      {new Date(u.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-5 py-3">
                      {canUpdate ? (
                        <div className="flex items-center justify-end gap-1">
                          <button
                            title="Manage roles"
                            onClick={() => setRolesUser(u)}
                            className="rounded-lg p-2 text-ink-400 hover:bg-ink-100 hover:text-ink-700"
                          >
                            <Shield className="h-4 w-4" />
                          </button>
                          <button
                            title="Edit"
                            onClick={() => setEditUser(u)}
                            className="rounded-lg p-2 text-ink-400 hover:bg-ink-100 hover:text-ink-700"
                          >
                            <Pencil className="h-4 w-4" />
                          </button>
                          {u.status === "pending" && canCreate && (
                            <button
                              title="Resend invite"
                              onClick={() => onResendInvite(u)}
                              className="rounded-lg p-2 text-ink-400 hover:bg-ink-100 hover:text-ink-700"
                            >
                              <Mail className="h-4 w-4" />
                            </button>
                          )}
                          <button
                            title="Deactivate"
                            onClick={() => onDelete(u)}
                            className="rounded-lg p-2 text-ink-400 hover:bg-red-50 hover:text-red-600"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                      ) : (
                        <span className="block text-right text-xs text-ink-400">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </LoadPanel>

        <div className="flex items-center justify-between border-t border-ink-100 px-5 py-3">
          <span className="text-sm text-ink-400">
            Page {page} of {totalPages}
          </span>
          <div className="flex gap-1">
            <Button variant="outline" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <Button variant="outline" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </Card>

      {createOpen && (
        <CreateUserModal
          roles={selectableRoles}
          onClose={() => setCreateOpen(false)}
          onCreated={() => {
            setCreateOpen(false);
            load();
          }}
        />
      )}
      {editUser && (
        <EditUserModal
          user={editUser}
          onClose={() => setEditUser(null)}
          onSaved={() => {
            setEditUser(null);
            load();
          }}
        />
      )}
      {rolesUser && (
        <RolesModal roles={selectableRoles} user={rolesUser} onClose={() => setRolesUser(null)} />
      )}
    </div>
  );
}

function CreateUserModal({
  roles: initialRoles,
  onClose,
  onCreated,
}: {
  roles: Role[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const toast = useToast();
  const [roles, setRoles] = useState<Role[]>(initialRoles);
  const [rolesLoading, setRolesLoading] = useState(initialRoles.length === 0);
  const [form, setForm] = useState({
    email: "",
    first_name: "",
    last_name: "",
    phone: "",
    role_ids: [] as string[],
    mfa_enabled: true,
  });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setRolesLoading(true);
    api
      .get<Role[]>("/api/roles")
      .then((list) => {
        if (cancelled) return;
        const selectable = filterSelectableRoles(list);
        setRoles(selectable);
        const defaultRole = selectable.find((r) => r.name === "user") ?? selectable[0];
        if (defaultRole) {
          setForm((prev) => (prev.role_ids.length ? prev : { ...prev, role_ids: [defaultRole.id] }));
        }
      })
      .catch((e: { message?: string }) => toast.error(e?.message || "Failed to load roles"))
      .finally(() => {
        if (!cancelled) setRolesLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [toast]);

  async function submit() {
    if (!form.role_ids.length) {
      toast.error("Select at least one role");
      return;
    }
    setLoading(true);
    try {
      await api.post("/api/users", {
        email: form.email,
        status: "pending",
        mfa_enabled: form.mfa_enabled,
        profile: { first_name: form.first_name, last_name: form.last_name, phone: form.phone || null },
        role_ids: form.role_ids,
      });
      toast.success("Invitation sent");
      onCreated();
    } catch (e: any) {
      toast.error(e?.message || "Create failed");
    } finally {
      setLoading(false);
    }
  }

  const canSubmit = Boolean(form.email.trim()) && form.role_ids.length > 0 && !rolesLoading;

  return (
    <Modal
      open
      onClose={onClose}
      title="Invite user"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="brand" loading={loading} disabled={!canSubmit} onClick={submit}>
            Send invite
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <Field label="First name">
            <Input value={form.first_name} onChange={(e) => setForm({ ...form, first_name: e.target.value })} />
          </Field>
          <Field label="Last name">
            <Input value={form.last_name} onChange={(e) => setForm({ ...form, last_name: e.target.value })} />
          </Field>
        </div>
        <Field label="Email">
          <Input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
        </Field>
        <p className="text-sm text-ink-500">
          An email invitation will be sent so the user can set their password and activate their account.
        </p>
        <Field label="Phone (encrypted at rest)">
          <Input value={form.phone} onChange={(e) => setForm({ ...form, phone: e.target.value })} />
        </Field>
        <Field
          label="Initial roles"
          hint={
            form.role_ids.length
              ? `${form.role_ids.length} role${form.role_ids.length === 1 ? "" : "s"} selected`
              : "Select one or more roles for this user"
          }
        >
          <RoleMultiSelect
            roles={roles}
            selectedIds={form.role_ids}
            onChange={(role_ids) => setForm((prev) => ({ ...prev, role_ids }))}
            loading={rolesLoading}
          />
        </Field>
        <label className="flex cursor-pointer items-center gap-3 rounded-lg border border-ink-200 bg-ink-50/50 px-3 py-2.5">
          <input
            type="checkbox"
            className="h-4 w-4 rounded border-ink-300 text-brand-600 focus:ring-brand-500"
            checked={form.mfa_enabled}
            onChange={(e) => setForm((prev) => ({ ...prev, mfa_enabled: e.target.checked }))}
          />
          <div>
            <p className="text-sm font-semibold text-ink-800">Require MFA</p>
            <p className="text-xs text-ink-500">Recommended for firm administrators. Can be changed later.</p>
          </div>
        </label>
      </div>
    </Modal>
  );
}

function EditUserModal({
  user,
  onClose,
  onSaved,
}: {
  user: User;
  onClose: () => void;
  onSaved: () => void;
}) {
  const toast = useToast();
  const [form, setForm] = useState({
    status: user.status,
    first_name: user.profile?.first_name || "",
    last_name: user.profile?.last_name || "",
    phone: user.profile?.phone || "",
    mfa_enabled: user.mfa_enabled,
  });
  const [loading, setLoading] = useState(false);

  async function submit() {
    setLoading(true);
    try {
      await api.patch(`/api/users/${user.id}`, {
        status: form.status,
        mfa_enabled: form.mfa_enabled,
        profile: { first_name: form.first_name, last_name: form.last_name, phone: form.phone || null },
      });
      toast.success("User updated");
      onSaved();
    } catch (e: any) {
      toast.error(e?.message || "Update failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={`Edit ${user.email}`}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="brand" loading={loading} onClick={submit}>
            Save changes
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <Field label="First name">
            <Input value={form.first_name} onChange={(e) => setForm({ ...form, first_name: e.target.value })} />
          </Field>
          <Field label="Last name">
            <Input value={form.last_name} onChange={(e) => setForm({ ...form, last_name: e.target.value })} />
          </Field>
        </div>
        <Field label="Phone">
          <Input value={form.phone} onChange={(e) => setForm({ ...form, phone: e.target.value })} />
        </Field>
        <Field label="Status">
          <Select value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value as User["status"] })}>
            <option value="active">active</option>
            <option value="disabled">disabled (suspended)</option>
            <option value="locked">locked</option>
            <option value="pending">pending</option>
          </Select>
        </Field>
        <label className="flex cursor-pointer items-center gap-3 rounded-lg border border-ink-200 bg-ink-50/50 px-3 py-2.5">
          <input
            type="checkbox"
            className="h-4 w-4 rounded border-ink-300 text-brand-600 focus:ring-brand-500"
            checked={form.mfa_enabled}
            onChange={(e) => setForm({ ...form, mfa_enabled: e.target.checked })}
          />
          <div>
            <p className="text-sm font-semibold text-ink-800">MFA required at sign-in</p>
            <p className="text-xs text-ink-500">Uncheck to allow sign-in without MFA (user must enroll again if re-enabled).</p>
          </div>
        </label>
      </div>
    </Modal>
  );
}

function RolesModal({ roles, user, onClose }: { roles: Role[]; user: User; onClose: () => void }) {
  const toast = useToast();
  const [assigned, setAssigned] = useState<Role[]>([]);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.get<Role[]>(`/api/authz/users/${user.id}/roles`);
      setAssigned(r);
    } finally {
      setLoading(false);
    }
  }, [user.id]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const assignedIds = new Set(assigned.map((r) => r.id));

  async function toggle(role: Role) {
    try {
      if (assignedIds.has(role.id)) {
        await api.del(`/api/authz/users/${user.id}/roles/${role.id}`);
        toast.success(`Removed ${role.name}`);
      } else {
        await api.post(`/api/authz/users/${user.id}/roles`, { role_id: role.id });
        toast.success(`Assigned ${role.name}`);
      }
      refresh();
    } catch (e: any) {
      toast.error(e?.message || "Failed to update role");
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={`Roles · ${user.email}`}
      footer={
        <Button variant="primary" onClick={onClose}>
          Done
        </Button>
      }
    >
      {loading ? (
        <Spinner />
      ) : (
        <div className="space-y-2">
          {roles.map((r) => {
            const on = assignedIds.has(r.id);
            return (
              <button
                key={r.id}
                onClick={() => toggle(r)}
                className={
                  "flex w-full items-center justify-between rounded-lg border px-4 py-3 text-left transition " +
                  (on ? "border-brand-300 bg-brand-50" : "border-ink-200 hover:bg-ink-50")
                }
              >
                <div>
                  <p className="text-sm font-semibold text-ink-800">{r.name}</p>
                  <p className="text-xs text-ink-400">{r.description || "—"}</p>
                </div>
                <Badge tone={on ? "green" : "neutral"}>{on ? "assigned" : "assign"}</Badge>
              </button>
            );
          })}
        </div>
      )}
    </Modal>
  );
}
