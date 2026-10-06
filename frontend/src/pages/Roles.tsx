import { useEffect, useState } from "react";
import { Lock, Pencil, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { Badge, Button, Card, Field, Input, LoadPanel, Modal, PageHeader } from "../components/ui";
import { InsightCharts } from "../components/charts";
import { countBy, namedValues } from "../lib/chartCounts";
import { api } from "../lib/api";
import { useConfirm } from "../lib/confirm";
import { useToast } from "../lib/toast";
import { useAuth } from "../lib/auth";
import type { Permission, Role } from "../lib/types";

export function Roles() {
  const toast = useToast();
  const { confirm } = useConfirm();
  const { hasPermission } = useAuth();
  const canManage = hasPermission("role:manage");

  const [roles, setRoles] = useState<Role[]>([]);
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [editing, setEditing] = useState<Role | null>(null);
  const [creating, setCreating] = useState(false);

  async function load() {
    setLoading(true);
    setLoadError(null);
    try {
      const [r, p] = await Promise.all([
        api.get<Role[]>("/api/roles", undefined, { timeoutMs: 8_000 }),
        api.get<Permission[]>("/api/permissions", undefined, { timeoutMs: 8_000 }).catch(() => []),
      ]);
      setRoles(r);
      setPermissions(p);
    } catch (e: any) {
      setLoadError(e?.message || "Failed to load roles");
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    load();
  }, []);

  async function onDelete(r: Role) {
    const ok = await confirm({
      title: "Delete role",
      message: `Delete role "${r.name}"? Users assigned to this role will lose its permissions.`,
      confirmLabel: "Delete",
      variant: "danger",
    });
    if (!ok) return;
    try {
      await api.del(`/api/roles/${r.id}`);
      toast.success("Role deleted");
      load();
    } catch (e: any) {
      toast.error(e?.message || "Delete failed");
    }
  }

  return (
    <div>
      <PageHeader
        title="Roles"
        subtitle="Bundle permissions into roles and assign them to users or groups."
        actions={
          canManage && (
            <Button variant="brand" onClick={() => setCreating(true)}>
              <Plus className="h-4 w-4" /> New role
            </Button>
          )
        }
      />
      {!loading && roles.length > 0 && (
        <InsightCharts
          left={{
            title: "Permissions per role",
            subtitle: "From /api/roles",
            data: namedValues(roles.map((r) => ({ name: r.name, value: r.permissions.length }))),
            kind: "bar",
          }}
          right={{
            title: "Role type",
            subtitle: "System vs custom",
            data: countBy(roles, (r) => (r.is_system ? "system" : "custom")),
            kind: "donut",
            centerLabel: "Roles",
          }}
        />
      )}
      <LoadPanel
        loading={loading}
        error={loadError}
        hasData={roles.length > 0}
        onRetry={() => void load()}
        empty={<p className="px-5 py-16 text-center text-sm text-ink-400">No roles found.</p>}
      >
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
                {canManage && !r.is_system && (
                  <div className="flex gap-1">
                    <button
                      onClick={() => setEditing(r)}
                      className="rounded-lg p-1.5 text-ink-400 hover:bg-ink-100 hover:text-ink-700"
                    >
                      <Pencil className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => onDelete(r)}
                      className="rounded-lg p-1.5 text-ink-400 hover:bg-red-50 hover:text-red-600"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                )}
                {canManage && r.is_system && r.name === "admin" && (
                  <button
                    onClick={() => setEditing(r)}
                    className="rounded-lg p-1.5 text-ink-400 hover:bg-ink-100 hover:text-ink-700"
                    title="Edit description"
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
                    r.permissions.slice(0, 8).map((p) => (
                      <code key={p} className="rounded bg-ink-100 px-1.5 py-0.5 text-[11px] text-ink-600">
                        {p}
                      </code>
                    ))
                  )}
                  {r.permissions.length > 8 && (
                    <span className="text-[11px] text-ink-400">+{r.permissions.length - 8} more</span>
                  )}
                </div>
              </div>
            </Card>
          ))}
        </div>
      </LoadPanel>

      {creating && (
        <RoleModal
          permissions={permissions}
          onClose={() => setCreating(false)}
          onSaved={() => {
            setCreating(false);
            load();
          }}
        />
      )}
      {editing && (
        <RoleModal
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

function RoleModal({
  role,
  permissions,
  onClose,
  onSaved,
}: {
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

  function toggle(code: string) {
    setSelected((s) => (s.includes(code) ? s.filter((c) => c !== code) : [...s, code]));
  }

  async function submit() {
    setLoading(true);
    try {
      if (isEdit) {
        await api.patch(`/api/roles/${role!.id}`, {
          description,
          permission_codes: isSystem ? undefined : selected,
        });
        toast.success("Role updated");
      } else {
        await api.post("/api/roles", { name, description, permission_codes: selected });
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
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button variant="brand" loading={loading} onClick={submit}>
            {isEdit ? "Save changes" : "Create role"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        {!isEdit && (
          <Field label="Role name">
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. support_agent" />
          </Field>
        )}
        <Field label="Description">
          <Input value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
        <Field label="Permissions">
          {isSystem && role?.name === "admin" ? (
            <p className="rounded-lg bg-indigo-50 px-3 py-2 text-sm text-indigo-800">
              Firm administrators receive <strong>all permissions</strong> automatically, including any
              custom permissions you create later.
            </p>
          ) : isSystem ? (
            <p className="rounded-lg bg-ink-50 px-3 py-2 text-sm text-ink-500">
              System role permissions cannot be modified.
            </p>
          ) : (
            <div className="max-h-64 space-y-1 overflow-y-auto rounded-lg border border-ink-200 p-2">
              {permissions.map((p) => {
                const on = selected.includes(p.code);
                return (
                  <label
                    key={p.id}
                    className="flex cursor-pointer items-center gap-3 rounded-md px-2 py-1.5 hover:bg-ink-50"
                  >
                    <input
                      type="checkbox"
                      checked={on}
                      onChange={() => toggle(p.code)}
                      className="h-4 w-4 rounded border-ink-300 text-brand-600 focus:ring-brand-500"
                    />
                    <code className="text-xs font-semibold text-ink-700">{p.code}</code>
                    <span className="truncate text-xs text-ink-400">{p.description}</span>
                  </label>
                );
              })}
            </div>
          )}
        </Field>
      </div>
    </Modal>
  );
}
