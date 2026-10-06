import { useEffect, useState } from "react";
import { Plus, UserPlus, UsersRound } from "lucide-react";
import { Badge, Button, Card, Field, Input, Modal, PageHeader } from "../components/ui";
import { api } from "../lib/api";
import { useToast } from "../lib/toast";
import { useAuth } from "../lib/auth";
import type { Group, Role, User } from "../lib/types";

export function Groups() {
  const { hasPermission } = useAuth();
  const canManage = hasPermission("role:manage");

  // The API exposes create + add-member but no list endpoint, so we keep a
  // session-local view of groups created here for convenience.
  const [groups, setGroups] = useState<Group[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [creating, setCreating] = useState(false);
  const [memberFor, setMemberFor] = useState<Group | null>(null);

  useEffect(() => {
    api.get<Role[]>("/api/roles").then(setRoles).catch(() => undefined);
  }, []);

  return (
    <div>
      <PageHeader
        title="Groups"
        subtitle="Group users and grant them roles in bulk. Members inherit every role attached to the group."
        actions={
          canManage && (
            <Button variant="brand" onClick={() => setCreating(true)}>
              <Plus className="h-4 w-4" /> New group
            </Button>
          )
        }
      />

      {!canManage && (
        <Card className="px-5 py-4 text-sm text-ink-500">
          You need the <code>role:manage</code> permission to create or modify groups.
        </Card>
      )}

      {groups.length === 0 ? (
        <Card className="px-5 py-16 text-center">
          <UsersRound className="mx-auto mb-3 h-8 w-8 text-ink-300" />
          <p className="text-sm font-semibold text-ink-700">No groups created in this session</p>
          <p className="mt-1 text-sm text-ink-400">
            Create a group to bundle roles and assign members in bulk.
          </p>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {groups.map((g) => (
            <Card key={g.id} className="flex flex-col">
              <div className="flex items-center gap-2 border-b border-ink-100 px-5 py-4">
                <UsersRound className="h-5 w-5 text-brand-600" />
                <h3 className="font-bold text-ink-900">{g.name}</h3>
              </div>
              <div className="flex-1 px-5 py-4">
                <p className="text-sm text-ink-500">{g.description || "No description"}</p>
              </div>
              <div className="border-t border-ink-100 px-5 py-3">
                <Button variant="outline" onClick={() => setMemberFor(g)} className="w-full">
                  <UserPlus className="h-4 w-4" /> Add member
                </Button>
              </div>
            </Card>
          ))}
        </div>
      )}

      {creating && (
        <CreateGroupModal
          roles={roles}
          onClose={() => setCreating(false)}
          onCreated={(g) => {
            setGroups((prev) => [g, ...prev]);
            setCreating(false);
          }}
        />
      )}
      {memberFor && <AddMemberModal group={memberFor} onClose={() => setMemberFor(null)} />}
    </div>
  );
}

function CreateGroupModal({
  roles,
  onClose,
  onCreated,
}: {
  roles: Role[];
  onClose: () => void;
  onCreated: (g: Group) => void;
}) {
  const toast = useToast();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [roleIds, setRoleIds] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);

  async function submit() {
    setLoading(true);
    try {
      const g = await api.post<Group>("/api/groups", { name, description, role_ids: roleIds });
      toast.success("Group created");
      onCreated(g);
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
      title="Create group"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button variant="brand" loading={loading} disabled={!name} onClick={submit}>Create</Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Group name">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Examiners" />
        </Field>
        <Field label="Description">
          <Input value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
        <Field label="Roles granted to members">
          <div className="flex flex-wrap gap-2">
            {roles.map((r) => {
              const on = roleIds.includes(r.id);
              return (
                <button
                  type="button"
                  key={r.id}
                  onClick={() => setRoleIds(on ? roleIds.filter((id) => id !== r.id) : [...roleIds, r.id])}
                  className={
                    "rounded-full border px-3 py-1 text-xs font-semibold transition " +
                    (on ? "border-brand-300 bg-brand-50 text-brand-700" : "border-ink-200 text-ink-500 hover:bg-ink-50")
                  }
                >
                  {r.name}
                </button>
              );
            })}
          </div>
        </Field>
      </div>
    </Modal>
  );
}

function AddMemberModal({ group, onClose }: { group: Group; onClose: () => void }) {
  const toast = useToast();
  const [results, setResults] = useState<User[]>([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => {
      api
        .get<{ items: User[] }>("/api/users", { page: 1, page_size: 8, search })
        .then((r) => setResults(r.items))
        .catch(() => undefined);
    }, 250);
    return () => clearTimeout(t);
  }, [search]);

  async function add(u: User) {
    setLoading(true);
    try {
      await api.post(`/api/groups/${group.id}/members/${u.id}`);
      toast.success(`Added ${u.email} to ${group.name}`);
    } catch (e: any) {
      toast.error(e?.message || "Failed to add member");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={`Add member · ${group.name}`}
      footer={<Button variant="primary" onClick={onClose}>Done</Button>}
    >
      <Field label="Find user">
        <Input
          autoFocus
          placeholder="Search by email"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </Field>
      <div className="mt-3 space-y-1">
        {results.map((u) => (
          <div key={u.id} className="flex items-center justify-between rounded-lg border border-ink-200 px-3 py-2">
            <div>
              <p className="text-sm font-semibold text-ink-800">{u.email}</p>
              <Badge tone={u.status === "active" ? "green" : "amber"}>{u.status}</Badge>
            </div>
            <Button variant="outline" loading={loading} onClick={() => add(u)}>
              <UserPlus className="h-4 w-4" /> Add
            </Button>
          </div>
        ))}
        {results.length === 0 && <p className="py-4 text-center text-sm text-ink-400">No matches.</p>}
      </div>
    </Modal>
  );
}
