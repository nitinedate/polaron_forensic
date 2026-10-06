import clsx from "clsx";

import type { Role } from "../lib/types";

const RESERVED_ROLE_NAMES = new Set(["superadmin", "tenant_admin", "super_admin"]);

export function filterSelectableRoles(roles: Role[]): Role[] {
  return roles.filter((r) => !RESERVED_ROLE_NAMES.has(r.name));
}

interface RoleMultiSelectProps {
  roles: Role[];
  selectedIds: string[];
  onChange: (ids: string[]) => void;
  loading?: boolean;
  emptyMessage?: string;
}

export function RoleMultiSelect({
  roles,
  selectedIds,
  onChange,
  loading = false,
  emptyMessage = "No roles available. Create roles under Access Control → Roles first.",
}: RoleMultiSelectProps) {
  if (loading) {
    return <p className="text-sm text-ink-400">Loading roles…</p>;
  }

  if (roles.length === 0) {
    return <p className="rounded-lg border border-dashed border-ink-200 px-3 py-4 text-sm text-ink-500">{emptyMessage}</p>;
  }

  function toggle(id: string) {
    onChange(selectedIds.includes(id) ? selectedIds.filter((x) => x !== id) : [...selectedIds, id]);
  }

  return (
    <div
      className="max-h-52 space-y-1 overflow-y-auto rounded-lg border border-ink-200 bg-ink-50/40 p-2"
      role="group"
      aria-label="Select roles"
    >
      {roles.map((r) => {
        const selected = selectedIds.includes(r.id);
        return (
          <label
            key={r.id}
            className={clsx(
              "flex cursor-pointer items-start gap-3 rounded-lg border px-3 py-2.5 transition",
              selected ? "border-brand-300 bg-brand-50" : "border-transparent bg-white hover:border-ink-200",
            )}
          >
            <input
              type="checkbox"
              className="mt-0.5 h-4 w-4 shrink-0 rounded border-ink-300 text-brand-600 focus:ring-brand-500"
              checked={selected}
              onChange={() => toggle(r.id)}
            />
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold text-ink-800">{r.name}</p>
              {r.description ? <p className="text-xs text-ink-400">{r.description}</p> : null}
            </div>
          </label>
        );
      })}
    </div>
  );
}
