import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Building2, KeyRound, ShieldCheck, UserCheck, UserCircle, Users } from "lucide-react";
import { StatCard } from "../components/StatCard";
import { Card, PageHeader, Badge } from "../components/ui";
import { ChartCard, MetricBarChart, MetricDonutChart } from "../components/charts";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import type { Permission, Role, Tenant, UserList } from "../lib/types";
import { VulnOverviewHubs } from "../components/vuln/VulnOverviewHubs";
import { aetherisService, isDedicatedMobileService, isForensicService, isLegacyMobileExtractService, isUnifiedService, isVulnService, mobilePlatformService } from "../lib/serviceMode";
import { forensicApi } from "../lib/forensicApi";
import type { Job } from "../lib/types/forensic";
import { countBy } from "../lib/chartCounts";

function NumberOnly({ label, value }: { label: string; value: number | string }) {
  return (
    <div>
      <p className="text-xs font-medium uppercase tracking-wide text-ink-400">{label}</p>
      <p className="mt-1 text-2xl font-bold tabular-nums text-ink-900">{value}</p>
    </div>
  );
}

interface Stats {
  users: number;
  roles: number;
  permissions: number;
  firms: number;
}

export function Dashboard() {
  const { user, isSuperAdmin, hasPermission } = useAuth();
  const canViewUsers = hasPermission("user:read");
  const canViewRoles = hasPermission("role:read");
  const canViewJobs = hasPermission("job:read");
  const [stats, setStats] = useState<Stats | null>(null);
  const [recent, setRecent] = useState<UserList["items"]>([]);
  const [systemRoles, setSystemRoles] = useState<Role[]>([]);
  const [firms, setFirms] = useState<Tenant[]>([]);
  const [users, setUsers] = useState<UserList["items"]>([]);
  const [diskJobs, setDiskJobs] = useState<Job[]>([]);
  const [mobileJobs, setMobileJobs] = useState<Job[]>([]);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        if (isSuperAdmin) {
          const tenantList = await api.get<Tenant[]>("/api/tenants", undefined, { timeoutMs: 8_000 });
          if (cancelled) return;
          setFirms(tenantList);
          setStats({ users: 0, roles: 0, permissions: 0, firms: tenantList.length });
        } else if (canViewUsers) {
          const [recentUsers, allUsers, roles, perms] = await Promise.all([
            api.get<UserList>("/api/users", { page: 1, page_size: 5 }, { timeoutMs: 8_000 }),
            api.get<UserList>("/api/users", { page: 1, page_size: 100 }, { timeoutMs: 8_000 }),
            canViewRoles ? api.get<Role[]>("/api/roles", undefined, { timeoutMs: 8_000 }) : Promise.resolve([]),
            hasPermission("permission:read")
              ? api.get<Permission[]>("/api/permissions", undefined, { timeoutMs: 8_000 })
              : Promise.resolve([]),
          ]);
          if (cancelled) return;
          setStats({
            users: recentUsers.total,
            roles: roles.length,
            permissions: perms.length,
            firms: 0,
          });
          setRecent(recentUsers.items);
          setUsers(allUsers.items);
          setSystemRoles(roles);
        }
      } catch {
        /* keep the dashboard shell; widgets fill in when the API answers */
      }
    })();

    if (canViewJobs && isForensicService()) {
      void forensicApi
        .listJobs({ page: 1, page_size: 100 }, { service: "forensic" })
        .then((res) => {
          if (!cancelled) setDiskJobs(res.items);
        })
        .catch(() => {
          if (!cancelled) setDiskJobs([]);
        });
    }
    if (canViewJobs && (isUnifiedService() || isDedicatedMobileService() || isLegacyMobileExtractService())) {
      if (isUnifiedService()) {
        void Promise.allSettled([
          forensicApi.listJobs({ page: 1, page_size: 100 }, { service: "mobile-android" }),
          forensicApi.listJobs({ page: 1, page_size: 100 }, { service: "mobile-ios" }),
        ]).then((results) => {
          if (cancelled) return;
          const merged: Job[] = [];
          for (const result of results) if (result.status === "fulfilled") merged.push(...result.value.items);
          setMobileJobs(merged);
        });
      } else {
        const platform = mobilePlatformService();
        const service =
          platform === "android" ? "mobile-android" :
          platform === "ios" ? "mobile-ios" :
          "mobile-extract";
        const type = platform ? `${platform}_mobile` : "mobile_extraction";
        void forensicApi
          .listJobs({ page: 1, page_size: 100, type }, { service })
          .then((res) => { if (!cancelled) setMobileJobs(res.items); })
          .catch(() => { if (!cancelled) setMobileJobs([]); });
      }
    }

    return () => {
      cancelled = true;
    };
  }, [isSuperAdmin, canViewUsers, canViewRoles, canViewJobs, hasPermission]);

  const userStatusCounts = useMemo(() => countBy(users, (u) => u.status), [users]);
  const firmStatusSeries = useMemo(() => countBy(firms, (f) => f.status), [firms]);
  const diskStatusSeries = useMemo(() => countBy(diskJobs, (j) => j.status), [diskJobs]);
  const mobileStatusSeries = useMemo(() => countBy(mobileJobs, (j) => j.status), [mobileJobs]);

  return (
    <div>
      <PageHeader
        title={`Welcome back${user?.profile?.first_name ? ", " + user.profile.first_name : ""}`}
        subtitle={
          isSuperAdmin
            ? "Platform overview — open a firm’s IAM console to manage users, roles, and permissions."
            : canViewUsers
              ? "Manage users, roles, and permissions for your organization."
              : "View and update your profile and security settings."
        }
      />

      {isSuperAdmin ? (
        <>
          <div className="row g-3 mb-4">
            <div className="col-12 col-sm-6 col-xl-3">
              <StatCard label="Provisioned Firms" value={stats?.firms ?? 0} icon={Building2} />
            </div>
          </div>
          <div className="row g-3 mb-4">
            <div className="col-12 col-lg-7">
              <ChartCard title="Firm status" subtitle="Live from /api/tenants">
                <MetricBarChart data={firmStatusSeries} emptyLabel="No firms provisioned yet" />
              </ChartCard>
            </div>
            <div className="col-12 col-lg-5">
              <ChartCard title="Plans" subtitle="Tenant plan mix">
                <MetricDonutChart data={countBy(firms, (f) => f.plan || "standard")} centerLabel="Firms" />
              </ChartCard>
            </div>
          </div>
          <Card>
            <div className="flex items-center justify-between border-b border-ink-100 px-5 py-4">
              <h3 className="font-bold text-ink-900">Recent firms</h3>
              <Link to="/tenants" className="text-sm font-semibold text-brand-700 hover:text-brand-800">
                Manage firms
              </Link>
            </div>
            {firms.length === 0 ? (
              <p className="px-5 py-8 text-center text-sm text-ink-400">No firms provisioned yet.</p>
            ) : (
              <ul className="divide-y divide-ink-100">
                {firms.slice(0, 5).map((f) => (
                  <li key={f.id} className="flex items-center justify-between px-5 py-3.5">
                    <div>
                      <p className="text-sm font-semibold text-ink-800">{f.name}</p>
                      <p className="text-xs text-ink-400">{f.slug}</p>
                    </div>
                    <div className="flex items-center gap-3">
                      <Link
                        to={`/tenants/${f.id}/iam`}
                        className="text-sm font-semibold text-brand-700 hover:text-brand-800"
                      >
                        Manage IAM
                      </Link>
                      <Badge tone={f.status === "active" ? "green" : "red"}>{f.status}</Badge>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </>
      ) : canViewUsers ? (
        <>
          <div className="row g-3 mb-4">
            <div className="col-12 col-sm-6 col-xl-3">
              <StatCard label="Total Users" value={stats?.users ?? 0} icon={Users} />
            </div>
            <div className="col-12 col-sm-6 col-xl-3">
              <StatCard label="Roles" value={stats?.roles ?? 0} icon={ShieldCheck} />
            </div>
            <div className="col-12 col-sm-6 col-xl-3">
              <StatCard label="Permissions" value={stats?.permissions ?? 0} icon={KeyRound} />
            </div>
            <div className="col-12 col-sm-6 col-xl-3">
              <StatCard label="Your MFA" value={user?.mfa_enabled ? "Enabled" : "Off"} icon={UserCheck} />
            </div>
          </div>

          <div className="row g-3 mb-4">
            <div className="col-12 col-lg-3">
              <Card className="h-full">
                <div className="border-b border-ink-100 px-5 py-3">
                  <h3 className="font-bold text-ink-900">Identity inventory</h3>
                </div>
                <div className="grid grid-cols-3 gap-2 px-5 py-4">
                  <NumberOnly label="Users" value={stats?.users ?? 0} />
                  <NumberOnly label="Roles" value={stats?.roles ?? 0} />
                  <NumberOnly label="Permissions" value={stats?.permissions ?? 0} />
                </div>
              </Card>
            </div>
            <div className="col-12 col-lg-3">
              <Card className="h-full">
                <div className="border-b border-ink-100 px-5 py-3">
                  <h3 className="font-bold text-ink-900">User status</h3>
                </div>
                <div className="grid grid-cols-2 gap-2 px-5 py-4 sm:grid-cols-3">
                  {userStatusCounts.length === 0 ? (
                    <p className="col-span-full text-sm text-ink-400">No users yet.</p>
                  ) : (
                    userStatusCounts.map((row) => (
                      <NumberOnly key={row.name} label={row.name} value={row.value} />
                    ))
                  )}
                </div>
              </Card>
            </div>
            <div className="col-12 col-lg-3">
              <Card className="h-full">
                <div className="border-b border-ink-100 px-5 py-3">
                  <h3 className="font-bold text-ink-900">Permissions per role</h3>
                </div>
                <div className="space-y-2 px-5 py-4">
                  {systemRoles.length === 0 ? (
                    <p className="text-sm text-ink-400">No roles found.</p>
                  ) : (
                    systemRoles.map((r) => (
                      <div key={r.id} className="flex items-center justify-between">
                        <span className="text-sm font-medium text-ink-700">{r.name}</span>
                        <span className="text-lg font-bold tabular-nums text-ink-900">{r.permissions.length}</span>
                      </div>
                    ))
                  )}
                </div>
              </Card>
            </div>
            <div className="col-12 col-lg-3">
              <Card className="h-full">
                <div className="flex items-center gap-2 border-b border-ink-100 px-5 py-3">
                  <ShieldCheck className="h-4 w-4 text-brand-600" />
                  <h3 className="font-bold text-ink-900">System roles</h3>
                </div>
                <div className="space-y-2 px-5 py-4">
                  {systemRoles.length === 0 ? (
                    <p className="text-sm text-ink-400">No roles found.</p>
                  ) : (
                    systemRoles.map((r) => (
                      <div key={r.id} className="flex items-center justify-between">
                        <span className="text-sm font-medium text-ink-700">{r.name}</span>
                        <span className="text-lg font-bold tabular-nums text-ink-900">{r.permissions.length}</span>
                      </div>
                    ))
                  )}
                </div>
              </Card>
            </div>
          </div>
        </>
      ) : (
        <Card className="mt-2 max-w-xl">
          <div className="flex items-start gap-4 p-6">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-brand-50 text-brand-600">
              <UserCircle className="h-6 w-6" />
            </div>
            <div>
              <h3 className="font-bold text-ink-900">Your account</h3>
              <p className="mt-1 text-sm text-ink-500">
                You can view and edit your profile and manage password / MFA settings. User management is
                restricted to firm administrators.
              </p>
              <div className="mt-4 flex flex-wrap gap-2">
                <Link
                  to="/profile"
                  className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-700"
                >
                  My profile
                </Link>
                <Link
                  to="/security"
                  className="rounded-lg border border-ink-200 px-4 py-2 text-sm font-semibold text-ink-700 hover:bg-ink-50"
                >
                  Security &amp; MFA
                </Link>
              </div>
            </div>
          </div>
        </Card>
      )}

      {canViewJobs && (isForensicService() || isUnifiedService() || isDedicatedMobileService() || isLegacyMobileExtractService()) && (
        <div className="row g-3 mt-2">
          {isForensicService() && (
            <div className={(isUnifiedService() || isDedicatedMobileService() || isLegacyMobileExtractService()) ? "col-12 col-lg-6" : "col-12"}>
              <ChartCard title="Disk jobs" subtitle="Live from /api/jobs">
                <MetricDonutChart data={diskStatusSeries} centerLabel="Jobs" emptyLabel="No disk jobs yet" />
              </ChartCard>
            </div>
          )}
          {(isUnifiedService() || isDedicatedMobileService() || isLegacyMobileExtractService()) && (
            <div className={isForensicService() ? "col-12 col-lg-6" : "col-12"}>
              <ChartCard
                title={`${isUnifiedService() ? "Mobile" : mobilePlatformService() === "ios" ? "iOS" : mobilePlatformService() === "android" ? "Android" : "Mobile"} jobs`}
                subtitle={isUnifiedService() ? "Android + iOS isolated APIs" : `Live from ${aetherisService()} API`}
              >
                <MetricDonutChart data={mobileStatusSeries} centerLabel="Jobs" emptyLabel="No mobile jobs yet" />
              </ChartCard>
            </div>
          )}
        </div>
      )}

      {isVulnService() && <VulnOverviewHubs />}

      {canViewUsers && !isSuperAdmin && (
        <Card className="mt-4">
          <div className="flex items-center justify-between border-b border-ink-100 px-5 py-4">
            <h3 className="font-bold text-ink-900">Recent users</h3>
            <Link to="/users" className="text-sm font-semibold text-brand-700 hover:text-brand-800">
              View all
            </Link>
          </div>
          {recent.length === 0 ? (
            <p className="px-5 py-8 text-center text-sm text-ink-400">No users yet.</p>
          ) : (
            <ul className="divide-y divide-ink-100">
              {recent.map((u) => (
                <li key={u.id} className="flex items-center gap-3 px-5 py-3.5">
                  <div className="flex h-9 w-9 items-center justify-center rounded-full bg-ink-900 text-xs font-bold text-white">
                    {u.email.slice(0, 1).toUpperCase()}
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-semibold text-ink-800">
                      {u.profile?.first_name
                        ? `${u.profile.first_name} ${u.profile.last_name ?? ""}`
                        : u.email}
                    </p>
                    <p className="truncate text-xs text-ink-400">{u.email}</p>
                  </div>
                  <Badge tone={u.status === "active" ? "green" : u.status === "locked" ? "red" : "amber"}>
                    {u.status}
                  </Badge>
                </li>
              ))}
            </ul>
          )}
        </Card>
      )}
    </div>
  );
}
