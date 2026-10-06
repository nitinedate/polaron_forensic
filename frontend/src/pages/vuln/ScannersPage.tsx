import { useCallback, useEffect, useState } from "react";
import { KeyRound, Pencil, Plus, Server } from "lucide-react";
import { Link } from "react-router-dom";
import { Badge, Button, Card, Field, Input, Modal, PageHeader, Select, Spinner } from "../../components/ui";
import { InsightCharts } from "../../components/charts";
import { countBy } from "../../lib/chartCounts";
import { vulnApi } from "../../lib/vulnApi";
import { useToast } from "../../lib/toast";
import { useAuth } from "../../lib/auth";
import type { NetworkToken, Scanner } from "../../lib/types/vuln";

const ROLE_LABEL: Record<string, string> = {
  persistent_edge: "Persistent Edge",
  portable: "Portable Assessment",
  remote_vpn: "Managed Remote / VPN",
  central: "Central GMP",
};

function scannerRole(s: Scanner): string {
  return (s.scanner_role || "").toLowerCase() || ((s.connection_mode || "").toLowerCase() === "edge_agent" ? "portable" : "central");
}

function formRole(scanner?: Scanner): "persistent_edge" | "portable" | "remote_vpn" | "central" {
  if (!scanner) return "persistent_edge";
  const role = scannerRole(scanner);
  if (role === "portable" || role === "persistent_edge" || role === "remote_vpn" || role === "central") {
    return role;
  }
  return "persistent_edge";
}

function isEdgeRole(role: string): boolean {
  return role === "persistent_edge" || role === "portable";
}

export function ScannersPage() {
  const toast = useToast();
  const { hasPermission } = useAuth();
  const canManage = hasPermission("scan:policy_manage");

  const [scanners, setScanners] = useState<Scanner[]>([]);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [requestTokenOpen, setRequestTokenOpen] = useState(false);
  const [networkTokens, setNetworkTokens] = useState<NetworkToken[]>([]);
  const [editScanner, setEditScanner] = useState<Scanner | null>(null);
  const [tokenReveal, setTokenReveal] = useState<{
    name: string;
    token: string;
    kind: "network" | "agent";
  } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [rows, tokens] = await Promise.all([
        vulnApi.listScanners(),
        vulnApi.listNetworkTokens().catch(() => [] as NetworkToken[]),
      ]);
      setScanners(rows);
      setNetworkTokens(tokens);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load scanners");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  async function reissueToken(scanner: Scanner) {
    const ok = window.confirm(
      "Reissue AGENT_TOKEN?\n\n" +
        "This replaces the only laptop token. Update AGENT_TOKEN in the laptop .env before the next Start-Laptop.\n\n" +
        "Continue?",
    );
    if (!ok) return;
    try {
      const res = await vulnApi.rotateScannerAgentToken(scanner.id);
      if (res.agent_token) {
        setTokenReveal({
          name: scanner.name,
          token: res.agent_token,
          kind: "agent",
        });
      }
      toast.success("AGENT_TOKEN reissued — update the laptop .env now");
      load();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Token reissue failed");
    }
  }

  return (
    <div>
      <PageHeader
        title="Scanners"
        subtitle="Client sites use a browser scanner token bound to one network. The server Central GMP scanner probes only those IPs. Nothing is installed on the client PC."
        actions={
          <div className="flex flex-wrap gap-2">
            <Link to="/vuln/connect">
              <Button variant="ghost">Connect client network</Button>
            </Link>
            {canManage && (
              <>
                <Button variant="outline" onClick={() => setRequestTokenOpen(true)}>
                  <KeyRound className="h-4 w-4" /> Request network token
                </Button>
                <Button variant="brand" onClick={() => setCreateOpen(true)}>
                  <Plus className="h-4 w-4" /> Add scanner
                </Button>
              </>
            )}
          </div>
        }
      />

      {!loading && scanners.length > 0 && (
        <InsightCharts
          left={{
            title: "Scanner status",
            subtitle: "From /api/scanners",
            data: countBy(scanners, (s) => s.status || "unknown"),
            kind: "bar",
          }}
          right={{
            title: "Scanner role",
            subtitle: "Deployment mix",
            data: countBy(scanners, (s) => ROLE_LABEL[scannerRole(s)] || scannerRole(s)),
            kind: "donut",
            centerLabel: "Scanners",
          }}
        />
      )}

      <Card className="mb-6 overflow-hidden">
        <div className="border-b border-ink-100 px-5 py-3">
          <h2 className="text-sm font-semibold text-ink-800">Network scanner tokens</h2>
          <p className="mt-1 text-xs text-ink-500">
            Each token authorizes one CIDR. Paste it on Connect client network from that site, then launch on Central GMP.
          </p>
        </div>
        {networkTokens.length === 0 ? (
          <p className="px-5 py-8 text-center text-sm text-ink-400">No network tokens yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="table-head border-b border-brand-300/70 text-xs uppercase tracking-wider text-ink-700">
                  <th className="px-5 py-3 font-semibold">Name</th>
                  <th className="px-5 py-3 font-semibold">Network</th>
                  <th className="px-5 py-3 font-semibold">Status</th>
                  <th className="px-5 py-3 font-semibold">Connected IP</th>
                  <th className="px-5 py-3 text-right font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-100">
                {networkTokens.map((t) => (
                  <tr key={t.id}>
                    <td className="px-5 py-3 font-semibold text-ink-800">{t.name}</td>
                    <td className="px-5 py-3 font-mono text-xs">{t.cidr}</td>
                    <td className="px-5 py-3">
                      <Badge
                        tone={
                          t.status === "connected" ? "green" : t.status === "revoked" ? "red" : "amber"
                        }
                      >
                        {t.status}
                      </Badge>
                      {t.token_hint ? <span className="ml-2 text-xs text-ink-400">…{t.token_hint}</span> : null}
                    </td>
                    <td className="px-5 py-3 font-mono text-xs text-ink-500">{t.connected_public_ip || "—"}</td>
                    <td className="px-5 py-3 text-right">
                      {canManage && t.status !== "revoked" ? (
                        <Button
                          variant="ghost"
                          onClick={async () => {
                            if (!window.confirm(`Revoke token for ${t.name}?`)) return;
                            try {
                              await vulnApi.revokeNetworkToken(t.id);
                              toast.success("Token revoked");
                              load();
                            } catch (e: unknown) {
                              toast.error(e instanceof Error ? e.message : "Revoke failed");
                            }
                          }}
                        >
                          Revoke
                        </Button>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card className="overflow-hidden">
        {loading ? (
          <Spinner />
        ) : scanners.length === 0 ? (
          <p className="px-5 py-16 text-center text-sm text-ink-400">No scanners configured.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="table-head border-b border-brand-300/70 text-xs uppercase tracking-wider text-ink-700">
                  <th className="px-5 py-3 font-semibold">Scanner</th>
                  <th className="px-5 py-3 font-semibold">Role</th>
                  <th className="px-5 py-3 font-semibold">URL</th>
                  <th className="px-5 py-3 font-semibold">Edition</th>
                  <th className="px-5 py-3 font-semibold">Status</th>
                  <th className="px-5 py-3 text-right font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-100">
                {scanners.map((s) => {
                  const role = scannerRole(s);
                  const edge = isEdgeRole(role);
                  const stale =
                    edge &&
                    s.online !== true &&
                    !(
                      s.last_heartbeat_at &&
                      Date.now() - Date.parse(s.last_heartbeat_at) <= 180_000
                    );
                  return (
                    <tr key={s.id} className="hover:bg-ink-50/60">
                      <td className="px-5 py-3">
                        <div className="flex items-center gap-3">
                          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-indigo-50">
                            <Server className="h-4 w-4 text-indigo-600" />
                          </div>
                          <div>
                            <span className="font-semibold text-ink-800">{s.name}</span>
                            {edge && s.agent_token_hint ? (
                              <p className="text-xs text-ink-400">token …{s.agent_token_hint}</p>
                            ) : null}
                            {edge && s.last_heartbeat_at ? (
                              <p className="text-xs text-ink-400">
                                last seen {new Date(s.last_heartbeat_at).toLocaleString()}
                              </p>
                            ) : edge ? (
                              <p className="text-xs text-amber-600">waiting for first heartbeat</p>
                            ) : null}
                          </div>
                        </div>
                      </td>
                      <td className="px-5 py-3">
                        <Badge tone={role === "persistent_edge" ? "green" : edge ? "indigo" : role === "remote_vpn" ? "amber" : "neutral"}>
                          {ROLE_LABEL[role] || role}
                        </Badge>
                      </td>
                      <td className="px-5 py-3 font-mono text-xs text-ink-500">{s.url}</td>
                      <td className="px-5 py-3 text-ink-500">{s.edition || "—"}</td>
                      <td className="px-5 py-3">
                        <Badge tone={stale ? "red" : s.status === "active" ? "green" : "neutral"}>
                          {stale ? "offline" : s.status}
                        </Badge>
                      </td>
                      <td className="px-5 py-3 text-right">
                        {canManage && (
                          <div className="flex justify-end gap-1">
                            {edge && (
                              <button
                                type="button"
                                title="Reissue AGENT_TOKEN (shown once)"
                                onClick={() => reissueToken(s)}
                                className="rounded-lg p-2 text-ink-400 hover:bg-ink-100 hover:text-ink-700"
                              >
                                <KeyRound className="h-4 w-4" />
                              </button>
                            )}
                            <button
                              type="button"
                              onClick={() => setEditScanner(s)}
                              className="rounded-lg p-2 text-ink-400 hover:bg-ink-100 hover:text-ink-700"
                            >
                              <Pencil className="h-4 w-4" />
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {requestTokenOpen && (
        <RequestNetworkTokenModal
          onClose={() => setRequestTokenOpen(false)}
          onCreated={(row) => {
            setRequestTokenOpen(false);
            if (row.token) {
              setTokenReveal({ name: row.name, token: row.token, kind: "network" });
            }
            load();
          }}
        />
      )}
      {createOpen && (
        <ScannerModal
          onClose={() => setCreateOpen(false)}
          onSaved={(created) => {
            setCreateOpen(false);
            if (created?.agent_token) {
              setTokenReveal({
                name: created.name,
                token: created.agent_token,
                kind: "agent",
              });
            }
            load();
          }}
        />
      )}
      {editScanner && (
        <ScannerModal
          scanner={editScanner}
          onClose={() => setEditScanner(null)}
          onSaved={() => {
            setEditScanner(null);
            load();
          }}
        />
      )}
      {tokenReveal && (
        <Modal
          open
          onClose={() => setTokenReveal(null)}
          title={tokenReveal.kind === "network" ? "Scanner token (copy now)" : "Agent token (copy now)"}
          footer={
            <Button variant="brand" onClick={() => setTokenReveal(null)}>
              Done
            </Button>
          }
        >
          <p className="mb-2 text-sm text-ink-600">
            {tokenReveal.kind === "network" ? (
              <>
                Paste this scanner token on <strong>Connect client network</strong> from the authorized
                site for <strong>{tokenReveal.name}</strong>. It is shown only once.
              </>
            ) : (
              <>
                Legacy laptop agent token for <strong>{tokenReveal.name}</strong>. Prefer a network
                scanner token and the server Central GMP scanner. Shown only once.
              </>
            )}
          </p>
          <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-ink-400">
            {tokenReveal.kind === "network" ? "SCANNER TOKEN" : "AGENT_TOKEN"}
          </p>
          <Input
            className="mb-3 font-mono text-sm"
            readOnly
            value={tokenReveal.token}
            onFocus={(e) => e.target.select()}
          />
        </Modal>
      )}
    </div>
  );
}

function ScannerModal({
  scanner,
  onClose,
  onSaved,
}: {
  scanner?: Scanner;
  onClose: () => void;
  onSaved: (created?: Scanner) => void;
}) {
  const toast = useToast();
  const [loading, setLoading] = useState(false);
  const [form, setForm] = useState({
    name: scanner?.name ?? "",
    url: scanner?.url ?? "agent://local",
    edition: scanner?.edition ?? "openvas",
    api_key_ref: "",
    status: scanner?.status ?? "active",
    scanner_role: formRole(scanner),
  });

  const role = form.scanner_role;
  const edge = role === "persistent_edge" || role === "portable";
  const remoteVpn = role === "remote_vpn";
  const centralGmp = role === "central";
  const gmpDriven = remoteVpn || centralGmp;

  async function submit() {
    setLoading(true);
    try {
      const gmpUrl = centralGmp
        ? form.url.trim() || "unix:///run/gvmd/gvmd.sock"
        : form.url;
      if (scanner) {
        await vulnApi.updateScanner(scanner.id, {
          name: form.name,
          scanner_role: form.scanner_role,
          connection_mode: edge ? "edge_agent" : "gmp",
          url: edge ? "agent://local" : gmpUrl,
          edition: form.edition || null,
          api_key_ref: form.api_key_ref.trim() || null,
          status: form.status as "active" | "disabled",
        });
        toast.success("Scanner updated");
        onSaved();
      } else {
        const created = await vulnApi.createScanner({
          name: form.name,
          url: edge ? "agent://local" : gmpUrl,
          edition: form.edition || "openvas",
          api_key_ref: edge ? null : form.api_key_ref.trim() || null,
          connection_mode: edge ? "edge_agent" : "gmp",
          scanner_role: form.scanner_role,
        });
        toast.success(
          role === "persistent_edge"
            ? "Persistent Edge scanner created"
            : role === "portable"
              ? "Portable Assessment scanner created"
              : role === "central"
                ? "Central GMP scanner created"
                : "Managed Remote / VPN scanner created",
        );
        onSaved(created);
      }
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Save failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={scanner ? "Edit scanner" : "Add scanner"}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="brand" loading={loading} onClick={submit}>
            Save
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Name" hint="e.g. Client-Site-A-Laptop">
          <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </Field>
        <Field
          label="Scanner role"
          hint="Central GMP is this server's OpenVAS. Persistent Edge is an always-on site box. Portable is the laptop kit. Remote/VPN is site gvmd reached from central over GMP."
        >
          <Select
            value={form.scanner_role}
            onChange={(e) => {
              const next = e.target.value as "persistent_edge" | "portable" | "remote_vpn" | "central";
              setForm({
                ...form,
                scanner_role: next,
                url:
                  next === "remote_vpn"
                    ? form.url.startsWith("agent://") || form.url.startsWith("unix://")
                      ? "tls://site-vpn-host:9390"
                      : form.url
                    : next === "central"
                      ? form.url.startsWith("agent://")
                        ? "unix:///run/gvmd/gvmd.sock"
                        : form.url || "unix:///run/gvmd/gvmd.sock"
                      : "agent://local",
              });
            }}
          >
            <option value="persistent_edge">Persistent Edge (always-on site appliance) — recommended</option>
            <option value="portable">Portable Assessment (laptop kit)</option>
            <option value="remote_vpn">Managed Remote / VPN (site gvmd over GMP TLS 9390)</option>
            <option value="central">Central GMP (this server's OpenVAS)</option>
          </Select>
        </Field>
        {gmpDriven && (
          <>
            <Field
              label="GMP URL"
              hint={
                centralGmp
                  ? "Local compose gvmd. Default unix:///run/gvmd/gvmd.sock; gmp://gvmd:9390 is also valid."
                  : "Central worker-nessus must reach this over the VPN. Community gvmd must expose TLS 9390 (not Unix-socket-only)."
              }
            >
              <Input
                className="font-mono text-sm"
                value={form.url}
                onChange={(e) => setForm({ ...form, url: e.target.value })}
                placeholder={centralGmp ? "unix:///run/gvmd/gvmd.sock" : "tls://site-vpn-host:9390"}
              />
            </Field>
            <Field
              label="GMP credentials (api_key_ref)"
              hint="Format username:password for the OpenVAS admin user. Leave blank to use server GVM_* settings."
            >
              <Input
                className="font-mono text-sm"
                type="password"
                value={form.api_key_ref}
                onChange={(e) => setForm({ ...form, api_key_ref: e.target.value })}
                placeholder="admin:your-password"
              />
            </Field>
            {remoteVpn ? (
              <p className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-950">
                Scan packets originate on the customer site. Central only drives gvmd over GMP. If VPN GMP is not
                available, the reverse-SSH tunnel script remains a fallback — not the primary path.
              </p>
            ) : (
              <p className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-800">
                Jobs on this scanner run against the OpenVAS in this Polaron server stack (gvmd/ospd), not a laptop
                or customer-site appliance.
              </p>
            )}
          </>
        )}
        {role === "persistent_edge" && (
          <p className="rounded-md border border-green-200 bg-green-50 px-3 py-2 text-sm text-green-950">
            Install the same Docker kit as the laptop scanner on an always-on box left on the customer LAN. After
            save, copy the agent tokens into that box. The appliance must not roam; jobs keep this site&apos;s
            targets only.
          </p>
        )}
        {role === "portable" && (
          <p className="rounded-md border border-indigo-100 bg-indigo-50/60 px-3 py-2 text-sm text-indigo-900">
            Portable laptop agents are legacy. Prefer <strong>Request network token</strong> and launch on
            Central GMP with IPs from that CIDR only.
          </p>
        )}
        <Field label="Edition">
          <Select value={form.edition} onChange={(e) => setForm({ ...form, edition: e.target.value })}>
            <option value="openvas">openvas</option>
            <option value="greenbone">greenbone</option>
            <option value="nessus">nessus</option>
          </Select>
        </Field>
        {scanner && (
          <Field label="Status">
            <Select value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value })}>
              <option value="active">active</option>
              <option value="disabled">disabled</option>
            </Select>
          </Field>
        )}
      </div>
    </Modal>
  );
}

function RequestNetworkTokenModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (row: NetworkToken) => void;
}) {
  const toast = useToast();
  const [loading, setLoading] = useState(false);
  const [form, setForm] = useState({
    name: "Client network",
    cidr: "",
    note: "",
    authorization_ref: "",
  });

  async function submit() {
    if (!form.cidr.trim()) {
      toast.error("Network CIDR is required");
      return;
    }
    setLoading(true);
    try {
      const row = await vulnApi.createNetworkToken({
        name: form.name.trim() || "Client network",
        cidr: form.cidr.trim(),
        note: form.note.trim() || undefined,
        authorization_ref: form.authorization_ref.trim() || undefined,
      });
      toast.success("Scanner token created — copy it now");
      onCreated(row);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Could not create token");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="Request network token"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="brand" loading={loading} onClick={() => void submit()}>
            Issue token
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <p className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-800">
          The token is valid only for this CIDR. After the client pastes it in the browser, Launch scan
          uses the server Central GMP scanner and rejects IPs outside the network.
        </p>
        <Field label="Name">
          <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </Field>
        <Field label="Network CIDR" hint="Example 203.0.113.0/24 — the only IPs this token may scan.">
          <Input
            className="font-mono text-sm"
            value={form.cidr}
            onChange={(e) => setForm({ ...form, cidr: e.target.value })}
            placeholder="203.0.113.0/24"
          />
        </Field>
        <Field label="Authorization reference" hint="Optional change ticket or written authority.">
          <Input
            value={form.authorization_ref}
            onChange={(e) => setForm({ ...form, authorization_ref: e.target.value })}
          />
        </Field>
        <Field label="Note">
          <Input value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} />
        </Field>
      </div>
    </Modal>
  );
}
