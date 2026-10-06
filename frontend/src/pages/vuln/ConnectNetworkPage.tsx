import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Button, Card, Field, Input, PageHeader, Spinner } from "../../components/ui";
import { vulnApi } from "../../lib/vulnApi";
import { useToast } from "../../lib/toast";
import type { NetworkToken } from "../../lib/types/vuln";

export function ConnectNetworkPage() {
  const toast = useToast();
  const [token, setToken] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [session, setSession] = useState<NetworkToken | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setSession(await vulnApi.getNetworkTokenSession());
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Could not load network session");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void load();
  }, [load]);

  async function connect() {
    const value = token.trim();
    if (!value) {
      toast.error("Paste the scanner token first");
      return;
    }
    setSaving(true);
    try {
      const row = await vulnApi.activateNetworkToken(value);
      setSession(row);
      setToken("");
      toast.success("Client network connected — launch scans on the server scanner");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Token was not accepted");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="Connect client network"
        subtitle="Paste the scanner token issued for this site. The server OpenVAS will scan only IPs in that network. Nothing is installed on this PC."
      />

      <Card className="mx-auto max-w-xl space-y-4 p-6">
        {loading ? (
          <Spinner />
        ) : (
          <>
            {session ? (
              <div className="rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-950">
                <p className="font-semibold">{session.name}</p>
                <p className="mt-1 font-mono">{session.cidr}</p>
                <p className="mt-1 text-emerald-800">
                  Connected{session.connected_public_ip ? ` from ${session.connected_public_ip}` : ""}.
                  The server can only probe hosts it can reach (public or already-routed ranges).
                </p>
              </div>
            ) : (
              <p className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-950">
                No network is connected on this login. Request a token on{" "}
                <Link className="font-semibold underline" to="/vuln/scanners">
                  Scanners
                </Link>{" "}
                (or use one you were given), then paste it here.
              </p>
            )}

            <Field label="Scanner token" hint="One-time token for this network only — not your login access token.">
              <Input
                className="font-mono text-sm"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="Paste scanner token"
                autoComplete="off"
              />
            </Field>
            <div className="flex flex-wrap gap-2">
              <Button variant="brand" loading={saving} onClick={() => void connect()}>
                Connect this network
              </Button>
              <Link to="/vuln/scans" className="inline-flex">
                <Button variant="ghost">Go to scan jobs</Button>
              </Link>
            </div>
          </>
        )}
      </Card>
    </div>
  );
}
