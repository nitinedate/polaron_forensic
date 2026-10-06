import { useState } from "react";
import { Copy, KeyRound, ShieldCheck, ShieldOff, Smartphone } from "lucide-react";
import { Badge, Button, Card, Field, Input, PageHeader } from "../components/ui";
import { api } from "../lib/api";
import { useConfirm } from "../lib/confirm";
import { useToast } from "../lib/toast";
import { useAuth } from "../lib/auth";
import type { TotpEnroll } from "../lib/types";

export function Security() {
  const { user, isTenantAdmin } = useAuth();

  return (
    <div>
      <PageHeader title="Security & MFA" subtitle="Manage your password and multi-factor authentication." />
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <ProfileCard email={user?.email || ""} />
        <ChangePasswordCard />
        {!isTenantAdmin && <MfaCard enabled={!!user?.mfa_enabled} />}
        {isTenantAdmin && (
          <Card className="px-5 py-5 lg:col-span-2">
            <p className="text-sm text-ink-600">
              Multi-factor authentication is not available for platform tenant administrators.
            </p>
          </Card>
        )}
      </div>
    </div>
  );
}

function ProfileCard({ email }: { email: string }) {
  const { user } = useAuth();
  return (
    <Card className="px-5 py-5">
      <h3 className="mb-4 font-bold text-ink-900">Profile</h3>
      <dl className="space-y-3 text-sm">
        <div className="flex justify-between">
          <dt className="text-ink-400">Email</dt>
          <dd className="font-semibold text-ink-800">{email}</dd>
        </div>
        <div className="flex justify-between">
          <dt className="text-ink-400">Name</dt>
          <dd className="font-semibold text-ink-800">
            {user?.profile?.first_name
              ? `${user.profile.first_name} ${user.profile.last_name ?? ""}`
              : "—"}
          </dd>
        </div>
        <div className="flex justify-between">
          <dt className="text-ink-400">Email verified</dt>
          <dd>
            {user?.is_email_verified ? <Badge tone="green">verified</Badge> : <Badge tone="amber">no</Badge>}
          </dd>
        </div>
        <div className="flex justify-between">
          <dt className="text-ink-400">MFA</dt>
          <dd>{user?.mfa_enabled ? <Badge tone="indigo">enabled</Badge> : <Badge>disabled</Badge>}</dd>
        </div>
      </dl>
    </Card>
  );
}

function ChangePasswordCard() {
  const toast = useToast();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (next !== confirm) {
      toast.error("New passwords do not match");
      return;
    }
    setLoading(true);
    try {
      await api.post("/api/users/me/change-password", { current_password: current, new_password: next });
      toast.success("Password changed");
      setCurrent("");
      setNext("");
      setConfirm("");
    } catch (e: any) {
      toast.error(e?.message || "Change failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="px-5 py-5">
      <div className="mb-4 flex items-center gap-2">
        <KeyRound className="h-5 w-5 text-brand-600" />
        <h3 className="font-bold text-ink-900">Change password</h3>
      </div>
      <form onSubmit={submit} className="space-y-3">
        <Field label="Current password">
          <Input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
        </Field>
        <Field label="New password" hint="Min 12 chars, mixed case, digit, and symbol.">
          <Input type="password" value={next} onChange={(e) => setNext(e.target.value)} required />
        </Field>
        <Field label="Confirm new password">
          <Input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
        </Field>
        <Button variant="brand" type="submit" loading={loading}>
          Update password
        </Button>
      </form>
    </Card>
  );
}

function normalizeMfaCode(value: string): string {
  return value.replace(/\D+/g, "");
}

function MfaCard({ enabled }: { enabled: boolean }) {
  const toast = useToast();
  const { confirm: confirmDialog } = useConfirm();
  const { refreshUser } = useAuth();
  const [enroll, setEnroll] = useState<TotpEnroll | null>(null);
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState<string[] | null>(null);
  const [loading, setLoading] = useState(false);

  async function startEnroll() {
    setLoading(true);
    try {
      setEnroll(await api.post<TotpEnroll>("/api/auth/mfa/totp/enroll"));
    } catch (e: any) {
      toast.error(e?.message || "Could not start enrollment");
    } finally {
      setLoading(false);
    }
  }

  async function confirm() {
    setLoading(true);
    try {
      const res = await api.post<{ recovery_codes: string[] }>("/api/auth/mfa/totp/confirm", {
        code: normalizeMfaCode(code),
      });
      setRecovery(res.recovery_codes);
      setEnroll(null);
      setCode("");
      await refreshUser();
      toast.success("MFA enabled");
    } catch (e: any) {
      toast.error(e?.message || "Invalid code");
    } finally {
      setLoading(false);
    }
  }

  async function replaceAuthenticator() {
    const ok = await confirmDialog({
      title: "Replace authenticator",
      message:
        "This disables your current MFA and shows a new QR code. Delete the old “Forensic Automation” entry in Google Authenticator first, then scan the new QR.",
      confirmLabel: "Replace authenticator",
      variant: "danger",
    });
    if (!ok) return;
    setLoading(true);
    try {
      await api.post("/api/auth/mfa/disable");
      await refreshUser();
      setEnroll(await api.post<TotpEnroll>("/api/auth/mfa/totp/enroll"));
      setCode("");
      toast.success("Scan the new QR code with your authenticator app");
    } catch (e: any) {
      toast.error(e?.message || "Could not replace authenticator");
    } finally {
      setLoading(false);
    }
  }

  async function disable() {
    const ok = await confirmDialog({
      title: "Disable MFA",
      message: "Disable multi-factor authentication for your account? You will only need your password to sign in.",
      confirmLabel: "Disable MFA",
      variant: "danger",
    });
    if (!ok) return;
    setLoading(true);
    try {
      await api.post("/api/auth/mfa/disable");
      await refreshUser();
      toast.success("MFA disabled");
    } catch (e: any) {
      toast.error(e?.message || "Could not disable MFA");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="px-5 py-5 lg:col-span-2">
      <div className="mb-4 flex items-center gap-2">
        <ShieldCheck className="h-5 w-5 text-brand-600" />
        <h3 className="font-bold text-ink-900">Multi-factor authentication</h3>
        {enabled && <Badge tone="green">enabled</Badge>}
      </div>

      {recovery ? (
        <div>
          <p className="mb-2 text-sm text-ink-600">
            Store these recovery codes somewhere safe. Each can be used once if you lose your device.
          </p>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {recovery.map((c) => (
              <code key={c} className="rounded-lg bg-ink-50 px-3 py-2 text-center text-sm font-semibold text-ink-700">
                {c}
              </code>
            ))}
          </div>
          <Button
            variant="outline"
            className="mt-4"
            onClick={() => {
              navigator.clipboard.writeText(recovery.join("\n"));
              toast.success("Recovery codes copied");
            }}
          >
            <Copy className="h-4 w-4" /> Copy codes
          </Button>
        </div>
      ) : enroll ? (
        <div className="flex flex-col gap-6 sm:flex-row">
          <div className="flex flex-col items-center">
            <img
              src={`data:image/png;base64,${enroll.qr_png_base64}`}
              alt="Scan with your authenticator app"
              className="h-44 w-44 rounded-xl border border-ink-200 bg-white p-2"
            />
            <p className="mt-2 text-xs text-ink-400">Scan with Google Authenticator, Authy, 1Password…</p>
          </div>
          <div className="flex-1">
            <Field label="Manual setup key">
              <Input readOnly value={enroll.secret} className="font-mono" />
            </Field>
            <div className="mt-4">
              <Field label="Enter the 6-digit code to confirm">
                <Input
                  inputMode="numeric"
                  placeholder="123456"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  className="max-w-[200px] text-center text-lg tracking-[0.3em]"
                />
              </Field>
            </div>
            <div className="mt-4 flex gap-2">
              <Button variant="brand" loading={loading} onClick={confirm}>
                Confirm &amp; enable
              </Button>
              <Button variant="ghost" onClick={() => setEnroll(null)}>
                Cancel
              </Button>
            </div>
          </div>
        </div>
      ) : enabled ? (
        <div className="space-y-3">
          <div className="flex items-center justify-between rounded-lg bg-emerald-50 px-4 py-3">
            <div className="flex items-center gap-2 text-sm text-emerald-700">
              <Smartphone className="h-4 w-4" /> Authenticator app is active on your account.
            </div>
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" loading={loading} onClick={replaceAuthenticator}>
                Replace authenticator
              </Button>
              <Button variant="danger" loading={loading} onClick={disable}>
                <ShieldOff className="h-4 w-4" /> Disable
              </Button>
            </div>
          </div>
          <p className="text-xs text-ink-500">
            If codes fail after a reinstall, delete the old “Forensic Automation” entry in your app, then use
            Replace authenticator to scan a fresh QR.
          </p>
        </div>
      ) : (
        <div className="flex items-center justify-between">
          <p className="text-sm text-ink-500">
            Add a second factor with a TOTP authenticator app for stronger account security.
          </p>
          <Button variant="brand" loading={loading} onClick={startEnroll}>
            <Smartphone className="h-4 w-4" /> Set up authenticator
          </Button>
        </div>
      )}
    </Card>
  );
}
