import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { AuthShell } from "../components/AuthShell";
import { Button, Field, Input, Spinner } from "../components/ui";
import { api, tokenStore } from "../lib/api";
import { useAuth } from "../lib/auth";
import { validatePassword } from "../lib/password";

interface InviteStatus {
  valid: boolean;
  email?: string | null;
  tenant_slug?: string | null;
  tenant_name?: string | null;
  role?: string | null;
  is_admin?: boolean;
  expires_at?: string | null;
  message?: string | null;
}

export function ActivateAccount() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const { logout } = useAuth();
  const tenant = (params.get("tenant") || "").trim().toLowerCase();
  const token = (params.get("token") || "").trim();

  const [status, setStatus] = useState<InviteStatus | null>(null);
  const [checking, setChecking] = useState(true);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!tenant || !token) {
      setStatus({ valid: false, message: "Invalid activation link. Use the link from your invite email." });
      setChecking(false);
      return;
    }
    (async () => {
      setChecking(true);
      try {
        const res = await api.get<InviteStatus>("/api/auth/invite/status", { token, tenant }, { auth: false });
        setStatus(res);
      } catch (e: any) {
        setStatus({ valid: false, message: e?.message || "Could not verify invitation" });
      } finally {
        setChecking(false);
      }
    })();
  }, [tenant, token]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (password !== confirm) {
      setError("Passwords do not match");
      return;
    }
    const pwdError = validatePassword(password);
    if (pwdError) {
      setError(pwdError);
      return;
    }
    setLoading(true);
    try {
      const res = await api.post<{ email: string; tenant: string }>(
        "/api/auth/activate",
        { token, new_password: password, tenant },
        { auth: false, tenant: false }
      );
      tokenStore.setTenant(res.tenant);
      await logout();
      navigate(
        `/login?tenant=${encodeURIComponent(res.tenant)}&email=${encodeURIComponent(res.email)}&activated=1`,
        { replace: true }
      );
    } catch (err: any) {
      setError(err?.message || "Activation failed");
    } finally {
      setLoading(false);
    }
  }

  const roleLabel = status?.is_admin ? "Firm Administrator" : status?.role || "User";

  return (
    <AuthShell
      title="Activate your account"
      subtitle="Set a password to complete your invitation and access your organization."
      footer={
        <Link to="/login" className="font-semibold text-ink-700 hover:text-ink-900">
          Back to sign in
        </Link>
      }
    >
      {checking ? (
        <Spinner />
      ) : !status?.valid ? (
        <div className="space-y-4">
          <div className="rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700">
            {status?.message || "This invitation link is not valid."}
          </div>
          {status?.email && status?.tenant_slug && (
            <p className="text-sm text-ink-500">
              Account: <span className="font-medium">{status.email}</span> · Organization:{" "}
              <span className="font-medium">{status.tenant_slug}</span>
            </p>
          )}
          <p className="text-sm text-ink-500">
            Ask your platform or firm administrator to resend the invite email.
          </p>
        </div>
      ) : (
        <form onSubmit={onSubmit} className="space-y-4">
          <div className="rounded-lg bg-brand-50 px-4 py-3 text-sm text-ink-700">
            <p>
              <span className="font-semibold">{status.tenant_name}</span>
              <span className="text-ink-400"> ({status.tenant_slug})</span>
            </p>
            <p className="mt-1">
              {status.email} · {roleLabel}
            </p>
          </div>
          <Field label="New password" hint="At least 12 characters with upper, lower, digit, and symbol.">
            <Input
              type="password"
              autoComplete="new-password"
              placeholder="••••••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </Field>
          <Field label="Confirm password">
            <Input
              type="password"
              autoComplete="new-password"
              placeholder="••••••••••••"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              required
            />
          </Field>
          {error && <p className="text-sm font-medium text-red-600">{error}</p>}
          <Button variant="brand" type="submit" loading={loading} className="w-full">
            Activate account
          </Button>
        </form>
      )}
    </AuthShell>
  );
}
