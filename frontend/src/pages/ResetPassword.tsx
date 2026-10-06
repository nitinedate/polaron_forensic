import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { AuthShell } from "../components/AuthShell";
import { Button, Field, Input } from "../components/ui";
import { api, DEFAULT_TENANT, tokenStore } from "../lib/api";

export function ResetPassword() {
  const [params] = useSearchParams();
  const [token, setToken] = useState(params.get("token") || "");
  const [tenant, setTenant] = useState(params.get("tenant") || tokenStore.tenant() || DEFAULT_TENANT);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const t = params.get("token");
    const org = params.get("tenant");
    if (t && org) {
      window.location.replace(`/activate?tenant=${encodeURIComponent(org)}&token=${encodeURIComponent(t)}`);
    }
  }, [params]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (password !== confirm) {
      setError("Passwords do not match");
      return;
    }
    setLoading(true);
    tokenStore.setTenant(tenant || DEFAULT_TENANT);
    try {
      await api.post(
        "/api/auth/reset-password",
        { token, new_password: password, tenant: tenant || DEFAULT_TENANT },
        { auth: false }
      );
      setDone(true);
    } catch (err: any) {
      setError(err?.message || "Could not reset password");
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthShell
      title="Choose a new password"
      subtitle="Your new password must meet the organization's complexity policy."
      footer={
        <Link to="/login" className="font-semibold text-ink-700 hover:text-ink-900">
          Back to sign in
        </Link>
      }
    >
      {done ? (
        <div className="space-y-4">
          <div className="rounded-lg bg-emerald-50 px-4 py-3 text-sm text-emerald-700">
            Your password has been reset. A confirmation email has been sent.
          </div>
          <Link
            to={`/login?tenant=${encodeURIComponent(tenant)}`}
            className="block w-full rounded-lg bg-brand-600 px-4 py-2.5 text-center text-sm font-semibold text-white hover:bg-brand-700"
          >
            Sign in
          </Link>
        </div>
      ) : (
        <form onSubmit={onSubmit} className="space-y-4">
          <Field label="Reset token" hint="From your password reset email.">
            <Input value={token} onChange={(e) => setToken(e.target.value)} required />
          </Field>
          <Field label="Organization">
            <Input value={tenant} onChange={(e) => setTenant(e.target.value)} />
          </Field>
          <Field label="New password">
            <Input
              type="password"
              autoComplete="new-password"
              placeholder="••••••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </Field>
          <Field label="Confirm new password">
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
            Reset password
          </Button>
        </form>
      )}
    </AuthShell>
  );
}
