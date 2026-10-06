import { useState } from "react";
import { Link } from "react-router-dom";
import { AuthShell } from "../components/AuthShell";
import { Button, Field, Input } from "../components/ui";
import { api, DEFAULT_TENANT, tokenStore } from "../lib/api";

export function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [tenant, setTenant] = useState(tokenStore.tenant() || DEFAULT_TENANT);
  const [sent, setSent] = useState(false);
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    tokenStore.setTenant(tenant || DEFAULT_TENANT);
    try {
      await api.post("/api/auth/forgot-password", { email }, { auth: false });
    } catch {
      /* response is intentionally uniform to avoid account enumeration */
    } finally {
      setSent(true);
      setLoading(false);
    }
  }

  return (
    <AuthShell
      title="Reset your password"
      subtitle="Enter your account email and we'll send a reset link if it exists."
      footer={
        <Link to="/login" className="font-semibold text-ink-700 hover:text-ink-900">
          Back to sign in
        </Link>
      }
    >
      {sent ? (
        <div className="rounded-lg bg-emerald-50 px-4 py-3 text-sm text-emerald-700">
          If an account exists for <span className="font-semibold">{email}</span>, a password reset link
          has been sent. Check your inbox.
        </div>
      ) : (
        <form onSubmit={onSubmit} className="space-y-4">
          <Field label="Email">
            <Input
              type="email"
              placeholder="you@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </Field>
          <Field label="Organization">
            <Input placeholder="acme" value={tenant} onChange={(e) => setTenant(e.target.value)} />
          </Field>
          <Button variant="brand" type="submit" loading={loading} className="w-full">
            Send reset link
          </Button>
        </form>
      )}
    </AuthShell>
  );
}
