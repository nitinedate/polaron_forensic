import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { AuthShell } from "../components/AuthShell";
import { Button, Field, Input } from "../components/ui";
import { useAuth } from "../lib/auth";
import { ApiError, DEFAULT_TENANT, tokenStore } from "../lib/api";
import type { MfaEnrollmentRequired, MfaRequired } from "../lib/types";

function normalizeMfaCode(value: string): string {
  return value.replace(/\D+/g, "");
}

export function Login() {
  const { login, requestAccessToken, loginWithToken, verifyMfa, confirmMfaEnrollment } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const [email, setEmail] = useState(searchParams.get("email") || "");
  const [password, setPassword] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [tenant, setTenant] = useState(searchParams.get("tenant") || tokenStore.tenant() || DEFAULT_TENANT);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const activated = searchParams.get("activated") === "1";

  useEffect(() => {
    const t = searchParams.get("tenant");
    const e = searchParams.get("email");
    if (t) {
      setTenant(t);
      tokenStore.setTenant(t);
    }
    if (e) setEmail(e);
  }, [searchParams]);

  const [mfa, setMfa] = useState<MfaRequired | null>(null);
  const [mfaEnroll, setMfaEnroll] = useState<MfaEnrollmentRequired | null>(null);
  const [code, setCode] = useState("");

  const org = (tenant || DEFAULT_TENANT).trim().toLowerCase();

  async function onSendToken(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setInfo(null);
    setLoading(true);
    try {
      await requestAccessToken(email, org);
      setInfo("If that account exists, the access token is in the login email. Paste it below. The same token works in this UI and on the laptop scanner.");
    } catch (err: unknown) {
      if (err instanceof Error) setError(err.message);
      else setError("Could not send the access token.");
    } finally {
      setLoading(false);
    }
  }

  async function onTokenContinue(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await loginWithToken(accessToken.trim(), org);
      navigate("/", { replace: true });
    } catch (err: unknown) {
      if (err instanceof ApiError && err.status === 401) {
        setError("Invalid access token or organization.");
      } else if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("Token sign-in failed");
      }
    } finally {
      setLoading(false);
    }
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const result = await login(email, password, org);
      if (result.status === "mfa_enroll" && result.mfaEnroll) {
        setMfaEnroll(result.mfaEnroll);
        setMfa(null);
      } else if (result.status === "mfa" && result.mfa) {
        setMfa(result.mfa);
        setMfaEnroll(null);
      } else {
        navigate("/", { replace: true });
      }
    } catch (err: unknown) {
      if (err instanceof ApiError && err.status === 401) {
        setError("Invalid email, password, or organization.");
      } else if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("Login failed");
      }
    } finally {
      setLoading(false);
    }
  }

  async function onVerify(e: React.FormEvent) {
    e.preventDefault();
    if (!mfa) return;
    setError(null);
    setLoading(true);
    try {
      await verifyMfa(mfa.mfa_token, normalizeMfaCode(code));
      navigate("/", { replace: true });
    } catch (err: any) {
      setError(err?.message || "Invalid code");
    } finally {
      setLoading(false);
    }
  }

  async function onConfirmEnrollment(e: React.FormEvent) {
    e.preventDefault();
    if (!mfaEnroll) return;
    setError(null);
    setLoading(true);
    try {
      await confirmMfaEnrollment(mfaEnroll.mfa_token, normalizeMfaCode(code));
      navigate("/", { replace: true });
    } catch (err: any) {
      setError(err?.message || "Invalid code");
    } finally {
      setLoading(false);
    }
  }

  if (mfaEnroll) {
    return (
      <AuthShell
        title="Set up authenticator"
        subtitle="Your organization requires MFA. Scan the QR code with Google Authenticator, Authy, or 1Password, then enter the 6-digit code to finish signing in."
        footer={
          <button
            type="button"
            className="font-semibold text-ink-700 hover:text-ink-900"
            onClick={() => {
              setMfaEnroll(null);
              setCode("");
              setError(null);
            }}
          >
            Back to sign in
          </button>
        }
      >
        <form onSubmit={onConfirmEnrollment} className="space-y-4">
          <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-start">
            <img
              src={`data:image/png;base64,${mfaEnroll.qr_png_base64}`}
              alt="Scan with your authenticator app"
              className="h-44 w-44 shrink-0 rounded-xl border border-ink-200 bg-white p-2"
            />
            <div className="w-full flex-1 space-y-4">
              <Field label="Manual setup key">
                <Input readOnly value={mfaEnroll.secret} className="bg-ink-50 font-mono text-sm" />
              </Field>
              <Field label="Verification code">
                <Input
                  autoFocus
                  inputMode="numeric"
                  placeholder="123456"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  className="text-center text-lg tracking-[0.4em]"
                />
              </Field>
            </div>
          </div>
          {error && <p className="text-sm font-medium text-red-600">{error}</p>}
          <Button variant="brand" type="submit" loading={loading} className="w-full" disabled={!code.trim()}>
            Confirm &amp; sign in
          </Button>
        </form>
      </AuthShell>
    );
  }

  if (mfa) {
    return (
      <AuthShell
        title="Two-factor authentication"
        subtitle={`Enter the 6-digit code from your authenticator app${
          mfa.methods.includes("email") ? " or the code emailed to you" : ""
        }.`}
        footer={
          <button type="button" className="font-semibold text-ink-700 hover:text-ink-900" onClick={() => setMfa(null)}>
            Back to sign in
          </button>
        }
      >
        <form onSubmit={onVerify} className="space-y-4">
          <Field label="Verification code">
            <Input
              autoFocus
              inputMode="numeric"
              placeholder="123456"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              className="text-center text-lg tracking-[0.4em]"
            />
          </Field>
          {error && <p className="text-sm font-medium text-red-600">{error}</p>}
          <p className="text-xs text-ink-500">
            Codes not working? Delete the old “Forensic Automation” entry in Google Authenticator, then ask an admin
            to reset MFA for your account, sign in with password only, and set up again under Security &amp; MFA.
          </p>
          <Button variant="brand" type="submit" loading={loading} className="w-full">
            Verify &amp; continue
          </Button>
        </form>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      title="Access token sign-in"
      subtitle="Request the token emailed to your login address, then paste it. The same token opens Forensic, Mobile extract, and the laptop scanner."
      footer={
        <>
          Trouble signing in?{" "}
          <Link to="/forgot-password" className="font-semibold text-brand-700 hover:text-brand-800">
            Reset your password
          </Link>
        </>
      }
    >
      <div className="space-y-6">
        {activated && (
          <div className="rounded-lg bg-emerald-50 px-4 py-3 text-sm text-emerald-700">
            Your account is active. Request an access token, or use password sign-in.
          </div>
        )}
        <form onSubmit={onSendToken} className="space-y-4">
          <Field label="Organization" hint="Platform admins use 'platform'. Firm users use their firm slug.">
            <Input placeholder="platform" value={tenant} onChange={(e) => setTenant(e.target.value)} />
          </Field>
          <Field label="Email">
            <Input
              type="email"
              autoComplete="username"
              placeholder="you@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </Field>
          <Button variant="brand" type="submit" loading={loading} className="w-full" disabled={!email.trim()}>
            Send token
          </Button>
        </form>

        <form onSubmit={onTokenContinue} className="space-y-4">
          <Field label="Access token" hint="Copy the token from your Polaron login email.">
            <Input
              autoComplete="off"
              placeholder="ath1.organization.you@company.com...."
              value={accessToken}
              onChange={(e) => setAccessToken(e.target.value)}
              required
              className="font-mono text-sm"
            />
          </Field>
          {info && <p className="text-sm text-ink-600">{info}</p>}
          {error && <p className="text-sm font-medium text-red-600">{error}</p>}
          <Button variant="brand" type="submit" loading={loading} className="w-full" disabled={!accessToken.trim()}>
            Continue
          </Button>
        </form>

        <div>
          <button
            type="button"
            className="text-sm font-semibold text-ink-600 hover:text-ink-900"
            onClick={() => setShowPassword((v) => !v)}
          >
            {showPassword ? "Hide password sign-in" : "Password sign-in"}
          </button>
          {showPassword && (
            <form onSubmit={onSubmit} className="mt-4 space-y-4">
              <Field label="Password">
                <Input
                  type="password"
                  autoComplete="current-password"
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </Field>
              <Button variant="brand" type="submit" loading={loading} className="w-full">
                Sign in with password
              </Button>
            </form>
          )}
        </div>
      </div>
    </AuthShell>
  );
}
