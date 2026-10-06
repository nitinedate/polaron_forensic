import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { api, tokenStore } from "./api";
import type { MfaEnrollmentRequired, MfaRequired, TokenPair, User } from "./types";

interface LoginResult {
  status: "ok" | "mfa" | "mfa_enroll";
  mfa?: MfaRequired;
  mfaEnroll?: MfaEnrollmentRequired;
}

interface AuthState {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string, tenant: string) => Promise<LoginResult>;
  requestAccessToken: (email: string, tenant: string) => Promise<void>;
  loginWithToken: (token: string, tenant: string) => Promise<void>;
  verifyMfa: (mfaToken: string, code: string) => Promise<void>;
  confirmMfaEnrollment: (mfaToken: string, code: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  hasPermission: (perm: string) => boolean;
  roles: string[];
  isSuperAdmin: boolean;
  isTenantAdmin: boolean;
  isFirmAdmin: boolean;
  isPlatformScope: boolean;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

function decodeJwt(token: string): any {
  try {
    const payload = token.split(".")[1];
    return JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
  } catch {
    return {};
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [perms, setPerms] = useState<string[]>([]);
  const [roles, setRoles] = useState<string[]>([]);
  const [scope, setScope] = useState<"platform" | "firm">("firm");

  const loadPermsFromToken = useCallback(() => {
    const token = tokenStore.access();
    if (token) {
      const claims = decodeJwt(token);
      setPerms(claims.perms || []);
      setRoles(claims.roles || []);
      setScope(claims.scope === "platform" ? "platform" : "firm");
    } else {
      setPerms([]);
      setRoles([]);
      setScope("firm");
    }
  }, []);

  const refreshUser = useCallback(async () => {
    const me = await api.get<User>("/api/users/me", undefined, { timeoutMs: 8_000 });
    setUser(me);
    loadPermsFromToken();
  }, [loadPermsFromToken]);

  useEffect(() => {
    const token = tokenStore.access();
    if (token) {
      const claims = decodeJwt(token);
      if (claims?.email || claims?.sub) {
        setUser({
          id: String(claims.sub || ""),
          email: String(claims.email || ""),
          username: null,
          status: "active",
          is_email_verified: true,
          mfa_enabled: false,
          last_login_at: null,
          created_at: "",
          profile: null,
        });
      }
      loadPermsFromToken();
    }
    // Render routes immediately. /users/me can hang without blanking the app.
    setLoading(false);
    if (tokenStore.access() || tokenStore.refresh()) {
      void refreshUser().catch(() => {
        tokenStore.clear();
        setUser(null);
        setPerms([]);
        setRoles([]);
        setScope("firm");
      });
    }
  }, [refreshUser, loadPermsFromToken]);

  useEffect(() => {
    const onExpired = () => {
      setUser(null);
      setPerms([]);
      setRoles([]);
      setScope("firm");
    };
    window.addEventListener("iam:session-expired", onExpired);
    return () => window.removeEventListener("iam:session-expired", onExpired);
  }, []);

  const login = useCallback(
    async (email: string, password: string, tenant: string): Promise<LoginResult> => {
      tokenStore.setTenant(tenant.trim().toLowerCase());
      const res = await api.post<TokenPair | MfaRequired | MfaEnrollmentRequired>(
        "/api/auth/login",
        { email, password },
        { auth: false }
      );
      if ((res as MfaEnrollmentRequired).mfa_enrollment_required) {
        return { status: "mfa_enroll", mfaEnroll: res as MfaEnrollmentRequired };
      }
      if ((res as MfaRequired).mfa_required) {
        return { status: "mfa", mfa: res as MfaRequired };
      }
      const pair = res as TokenPair;
      tokenStore.set(pair.access_token, pair.refresh_token);
      await refreshUser();
      return { status: "ok" };
    },
    [refreshUser]
  );

  const requestAccessToken = useCallback(async (email: string, tenant: string) => {
    tokenStore.setTenant(tenant.trim().toLowerCase());
    await api.post("/api/auth/request-access-token", { email }, { auth: false });
  }, []);

  const loginWithToken = useCallback(
    async (token: string, tenant: string) => {
      tokenStore.setTenant(tenant.trim().toLowerCase());
      const pair = await api.post<TokenPair>("/api/auth/token-login", { token }, { auth: false });
      tokenStore.set(pair.access_token, pair.refresh_token);
      await refreshUser();
    },
    [refreshUser]
  );

  const verifyMfa = useCallback(
    async (mfaToken: string, code: string) => {
      const pair = await api.post<TokenPair>(
        "/api/auth/mfa/verify",
        { mfa_token: mfaToken, code },
        { auth: false }
      );
      tokenStore.set(pair.access_token, pair.refresh_token);
      await refreshUser();
    },
    [refreshUser]
  );

  const confirmMfaEnrollment = useCallback(
    async (mfaToken: string, code: string) => {
      const pair = await api.post<TokenPair>(
        "/api/auth/mfa/totp/setup/confirm",
        { mfa_token: mfaToken, code },
        { auth: false }
      );
      tokenStore.set(pair.access_token, pair.refresh_token);
      await refreshUser();
    },
    [refreshUser]
  );

  const logout = useCallback(async () => {
    const refresh = tokenStore.refresh();
    try {
      if (refresh) await api.post("/api/auth/logout", { refresh_token: refresh }, { auth: false });
    } catch {
      /* ignore */
    }
    tokenStore.clear();
    setUser(null);
    setPerms([]);
    setRoles([]);
    setScope("firm");
  }, []);

  const hasPermission = useCallback(
    (perm: string) => perms.includes("*") || perms.includes(perm),
    [perms]
  );

  const isSuperAdmin = roles.includes("superadmin") || roles.includes("super_admin");
  const isTenantAdmin = isSuperAdmin || roles.includes("tenant_admin");
  const isFirmAdmin = roles.includes("admin");
  const isPlatformScope = scope === "platform";

  const value = useMemo<AuthState>(
    () => ({
      user,
      loading,
      login,
      requestAccessToken,
      loginWithToken,
      verifyMfa,
      confirmMfaEnrollment,
      logout,
      refreshUser,
      hasPermission,
      roles,
      isSuperAdmin,
      isTenantAdmin,
      isFirmAdmin,
      isPlatformScope,
    }),
    [user, loading, login, requestAccessToken, loginWithToken, verifyMfa, confirmMfaEnrollment, logout, refreshUser, hasPermission, roles, isSuperAdmin, isTenantAdmin, isFirmAdmin, isPlatformScope]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
