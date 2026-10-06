export interface Profile {
  first_name: string | null;
  last_name: string | null;
  phone: string | null;
  avatar_url: string | null;
  locale: string;
  timezone: string;
}

export interface User {
  id: string;
  email: string;
  username: string | null;
  status: "pending" | "active" | "locked" | "disabled";
  is_email_verified: boolean;
  mfa_enabled: boolean;
  last_login_at: string | null;
  created_at: string;
  profile: Profile | null;
}

export interface UserList {
  items: User[];
  total: number;
  page: number;
  page_size: number;
}

export interface Permission {
  id: string;
  code: string;
  resource: string;
  action: string;
  description: string | null;
}

export interface Role {
  id: string;
  name: string;
  description: string | null;
  is_system: boolean;
  permissions: string[];
}

export interface Group {
  id: string;
  name: string;
  description: string | null;
}

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  schema_name: string;
  status: string;
  plan: string;
  primary_host: string | null;
  created_at: string;
}

export interface TenantDetail extends Tenant {
  admin_email: string | null;
  admin_status: string | null;
}

export interface TenantUser {
  id: string;
  email: string;
  status: string;
  mfa_enabled: boolean;
  is_email_verified: boolean;
  created_at: string;
  roles: string[];
  profile: Profile | null;
}

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface MfaRequired {
  mfa_required: true;
  mfa_token: string;
  methods: string[];
}

export interface MfaEnrollmentRequired {
  mfa_enrollment_required: true;
  mfa_token: string;
  secret: string;
  otpauth_uri: string;
  qr_png_base64: string;
}

export interface TotpEnroll {
  secret: string;
  otpauth_uri: string;
  qr_png_base64: string;
}

export interface CheckResult {
  allowed: boolean;
  user_id: string;
  effective_permissions: string[];
  missing: string[];
}
