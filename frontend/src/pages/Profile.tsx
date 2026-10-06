import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Lock, Mail, ShieldCheck } from "lucide-react";
import { Badge, Button, Card, Field, Input, PageHeader, Spinner } from "../components/ui";
import { api } from "../lib/api";
import { useToast } from "../lib/toast";
import { useAuth } from "../lib/auth";
import type { User } from "../lib/types";

export function Profile() {
  const toast = useToast();
  const { refreshUser } = useAuth();
  const [me, setMe] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [form, setForm] = useState({ first_name: "", last_name: "", phone: "" });

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const res = await api.get<User>("/api/users/me");
        setMe(res);
        setForm({
          first_name: res.profile?.first_name || "",
          last_name: res.profile?.last_name || "",
          phone: res.profile?.phone || "",
        });
      } catch (e: any) {
        toast.error(e?.message || "Failed to load your profile");
      } finally {
        setLoading(false);
      }
    })();
  }, [toast]);

  async function save() {
    setSaving(true);
    try {
      const updated = await api.patch<User>("/api/users/me", {
        first_name: form.first_name,
        last_name: form.last_name,
        phone: form.phone || null,
      });
      setMe(updated);
      toast.success("Profile updated");
      await refreshUser();
    } catch (e: any) {
      toast.error(e?.message || "Update failed");
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <div>
        <PageHeader title="My Profile" subtitle="View and edit your personal details." />
        <Card>
          <Spinner />
        </Card>
      </div>
    );
  }

  return (
    <div>
      <PageHeader title="My Profile" subtitle="View and edit your personal details." />

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <div className="border-b border-ink-100 p-5">
            <h3 className="text-sm font-bold text-ink-900">Personal details</h3>
            <p className="text-xs text-ink-400">Update your name and contact phone number.</p>
          </div>
          <div className="space-y-4 p-5">
            <div className="grid grid-cols-2 gap-3">
              <Field label="First name">
                <Input
                  value={form.first_name}
                  onChange={(e) => setForm({ ...form, first_name: e.target.value })}
                />
              </Field>
              <Field label="Last name">
                <Input
                  value={form.last_name}
                  onChange={(e) => setForm({ ...form, last_name: e.target.value })}
                />
              </Field>
            </div>
            <Field label="Phone (encrypted at rest)">
              <Input value={form.phone} onChange={(e) => setForm({ ...form, phone: e.target.value })} />
            </Field>
            <div className="flex justify-end">
              <Button variant="brand" loading={saving} onClick={save}>
                Save changes
              </Button>
            </div>
          </div>
        </Card>

        <Card>
          <div className="border-b border-ink-100 p-5">
            <h3 className="text-sm font-bold text-ink-900">Account</h3>
          </div>
          <div className="space-y-4 p-5 text-sm">
            <div className="flex items-center gap-2 text-ink-600">
              <Mail className="h-4 w-4 text-ink-400" />
              <span className="truncate">{me?.email}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-ink-500">Status</span>
              <Badge tone={me?.status === "active" ? "green" : "amber"}>{me?.status}</Badge>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-ink-500">Email verified</span>
              <Badge tone={me?.is_email_verified ? "green" : "amber"}>
                {me?.is_email_verified ? "yes" : "no"}
              </Badge>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-ink-500">MFA</span>
              <Badge tone={me?.mfa_enabled ? "indigo" : "neutral"}>
                {me?.mfa_enabled ? "on" : "off"}
              </Badge>
            </div>
            <Link
              to="/security"
              className="mt-2 flex items-center justify-center gap-2 rounded-lg border border-ink-200 px-3 py-2 text-sm font-semibold text-ink-600 hover:bg-ink-50"
            >
              <Lock className="h-4 w-4" />
              Password &amp; MFA
            </Link>
          </div>
        </Card>
      </div>

      <p className="mt-4 flex items-center gap-1.5 text-xs text-ink-400">
        <ShieldCheck className="h-3.5 w-3.5" />
        Your access is determined by the roles and permissions assigned to your account.
      </p>
    </div>
  );
}
