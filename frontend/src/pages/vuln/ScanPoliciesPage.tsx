import { useCallback, useEffect, useState } from "react";
import { Plus, Shield } from "lucide-react";
import { Badge, Button, Card, Field, Input, Modal, PageHeader, Select, Spinner } from "../../components/ui";
import { vulnApi } from "../../lib/vulnApi";
import { useToast } from "../../lib/toast";
import { useAuth } from "../../lib/auth";
import type { ScanPolicy, Scanner } from "../../lib/types/vuln";

export function ScanPoliciesPage() {
  const toast = useToast();
  const { hasPermission } = useAuth();
  const canManage = hasPermission("scan:policy_manage");

  const [policies, setPolicies] = useState<ScanPolicy[]>([]);
  const [scanners, setScanners] = useState<Scanner[]>([]);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [p, s] = await Promise.all([vulnApi.listScanPolicies(), vulnApi.listScanners()]);
      setPolicies(p);
      setScanners(s);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load policies");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div>
      <PageHeader
        title="Scan policies"
        subtitle="Define reusable Nessus scan templates and compliance frameworks."
        actions={
          canManage && (
            <Button variant="brand" onClick={() => setCreateOpen(true)}>
              <Plus className="h-4 w-4" /> New policy
            </Button>
          )
        }
      />

      <Card className="overflow-hidden">
        {loading ? (
          <Spinner />
        ) : policies.length === 0 ? (
          <p className="px-5 py-16 text-center text-sm text-ink-400">No scan policies defined.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="table-head border-b border-brand-300/70 text-xs uppercase tracking-wider text-ink-700">
                  <th className="px-5 py-3 font-semibold">Policy</th>
                  <th className="px-5 py-3 font-semibold">Type</th>
                  <th className="px-5 py-3 font-semibold">Framework</th>
                  <th className="px-5 py-3 font-semibold">Created</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-100">
                {policies.map((p) => (
                  <tr key={p.id} className="hover:bg-ink-50/60">
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-3">
                        <Shield className="h-4 w-4 text-brand-600" />
                        <span className="font-semibold text-ink-800">{p.name}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3">
                      <Badge tone="indigo">{p.policy_type}</Badge>
                    </td>
                    <td className="px-5 py-3 text-ink-500">{p.compliance_framework || "—"}</td>
                    <td className="px-5 py-3 text-ink-500">
                      {new Date(p.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {createOpen && (
        <PolicyModal
          scanners={scanners}
          onClose={() => setCreateOpen(false)}
          onSaved={() => {
            setCreateOpen(false);
            load();
          }}
        />
      )}
    </div>
  );
}

function PolicyModal({
  scanners,
  onClose,
  onSaved,
}: {
  scanners: Scanner[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const toast = useToast();
  const [loading, setLoading] = useState(false);
  const [form, setForm] = useState({
    name: "",
    policy_type: "basic",
    scanner_id: "",
    compliance_framework: "",
    case_id: "",
  });

  async function submit() {
    setLoading(true);
    try {
      await vulnApi.createScanPolicy({
        name: form.name,
        policy_type: form.policy_type,
        scanner_id: form.scanner_id || null,
        compliance_framework: form.compliance_framework || null,
        case_id: form.case_id || null,
      });
      toast.success("Policy created");
      onSaved();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Create failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="New scan policy"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="brand" loading={loading} onClick={submit}>
            Create
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Name">
          <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </Field>
        <Field label="Policy type">
          <Select
            value={form.policy_type}
            onChange={(e) => setForm({ ...form, policy_type: e.target.value })}
          >
            <option value="basic">basic</option>
            <option value="advanced">advanced</option>
            <option value="compliance">compliance</option>
          </Select>
        </Field>
        <Field label="Scanner">
          <Select
            value={form.scanner_id}
            onChange={(e) => setForm({ ...form, scanner_id: e.target.value })}
          >
            <option value="">— select —</option>
            {scanners.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Compliance framework">
          <Input
            value={form.compliance_framework}
            onChange={(e) => setForm({ ...form, compliance_framework: e.target.value })}
          />
        </Field>
      </div>
    </Modal>
  );
}
