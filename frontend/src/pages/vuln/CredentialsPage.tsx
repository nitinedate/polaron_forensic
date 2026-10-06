import { useCallback, useEffect, useState } from "react";
import { Badge, Button, Card, Field, Input, Modal, PageHeader, Select, Spinner } from "../../components/ui";
import { vulnApi } from "../../lib/vulnApi";
import { useAuth } from "../../lib/auth";
import { useToast } from "../../lib/toast";

type Cred = {
  id: string;
  name: string;
  vault_ref: string;
  credential_type: string;
  lifecycle_state: string;
  last_test_result: string | null;
};

export function CredentialsPage() {
  const { hasPermission } = useAuth();
  const canManage = hasPermission("credential:manage");
  const toast = useToast();
  const [items, setItems] = useState<Cred[]>([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ name: "", vault_ref: "", credential_type: "ssh" });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setItems((await vulnApi.listCredentials()) as Cred[]);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load credentials");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  const create = async () => {
    if (!form.name.trim() || !form.vault_ref.trim()) {
      toast.error("Name and vault reference required (never store plaintext passwords)");
      return;
    }
    try {
      await vulnApi.createCredential(form);
      toast.success("Credential reference saved");
      setOpen(false);
      load();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Create failed");
    }
  };

  return (
    <div>
      <PageHeader
        title="Scan credentials"
        subtitle="Vault references only — plaintext secrets are never stored (BRD §8)."
        actions={
          canManage ? (
            <Button variant="brand" onClick={() => setOpen(true)}>
              Add vault ref
            </Button>
          ) : null
        }
      />
      {loading ? (
        <div className="flex justify-center py-12">
          <Spinner />
        </div>
      ) : (
        <Card className="overflow-hidden p-0">
          <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead>
              <tr className="table-head border-b border-brand-300/70 text-ink-700">
                <th className="px-4 py-3">Name</th>
                <th className="px-4 py-3">Vault ref</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">State</th>
                <th className="px-4 py-3">Last test</th>
              </tr>
            </thead>
            <tbody>
              {items.map((c) => (
                <tr key={c.id} className="border-b border-ink-50">
                  <td className="px-4 py-3">{c.name}</td>
                  <td className="px-4 py-3 font-mono text-xs">{c.vault_ref}</td>
                  <td className="px-4 py-3">{c.credential_type}</td>
                  <td className="px-4 py-3">
                    <Badge>{c.lifecycle_state}</Badge>
                  </td>
                  <td className="px-4 py-3">{c.last_test_result || "—"}</td>
                </tr>
              ))}
              {items.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-ink-400">
                    No credential references yet.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
          </div>
        </Card>
      )}
      {open && (
        <Modal
          open
          onClose={() => setOpen(false)}
          title="Add credential vault reference"
          footer={
            <>
              <Button variant="ghost" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button variant="brand" onClick={create}>
                Save
              </Button>
            </>
          }
        >
          <div className="space-y-3">
            <Field label="Name">
              <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </Field>
            <Field label="Vault reference" hint="e.g. vault://secret/nessus/win-scan">
              <Input value={form.vault_ref} onChange={(e) => setForm({ ...form, vault_ref: e.target.value })} />
            </Field>
            <Field label="Type">
              <Select
                value={form.credential_type}
                onChange={(e) => setForm({ ...form, credential_type: e.target.value })}
              >
                <option value="ssh">SSH</option>
                <option value="windows">Windows</option>
                <option value="snmp">SNMP</option>
                <option value="database">Database</option>
              </Select>
            </Field>
          </div>
        </Modal>
      )}
    </div>
  );
}
