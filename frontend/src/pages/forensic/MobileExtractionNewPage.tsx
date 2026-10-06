import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, HardDriveDownload, Smartphone } from "lucide-react";
import { Button, Card, Field, Input, PageHeader, Select } from "../../components/ui";
import { forensicApi } from "../../lib/forensicApi";
import { useToast } from "../../lib/toast";

const MOBILE_OS_OPTIONS = [
  { value: "android", label: "Android" },
  { value: "ios", label: "iOS" },
  { value: "other", label: "Other / Unknown" },
] as const;

export function MobileExtractionNewPage() {
  const navigate = useNavigate();
  const toast = useToast();
  const [loading, setLoading] = useState(false);
  const [form, setForm] = useState({
    mobile_os: "",
    case_id: "",
    legal_ack: false,
  });

  async function submit() {
    if (loading) return;
    if (!form.mobile_os) {
      toast.error("Select a Mobile OS before continuing");
      return;
    }
    if (!form.legal_ack) {
      toast.error("Acknowledge legal authority before starting mobile extraction");
      return;
    }
    setLoading(true);
    try {
      const job = await forensicApi.createJob({
        type: "mobile_extraction",
        domain_pack: "forensic",
        case_id: form.case_id || null,
        mobile_os: form.mobile_os,
        source_type: "mobile",
        acquisition_mode: "import",
        legal_authority_acknowledged: true,
      });
      toast.success("Mobile extraction job created — select the extraction folder");
      navigate(`/forensic/jobs/${job.id}`, {
        state: { autoSelectFolder: true, lockedSourceType: "mobile", mobileOs: form.mobile_os },
      });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Create failed";
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="New mobile extraction"
        subtitle="Upload .pas / .ufd / .ufdx / .zip from any computer in the browser. Live USB extract needs the helper on the PC the phone is plugged into."
        actions={
          <Button variant="ghost" onClick={() => navigate("/forensic/mobile")}>
            <ArrowLeft className="h-4 w-4" /> Back
          </Button>
        }
      />

      <Card className="max-w-3xl p-6">
        {/* Two evidence modes. Import ingests an extraction another tool produced;
            acquire images the handset directly through the collection orchestrator. */}
        <div className="mb-5 grid gap-2 sm:grid-cols-2">
          <div className="rounded-lg border border-brand-300 bg-brand-50 px-3 py-3">
            <div className="flex items-center gap-2 text-brand-800">
              <Smartphone className="h-5 w-5" />
              <p className="text-sm font-semibold">Import existing extraction</p>
            </div>
            <p className="mt-1 text-xs text-brand-700">
              Upload .pas / .ufd / .ufdx / .zip or a backup folder from this computer — works from any
              browser, not only the server. A working copy is built for analysis.
            </p>
          </div>
          <button
            type="button"
            onClick={() => navigate("/forensic/mobile/acquire")}
            className="rounded-lg border border-ink-100 bg-white px-3 py-3 text-left transition hover:border-brand-200"
          >
            <div className="flex items-center gap-2 text-ink-800">
              <HardDriveDownload className="h-5 w-5 text-brand-600" />
              <p className="text-sm font-semibold">Acquire from a connected device</p>
            </div>
            <p className="mt-1 text-xs text-ink-500">
              Image a handset, SIM or memory card directly. Least intrusive sufficient method,
              inline hashing, sealed original and verified working copy.
            </p>
          </button>
        </div>
        <div className="space-y-4">
          <Field label="Mobile OS" hint="Required. Routes the artifact catalog, parsers, and report objectives.">
            <Select
              value={form.mobile_os}
              onChange={(e) => setForm({ ...form, mobile_os: e.target.value })}
            >
              <option value="">Select Mobile OS…</option>
              {MOBILE_OS_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Case ID (optional)" hint="Link to an existing case record.">
            <Input
              value={form.case_id}
              onChange={(e) => setForm({ ...form, case_id: e.target.value })}
              placeholder="UUID"
            />
          </Field>
          <label className="flex items-start gap-3 rounded-lg border border-ink-100 bg-ink-50/60 px-3 py-3 text-sm text-ink-700">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={form.legal_ack}
              onChange={(e) => setForm({ ...form, legal_ack: e.target.checked })}
            />
            <span>
              I confirm lawful authority and authorized scope for this mobile evidence import. Locked-device bypass is
              not provided; use specialist hand-off when required.
            </span>
          </label>
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="ghost" onClick={() => navigate("/forensic/mobile")}>
              Cancel
            </Button>
            <Button
              variant="brand"
              loading={loading}
              disabled={loading || !form.mobile_os || !form.legal_ack}
              onClick={() => void submit()}
            >
              {loading ? "Creating…" : "Create & add extraction"}
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
}
