import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { Button, Card, Field, Input, PageHeader, Select } from "../../components/ui";
import { forensicApi } from "../../lib/forensicApi";
import { useToast } from "../../lib/toast";

const MOBILE_OS_OPTIONS = [
  { value: "android", label: "Android" },
  { value: "ios", label: "iOS" },
  { value: "other", label: "Other / Unknown" },
] as const;

const DISK_JOB_TYPES = new Set(["host_disk", "forensic", "vulnerability"]);

export function JobNewPage() {
  const navigate = useNavigate();
  const toast = useToast();
  const [loading, setLoading] = useState(false);
  const [form, setForm] = useState({
    type: "host_disk",
    domain_pack: "forensic",
    case_id: "",
    mobile_os: "",
    legal_ack: false,
  });

  const isMobile = form.type === "mobile_extraction";

  async function submit() {
    if (loading) return;
    if (isMobile) {
      if (!form.mobile_os) {
        toast.error("Select a Mobile OS before continuing");
        return;
      }
      if (!form.legal_ack) {
        toast.error("Acknowledge legal authority before starting mobile extraction");
        return;
      }
    }
    setLoading(true);
    try {
      if (isMobile) {
        // Routes to mobile-build / mobile_forensic — never disk E01 extract.
        const job = await forensicApi.createJob({
          type: "mobile_extraction",
          domain_pack: "forensic",
          case_id: form.case_id || null,
          mobile_os: form.mobile_os,
          source_type: "mobile",
          acquisition_mode: "import",
          legal_authority_acknowledged: true,
        });
        toast.success("Mobile job created — select folder with .pas / .ufd / .ufdx / .zip");
        navigate(`/forensic/jobs/${job.id}`, {
          state: {
            autoSelectFolder: true,
            lockedSourceType: "mobile",
            mobileOs: form.mobile_os,
          },
        });
        return;
      }

      const job = await forensicApi.createJob({
        type: form.type,
        domain_pack: form.domain_pack,
        case_id: form.case_id || null,
      });
      toast.success("Job created — pick the image folder on this computer");
      navigate(`/forensic/jobs/${job.id}`, {
        state: { autoSelectFolder: true },
      });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Create failed";
      toast.error(
        msg.includes("timed out")
          ? "Create job timed out — check API is running (docker compose ps api). If a pipeline is running, wait a moment and retry."
          : msg,
      );
    } finally {
      setLoading(false);
    }
  }

  function onTypeChange(type: string) {
    setForm((prev) => ({
      ...prev,
      type,
      domain_pack: type === "mobile_extraction" ? "forensic" : prev.domain_pack,
      // Reset mobile-only fields when leaving mobile type.
      ...(DISK_JOB_TYPES.has(type)
        ? { mobile_os: "", legal_ack: false }
        : {}),
    }));
  }

  return (
    <div>
      <PageHeader
        title="New forensic job"
        subtitle={
          isMobile
            ? "Import a mobile extraction package (.pas / .ufd / .ufdx / .zip). Analysis uses the mobile pipeline — separate from disk E01 extract."
            : "Evidence stays on your drive. Creating the job does not start processing; select an evidence folder first, then the required mount and pipeline steps begin."
        }
        actions={
          <Button variant="ghost" onClick={() => navigate("/forensic/jobs")}>
            <ArrowLeft className="h-4 w-4" /> Back
          </Button>
        }
      />

      <Card className="max-w-xl p-6">
        <div className="space-y-4">
          <Field label="Job type">
            <Select value={form.type} onChange={(e) => onTypeChange(e.target.value)}>
              <option value="host_disk">Host disk (E01 on workstation — recommended)</option>
              <option value="forensic">Disk / general forensic</option>
              <option value="mobile_extraction">
                Mobile image (.pas / .ufd / .ufdx / .zip)
              </option>
              <option value="vulnerability">vulnerability</option>
            </Select>
            {isMobile ? (
              <p className="mt-1 text-xs text-ink-500">
                Uses the mobile extraction pipeline (not disk imaging). For live handset imaging use{" "}
                <a className="text-brand-700 underline" href="/forensic/mobile/acquire">
                  Acquire from device
                </a>
                .
              </p>
            ) : (
              <p className="mt-1 text-xs text-ink-500">
                Disk jobs use E01/EWF extract. Choose{" "}
                <span className="font-medium text-ink-700">Mobile image</span> for phone/backup
                packages.
              </p>
            )}
          </Field>

          {isMobile ? (
            <>
              <Field
                label="Mobile OS"
                hint="Required. Routes mobile catalog, parsers, and report objectives."
              >
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
              <label className="flex items-start gap-3 rounded-lg border border-ink-100 bg-ink-50/60 px-3 py-3 text-sm text-ink-700">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={form.legal_ack}
                  onChange={(e) => setForm({ ...form, legal_ack: e.target.checked })}
                />
                <span>
                  I confirm lawful authority and authorized scope for this mobile evidence import.
                  Locked-device bypass is not provided; use specialist hand-off when required.
                </span>
              </label>
            </>
          ) : (
            <Field label="Domain pack">
              <Select
                value={form.domain_pack}
                onChange={(e) => setForm({ ...form, domain_pack: e.target.value })}
              >
                <option value="forensic">forensic</option>
                <option value="nessus">nessus</option>
              </Select>
            </Field>
          )}

          <Field label="Case ID (optional)" hint="Link to an existing case record.">
            <Input
              value={form.case_id}
              onChange={(e) => setForm({ ...form, case_id: e.target.value })}
              placeholder="UUID"
            />
          </Field>

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="ghost" onClick={() => navigate("/forensic/jobs")}>
              Cancel
            </Button>
            <Button
              variant="brand"
              loading={loading}
              disabled={loading || (isMobile && (!form.mobile_os || !form.legal_ack))}
              onClick={() => void submit()}
            >
              {loading
                ? isMobile
                  ? "Creating…"
                  : "Mounting drives…"
                : isMobile
                  ? "Create & select folder"
                  : "Create job"}
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
}
