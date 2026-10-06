import { useRef, useState } from "react";
import { Check, MessageSquare, Pencil, X } from "lucide-react";
import { Badge, Button } from "../ui";
import { forensicApi } from "../../lib/forensicApi";
import { useToast } from "../../lib/toast";
import { mergeContinuedTables, parseMarkdownTables, serializeEditableBody } from "../../lib/reportTextDiff";
import { editorsForSection } from "./ReportEditContext";
import type { ReportSection } from "../../lib/types/forensic";

interface ReportSectionReviewProps {
  jobId: string;
  section: ReportSection;
  onUpdated: (section: ReportSection) => void;
  editing: boolean;
  setEditing: (value: boolean) => void;
}

const STATUS_TONE: Record<string, "neutral" | "green" | "amber" | "red" | "indigo"> = {
  pending: "amber",
  approved: "green",
  verified: "green",
  rejected: "red",
  needs_review: "amber",
};

function existingBaseline(section: ReportSection): string {
  const sj = (section.structured_json ?? {}) as Record<string, unknown>;
  return String(sj.human_edit_baseline ?? "").trim();
}

/**
 * Approve / reject / edit controls. Editing happens on the A4 page itself
 * (not in a markdown box). New and changed words are shown in blue.
 */
export function ReportSectionReview({
  jobId,
  section,
  onUpdated,
  editing,
  setEditing,
}: ReportSectionReviewProps) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [showFeedback, setShowFeedback] = useState(false);
  const [feedback, setFeedback] = useState("");
  const preEditNarrative = useRef(section.narrative_content ?? "");

  async function setStatus(status: string) {
    setBusy(true);
    try {
      const updated = await forensicApi.patchReportSection(jobId, section.section_key, {
        verification_status: status,
      });
      onUpdated(updated);
      toast.success(`Section ${status}`);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Update failed");
    } finally {
      setBusy(false);
    }
  }

  async function saveEdit() {
    const roots = editorsForSection(section.section_key);
    const draft = roots.map((el) => serializeEditableBody(el)).filter(Boolean).join("\n\n").trim();
    if (!draft) {
      toast.error("The page is empty — add text before saving");
      return;
    }
    setBusy(true);
    try {
      const sourceCards = section.section_key === "suspicious_activity" && Boolean((section.structured_json?.suspicious_activity as unknown[])?.length);
      const baseline = existingBaseline(section) || (sourceCards ? String(section.structured_json?.examiner_observations_md || "### Examiner observations\n\nNo examiner observations recorded.") : preEditNarrative.current);
      const parsedTables = mergeContinuedTables(parseMarkdownTables(draft));
      const structured: Record<string, unknown> = {
        ...(section.structured_json ?? {}),
        human_edit_baseline: baseline,
      };
      if (sourceCards) structured.examiner_observations_md = draft;
      if (parsedTables.length > 0) {
        structured.tables = parsedTables;
      }
      const updated = await forensicApi.patchReportSection(jobId, section.section_key, {
        narrative_content: draft,
        structured_json: structured,
        verification_status: "approved",
      });
      onUpdated({
        ...updated,
        narrative_content: updated.narrative_content ?? draft,
        structured_json: updated.structured_json ?? structured,
      });
      setEditing(false);
      toast.success("Saved to the report draft");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Save failed");
    } finally {
      setBusy(false);
    }
  }

  async function sendFeedback() {
    if (!feedback.trim()) {
      toast.error("Enter what needs changing");
      return;
    }
    setBusy(true);
    try {
      await forensicApi.submitFeedback(jobId, {
        section_key: section.section_key,
        feedback_type: "change_request",
        content: feedback.trim(),
      });
      const updated = await forensicApi.patchReportSection(jobId, section.section_key, {
        verification_status: "needs_review",
      });
      onUpdated(updated);
      setShowFeedback(false);
      setFeedback("");
      toast.success("Change request recorded");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Feedback failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mt-3">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <Badge tone={STATUS_TONE[section.verification_status] ?? "neutral"}>
          {section.verification_status}
        </Badge>
        {editing ? (
          <span className="text-xs text-ink-500">
            Click the page and type. New or changed words appear in{" "}
            <span className="font-semibold text-[#1d4ed8]">blue</span>.
          </span>
        ) : (
          <span className="text-xs text-ink-400">Edit the report page directly</span>
        )}
      </div>

      {editing ? (
        <div className="flex gap-2">
          <Button variant="brand" onClick={saveEdit} disabled={busy}>
            <Check className="h-4 w-4" /> Save and approve
          </Button>
          <Button
            variant="ghost"
            onClick={() => setEditing(false)}
            disabled={busy}
          >
            Cancel
          </Button>
        </div>
      ) : (
        <div className="flex flex-wrap gap-2">
          <Button variant="brand" onClick={() => setStatus("approved")} disabled={busy}>
            <Check className="h-4 w-4" /> Approve
          </Button>
          <Button variant="outline" onClick={() => setStatus("rejected")} disabled={busy}>
            <X className="h-4 w-4" /> Reject
          </Button>
          <Button
            variant="outline"
            onClick={() => {
              preEditNarrative.current = section.narrative_content ?? "";
              setEditing(true);
            }}
          >
            <Pencil className="h-4 w-4" /> Edit page
          </Button>
          <Button variant="outline" onClick={() => setShowFeedback((v) => !v)}>
            <MessageSquare className="h-4 w-4" /> Request changes
          </Button>
        </div>
      )}

      {showFeedback && !editing && (
        <div className="mt-2">
          <input
            className="input w-full text-sm"
            placeholder="What needs to change on this page?"
            value={feedback}
            onChange={(e) => setFeedback(e.target.value)}
          />
          <div className="mt-2 flex justify-end">
            <Button variant="brand" onClick={sendFeedback} disabled={busy}>
              Submit change request
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
