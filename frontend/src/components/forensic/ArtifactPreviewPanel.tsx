import { useEffect, useMemo, useState } from "react";
import { Download, ExternalLink, Paperclip, Smartphone } from "lucide-react";
import { Spinner, Button } from "../ui";
import { forensicApi } from "../../lib/forensicApi";
import {
  artifactCanDownload,
  artifactContentTarget,
  artifactDownloadName,
  artifactThumbnailPayload,
  downloadBase64File,
  stripWhatsAppProtocolPrefix,
} from "../../lib/artifactContent";
import { useToast } from "../../lib/toast";
import type {
  Artifact,
  ArtifactEmailAttachment,
  ArtifactMediaProperties,
  ArtifactPreview,
  ArtifactReview,
} from "../../lib/types/forensic";

function formatDuration(seconds?: number | null): string {
  if (seconds == null || !Number.isFinite(seconds)) return "";
  const total = Math.max(0, Math.round(seconds));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  return h > 0 ? `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}` : `${m}:${String(s).padStart(2, "0")}`;
}

function formatBytes(size?: number): string {
  if (size == null) return "";
  if (size < 1024) return `${size} B`;
  if (size < 1024 ** 2) return `${(size / 1024).toFixed(1)} KB`;
  if (size < 1024 ** 3) return `${(size / 1024 ** 2).toFixed(1)} MB`;
  if (size < 1024 ** 4) return `${(size / 1024 ** 3).toFixed(2)} GB`;
  return `${(size / 1024 ** 4).toFixed(2)} TB`;
}

function SandboxedHtmlEvidence({ html, title }: { html: string; title: string }) {
  const srcDoc = useMemo(() => {
    const csp = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; media-src data:; style-src 'unsafe-inline'; font-src data:; form-action 'none'; base-uri 'none'; frame-src 'none'">`;
    return `${csp}${html || ""}`;
  }, [html]);
  return (
    <iframe
      title={title}
      sandbox=""
      srcDoc={srcDoc}
      className="h-96 w-full rounded border border-ink-100 bg-white"
    />
  );
}

function EmailPreviewView({
  jobId,
  artifactId,
  preview,
  onOpenLinkedArtifact,
}: {
  jobId: string;
  artifactId: string;
  preview: ArtifactPreview;
  onOpenLinkedArtifact?: (artifactId: string) => void;
}) {
  const toast = useToast();
  const [bodyTab, setBodyTab] = useState<"html" | "text" | "raw">(
    preview.body_html ? "html" : preview.body_text ? "text" : "raw"
  );
  const [openingPart, setOpeningPart] = useState<number | null>(null);
  const headers = preview.email ?? {};

  async function openAttachment(att: ArtifactEmailAttachment) {
    if (att.artifact_id && onOpenLinkedArtifact) {
      onOpenLinkedArtifact(att.artifact_id);
      return;
    }
    if (att.part_index == null) {
      toast.error(`Cannot open “${att.filename}” — no MIME part index. Opening parent email instead.`);
      try {
        await forensicApi.openArtifactContent(jobId, artifactId);
      } catch (e: unknown) {
        toast.error(e instanceof Error ? e.message : "Could not open attachment");
      }
      return;
    }
    setOpeningPart(att.part_index);
    try {
      await forensicApi.openEmailAttachmentContent(jobId, artifactId, att.part_index, att.content_type);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Could not open attachment — trying parent email");
      try {
        await forensicApi.openArtifactContent(jobId, artifactId);
      } catch {
        /* ignore */
      }
    } finally {
      setOpeningPart(null);
    }
  }

  async function downloadAttachment(att: ArtifactEmailAttachment) {
    setOpeningPart(att.part_index ?? -1);
    try {
      if (att.artifact_id) {
        await forensicApi.downloadArtifactContent(jobId, att.artifact_id, att.filename);
        return;
      }
      if (att.part_index == null) {
        toast.error(`Cannot download “${att.filename}” — no MIME part index.`);
        return;
      }
      await forensicApi.downloadEmailAttachmentContent(jobId, artifactId, att.part_index, att.filename);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Could not download attachment");
    } finally {
      setOpeningPart(null);
    }
  }

  const bodyContent =
    bodyTab === "html"
      ? preview.body_html
      : bodyTab === "text"
        ? preview.body_text || preview.body
        : preview.body;

  return (
    <div className="space-y-4">
      <div className="overflow-hidden rounded-2xl border border-ink-300 bg-gradient-to-b from-white to-brand-50/30 shadow-panel">
        <table className="w-full text-left text-xs">
          <tbody>
            {[
              ["From", headers.from],
              ["To", headers.to],
              ["Cc", headers.cc],
              ["Subject", headers.subject],
              ["Date", headers.date],
            ]
              .filter(([, value]) => value)
              .map(([label, value]) => (
                <tr key={label} className="border-b border-ink-50 last:border-0">
                  <th className="w-20 shrink-0 bg-ink-50/70 px-3 py-2 font-semibold text-ink-500">{label}</th>
                  <td className="px-3 py-2 text-ink-800">{value}</td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>

      <div>
        <div className="mb-2 flex flex-wrap gap-2">
          {preview.body_html ? (
            <button
              type="button"
              onClick={() => setBodyTab("html")}
              className={
                bodyTab === "html"
                  ? "rounded-md bg-brand-600 px-2.5 py-1 text-xs font-semibold text-white"
                  : "rounded-md border border-ink-200 px-2.5 py-1 text-xs text-ink-600"
              }
            >
              HTML body
            </button>
          ) : null}
          {(preview.body_text || preview.body) ? (
            <button
              type="button"
              onClick={() => setBodyTab("text")}
              className={
                bodyTab === "text"
                  ? "rounded-md bg-brand-600 px-2.5 py-1 text-xs font-semibold text-white"
                  : "rounded-md border border-ink-200 px-2.5 py-1 text-xs text-ink-600"
              }
            >
              Plain text
            </button>
          ) : null}
          <button
            type="button"
            onClick={() => setBodyTab("raw")}
            className={
              bodyTab === "raw"
                ? "rounded-md bg-brand-600 px-2.5 py-1 text-xs font-semibold text-white"
                : "rounded-md border border-ink-200 px-2.5 py-1 text-xs text-ink-600"
            }
          >
            Raw source
          </button>
        </div>
        {bodyTab === "html" && preview.body_html ? (
          <SandboxedHtmlEvidence html={preview.body_html} title="Sandboxed recovered email HTML" />
        ) : bodyContent ? (
          <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded border border-ink-100 bg-white p-3 font-mono text-xs leading-relaxed text-ink-700">
            {bodyContent}
          </pre>
        ) : (
          <p className="text-sm text-ink-400">No message body found in this email file.</p>
        )}
      </div>

      {preview.attachments && preview.attachments.length > 0 ? (
        <div className="rounded-lg border border-ink-100 bg-white">
          <p className="flex items-center gap-1 border-b border-ink-100 px-3 py-2 text-xs font-semibold uppercase text-ink-400">
            <Paperclip className="h-3.5 w-3.5" />
            Attachments ({preview.attachments.length})
          </p>
          <ul className="divide-y divide-ink-50">
            {preview.attachments.map((att) => (
              <li key={`${att.part_index ?? att.filename}-${att.filename}`} className="flex items-center gap-2 px-3 py-2">
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium text-ink-800">{att.filename}</p>
                  <p className="text-[11px] text-ink-400">
                    {att.content_type || "application/octet-stream"}
                    {att.size != null ? ` · ${formatBytes(att.size)}` : ""}
                    {att.inline ? " · inline" : ""}
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-1">
                  <Button
                    variant="outline"
                    className="h-7 px-2 text-xs"
                    disabled={openingPart === att.part_index && att.part_index != null}
                    onClick={() => void openAttachment(att)}
                  >
                    {att.artifact_id ? "View indexed file" : openingPart === att.part_index ? "Opening…" : "Open"}
                  </Button>
                  <Button
                    variant="ghost"
                    className="h-7 px-2 text-xs"
                    disabled={openingPart === att.part_index && att.part_index != null}
                    onClick={() => void downloadAttachment(att)}
                  >
                    <Download className="h-3.5 w-3.5" /> Download
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function OsDetailsTable({ rows }: { rows: Array<Record<string, string | null>> }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left text-xs">
        <thead>
          <tr className="bg-brand-600 text-white">
            <th className="border border-brand-500 px-3 py-2 font-semibold">Sr. No.</th>
            <th className="border border-brand-500 px-3 py-2 font-semibold">Artifacts Details</th>
            <th className="border border-brand-500 px-3 py-2 font-semibold">Value</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className={i % 2 === 0 ? "bg-sky-50" : "bg-white"}>
              <td className="border border-ink-100 px-3 py-1.5 text-ink-500">{i + 1}</td>
              <td className="border border-ink-100 px-3 py-1.5 font-medium text-ink-700">
                {row.artifact_detail}
              </td>
              <td className="border border-ink-100 px-3 py-1.5 text-ink-600">{row.value || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function UserDetailsTable({ rows }: { rows: Array<Record<string, string | null>> }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left text-xs">
        <thead>
          <tr className="bg-emerald-600 text-white">
            <th className="border border-emerald-500 px-2 py-2 font-semibold">Sr. No.</th>
            <th className="border border-emerald-500 px-2 py-2 font-semibold">Username</th>
            <th className="border border-emerald-500 px-2 py-2 font-semibold">Type of User</th>
            <th className="border border-emerald-500 px-2 py-2 font-semibold">Profile path</th>
            <th className="border border-emerald-500 px-2 py-2 font-semibold">Last Local Login</th>
            <th className="border border-emerald-500 px-2 py-2 font-semibold">Last Password Change</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className={i % 2 === 0 ? "bg-emerald-50/50" : "bg-white"}>
              <td className="border border-ink-100 px-2 py-1.5">{row.sr_no ?? i + 1}</td>
              <td className="border border-ink-100 px-2 py-1.5 font-medium">{row.username || "—"}</td>
              <td className="border border-ink-100 px-2 py-1.5">{row.user_type || "—"}</td>
              <td className="border border-ink-100 px-2 py-1.5 font-mono text-[11px]">
                {row.profile_path || "—"}
              </td>
              <td className="border border-ink-100 px-2 py-1.5">{row.last_local_login || "—"}</td>
              <td className="border border-ink-100 px-2 py-1.5">{row.last_password_change || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function LlmAnalysisBlock({ analysis }: { analysis: Record<string, unknown> }) {
  const extractions =
    (analysis.extractions as Array<{ field?: string; value?: string; source_excerpt?: string }> | undefined) ??
    [];
  const facts = (analysis.key_facts as string[] | undefined) ?? [];
  const verified = analysis.grounding_verified === true;

  if (extractions.length === 0 && facts.length === 0) {
    return null;
  }

  return (
    <div className="space-y-3 rounded-lg border border-emerald-200 bg-emerald-50/50 p-3 text-sm">
      <p className="text-xs font-semibold uppercase text-emerald-800">
        Verified extractions{verified ? " (source-grounded)" : ""}
      </p>
      {extractions.length > 0 && (
        <ul className="space-y-2 text-xs text-ink-700">
          {extractions.slice(0, 20).map((row, i) => (
            <li key={i} className="rounded border border-emerald-100 bg-white px-2 py-1.5">
              <span className="font-medium text-ink-600">{row.field || "detail"}:</span> {row.value}
              {row.source_excerpt ? (
                <p className="mt-1 font-mono text-[10px] text-ink-400">"{row.source_excerpt}"</p>
              ) : null}
            </li>
          ))}
        </ul>
      )}
      {facts.length > 0 && (
        <ul className="list-disc space-y-1 pl-4 text-xs text-ink-600">
          {facts.slice(0, 12).map((f, i) => (
            <li key={i}>{f}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

function StructuredPreview({ body }: { body: string }) {
  try {
    const data = JSON.parse(body) as Record<string, unknown>;
    const llm = data.llm_analysis as Record<string, unknown> | undefined;
    if (llm && llm.status === "ok") {
      return <LlmAnalysisBlock analysis={llm} />;
    }
    const osTable = data.os_details_table as Array<Record<string, string | null>> | undefined;
    const userTable = data.user_details_table as Array<Record<string, string | null>> | undefined;
    if (osTable?.length || userTable?.length) {
      return (
        <div className="space-y-6">
          {osTable && osTable.length > 0 && (
            <div className="space-y-2">
              <p className="text-xs font-semibold uppercase text-ink-400">Operating System Details</p>
              <OsDetailsTable rows={osTable} />
            </div>
          )}
          {userTable && userTable.length > 0 && (
            <div className="space-y-2">
              <p className="text-xs font-semibold uppercase text-ink-400">User Accounts</p>
              <UserDetailsTable rows={userTable} />
            </div>
          )}
        </div>
      );
    }
    if (data.users && Array.isArray(data.users)) {
      const users = data.users as Array<Record<string, string | null>>;
      const os = (data.os || {}) as Record<string, string>;
      const hw = (data.hardware || {}) as Record<string, string>;
      return (
        <div className="space-y-4 text-sm text-ink-700">
          {Object.keys(os).length > 0 && (
            <div>
              <p className="mb-1 text-xs font-semibold uppercase text-ink-400">Operating System</p>
              <ul className="space-y-0.5">
                {Object.entries(os).map(([k, v]) => (
                  <li key={k}>
                    <span className="text-ink-500">{k}:</span> {v}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {Object.keys(hw).length > 0 && (
            <div>
              <p className="mb-1 text-xs font-semibold uppercase text-ink-400">Hardware</p>
              <ul className="space-y-0.5">
                {Object.entries(hw).map(([k, v]) => (
                  <li key={k}>
                    <span className="text-ink-500">{k}:</span> {v}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {users.length > 0 && (
            <div>
              <p className="mb-1 text-xs font-semibold uppercase text-ink-400">Login Users</p>
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="table-head border-b border-brand-300/70 text-ink-700">
                    <th className="py-1 pr-2">User</th>
                    <th className="py-1 pr-2">Profile</th>
                    <th className="py-1 pr-2">Last login</th>
                    <th className="py-1">Pwd change</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={String(u.username)} className="border-b border-ink-50">
                      <td className="py-1 pr-2 font-medium">{u.username}</td>
                      <td className="py-1 pr-2 font-mono text-[11px]">{u.profile_path}</td>
                      <td className="py-1 pr-2">{u.last_login || "—"}</td>
                      <td className="py-1">{u.last_password_change || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      );
    }
    const hits = data.search_hits as Array<{ table?: string; text?: string }> | undefined;
    if (hits && hits.length > 0) {
      return (
        <ul className="max-h-64 space-y-1 overflow-auto text-sm text-ink-700">
          {hits.slice(0, 50).map((hit, i) => (
            <li key={i} className="rounded border border-ink-100 bg-white px-2 py-1 text-xs">
              <span className="font-medium text-ink-500">[{hit.table}]</span> {hit.text}
            </li>
          ))}
        </ul>
      );
    }
    if (data.entries && Array.isArray(data.entries)) {
      const entries = data.entries as Array<Record<string, unknown>>;
      return (
        <ul className="max-h-64 space-y-1 overflow-auto text-sm text-ink-700">
          {entries.slice(0, 40).map((row, i) => (
            <li key={i} className="rounded border border-ink-100 bg-white px-2 py-1 text-xs">
              {Object.entries(row)
                .map(([k, v]) => `${k}: ${String(v ?? "")}`)
                .join(" · ")}
            </li>
          ))}
        </ul>
      );
    }
  } catch {
    /* fall through */
  }
  return (
    <pre className="max-h-64 overflow-auto whitespace-pre-wrap font-mono text-xs leading-relaxed text-ink-700">
      {body}
    </pre>
  );
}

export function ArtifactPreviewPanel({
  jobId,
  artifact,
  onOpenLinkedArtifact,
}: {
  jobId: string;
  artifact: Artifact;
  onOpenLinkedArtifact?: (artifactId: string) => void;
}) {
  const [preview, setPreview] = useState<ArtifactPreview | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [blobUrl, setBlobUrl] = useState<string | null>(null);
  const [opening, setOpening] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [properties, setProperties] = useState<ArtifactMediaProperties | null>(null);
  const [review, setReview] = useState<ArtifactReview | null>(null);
  const toast = useToast();

  useEffect(() => {
    const controller = new AbortController();
    let cancelled = false;
    setLoading(true);
    setError(null);
    setPreview(null);

    const meta = artifact.metadata || {};
    const evidenceKind = String(meta.evidence_kind || "");
    const mediaArtifactId = meta.media_artifact_id ? String(meta.media_artifact_id) : null;
    const thumbB64 =
      typeof meta.thumbnail_base64 === "string" && meta.thumbnail_base64.length > 80
        ? String(meta.thumbnail_base64)
        : null;
    const thumbType = String(meta.thumbnail_content_type || "image/jpeg");
    // Virtual evidence rows (URL visits / chat messages) carry preview payload in metadata.
    if (
      evidenceKind === "url_visit" ||
      evidenceKind === "whatsapp_message" ||
      evidenceKind === "whatsapp_deleted_message" ||
      evidenceKind === "contact" ||
      evidenceKind === "chat_message" ||
      evidenceKind === "sms_message" ||
      evidenceKind === "outlook_message" ||
      evidenceKind === "carved_signature" ||
      evidenceKind === "browser_history_db" ||
      String(artifact.id).startsWith("ev-") ||
      String(artifact.id).startsWith("carve-")
    ) {
      const bodyRaw = String(meta.preview_body || meta.body || meta.url || "");
      const body =
        evidenceKind === "whatsapp_deleted_message" || Boolean(meta.is_deleted)
          ? stripWhatsAppProtocolPrefix(bodyRaw) && /Original content:/i.test(bodyRaw)
            ? bodyRaw.replace(
                /(Original content:\s*)([\s\S]*?)(?=\n\s*(?:Protocol residue|Recovery status|\[ATTACHMENT\]|⚠)|$)/i,
                (_m, label: string, section: string) => {
                  const cleaned =
                    stripWhatsAppProtocolPrefix(`Original content:\n${section}`) ||
                    section.trim();
                  return `${label}${cleaned}`;
                },
              )
            : stripWhatsAppProtocolPrefix(bodyRaw) || bodyRaw
          : bodyRaw;
      const chatApp = String(meta.social_app || evidenceKind || "chat").replace(/_/g, " ");
      const mediaUrl = mediaArtifactId
        ? `/api/jobs/${jobId}/artifacts/${mediaArtifactId}/content`
        : null;
      const buildTextPreview = (mediaPreview?: ArtifactPreview | null) => {
        if (cancelled || controller.signal.aborted) return;
        const mediaType = String(mediaPreview?.content_type || "");
        const mediaIsPlayable =
          Boolean(mediaPreview) &&
          !/sqlite/i.test(mediaType) &&
          (/^(image|audio|video)\//i.test(mediaType) || mediaType === "application/pdf");
        const fromThumb =
          !mediaIsPlayable && thumbB64
            ? {
                content_type: thumbType,
                body: thumbB64,
                encoding: "base64" as const,
              }
            : {};
        setPreview({
          artifact_id: artifact.id,
          title: artifact.title,
          artifact_type: artifact.artifact_type || evidenceKind || "evidence",
          content_type: "text/plain",
          body,
          body_text: body,
          content_url: mediaUrl,
          encoding: undefined,
          ...(mediaIsPlayable
            ? {
                content_type: mediaType,
                body: mediaPreview?.body || "",
                body_text: body,
                encoding: mediaPreview?.encoding,
                content_url: mediaPreview?.content_url || mediaUrl,
              }
            : fromThumb),
          email:
            evidenceKind === "whatsapp_message" ||
            evidenceKind === "whatsapp_deleted_message" ||
            evidenceKind === "chat_message" ||
            evidenceKind === "sms_message"
              ? {
                  from: String(meta.sender || ""),
                  subject:
                    evidenceKind === "whatsapp_deleted_message"
                      ? "⚠ RECOVERED / DELETED WhatsApp message"
                      : `${chatApp} message`,
                  date: meta.timestamp ? String(meta.timestamp) : "",
                }
              : evidenceKind === "outlook_message"
                ? {
                    from: String(meta.from || ""),
                    subject: String(meta.subject || artifact.title || "Outlook message"),
                  }
                : undefined,
          attachments: undefined,
          attachment_count: 0,
        });
        setLoading(false);
      };

      if (mediaArtifactId) {
        forensicApi
          .getArtifactPreview(jobId, mediaArtifactId)
          .then((p) => buildTextPreview(p))
          .catch(() => buildTextPreview(null));
      } else {
        buildTextPreview(null);
      }
      return () => {
        cancelled = true;
        controller.abort();
      };
    }

    forensicApi
      .getArtifactPreview(jobId, artifact.id)
      .then((p) => {
        if (!cancelled && !controller.signal.aborted) setPreview(p);
      })
      .catch((e: unknown) => {
        if (cancelled || controller.signal.aborted) return;
        const msg = e instanceof Error ? e.message : "Preview unavailable";
        setError(msg.includes("502") ? "Server busy — retry in a moment." : msg);
      })
      .finally(() => {
        if (!cancelled && !controller.signal.aborted) setLoading(false);
      });
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [jobId, artifact.id, artifact.metadata, artifact.title, artifact.artifact_type]);

  // Stream any URL-encoded preview (image/video/audio/PDF/binary) — no size gate.
  const needsAuthBlob = preview?.encoding === "url" && Boolean(preview.content_url);
  const contentTarget = artifactContentTarget(artifact);
  const contentArtifactId = contentTarget.id;

  useEffect(() => {
    let cancelled = false;
    setProperties(null);
    setReview(null);
    if (!contentArtifactId || String(contentArtifactId).startsWith("ev-") || String(contentArtifactId).startsWith("carve-")) {
      return () => { cancelled = true; };
    }
    Promise.allSettled([
      forensicApi.getArtifactProperties(jobId, contentArtifactId),
      forensicApi.getArtifactReview(jobId, contentArtifactId),
    ]).then(([propResult, reviewResult]) => {
      if (cancelled) return;
      if (propResult.status === "fulfilled") setProperties(propResult.value);
      if (reviewResult.status === "fulfilled") setReview(reviewResult.value);
    });
    return () => { cancelled = true; };
  }, [jobId, contentArtifactId]);

  useEffect(() => {
    if (!needsAuthBlob || !contentArtifactId) {
      setBlobUrl(null);
      return;
    }
    let cancelled = false;
    let objectUrl: string | null = null;
    forensicApi
      .fetchArtifactContent(jobId, contentArtifactId)
      .then((blob) => {
        if (cancelled) return;
        objectUrl = URL.createObjectURL(blob);
        setBlobUrl(objectUrl);
      })
      .catch(() => {
        if (!cancelled) setBlobUrl(null);
      });
    return () => {
      cancelled = true;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [needsAuthBlob, jobId, contentArtifactId]);

  const device =
    preview?.device_name ||
    (artifact.metadata?.device_name as string | undefined) ||
    null;

  const llmAnalysis = artifact.metadata?.llm_analysis as Record<string, unknown> | undefined;

  const hasStoredContent = Boolean(contentArtifactId);
  const canDownload = artifactCanDownload(artifact);

  const imageSrc = useMemo(() => {
    if (!preview) return null;
    if (preview.encoding === "base64" && preview.content_type.startsWith("image/")) {
      return `data:${preview.content_type};base64,${preview.body}`;
    }
    // Large / converted images stream via authenticated blob URL.
    if (preview.encoding === "url" && blobUrl && preview.content_type.startsWith("image/")) {
      return blobUrl;
    }
    return null;
  }, [preview, blobUrl]);

  const mediaSrc = blobUrl;

  const visitUrl =
    String(artifact.metadata?.evidence_kind || "") === "url_visit" &&
    typeof artifact.metadata?.url === "string" &&
    /^https?:\/\//i.test(artifact.metadata.url)
      ? String(artifact.metadata.url)
      : null;

  async function openInNewTab() {
    if (!contentArtifactId) {
      setError("No photo, video, or audio file is linked to this row — the chat database is not opened here.");
      return;
    }
    setOpening(true);
    try {
      await forensicApi.openArtifactContent(jobId, contentArtifactId);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Could not open content");
    } finally {
      setOpening(false);
    }
  }

  async function downloadFile() {
    const thumb = artifactThumbnailPayload(artifact);
    if (!contentArtifactId && !thumb) {
      toast.error("Nothing to download — no media file or recovered preview is linked to this item.");
      return;
    }
    setDownloading(true);
    try {
      if (contentArtifactId) {
        await forensicApi.downloadArtifactContent(jobId, contentArtifactId, artifactDownloadName(artifact));
      } else if (thumb) {
        downloadBase64File(thumb.base64, thumb.fileName, thumb.contentType);
        toast.success("Saved recovered media preview");
      }
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Download failed");
    } finally {
      setDownloading(false);
    }
  }

  function openVisitUrl() {
    if (!visitUrl) return;
    window.open(visitUrl, "_blank", "noopener,noreferrer");
  }

  return (
    <div className="mt-4 overflow-hidden rounded-2xl border border-ink-300 bg-gradient-to-b from-brand-50/50 to-white shadow-card">
      <div className="flex items-center justify-between gap-2 border-b border-ink-300 bg-white/60 px-4 py-2.5">
        <span className="text-xs font-semibold uppercase tracking-wider text-ink-400">Preview</span>
        <div className="flex items-center gap-1">
          {visitUrl ? (
            <Button variant="outline" className="h-7 gap-1 px-2 text-xs" onClick={openVisitUrl}>
              <ExternalLink className="h-3.5 w-3.5" />
              Open page
            </Button>
          ) : null}
          {hasStoredContent ? (
            <Button variant="ghost" className="h-7 gap-1 px-2 text-xs" disabled={opening} onClick={openInNewTab}>
              <ExternalLink className="h-3.5 w-3.5" />
              {opening ? "Opening…" : "Open in new tab"}
            </Button>
          ) : null}
          {canDownload ? (
            <Button variant="ghost" className="h-7 gap-1 px-2 text-xs" disabled={downloading} onClick={() => void downloadFile()}>
              <Download className="h-3.5 w-3.5" />
              {downloading ? "Saving…" : "Download"}
            </Button>
          ) : null}
        </div>
      </div>
      <div className="p-4">
        {properties ? (
          <div className="mb-3 rounded-xl border border-ink-100 bg-white p-3">
            <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-ink-600">
              <span><strong className="text-ink-800">Actual size:</strong> {formatBytes(properties.size_bytes ?? undefined) || "—"}</span>
              {properties.width && properties.height ? (
                <span><strong className="text-ink-800">Pixels:</strong> {properties.width.toLocaleString()} × {properties.height.toLocaleString()} ({properties.pixels?.toLocaleString() ?? "—"})</span>
              ) : null}
              {properties.duration_seconds != null ? (
                <span><strong className="text-ink-800">Duration:</strong> {formatDuration(properties.duration_seconds)}</span>
              ) : null}
              {properties.content_type ? <span><strong className="text-ink-800">Type:</strong> {properties.content_type}</span> : null}
              {properties.format ? <span><strong className="text-ink-800">Format:</strong> {properties.format}</span> : null}
              {properties.is_deleted ? <span className="font-semibold text-amber-700">Deleted / recovered evidence</span> : null}
            </div>
            {properties.probe_error ? <p className="mt-1 text-[11px] text-ink-400">Media probe: {properties.probe_error}</p> : null}
          </div>
        ) : null}
        {review?.flagged ? (
          <div className="mb-3 rounded-xl border border-amber-200 bg-amber-50/70 p-3">
            <p className="text-xs font-bold uppercase tracking-wide text-amber-800">Examiner review flags · {review.severity}</p>
            <div className="mt-2 space-y-1">
              {review.signals.map((signal) => (
                <p key={signal.code} className="text-xs text-amber-900"><strong>{signal.label}:</strong> {signal.detail}</p>
              ))}
            </div>
            <p className="mt-2 text-[10px] text-amber-700">{review.disclaimer}</p>
          </div>
        ) : null}
        {device && (
          <p className="mb-3 flex items-center gap-2 text-xs text-ink-500">
            <Smartphone className="h-3.5 w-3.5" />
            Device: <span className="font-medium text-ink-700">{device}</span>
          </p>
        )}
        {loading && <Spinner className="py-6" />}
        {error && !loading && <p className="text-sm text-ink-400">{error}</p>}
        {preview && !loading && (
          <>
            {llmAnalysis?.status === "ok" && (
              <div className="mb-3">
                <LlmAnalysisBlock analysis={llmAnalysis} />
              </div>
            )}
            {imageSrc && (
              <div className="mb-3 flex justify-center rounded border border-ink-100 bg-white p-2">
                <img
                  src={imageSrc}
                  alt={preview.title || artifact.title || "artifact"}
                  className="max-h-80 max-w-full cursor-pointer object-contain hover:ring-2 hover:ring-brand-400"
                  onClick={() => void downloadFile()}
                  title="Click to download"
                />
              </div>
            )}
            {mediaSrc && preview.content_type === "application/pdf" && (
              <iframe
                src={mediaSrc}
                title={preview.title || "PDF preview"}
                className="mb-3 h-96 w-full rounded border border-ink-100 bg-white"
              />
            )}
            {preview.content_type === "application/pdf" && (preview.body_text || preview.body) ? (
              <pre className="mb-3 max-h-72 overflow-auto whitespace-pre-wrap font-mono text-xs leading-relaxed text-ink-700">
                {preview.body_text || preview.body}
              </pre>
            ) : null}
            {mediaSrc && preview.content_type.startsWith("video/") && (
              <video src={mediaSrc} controls className="mb-3 max-h-80 w-full rounded border border-ink-100 bg-black" />
            )}
            {mediaSrc && preview.content_type.startsWith("audio/") && (
              <audio src={mediaSrc} controls className="mb-3 w-full" />
            )}
            {/* Chat/deleted rows may show an inline image AND forensic text metadata. */}
            {imageSrc && preview.body_text ? (
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap font-mono text-xs leading-relaxed text-ink-700">
                {preview.body_text}
              </pre>
            ) : null}
            {!imageSrc && !(mediaSrc && preview.content_type.startsWith("video/")) && !(mediaSrc && preview.content_type === "application/pdf") && (
              <>
                {preview.email ||
                preview.content_type === "message/rfc822" ||
                (preview.attachments && preview.attachments.length > 0 && /eml|mail|message/i.test(preview.artifact_type || "")) ? (
                  <EmailPreviewView
                    jobId={jobId}
                    artifactId={artifact.id}
                    preview={{
                      ...preview,
                      email: preview.email ?? {
                        subject: preview.title || artifact.title || "Email message",
                      },
                    }}
                    onOpenLinkedArtifact={onOpenLinkedArtifact}
                  />
                ) : preview.content_type === "text/html" ? (
                  <SandboxedHtmlEvidence html={preview.body || ""} title="Sandboxed recovered HTML evidence" />
                ) : preview.content_type === "application/json" ? (
                  <StructuredPreview body={preview.body} />
                ) : preview.encoding === "url" &&
                  preview.body &&
                  !/^(image\/|audio\/|video\/|text\/|application\/pdf|application\/json|message\/)/i.test(
                    preview.content_type || ""
                  ) ? (
                  <div className="space-y-2 text-sm text-ink-600">
                    <pre className="max-h-96 overflow-auto whitespace-pre-wrap font-mono text-xs leading-relaxed text-ink-700">
                      {preview.body}
                    </pre>
                    {hasStoredContent ? (
                      <p>
                        Use <strong>Open in new tab</strong> to download or view the original file.
                      </p>
                    ) : null}
                  </div>
                ) : preview.body ? (
                  <pre className="max-h-96 overflow-auto whitespace-pre-wrap font-mono text-xs leading-relaxed text-ink-700">
                    {preview.body}
                  </pre>
                ) : mediaSrc ? (
                  <p className="text-sm text-ink-500">
                    Content ready — use <strong>Open in new tab</strong> to view or download the original file
                    (any size).
                  </p>
                ) : hasStoredContent ? (
                  <p className="text-sm text-ink-500">
                    Loading content stream… If it does not appear, use <strong>Open in new tab</strong>.
                  </p>
                ) : null}
              </>
            )}
          </>
        )}
      </div>
    </div>
  );
}
