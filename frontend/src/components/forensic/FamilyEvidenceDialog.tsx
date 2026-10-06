import { useEffect, useMemo, useRef, useState, type UIEvent } from "react";
import { ARTIFACT_PAGE_SIZE } from "./useInfiniteArtifactPage";
import { ArrowLeft, Copy, Download, ExternalLink, FileText, FolderOpen, Loader2, MessagesSquare, Users, X } from "lucide-react";
import { Badge, Button } from "../ui";
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
import type { Artifact, FileForensicsSummary, ThreadSummary } from "../../lib/types/forensic";
import { ArtifactPreviewPanel } from "./ArtifactPreviewPanel";

const PAGE_SIZE = ARTIFACT_PAGE_SIZE;

const CHAT_FAMILIES = new Set([
  "whatsapp_messages",
  "whatsapp_chats",
  "whatsapp_deleted_messages",
  "sms",
  "sms_chats",
  "telegram",
  "telegram_deleted",
  "signal",
  "signal_deleted",
  "instagram",
  "instagram_deleted",
  "facebook",
  "facebook_deleted",
  "linkedin",
  "deleted_social",
  "deleted_chat_residuals",
]);

const MEDIA_FAMILIES = new Set([
  "pictures",
  "videos",
  "audio",
  "documents",
  "whatsapp_media",
]);

const FILE_FORENSIC_FAMILIES = new Set([
  "critical_files",
  "anomalous_files",
  "modified_files",
  "deleted_files",
  "deleted_photos",
  "deleted_videos",
  "deleted_documents",
  "deleted_with_dates",
]);

const DELETED_FAMILIES = new Set([
  "whatsapp_deleted_messages",
  "telegram_deleted",
  "signal_deleted",
  "instagram_deleted",
  "facebook_deleted",
  "deleted_social",
  "deleted_chat_residuals",
]);

type MessageFilter = "all" | "current" | "deleted" | "media" | "calls";
type FileFilter =
  | "all"
  | "deleted"
  | "photos"
  | "videos"
  | "documents"
  | "extensionless"
  | "anomalous"
  | "modified"
  | "with_dates";
type GroupMode = "person" | "conversation" | "album" | null;

export type FamilyEvidenceTarget = {
  key: string;
  label: string;
  description?: string | null;
  catalog_key?: string | null;
  browse_query?: string | null;
  count?: number;
};

interface FamilyEvidenceDialogProps {
  jobId: string;
  open: boolean;
  family: FamilyEvidenceTarget | null;
  onClose: () => void;
}

function formatTs(value: unknown): string {
  if (!value) return "";
  const s = String(value);
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return s.slice(0, 16);
  return d.toLocaleString(undefined, {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function recoveryMeta(art: Artifact): {
  classification: string;
  confidence: string;
  state: string;
} {
  const recovery = (art.metadata?.recovery || {}) as Record<string, unknown>;
  return {
    classification: String(recovery.classification || art.metadata?.recovery_state || "—"),
    confidence: String(recovery.confidence || art.confidence || "—"),
    state: String(recovery.state || art.metadata?.recovery_state || "—"),
  };
}

/**
 * Left = people/groups/albums (or messages/files inside one);
 * Right = selected item preview/content.
 * Person/group threads support All | Current | Deleted | Media | Calls tabs.
 */
export function FamilyEvidenceDialog({ jobId, open, family, onClose }: FamilyEvidenceDialogProps) {
  const toast = useToast();
  const [items, setItems] = useState<Artifact[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const loadMoreLock = useRef(false);
  const [active, setActive] = useState<Artifact | null>(null);
  const [opening, setOpening] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [groupId, setGroupId] = useState<string | null>(null);
  const [groupLabel, setGroupLabel] = useState<string | null>(null);
  const [groupMode, setGroupMode] = useState<GroupMode>(null);
  const [isGroupIdentity, setIsGroupIdentity] = useState(false);
  const [messageFilter, setMessageFilter] = useState<MessageFilter>("all");
  const [fileFilter, setFileFilter] = useState<FileFilter>("all");
  const [threadSummary, setThreadSummary] = useState<ThreadSummary | null>(null);
  const [fileSummary, setFileSummary] = useState<FileForensicsSummary | null>(null);
  /** Guards against stale Names-list responses overwriting an opened person thread. */
  const groupIdRef = useRef<string | null>(null);

  const hasMore = items.length < total;
  const familyKey = family?.key || "";
  const supportsConversation = CHAT_FAMILIES.has(familyKey);
  const supportsAlbum = MEDIA_FAMILIES.has(familyKey);
  const supportsFileForensics = FILE_FORENSIC_FAMILIES.has(familyKey);
  const inThread = Boolean(groupId);
  const chatThread = inThread && (groupMode === "person" || groupMode === "conversation");

  useEffect(() => {
    setPage(1);
    setActive(null);
    setGroupId(null);
    groupIdRef.current = null;
    setGroupLabel(null);
    setGroupMode(null);
    setIsGroupIdentity(false);
    setThreadSummary(null);
    setFileSummary(null);
    setMessageFilter(DELETED_FAMILIES.has(familyKey) ? "deleted" : "all");
    if (familyKey === "deleted_photos") setFileFilter("photos");
    else if (familyKey === "deleted_videos") setFileFilter("videos");
    else if (familyKey === "deleted_documents") setFileFilter("documents");
    else if (familyKey === "deleted_with_dates") setFileFilter("with_dates");
    else if (familyKey === "anomalous_files") setFileFilter("anomalous");
    else if (familyKey === "modified_files") setFileFilter("modified");
    else if (familyKey === "deleted_files" || familyKey === "critical_files") setFileFilter("all");
    else setFileFilter("all");
  }, [family?.key, open, familyKey]);

  useEffect(() => {
    if (!open || !family) return;
    const key = family.key;
    const requestGroupId = groupId;
    let cancelled = false;
    if (page === 1) setLoading(true);
    else setLoadingMore(true);

    (async () => {
      try {
        const res = await forensicApi.listArtifacts(jobId, {
          page,
          page_size: PAGE_SIZE,
          family: key,
          q: family.browse_query && !key ? family.browse_query : undefined,
          group_by: supportsConversation
            ? "person"
            : supportsFileForensics
              ? "flat"
              : supportsAlbum
                ? "album"
                : "flat",
          group_id: groupId || undefined,
          message_filter: groupId && supportsConversation ? messageFilter : undefined,
          file_filter: supportsFileForensics ? fileFilter : undefined,
        });
        if (cancelled) return;
        // Drop stale responses from a prior Names list fetch after the user opened a person.
        if (groupIdRef.current !== requestGroupId) return;
        const isRuntimeJunk = (item: Artifact) => {
          const path = `${item.source_path || ""} ${item.file_name || ""} ${item.title || ""}`.toLowerCase();
          return (
            /\.(apk|dex|odex|vdex|art|oat|so|jar|prof)(\b|@|$)/i.test(path) ||
            path.includes("/dalvik-cache/") ||
            path.includes("/preload/") ||
            path.includes(".apk@") ||
            path.includes("facebook-appmanager") ||
            path.includes("facebook.appmanager") ||
            path.includes("facebook-services")
          );
        };
        const isPersonSummary = (item: Artifact) => {
          const kind = String(item.metadata?.evidence_kind || item.artifact_type || "").toLowerCase();
          return ["person", "group", "conversation", "album"].includes(kind);
        };
        const next = (res.items || []).filter((item) => {
          if (isRuntimeJunk(item)) return false;
          // Thread view must never re-render the people/groups list as "messages".
          if (requestGroupId && isPersonSummary(item)) return false;
          return true;
        });
        setItems((prev) => {
          if (page <= 1) return next;
          const seen = new Set(prev.map((row) => row.id));
          return [...prev, ...next.filter((row) => !seen.has(row.id))];
        });
        setTotal(
          next.length === (res.items || []).length
            ? res.total
            : Math.max(res.total - ((res.items?.length || 0) - next.length), next.length)
        );
        const mode =
          res.group_by === "person" || res.group_by === "conversation" || res.group_by === "album"
            ? res.group_by
            : supportsConversation
              ? "person"
              : supportsAlbum
                ? "album"
                : null;
        setGroupMode(mode);
        setThreadSummary(res.thread_summary || null);
        setFileSummary(res.file_summary || null);
        if (res.thread_summary?.is_group != null) {
          setIsGroupIdentity(Boolean(res.thread_summary.is_group));
        }
        if (res.thread_summary?.person_name && groupId) {
          setGroupLabel(res.thread_summary.person_name);
        }
        setActive((prev) => {
          if (page > 1 && prev) return prev;
          if (prev && next.some((item) => item.id === prev.id)) return prev;
          return next[0] ?? null;
        });
      } catch (e: unknown) {
        if (cancelled) return;
        if (groupIdRef.current !== requestGroupId) return;
        // Keep prior items on timeout/error when scrolling; only clear page-1 hard failures.
        if (page <= 1) {
          setItems([]);
          setTotal(0);
          setActive(null);
          setThreadSummary(null);
          setFileSummary(null);
        }
        const msg = e instanceof Error ? e.message : "Could not load family evidence";
        toast.error(
          /abort|timeout/i.test(msg)
            ? "Still building the contact list — wait a moment and open again (next open is instant)."
            : msg
        );
      } finally {
        if (!cancelled && groupIdRef.current === requestGroupId) {
          setLoading(false);
          setLoadingMore(false);
          loadMoreLock.current = false;
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [
    jobId,
    open,
    family,
    page,
    toast,
    groupId,
    supportsConversation,
    supportsAlbum,
    supportsFileForensics,
    messageFilter,
    fileFilter,
  ]);

  useEffect(() => {
    if (!open) return;
    const onKey = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        if (groupId) {
          groupIdRef.current = null;
          setGroupId(null);
          setGroupLabel(null);
          setThreadSummary(null);
          setItems([]);
          setPage(1);
          setActive(null);
        } else {
          onClose();
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose, groupId]);

  function openGroup(art: Artifact) {
    const meta = art.metadata || {};
    const kind = String(meta.evidence_kind || art.artifact_type || "");
    if (kind === "person" || kind === "group" || art.artifact_type === "person" || art.artifact_type === "group") {
      const pid = String(meta.person_id || "");
      if (!pid) return;
      groupIdRef.current = pid;
      setItems([]);
      setTotal(0);
      setGroupId(pid);
      setGroupLabel(String(meta.person_name || art.title || "Contact"));
      setIsGroupIdentity(Boolean(meta.is_group) || kind === "group");
      const deletedBucket =
        Boolean(meta.deleted_bucket) ||
        pid.endsWith("::deleted") ||
        String(art.title || "").toLowerCase().includes("[deleted]");
      setMessageFilter(deletedBucket ? "deleted" : "all");
      setPage(1);
      setActive(null);
      return;
    }
    if (kind === "conversation" || art.artifact_type === "conversation") {
      const cid = String(meta.conversation_id || "");
      if (!cid) return;
      groupIdRef.current = cid;
      setItems([]);
      setTotal(0);
      setGroupId(cid);
      setGroupLabel(String(meta.conversation || art.title || "Conversation"));
      setIsGroupIdentity(Boolean(meta.is_group));
      setPage(1);
      setActive(null);
      return;
    }
    if (kind === "album" || art.artifact_type === "album") {
      const aid = String(meta.album_id || "");
      if (!aid) return;
      groupIdRef.current = aid;
      setItems([]);
      setTotal(0);
      setGroupId(aid);
      setGroupLabel(String(meta.album || art.title || "Album"));
      setIsGroupIdentity(false);
      setPage(1);
      setActive(null);
    }
  }

  function onSelectLeft(art: Artifact) {
    const kind = String(art.metadata?.evidence_kind || art.artifact_type || "");
    if (
      !inThread &&
      (kind === "person" ||
        kind === "group" ||
        kind === "conversation" ||
        kind === "album" ||
        art.artifact_type === "person" ||
        art.artifact_type === "group" ||
        art.artifact_type === "conversation" ||
        art.artifact_type === "album")
    ) {
      openGroup(art);
      return;
    }
    setActive(art);
  }

  async function openContent(art: Artifact) {
    const target = artifactContentTarget(art);
    if (!target.id) {
      toast.error("No photo, video, or audio file is linked — the chat database is not opened here.");
      return;
    }
    setOpening(true);
    try {
      await forensicApi.openArtifactContent(jobId, target.id);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Could not open content");
    } finally {
      setOpening(false);
    }
  }

  async function downloadContent(art: Artifact) {
    const target = artifactContentTarget(art);
    const thumb = artifactThumbnailPayload(art);
    if (!target.id && !thumb) {
      toast.error("Nothing to download — no media file or recovered preview is linked to this item.");
      return;
    }
    setDownloading(true);
    try {
      if (target.id) {
        await forensicApi.downloadArtifactContent(jobId, target.id, artifactDownloadName(art));
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

  async function copyPath(path: string) {
    try {
      await navigator.clipboard.writeText(path);
      toast.success("Path copied");
    } catch {
      toast.error("Could not copy path");
    }
  }

  const messagesByApp = useMemo(() => {
    if (!chatThread) return [] as { app: string; items: Artifact[] }[];
    const order: string[] = [];
    const map = new Map<string, Artifact[]>();
    for (const art of items) {
      const app = String(art.metadata?.application || art.metadata?.social_app || "Chat");
      const key = app.charAt(0).toUpperCase() + app.slice(1);
      if (!map.has(key)) {
        map.set(key, []);
        order.push(key);
      }
      map.get(key)!.push(art);
    }
    return order.map((app) => ({ app, items: map.get(app) || [] }));
  }, [items, chatThread]);

  function onListScroll(event: UIEvent<HTMLElement>) {
    if (!hasMore || loading || loadingMore || loadMoreLock.current) return;
    const el = event.currentTarget;
    if (el.scrollHeight - el.scrollTop - el.clientHeight < 96) {
      loadMoreLock.current = true;
      setPage((p) => p + 1);
    }
  }

  if (!open || !family) return null;

  const listHeading = inThread
    ? groupMode === "album"
      ? "Files"
      : messageFilter === "deleted"
        ? "Deleted / Recovered"
        : "Messages"
    : supportsFileForensics
      ? "Critical files"
      : groupMode === "album"
        ? "Albums"
        : groupMode === "person"
          ? "People & groups"
          : groupMode === "conversation"
            ? "Conversations"
            : "Names";

  const summary = threadSummary;
  const fsum = fileSummary;
  const subtitle = inThread
    ? groupMode === "album"
      ? `${total.toLocaleString()} file${total === 1 ? "" : "s"} in ${groupLabel || "group"}`
      : summary
        ? `${summary.message_count.toLocaleString()} total · ${summary.current_count.toLocaleString()} current · ${summary.deleted_count.toLocaleString()} deleted/recovered`
        : `${total.toLocaleString()} message${total === 1 ? "" : "s"} in ${groupLabel || "thread"}`
    : supportsFileForensics && fsum
      ? `${fsum.total.toLocaleString()} critical · ${fsum.deleted.toLocaleString()} deleted · ${fsum.anomalous.toLocaleString()} anomalous · ${fsum.modified.toLocaleString()} modified · ${fsum.extensionless.toLocaleString()} extensionless`
      : groupMode === "person"
        ? `${total.toLocaleString()} person${total === 1 ? "" : "s"} / group${total === 1 ? "" : "s"} · open one for the full cross-app chat`
        : groupMode === "conversation"
          ? `${total.toLocaleString()} conversation${total === 1 ? "" : "s"} · open one for the full thread`
          : groupMode === "album"
            ? `${total.toLocaleString()} album${total === 1 ? "" : "s"} / folder${total === 1 ? "" : "s"} · open one for files`
            : `${total.toLocaleString()} item${total === 1 ? "" : "s"} · select a name on the left to preview`;

  const tabs: { id: MessageFilter; label: string; count?: number }[] = [
    { id: "all", label: "All Chats", count: summary?.message_count },
    { id: "current", label: "Current", count: summary?.current_count },
    { id: "deleted", label: "Deleted/Recovered", count: summary?.deleted_count },
    { id: "media", label: "Media", count: summary?.media_count },
    { id: "calls", label: "Calls", count: summary?.call_count },
  ];

  const fileTabs: { id: FileFilter; label: string; count?: number }[] = [
    { id: "all", label: "All", count: fsum?.total },
    { id: "deleted", label: "Deleted", count: fsum?.deleted },
    { id: "photos", label: "Photos", count: fsum?.photos },
    { id: "videos", label: "Videos", count: fsum?.videos },
    { id: "documents", label: "Documents", count: fsum?.documents },
    { id: "extensionless", label: "Extensionless", count: fsum?.extensionless },
    { id: "anomalous", label: "Anomalous", count: fsum?.anomalous },
    { id: "modified", label: "Modified", count: fsum?.modified },
    { id: "with_dates", label: "With dates", count: fsum?.with_dates },
  ];

  return (
    <div className="fixed inset-0 z-[200] flex items-center justify-center p-3 sm:p-6">
      <div className="absolute inset-0 bg-ink-950/50 backdrop-blur-sm" onClick={onClose} />
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="family-evidence-title"
        className="relative z-[201] flex h-[min(90vh,940px)] w-full max-w-6xl flex-col overflow-hidden rounded-2xl border border-ink-200 bg-white shadow-2xl"
      >
        <div className="flex items-start justify-between gap-3 border-b border-ink-100 px-5 py-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              {inThread ? (
                <Button
                  variant="outline"
                  className="h-7 gap-1 px-2 text-xs"
                  onClick={() => {
                    groupIdRef.current = null;
                    setGroupId(null);
                    setGroupLabel(null);
                    setThreadSummary(null);
                    setItems([]);
                    setPage(1);
                    setActive(null);
                  }}
                >
                  <ArrowLeft className="h-3.5 w-3.5" />
                  All {groupMode === "album" ? "albums" : "people & groups"}
                </Button>
              ) : null}
              <h3 id="family-evidence-title" className="truncate text-lg font-bold text-ink-900">
                {inThread && groupLabel
                  ? `${isGroupIdentity ? "GROUP" : "PERSON"}: ${groupLabel}`
                  : family.label}
              </h3>
              {inThread && isGroupIdentity ? <Badge tone="neutral">group</Badge> : null}
              {inThread && messageFilter === "deleted" ? (
                <Badge tone="amber">Deleted / Recovered only</Badge>
              ) : null}
            </div>
            <p className="mt-1 text-xs text-ink-500">
              {subtitle}
              {typeof family.count === "number" && !inThread && family.count !== total
                ? ` · board count ${family.count.toLocaleString()}`
                : ""}
            </p>
            {chatThread && summary ? (
              <p className="mt-1 text-xs text-ink-600">
                {isGroupIdentity ? (
                  <>
                    Participants: {summary.participant_count.toLocaleString()}
                    {summary.applications?.length
                      ? ` · Apps: ${summary.applications.join(", ")}`
                      : ""}
                    {summary.deleted_count
                      ? ` · Recovered/deleted: ${summary.deleted_count.toLocaleString()}`
                      : ""}
                  </>
                ) : (
                  <>
                    {summary.applications?.length
                      ? `Apps: ${summary.applications.join(", ")} · `
                      : ""}
                    Total: {summary.message_count.toLocaleString()} · Current:{" "}
                    {summary.current_count.toLocaleString()} · Deleted/Recovered:{" "}
                    {summary.deleted_count.toLocaleString()}
                    {summary.fragment_count
                      ? ` · Fragments: ${summary.fragment_count.toLocaleString()}`
                      : ""}
                  </>
                )}
              </p>
            ) : null}
            {family.description && !inThread ? (
              <p className="mt-1 text-sm text-ink-600">{family.description}</p>
            ) : null}
            {supportsConversation && !inThread ? (
              <p className="mt-1 text-xs text-ink-500">
                Each row is a person or group. Open one for the full chronological chat
                (deleted/recovered messages, media, calls). Scroll the list for the next{" "}
                {PAGE_SIZE} when there are more than {PAGE_SIZE}.
                {typeof family.count === "number" && family.count > total
                  ? ` Board inventory is ${family.count.toLocaleString()} raw records; this list is grouped people/groups.`
                  : ""}
              </p>
            ) : null}
            {supportsFileForensics && !inThread ? (
              <p className="mt-1 text-xs text-ink-500">
                Windows Recycle Bin, Linux Trash, iOS .trashed / deleted_recovery, extensionless
                files, spoofed extensions, and modified/renamed recoveries — use tabs to focus the
                examiner view.
              </p>
            ) : null}
            {supportsAlbum && !inThread && !supportsFileForensics ? (
              <p className="mt-1 text-xs text-ink-500">
                Each row is an album or media folder. Open one to browse every picture, audio, video,
                or document in that group.
              </p>
            ) : null}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1 text-ink-400 hover:bg-ink-100 hover:text-ink-700"
            aria-label="Close"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {chatThread ? (
          <div className="flex flex-wrap gap-1 border-b border-ink-100 px-4 py-2">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => {
                  setMessageFilter(tab.id);
                  setPage(1);
                  setActive(null);
                }}
                className={`rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                  messageFilter === tab.id
                    ? "bg-ink-900 text-white"
                    : "bg-ink-50 text-ink-600 hover:bg-ink-100"
                }`}
              >
                {tab.label}
                {typeof tab.count === "number" ? (
                  <span className="ml-1 opacity-80">({tab.count.toLocaleString()})</span>
                ) : null}
              </button>
            ))}
          </div>
        ) : null}

        {supportsFileForensics && !inThread ? (
          <div className="flex flex-wrap gap-1 border-b border-ink-100 px-4 py-2">
            {fileTabs.map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => {
                  setFileFilter(tab.id);
                  setPage(1);
                  setActive(null);
                }}
                className={`rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                  fileFilter === tab.id
                    ? "bg-ink-900 text-white"
                    : "bg-ink-50 text-ink-600 hover:bg-ink-100"
                }`}
              >
                {tab.label}
                {typeof tab.count === "number" ? (
                  <span className="ml-1 opacity-80">({tab.count.toLocaleString()})</span>
                ) : null}
              </button>
            ))}
          </div>
        ) : null}

        <div className="grid min-h-0 flex-1 grid-cols-1 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1.2fr)]">
          <div className="flex min-h-0 flex-col border-r border-ink-100">
            <div className="flex items-center justify-between border-b border-ink-100 px-3 py-2">
              <p className="text-xs font-semibold uppercase tracking-wide text-ink-500">{listHeading}</p>
              <Badge tone="neutral">{total}</Badge>
            </div>
            {loading && items.length === 0 ? (
              <div className="flex flex-1 items-center justify-center text-ink-400">
                <Loader2 className="h-5 w-5 animate-spin" />
              </div>
            ) : items.length === 0 ? (
              <p className="p-4 text-sm text-ink-400">
                {loading ? (
                  <>Building contact list from ChatStorage…</>
                ) : chatThread && messageFilter === "deleted" ? (
                  <>No deleted/recovered messages for this {isGroupIdentity ? "group" : "person"}.</>
                ) : chatThread && messageFilter === "media" ? (
                  <>No media attachments in this thread.</>
                ) : chatThread && messageFilter === "calls" ? (
                  <>No call records linked to this thread.</>
                ) : supportsConversation ? (
                  <>No people or groups recovered for this family in the dump.</>
                ) : supportsAlbum ? (
                  <>No media albums or folders for this family in the dump.</>
                ) : (
                  <>No evidence rows for this family in the dump.</>
                )}
              </p>
            ) : chatThread ? (
              <div className="min-h-0 flex-1 overflow-y-auto" onScroll={onListScroll}>
                {messagesByApp.map(({ app, items: appItems }) => (
                  <div key={app} className="border-b border-ink-100 pb-2">
                    <div className="sticky top-0 z-10 bg-ink-50/95 px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-ink-600 backdrop-blur">
                      {app}
                      <span className="ml-2 font-normal normal-case text-ink-400">
                        {appItems.length.toLocaleString()}
                      </span>
                    </div>
                    <ul className="space-y-2 bg-[#efeae2] px-3 py-3">
                      {appItems.map((art) => {
                        const meta = art.metadata || {};
                        const deleted = Boolean(meta.is_deleted || art.tags?.includes("deleted"));
                        const fromMe = Boolean(meta.from_me);
                        const sender = String(
                          meta.sender_display_name || meta.sender || "Unknown"
                        );
                        const bodyRaw = String(meta.body || art.title || "");
                        const body =
                          deleted
                            ? stripWhatsAppProtocolPrefix(bodyRaw) ||
                              stripWhatsAppProtocolPrefix(String(meta.original_content || "")) ||
                              bodyRaw
                            : bodyRaw;
                        const rec = recoveryMeta(art);
                        const thumb =
                          typeof meta.thumbnail_base64 === "string" && meta.thumbnail_base64.length > 80
                            ? `data:${String(meta.thumbnail_content_type || "image/jpeg")};base64,${meta.thumbnail_base64}`
                            : null;
                        return (
                          <li
                            key={art.id}
                            className={`flex ${fromMe ? "justify-end" : "justify-start"}`}
                          >
                            <button
                              type="button"
                              onClick={() => setActive(art)}
                              className={`relative flex max-w-[84%] flex-col gap-1 rounded-xl border px-3 py-2 text-left shadow-sm transition ${
                                deleted
                                  ? fromMe
                                    ? "border-amber-300 bg-amber-50 ring-1 ring-amber-200"
                                    : "border-amber-300 bg-white ring-1 ring-amber-100"
                                  : fromMe
                                    ? "border-emerald-200 bg-[#d9fdd3]"
                                    : "border-white bg-white"
                              } ${
                                active?.id === art.id
                                  ? "ring-2 ring-brand-400"
                                  : "hover:shadow-md"
                              }`}
                            >
                              <span className="flex flex-wrap items-center gap-2 text-[11px] text-ink-500">
                                <span className={`font-semibold ${fromMe ? "text-emerald-800" : "text-brand-700"}`}>
                                  {fromMe ? "You" : sender}
                                </span>
                                {deleted ? <Badge tone="amber">deleted</Badge> : null}
                                {deleted && fromMe ? (
                                  <Badge tone="indigo">deleted by me</Badge>
                                ) : null}
                              </span>
                              {thumb ? (
                                <div className="mt-1">
                                  <img
                                    src={thumb}
                                    alt={String(meta.media_name || "WhatsApp media")}
                                    title="Click to inspect or download the recovered original"
                                    className={`max-h-64 max-w-full cursor-pointer rounded-lg border border-ink-100 bg-white object-contain hover:ring-2 hover:ring-brand-400 ${
                                      meta.preview_quality === "full_file_preview"
                                        ? ""
                                        : "image-pixelated"
                                    }`}
                                    style={
                                      meta.preview_quality === "full_file_preview"
                                        ? undefined
                                        : { imageRendering: "auto" }
                                    }
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      setActive(art);
                                      void downloadContent(art);
                                    }}
                                  />
                                  {meta.preview_quality !== "full_file_preview" &&
                                  !meta.media_artifact_id ? (
                                    <span className="mt-0.5 block text-[10px] text-amber-700">
                                      Low-res chat thumbnail only — original file not in this extract
                                    </span>
                                  ) : null}
                                  {meta.media_artifact_id ? (
                                    <span className="mt-0.5 block text-[10px] text-emerald-700">
                                      Full file linked — click to download original
                                    </span>
                                  ) : null}
                                </div>
                              ) : null}
                              <span className="whitespace-pre-wrap text-sm text-ink-800">
                                {body || "—"}
                              </span>
                              {meta.media_name ? (
                                <span
                                  role="link"
                                  tabIndex={0}
                                  title="Click to download attachment"
                                  className="cursor-pointer text-[11px] text-brand-700 underline-offset-2 hover:underline"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setActive(art);
                                    void downloadContent(art);
                                  }}
                                  onKeyDown={(e) => {
                                    if (e.key === "Enter" || e.key === " ") {
                                      e.preventDefault();
                                      e.stopPropagation();
                                      setActive(art);
                                      void downloadContent(art);
                                    }
                                  }}
                                >
                                  [{String(meta.message_type || "media").toString()}]{" "}
                                  {String(meta.media_name)}
                                </span>
                              ) : null}
                              {deleted && messageFilter === "deleted" ? (
                                <span className="mt-0.5 text-[10px] text-ink-500">
                                  Recovery: {String(rec.state).replace(/_/g, " ")} ·{" "}
                                  {rec.classification} · Confidence:{" "}
                                  {String(rec.confidence).toString()}
                                </span>
                              ) : null}
                              <span className="self-end text-[10px] text-ink-500">
                                {formatTs(art.artifact_datetime || meta.timestamp)}
                              </span>
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                ))}
                {hasMore || loadingMore ? (
                  <div className="flex items-center justify-center gap-2 border-t border-ink-100 px-3 py-2 text-[11px] text-ink-400">
                    {loadingMore ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
                    {loadingMore
                      ? "Loading next 20…"
                      : `Scroll for next ${PAGE_SIZE} · ${items.length.toLocaleString()} of ${total.toLocaleString()}`}
                  </div>
                ) : null}
              </div>
            ) : (
              <>
                <ul className="min-h-0 flex-1 divide-y divide-ink-50 overflow-y-auto" onScroll={onListScroll}>
                  {items.map((art) => {
                    const kind = String(art.metadata?.evidence_kind || art.artifact_type || "");
                    const isGroupRow =
                      !inThread &&
                      ["person", "group", "conversation", "album"].includes(kind);
                    const Icon =
                      kind === "album"
                        ? FolderOpen
                        : kind === "group" || art.metadata?.is_group
                          ? Users
                          : kind === "person" || kind === "conversation"
                            ? MessagesSquare
                            : FileText;
                    const msgCount = art.metadata?.message_count as number | undefined;
                    const fileCount = art.metadata?.file_count as number | undefined;
                    const deletedCount = art.metadata?.deleted_count as number | undefined;
                    const apps = art.metadata?.applications as string[] | undefined;
                    return (
                      <li key={art.id}>
                        <button
                          type="button"
                          onClick={() => onSelectLeft(art)}
                          className={`flex w-full items-start gap-2 px-3 py-2.5 text-left hover:bg-ink-50 ${
                            active?.id === art.id ||
                            (isGroupRow &&
                              groupId &&
                              String(
                                art.metadata?.person_id ||
                                  art.metadata?.conversation_id ||
                                  art.metadata?.album_id
                              ) === groupId)
                              ? "bg-brand-50/70"
                              : ""
                          }`}
                        >
                          <Icon className="mt-0.5 h-4 w-4 shrink-0 text-ink-400" />
                          <span className="min-w-0">
                            <span className="flex flex-wrap items-center gap-1.5">
                              <span className="block truncate text-sm font-medium text-ink-800">
                                {kind === "group" || art.metadata?.is_group
                                  ? `GROUP: ${art.title || "Group"}`
                                  : kind === "person"
                                    ? `${art.title || "Person"}`
                                    : art.title || art.file_name || art.source_path || art.artifact_type}
                              </span>
                              {art.metadata?.is_group ? <Badge tone="neutral">group</Badge> : null}
                              {art.metadata?.deleted_bucket ||
                              String(art.title || "").toLowerCase().includes("[deleted]") ? (
                                <Badge tone="amber">deleted</Badge>
                              ) : typeof deletedCount === "number" && deletedCount > 0 ? (
                                <Badge tone="amber">deleted</Badge>
                              ) : null}
                              {art.metadata?.is_deleted || art.tags?.includes("deleted") ? (
                                kind === "person" || kind === "group" ? null : (
                                  <Badge tone="amber">deleted</Badge>
                                )
                              ) : null}
                              {art.metadata?.extension_mismatch || art.metadata?.is_anomalous ? (
                                <Badge tone="red">anomalous</Badge>
                              ) : null}
                              {art.metadata?.extensionless ? (
                                <Badge tone="neutral">no ext</Badge>
                              ) : null}
                              {art.metadata?.is_modified ? (
                                <Badge tone="indigo">modified</Badge>
                              ) : null}
                            </span>
                            {supportsFileForensics ? (
                              <span className="mt-0.5 block text-[10px] text-ink-500">
                                {art.metadata?.detected_kind
                                  ? `${String(art.metadata.detected_kind)}`
                                  : "file"}
                                {art.metadata?.declared_extension
                                  ? ` · declared ${String(art.metadata.declared_extension)}`
                                  : ""}
                                {art.metadata?.detected_extension
                                  ? ` · magic ${String(art.metadata.detected_extension)}`
                                  : ""}
                                {art.metadata?.original_name
                                  ? ` · was ${String(art.metadata.original_name)}`
                                  : ""}
                                {art.metadata?.forensic_platform
                                  ? ` · ${String(art.metadata.forensic_platform)}`
                                  : ""}
                              </span>
                            ) : null}
                            {typeof msgCount === "number" ? (
                              <span className="mt-0.5 block text-[10px] text-brand-700">
                                {msgCount.toLocaleString()} message{msgCount === 1 ? "" : "s"}
                                {typeof deletedCount === "number" && deletedCount > 0
                                  ? ` · ${deletedCount.toLocaleString()} deleted/recovered`
                                  : ""}
                                {apps?.length ? ` · ${apps.join(", ")}` : ""}
                                {art.metadata?.last_message
                                  ? ` · ${String(art.metadata.last_message).slice(0, 80)}`
                                  : ""}
                              </span>
                            ) : null}
                            {typeof fileCount === "number" ? (
                              <span className="mt-0.5 block text-[10px] text-brand-700">
                                {fileCount.toLocaleString()} file{fileCount === 1 ? "" : "s"}
                              </span>
                            ) : null}
                            {isGroupRow ? (
                              <span className="mt-0.5 block text-[10px] text-ink-500">
                                Click to open full {kind === "album" ? "album" : "chat"}
                              </span>
                            ) : null}
                          </span>
                        </button>
                      </li>
                    );
                  })}
                </ul>
                {hasMore || loadingMore ? (
                  <div className="flex items-center justify-center gap-2 border-t border-ink-100 px-3 py-2 text-[11px] text-ink-400">
                    {loadingMore ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
                    {loadingMore
                      ? "Loading next 20…"
                      : `Scroll for next ${PAGE_SIZE} · ${items.length.toLocaleString()} of ${total.toLocaleString()}`}
                  </div>
                ) : null}
              </>
            )}
          </div>

          <div className="flex min-h-0 flex-col overflow-y-auto">
            <div className="flex items-center justify-between border-b border-ink-100 px-3 py-2">
              <p className="text-xs font-semibold uppercase tracking-wide text-ink-500">
                {chatThread ? "Message detail" : "Content"}
              </p>
              {active &&
              !["conversation", "person", "group", "album"].includes(
                String(active.metadata?.evidence_kind || active.artifact_type)
              ) ? (
                <div className="flex items-center gap-1">
                  {active.source_path ? (
                    <Button
                      variant="ghost"
                      className="h-7 gap-1 px-2 text-xs"
                      onClick={() => void copyPath(active.source_path!)}
                    >
                      <Copy className="h-3.5 w-3.5" /> Copy path
                    </Button>
                  ) : null}
                  <Button
                    variant="outline"
                    className="h-7 gap-1 px-2 text-xs"
                    disabled={opening || !artifactContentTarget(active).id}
                    onClick={() => void openContent(active)}
                  >
                    <ExternalLink className="h-3.5 w-3.5" />
                    {opening ? "Opening…" : "Open file"}
                  </Button>
                  <Button
                    variant="outline"
                    className="h-7 gap-1 px-2 text-xs"
                    disabled={downloading || !artifactCanDownload(active)}
                    onClick={() => void downloadContent(active)}
                  >
                    <Download className="h-3.5 w-3.5" />
                    {downloading ? "Saving…" : "Download"}
                  </Button>
                </div>
              ) : null}
            </div>
            {!active && !inThread ? (
              <p className="p-4 text-sm text-ink-400">
                {groupMode === "person"
                  ? "Open a person or group on the left to read the full cross-app chat."
                  : groupMode === "conversation"
                    ? "Open a conversation on the left to read the full chat."
                    : groupMode === "album"
                      ? "Open an album on the left to browse its files."
                      : "Select a file name on the left to view content."}
              </p>
            ) : !active ? (
              <p className="p-4 text-sm text-ink-400">Select a message on the left to inspect detail.</p>
            ) : (
              <div className="space-y-3 p-4">
                <p className="font-semibold text-ink-900">
                  {String(
                    active.metadata?.sender_display_name ||
                      active.metadata?.sender ||
                      active.title ||
                      active.file_name ||
                      "Untitled"
                  )}
                </p>
                {chatThread ? (
                  <div className="rounded-lg border border-ink-100 bg-ink-50/60 p-3 text-xs text-ink-700">
                    <p>
                      <span className="font-semibold">Application:</span>{" "}
                      {String(active.metadata?.application || active.metadata?.social_app || "—")}
                    </p>
                    <p className="mt-1">
                      <span className="font-semibold">Time:</span>{" "}
                      {formatTs(active.artifact_datetime || active.metadata?.timestamp)}
                    </p>
                    {typeof active.metadata?.thumbnail_base64 === "string" &&
                    active.metadata.thumbnail_base64.length > 80 ? (
                      <div className="mt-2">
                        <p className="mb-1 font-semibold">
                          {active.metadata?.preview_quality === "full_file_preview"
                            ? "Media preview"
                            : active.metadata?.is_deleted || active.tags?.includes("deleted")
                              ? "Recovered media preview"
                              : "Media preview"}
                          <span className="ml-2 font-normal text-ink-500">(click to download)</span>
                        </p>
                        {active.metadata?.preview_quality !== "full_file_preview" &&
                        !active.metadata?.media_artifact_id ? (
                          <p className="mb-1 text-[11px] text-amber-700">
                            WhatsApp only left a tiny chat thumbnail here
                            {String(active.metadata?.mime_recovered || "").includes("pdf")
                              ? " (deleted PDF)"
                              : ""}
                            . The full original is not present in this extract, so pixels cannot be
                            sharpened further.
                          </p>
                        ) : null}
                        {active.metadata?.media_artifact_id ? (
                          <p className="mb-1 text-[11px] text-emerald-700">
                            Full attachment is linked — Download saves the original dump file.
                          </p>
                        ) : null}
                        <img
                          src={`data:${String(active.metadata?.thumbnail_content_type || "image/jpeg")};base64,${active.metadata.thumbnail_base64}`}
                          alt={String(active.metadata?.media_name || "WhatsApp media")}
                          title="Click to download"
                          className="max-h-72 max-w-full cursor-pointer rounded-md border border-ink-200 bg-white object-contain hover:ring-2 hover:ring-brand-400"
                          onClick={() => void downloadContent(active)}
                        />
                      </div>
                    ) : null}
                    <p className="mt-1 whitespace-pre-wrap">
                      <span className="font-semibold">Message:</span>{" "}
                      {String(active.metadata?.body || "—")}
                    </p>
                    {active.metadata?.is_deleted || active.tags?.includes("deleted") ? (
                      <div className="mt-2 border-t border-ink-200 pt-2">
                        <p>
                          <span className="font-semibold">Recovery:</span>{" "}
                          {String(recoveryMeta(active).state).replace(/_/g, " ")}
                        </p>
                        <p>
                          <span className="font-semibold">Classification:</span>{" "}
                          {recoveryMeta(active).classification}
                        </p>
                        <p>
                          <span className="font-semibold">Confidence:</span>{" "}
                          {String(recoveryMeta(active).confidence)}
                        </p>
                      </div>
                    ) : null}
                    {active.metadata?.provenance &&
                    typeof active.metadata.provenance === "object" ? (
                      <div className="mt-2 border-t border-ink-200 pt-2 font-mono text-[10px] text-ink-500">
                        <p>
                          source:{" "}
                          {String(
                            (active.metadata.provenance as Record<string, unknown>).source_file ||
                              active.source_path ||
                              "—"
                          )}
                        </p>
                        <p>
                          parser:{" "}
                          {String(
                            (active.metadata.provenance as Record<string, unknown>).parser ||
                              active.parser_version ||
                              "—"
                          )}
                        </p>
                      </div>
                    ) : null}
                  </div>
                ) : null}
                {active.source_path && !chatThread ? (
                  <p className="break-all font-mono text-xs text-ink-500">{active.source_path}</p>
                ) : null}
                <ArtifactPreviewPanel jobId={jobId} artifact={active} />
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
