import { useCallback, useEffect, useRef, useState } from "react";
import {
  ArrowLeft,
  Copy,
  ExternalLink,
  FileText,
  FolderOpen,
  Loader2,
  MessagesSquare,
  Users,
} from "lucide-react";
import { Badge, Button } from "../ui";
import { forensicApi } from "../../lib/forensicApi";
import { artifactContentTarget } from "../../lib/artifactContent";
import { useToast } from "../../lib/toast";
import type { Artifact, ThreadSummary } from "../../lib/types/forensic";
import type { ArtifactBrowseSelection } from "./ArtifactCatalogSelector";
import { ArtifactPreviewPanel } from "./ArtifactPreviewPanel";
import { ARTIFACT_PAGE_SIZE, useInfiniteArtifactPage } from "./useInfiniteArtifactPage";

interface ArtifactBrowsePanelProps {
  jobId: string;
  selection: ArtifactBrowseSelection;
}

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
  "deleted_photos",
  "deleted_videos",
  "deleted_documents",
]);

type MessageFilter = "all" | "current" | "deleted" | "media" | "calls";

function InvestigationPrompt({ selection }: { selection: ArtifactBrowseSelection }) {
  if (!selection.promptQuestion && !selection.scope) return null;
  return (
    <div className="border-b border-brand-100 bg-brand-50/50 px-4 py-3">
      <p className="text-xs font-semibold uppercase tracking-wide text-brand-700">
        {selection.scope
          ? `Saved evidences — ${selection.label || selection.scope}`
          : `Prompt${selection.label ? ` — ${selection.label}` : ""}`}
      </p>
      {selection.promptQuestion ? (
        <p className="mt-1 text-sm text-ink-700">{selection.promptQuestion}</p>
      ) : (
        <p className="mt-1 text-sm text-ink-700">
          Showing files already saved for this job. Use this when you need every evidence file, not only catalog matches.
        </p>
      )}
    </div>
  );
}

function isDeletedArtifact(art: Artifact): boolean {
  const kind = String(art.metadata?.evidence_kind || art.artifact_type || "");
  // Person/group summaries: only the explicit [deleted] bucket is deleted.
  if (["person", "group", "conversation", "album"].includes(kind)) {
    return Boolean(
      art.metadata?.deleted_bucket ||
        String(art.title || "").toLowerCase().includes("[deleted]")
    );
  }
  return Boolean(
    art.tags?.includes("deleted") ||
      art.metadata?.is_deleted ||
      art.metadata?.deleted_at
  );
}

function formatDateLine(art: Artifact): { text: string; deleted: boolean } | null {
  const kind = String(art.metadata?.evidence_kind || art.artifact_type || "");
  const personLike = ["person", "group", "conversation", "album"].includes(kind);
  const deleted = isDeletedArtifact(art);
  const raw = personLike
    ? art.artifact_datetime || art.metadata?.last_timestamp || art.metadata?.timestamp
    : (deleted && art.metadata?.deleted_at
        ? String(art.metadata.deleted_at)
        : art.artifact_datetime) ||
      art.metadata?.timestamp ||
      null;
  if (!raw) return null;
  const day = String(raw).slice(0, 10);
  // Never label a live contact's last-message date as "Deleted …".
  if (personLike) {
    return {
      text: deleted ? `Deleted bucket · last ${day}` : `Last activity ${day}`,
      deleted,
    };
  }
  return deleted
    ? { text: `Deleted ${day}`, deleted: true }
    : { text: day, deleted: false };
}

function chatMessageText(art: Artifact): string {
  const meta = art.metadata || {};
  return String(
    meta.original_content ||
      meta.body ||
      meta.message ||
      meta.preview_body ||
      art.title ||
      "(message content unavailable)"
  ).trim();
}

function chatSender(art: Artifact): string {
  const meta = art.metadata || {};
  return String(meta.sender_display_name || meta.sender || (meta.from_me ? "Device Owner" : "Unknown"));
}

function chatTimestamp(art: Artifact): string {
  const meta = art.metadata || {};
  return String(art.artifact_datetime || meta.timestamp || meta.deleted_at || "—");
}

function chatRecordHash(art: Artifact): string {
  const meta = art.metadata || {};
  const provenance = (meta.provenance || {}) as Record<string, unknown>;
  return String(meta.record_hash_sha256 || provenance.record_hash_sha256 || art.id || "—");
}

export function ArtifactBrowsePanel({ jobId, selection }: ArtifactBrowsePanelProps) {
  const toast = useToast();
  const [active, setActive] = useState<Artifact | null>(null);
  const [opening, setOpening] = useState(false);
  const [evidenceDomain, setEvidenceDomain] = useState<string | null>(null);
  const [groupId, setGroupId] = useState<string | null>(null);
  const [groupLabel, setGroupLabel] = useState<string | null>(null);
  const [, setGroupBy] = useState<string | null>(null);
  const [messageFilter, setMessageFilter] = useState<MessageFilter>("all");
  const [threadSummary, setThreadSummary] = useState<ThreadSummary | null>(null);
  const [threadItems, setThreadItems] = useState<Artifact[]>([]);
  const [threadTotal, setThreadTotal] = useState(0);
  const [threadLoading, setThreadLoading] = useState(false);
  const groupIdRef = useRef<string | null>(null);

  const browsing =
    selection.scope != null ||
    selection.catalogKey !== null ||
    selection.catalogSection !== null ||
    Boolean(selection.family);
  const familyKey = selection.family || "";
  const wantsChatGroups =
    CHAT_FAMILIES.has(familyKey) ||
    (!familyKey && Boolean(selection.catalogKey));
  const wantsAlbumGroups = MEDIA_FAMILIES.has(familyKey);
  const inThread = Boolean(groupId);
  const chatThread = inThread && wantsChatGroups;

  const fetchPage = useCallback(
    async (pageNum: number, pageSize: number) => {
      if (!browsing) {
        setActive(null);
        return { items: [] as Artifact[], total: 0 };
      }
      const requestGroupId = wantsChatGroups ? null : groupId;
      try {
        const res = await forensicApi.listArtifacts(jobId, {
          page: pageNum,
          page_size: pageSize,
          family: selection.family ?? undefined,
          scope: selection.family ? undefined : selection.scope ?? undefined,
          catalog_key:
            selection.family || selection.scope ? undefined : selection.catalogKey ?? undefined,
          catalog_section:
            selection.family || selection.scope ? undefined : selection.catalogSection ?? undefined,
          q: selection.q ?? undefined,
          group_by: wantsChatGroups ? "person" : wantsAlbumGroups ? "album" : undefined,
          group_id: requestGroupId || undefined,
          message_filter: requestGroupId && wantsChatGroups ? messageFilter : undefined,
        });
        if (!wantsChatGroups && groupIdRef.current !== requestGroupId) {
          return { items: [] as Artifact[], total: 0 };
        }
        const items = (res.items || []).filter((item) => {
          if (!requestGroupId) return true;
          const kind = String(item.metadata?.evidence_kind || item.artifact_type || "").toLowerCase();
          return !["person", "group", "conversation", "album"].includes(kind);
        });
        setEvidenceDomain(res.evidence_domain ?? "file");
        setGroupBy(res.group_by ?? null);
        if (!wantsChatGroups) setThreadSummary(res.thread_summary || null);
        if (!wantsChatGroups) {
          setActive((prev) => {
            if (pageNum > 1 && prev) return prev;
            if (prev && items.some((item) => item.id === prev.id)) return prev;
            return items[0] ?? null;
          });
        }
        // Always use server total so infinite scroll can load page 2+ (149, not 20).
        return { items, total: res.total };
      } catch (e: unknown) {
        if (!wantsChatGroups && groupIdRef.current !== requestGroupId) {
          return { items: [] as Artifact[], total: 0 };
        }
        setEvidenceDomain(null);
        setActive(null);
        setThreadSummary(null);
        const msg = e instanceof Error ? e.message : "Could not load artifact files";
        toast.error(msg.includes("502") ? "Server busy loading evidence — wait a moment and try again." : msg);
        return { items: [] as Artifact[], total: 0 };
      }
    },
    [
      jobId,
      selection.catalogKey,
      selection.catalogSection,
      selection.scope,
      selection.q,
      selection.family,
      browsing,
      toast,
      groupId,
      wantsChatGroups,
      wantsAlbumGroups,
      messageFilter,
    ]
  );

  const listKey = [
    jobId,
    selection.catalogKey,
    selection.catalogSection,
    selection.scope,
    selection.q,
    selection.family,
    wantsChatGroups ? "contacts" : groupId,
    wantsChatGroups ? "all" : messageFilter,
    browsing ? "1" : "0",
  ].join("|");

  const { items, total, loading, loadingMore, hasMore, onListScroll } = useInfiniteArtifactPage(
    listKey,
    fetchPage
  );

  useEffect(() => {
    setGroupId(null);
    groupIdRef.current = null;
    setGroupLabel(null);
    setGroupBy(null);
    setThreadSummary(null);
    setThreadItems([]);
    setThreadTotal(0);
    setMessageFilter(familyKey.includes("deleted") ? "deleted" : "all");
  }, [selection.catalogKey, selection.catalogSection, selection.scope, selection.q, selection.family, familyKey]);

  useEffect(() => {
    if (!groupId || !wantsChatGroups) {
      setThreadItems([]);
      setThreadTotal(0);
      if (!groupId) setThreadSummary(null);
      return;
    }
    let cancelled = false;
    const selectedGroupId = groupId;
    async function loadThread() {
      setThreadLoading(true);
      try {
        const pageSize = 8000;
        let pageNum = 1;
        let all: Artifact[] = [];
        let totalRows = 0;
        let summary: ThreadSummary | null = null;
        do {
          const res = await forensicApi.listArtifacts(jobId, {
            page: pageNum,
            page_size: pageSize,
            family: selection.family ?? undefined,
            scope: selection.family ? undefined : selection.scope ?? undefined,
            catalog_key:
              selection.family || selection.scope ? undefined : selection.catalogKey ?? undefined,
            catalog_section:
              selection.family || selection.scope ? undefined : selection.catalogSection ?? undefined,
            q: selection.q ?? undefined,
            group_by: "person",
            group_id: selectedGroupId,
            message_filter: messageFilter,
          });
          if (cancelled || groupIdRef.current !== selectedGroupId) return;
          const rows = (res.items || []).filter((item) => {
            const kind = String(item.metadata?.evidence_kind || item.artifact_type || "").toLowerCase();
            return !["person", "group", "conversation", "album"].includes(kind);
          });
          const seen = new Set(all.map((row) => row.id));
          all = [...all, ...rows.filter((row) => !seen.has(row.id))];
          totalRows = Number(res.total || all.length);
          summary = res.thread_summary || summary;
          pageNum += 1;
          if (rows.length === 0) break;
        } while (all.length < totalRows && pageNum <= 20);

        if (!cancelled && groupIdRef.current === selectedGroupId) {
          setThreadItems(all);
          setThreadTotal(totalRows);
          setThreadSummary(summary);
        }
      } catch (e: unknown) {
        if (!cancelled) {
          toast.error(e instanceof Error ? e.message : "Could not load the WhatsApp conversation");
          setThreadItems([]);
          setThreadTotal(0);
        }
      } finally {
        if (!cancelled) setThreadLoading(false);
      }
    }
    void loadThread();
    return () => {
      cancelled = true;
    };
  }, [
    groupId,
    wantsChatGroups,
    messageFilter,
    jobId,
    selection.family,
    selection.scope,
    selection.catalogKey,
    selection.catalogSection,
    selection.q,
    toast,
  ]);

  function openGroup(art: Artifact) {
    const meta = art.metadata || {};
    const kind = String(meta.evidence_kind || art.artifact_type || "");
    if (kind === "person" || kind === "group" || art.artifact_type === "person" || art.artifact_type === "group") {
      const pid = String(meta.person_id || "");
      if (!pid) return;
      groupIdRef.current = pid;
      setGroupId(pid);
      setGroupLabel(String(meta.person_name || art.title || "Contact"));
      const deletedBucket =
        Boolean(meta.deleted_bucket) ||
        pid.endsWith("::deleted") ||
        String(art.title || "").toLowerCase().includes("[deleted]");
      // Live contact → all messages; [deleted] contact → deleted only.
      setMessageFilter(deletedBucket ? "deleted" : "all");
      setActive(null);
      return;
    }
    if (kind === "conversation" || art.artifact_type === "conversation") {
      const cid = String(meta.conversation_id || "");
      if (!cid) return;
      groupIdRef.current = cid;
      setGroupId(cid);
      setGroupLabel(String(meta.conversation || art.title || "Conversation"));
      setMessageFilter("all");
      setActive(null);
      return;
    }
    if (kind === "album" || art.artifact_type === "album") {
      const aid = String(meta.album_id || "");
      if (!aid) return;
      groupIdRef.current = aid;
      setGroupId(aid);
      setGroupLabel(String(meta.album || art.title || "Album"));
      setActive(null);
    }
  }

  function onSelectLeft(art: Artifact) {
    const kind = String(art.metadata?.evidence_kind || art.artifact_type || "");
    if (
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

  async function openLinkedArtifact(artifactId: string) {
    try {
      const linked = await forensicApi.getArtifact(jobId, artifactId);
      setActive(linked);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Could not open linked attachment");
    }
  }

  async function openContent(art: Artifact) {
    const meta = art.metadata || {};
    const evidenceKind = String(meta.evidence_kind || art.artifact_type || "").toLowerCase();
    const sourceId = meta.source_artifact_id ? String(meta.source_artifact_id) : "";
    const partIndex = Number(meta.part_index);

    // MIME attachment rows are virtual: opening the parent EML would show the
    // message, not the selected attachment.  Use the exact MIME walk index.
    if (evidenceKind === "email_attachment_part" && sourceId && Number.isInteger(partIndex) && partIndex >= 0) {
      setOpening(true);
      try {
        await forensicApi.openEmailAttachmentContent(
          jobId,
          sourceId,
          partIndex,
          String(meta.content_type || "application/octet-stream")
        );
      } catch (e: unknown) {
        toast.error(e instanceof Error ? e.message : "Could not open email attachment");
      } finally {
        setOpening(false);
      }
      return;
    }

    const target = artifactContentTarget(art);
    if (!target.id) {
      toast.error("No openable source file is linked to this evidence row.");
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

  async function copyPath(path: string) {
    try {
      await navigator.clipboard.writeText(path);
      toast.success("Path copied");
    } catch {
      toast.error("Could not copy path");
    }
  }

  const listTitle =
    evidenceDomain === "url_visit"
      ? "URL visits"
      : evidenceDomain === "person"
        ? "People / groups"
        : evidenceDomain === "person_thread" || evidenceDomain === "conversation_thread"
          ? groupLabel || "Conversation"
          : evidenceDomain === "conversation"
            ? "Conversations"
            : evidenceDomain === "whatsapp_message"
              ? "Messages (existing)"
              : evidenceDomain === "whatsapp_deleted_message"
                ? "Messages (deleted)"
                : evidenceDomain === "outlook_message"
                  ? "Outlook messages"
                  : evidenceDomain === "email_attachment"
                    ? "Email attachments"
                  : evidenceDomain === "carved_signature" ||
                      evidenceDomain === "file_plus_carve"
                    ? "Files + carved"
                    : "Evidence";

  const filterTabs: { id: MessageFilter; label: string; count?: number }[] = [
    { id: "all", label: "All", count: threadSummary?.message_count },
    { id: "current", label: "Current", count: threadSummary?.current_count },
    { id: "deleted", label: "Deleted", count: threadSummary?.deleted_count },
    { id: "media", label: "Media", count: threadSummary?.media_count },
    { id: "calls", label: "Calls", count: threadSummary?.call_count },
  ];

  if (!browsing) {
    return (
      <div className="flex h-full items-center justify-center p-6 text-center text-sm text-ink-400">
        Select a category or artifact on the left, or use <strong className="mx-1">Show all evidences</strong> to
        list every saved file.
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <InvestigationPrompt selection={selection} />
      <div className="grid min-h-0 flex-1 grid-cols-1 gap-0 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
        <div className="flex min-h-0 flex-col border-r border-ink-100">
          <div className="flex items-center justify-between gap-2 border-b border-ink-100 px-3 py-2">
            <div className="min-w-0">
              {groupId ? (
                <button
                  type="button"
                  className="mb-0.5 flex items-center gap-1 text-[11px] text-brand-700 hover:underline"
                  onClick={() => {
                    groupIdRef.current = null;
                    setGroupId(null);
                    setGroupLabel(null);
                    setThreadSummary(null);
                    setActive(null);
                  }}
                >
                  <ArrowLeft className="h-3 w-3" /> Back to list
                </button>
              ) : null}
              <p className="truncate text-xs font-semibold uppercase tracking-wide text-ink-500">
                {listTitle}
              </p>
              {!groupId && (evidenceDomain === "person" || wantsChatGroups) ? (
                <p className="text-[10px] font-normal normal-case tracking-normal text-ink-400">
                  Click a contact to open all messages
                </p>
              ) : null}
            </div>
            <Badge tone="neutral">{total}</Badge>
          </div>
          {chatThread && !wantsChatGroups ? (
            <div className="flex flex-wrap gap-1 border-b border-ink-100 px-2 py-1.5">
              {filterTabs.map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => {
                    setMessageFilter(tab.id);
                  }}
                  className={`rounded px-2 py-0.5 text-[11px] ${
                    messageFilter === tab.id
                      ? "bg-brand-100 font-semibold text-brand-800"
                      : "text-ink-500 hover:bg-ink-50"
                  }`}
                >
                  {tab.label}
                  {typeof tab.count === "number" ? ` (${tab.count})` : ""}
                </button>
              ))}
            </div>
          ) : null}
          {loading && items.length === 0 ? (
            <div className="flex items-center justify-center p-6 text-ink-400">
              <Loader2 className="h-4 w-4 animate-spin" />
            </div>
          ) : items.length === 0 ? (
            <p className="p-4 text-sm text-ink-400">
              {chatThread && messageFilter === "deleted"
                ? "No deleted/recovered messages for this contact."
                : "No matching evidence rows for this catalog item yet. If the count is above zero, re-run artifact inventory or open the source files under Web Related / Email."}
            </p>
          ) : (
            <>
              <ul
                className="min-h-0 flex-1 divide-y divide-ink-50 overflow-y-auto"
                onScroll={onListScroll}
              >
                {items.map((art) => {
                  const kind = String(art.metadata?.evidence_kind || art.artifact_type || "");
                  const isGroupRow =
                    (wantsChatGroups || !inThread) &&
                    ["person", "group", "conversation", "album"].includes(kind);
                  const Icon =
                    kind === "album"
                      ? FolderOpen
                      : kind === "group" || art.metadata?.is_group
                        ? Users
                        : kind === "person" || kind === "conversation"
                          ? MessagesSquare
                          : FileText;
                  const deleted = isDeletedArtifact(art);
                  const dateLine = formatDateLine(art);
                  const msgCount = art.metadata?.message_count as number | undefined;
                  const deletedCount = art.metadata?.deleted_count as number | undefined;
                  return (
                    <li key={art.id}>
                      <button
                        type="button"
                        onClick={() => onSelectLeft(art)}
                        className={`flex w-full items-start gap-2 px-3 py-2 text-left hover:bg-ink-50 ${
                          active?.id === art.id ? "bg-brand-50/60" : ""
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
                                  : art.title || art.source_path || art.artifact_type}
                            </span>
                            {(art.metadata?.deleted_bucket ||
                              String(art.title || "").toLowerCase().includes("[deleted]") ||
                              (deleted && kind === "person")) ? (
                              <Badge tone="amber">deleted</Badge>
                            ) : deleted && !["person", "group", "conversation", "album"].includes(kind) ? (
                              <Badge tone="amber">deleted</Badge>
                            ) : null}
                            {typeof deletedCount === "number" && deletedCount > 0 && isGroupRow ? (
                              <Badge tone="amber">{deletedCount} deleted</Badge>
                            ) : null}
                          </span>
                          {typeof msgCount === "number" && isGroupRow ? (
                            <span className="mt-0.5 block text-[10px] text-ink-500">
                              {msgCount.toLocaleString()} messages
                              {typeof art.metadata?.current_count === "number"
                                ? ` · ${Number(art.metadata.current_count).toLocaleString()} current`
                                : ""}
                            </span>
                          ) : null}
                          {art.metadata?.visit_count != null || art.metadata?.url ? (
                            <span className="mt-0.5 block text-[10px] text-brand-700">
                              {art.metadata?.visit_count != null
                                ? `Visits: ${String(art.metadata.visit_count)}`
                                : "URL"}
                              {art.metadata?.content_type_label
                                ? ` · ${String(art.metadata.content_type_label)}`
                                : art.metadata?.content_type
                                  ? ` · ${String(art.metadata.content_type)}`
                                  : ""}
                              {art.metadata?.browser ? ` · ${String(art.metadata.browser)}` : ""}
                              {art.metadata.host ? ` · ${String(art.metadata.host)}` : ""}
                            </span>
                          ) : null}
                          {art.metadata?.url && art.title !== art.metadata.url ? (
                            <span className="mt-0.5 block truncate font-mono text-[10px] text-ink-500">
                              {String(art.metadata.url)}
                            </span>
                          ) : null}
                          {art.metadata?.sender && !isGroupRow ? (
                            <span className="mt-0.5 block text-[10px] text-brand-700">
                              From: {String(art.metadata.sender)}
                            </span>
                          ) : null}
                          {art.source_path && !isGroupRow ? (
                            <span className="mt-0.5 block truncate font-mono text-[10px] text-ink-400">
                              {art.source_path}
                            </span>
                          ) : null}
                          {dateLine ? (
                            <span
                              className={`mt-0.5 block text-[10px] ${
                                dateLine.deleted ? "text-amber-700" : "text-ink-500"
                              }`}
                            >
                              {dateLine.text}
                            </span>
                          ) : null}
                        </span>
                      </button>
                    </li>
                  );
                })}
                {hasMore || loadingMore ? (
                  <li className="flex items-center justify-center gap-2 px-3 py-3 text-[11px] text-ink-400">
                    {loadingMore ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
                    {loadingMore
                      ? "Loading next 20…"
                      : `Scroll for next ${PAGE_SIZE} · ${items.length.toLocaleString()} of ${total.toLocaleString()}`}
                  </li>
                ) : items.length > PAGE_SIZE ? (
                  <li className="px-3 py-2 text-center text-[11px] text-ink-400">
                    {items.length.toLocaleString()} of {total.toLocaleString()}
                  </li>
                ) : null}
              </ul>
            </>
          )}
        </div>
        <div className="flex min-h-0 flex-col overflow-y-auto">
          <div className="flex items-center justify-between border-b border-ink-100 px-3 py-2">
            <p className="text-xs font-semibold uppercase tracking-wide text-ink-500">Detail</p>
            {active ? (
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
                {typeof active.metadata?.url === "string" &&
                /^https?:\/\//i.test(String(active.metadata.url)) ? (
                  <Button
                    variant="outline"
                    className="h-7 gap-1 px-2 text-xs"
                    onClick={() =>
                      window.open(String(active.metadata?.url), "_blank", "noopener,noreferrer")
                    }
                  >
                    <ExternalLink className="h-3.5 w-3.5" /> Open page
                  </Button>
                ) : null}
                <Button variant="outline" className="h-7 gap-1 px-2 text-xs" onClick={() => openContent(active)} disabled={opening}>
                  <ExternalLink className="h-3.5 w-3.5" />{" "}
                  {opening
                    ? "Opening…"
                    : String(active.id).startsWith("ev-")
                      ? "Open source"
                      : "Open file"}
                </Button>
              </div>
            ) : null}
          </div>
          {chatThread ? (
            <div className="flex min-h-0 flex-1 flex-col bg-[#efeae2]">
              <div className="border-b border-ink-100 bg-white px-4 py-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <p className="font-semibold text-ink-900">{groupLabel || threadSummary?.person_name || "WhatsApp conversation"}</p>
                    <p className="text-[11px] text-ink-500">
                      {threadTotal.toLocaleString()} message records
                      {threadSummary?.deleted_count ? ` · ${threadSummary.deleted_count.toLocaleString()} deleted/recovered` : ""}
                    </p>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {filterTabs.map((tab) => (
                      <button
                        key={tab.id}
                        type="button"
                        onClick={() => setMessageFilter(tab.id)}
                        className={`rounded-full px-2.5 py-1 text-[11px] ${
                          messageFilter === tab.id
                            ? "bg-brand-100 font-semibold text-brand-800"
                            : "bg-white text-ink-500 hover:bg-ink-50"
                        }`}
                      >
                        {tab.label}{typeof tab.count === "number" ? ` (${tab.count})` : ""}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
              <div className="min-h-0 flex-1 overflow-y-auto px-4 py-4">
                {threadLoading ? (
                  <div className="flex items-center justify-center gap-2 py-10 text-sm text-ink-500">
                    <Loader2 className="h-4 w-4 animate-spin" /> Loading complete conversation…
                  </div>
                ) : threadItems.length === 0 ? (
                  <p className="py-8 text-center text-sm text-ink-500">No messages found for this contact/group.</p>
                ) : (
                  <div className="space-y-2">
                    {threadItems.map((art) => {
                      const meta = art.metadata || {};
                      const deleted = isDeletedArtifact(art);
                      const fromMe = Boolean(meta.from_me) || chatSender(art) === "Device Owner";
                      const hash = chatRecordHash(art);
                      return (
                        <div key={art.id} className={`flex ${fromMe ? "justify-end" : "justify-start"}`}>
                          <button
                            type="button"
                            onClick={() => setActive(art)}
                            className={`max-w-[86%] rounded-lg border px-3 py-2 text-left shadow-sm ${
                              deleted
                                ? "border-red-300 bg-red-50 text-red-950"
                                : fromMe
                                  ? "border-[#c7e7bd] bg-[#d9fdd3] text-ink-900"
                                  : "border-white bg-white text-ink-900"
                            }`}
                          >
                            <div className="mb-1 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[10px]">
                              <span className="font-semibold">{chatSender(art)}</span>
                              {deleted ? <span className="font-bold text-red-700">DELETED / RECOVERED</span> : null}
                            </div>
                            <p className="whitespace-pre-wrap break-words text-[13px] leading-relaxed">{chatMessageText(art)}</p>
                            <div className={`mt-1.5 space-y-0.5 text-[9px] ${deleted ? "text-red-700" : "text-ink-500"}`}>
                              <p>{chatTimestamp(art)}</p>
                              <p className="break-all font-mono">SHA-256 record: {hash}</p>
                            </div>
                          </button>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          ) : !active ? (
            <p className="p-4 text-sm text-ink-400">Select a file to view details and preview.</p>
          ) : (
            <div className="p-4">
              <p className="font-semibold text-ink-900">{active.title || "Untitled"}</p>
              {isDeletedArtifact(active) ? (
                <Badge tone="amber">Deleted / recovered</Badge>
              ) : null}
              {active.metadata?.original_path ? (
                <p className="mt-1 break-all text-xs text-ink-600">
                  Original path:{" "}
                  <span className="font-mono">{String(active.metadata.original_path)}</span>
                </p>
              ) : null}
              {active.source_path ? (
                <p className="mt-1 break-all font-mono text-xs text-ink-500">{active.source_path}</p>
              ) : null}
              <ArtifactPreviewPanel
                jobId={jobId}
                artifact={active}
                onOpenLinkedArtifact={(artifactId) => void openLinkedArtifact(artifactId)}
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
