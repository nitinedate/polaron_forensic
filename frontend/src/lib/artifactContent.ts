import type { Artifact } from "./types/forensic";

const SQLITE_NAME = /\.(sqlite3?|db|sqlitedb)(-wal|-shm|-journal)?$/i;

export function isSqliteFileName(name?: string | null): boolean {
  const base = String(name || "").split(/[\\/]/).pop() || "";
  return SQLITE_NAME.test(base);
}

/** Prefer the real photo/video/audio file. Never treat a chat SQLite DB as the viewed file. */
export function artifactContentTarget(art: Artifact | null | undefined): {
  id: string | null;
  kind: "media" | "file" | "none";
} {
  if (!art) return { id: null, kind: "none" };
  const meta = art.metadata || {};
  const mediaId = meta.media_artifact_id ? String(meta.media_artifact_id) : null;
  if (mediaId) return { id: mediaId, kind: "media" };

  const id = String(art.id || "");
  const sourceId = meta.source_artifact_id ? String(meta.source_artifact_id) : null;
  const sourcePath = String(meta.source_path || art.source_path || art.file_name || "");
  const virtual = id.startsWith("ev-") || id.startsWith("carve-");
  if (virtual) {
    if (sourceId && !isSqliteFileName(sourcePath)) return { id: sourceId, kind: "file" };
    return { id: null, kind: "none" };
  }
  if (isSqliteFileName(art.file_name || art.source_path || sourcePath)) {
    const kind = String(meta.evidence_kind || art.artifact_type || "").toLowerCase();
    if (kind.includes("message") || kind.includes("chat") || kind.includes("whatsapp")) {
      return { id: null, kind: "none" };
    }
  }
  return { id: id || null, kind: "file" };
}

export function artifactDownloadName(art: Artifact | null | undefined): string {
  if (!art) return "attachment";
  const meta = art.metadata || {};
  const named = String(meta.media_name || meta.media_filename || art.file_name || art.title || "").trim();
  const base = named.split(/[\\/]/).pop() || "attachment";
  if (isSqliteFileName(base)) return "attachment.bin";
  return base.replace(/[^\w.\-()+ ]+/g, "_").slice(0, 180) || "attachment";
}

/** Carved ChatStorage thumbnail when the dump file is missing. */
export function artifactThumbnailPayload(art: Artifact | null | undefined): {
  base64: string;
  contentType: string;
  fileName: string;
} | null {
  if (!art) return null;
  const meta = art.metadata || {};
  const base64 = typeof meta.thumbnail_base64 === "string" ? meta.thumbnail_base64 : "";
  if (base64.length < 80) return null;
  const contentType = String(meta.thumbnail_content_type || "image/jpeg");
  let fileName = artifactDownloadName(art);
  if (!/\.(jpe?g|png|webp|gif|heic)$/i.test(fileName)) {
    const ext = contentType.includes("png") ? "png" : contentType.includes("webp") ? "webp" : "jpg";
    fileName = `${fileName.replace(/\.[^.]+$/, "") || "recovered-media"}.${ext}`;
  }
  return { base64, contentType, fileName };
}

export function artifactCanDownload(art: Artifact | null | undefined): boolean {
  return Boolean(artifactContentTarget(art).id || artifactThumbnailPayload(art));
}

/**
 * Strip WhatsApp JID / stanza / base64 residue glued onto recovered chat text.
 * Display-time safety net when cached browse rows still include protocol noise.
 */
export function stripWhatsAppProtocolPrefix(text: string): string {
  const raw = String(text || "").trim();
  if (!raw) return "";
  let s = raw;
  if (/Original content:/i.test(s)) {
    const after = s.split(/Original content:/i)[1] || "";
    s = after
      .split(/\n\s*(?:Protocol residue|Recovery status|\[ATTACHMENT\]|⚠)/i)[0]
      .trim();
  }
  s = s.replace(/^[\s\[\(\{<]+/, "").replace(/[\s\]\)\}>]+$/, "").trim();
  const jid = s.match(
    /^(~?(?:\d{5,20}(?:-\d{5,20})?)@(?:g\.us|lid|s\.whatsapp\.net|c\.us))/i,
  );
  if (jid) {
    let after = s.slice(jid[0].length);
    const ids = after.match(
      /^(?:[A-Za-z0-9+/]{4,}={1,2})?(?:3EB0[0-9A-Fa-f]{8,36}|[0-9A-Fa-f]{16,40})?/,
    );
    if (ids && ids[0]) after = after.slice(ids[0].length);
    after = after.replace(/^\s+/, "");
    const prose = after.match(/([A-Za-z].*)$/s);
    if (prose && /[a-z]{2,}/.test(prose[1])) return prose[1].trim();
    if (/[a-zA-Z]{3,}/.test(after) && !/@g\.us|@lid/i.test(after)) return after.trim();
    return raw.includes("Original content:") ? raw : "";
  }
  const hexProse = s.match(/^[0-9A-Fa-f+/=_-]{12,}([A-Z][a-z].*)$/s);
  if (hexProse) return hexProse[1].trim();
  return raw;
}

/** Trigger a browser download from inline base64 (thumbnail carve). */
export function downloadBase64File(base64: string, fileName: string, contentType: string): void {
  const bin = atob(base64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
  const blob = new Blob([bytes], { type: contentType || "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName || "attachment.bin";
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

