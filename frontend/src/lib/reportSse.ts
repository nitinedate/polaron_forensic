import { resolveApiUrl, tokenStore } from "./api";
import { serviceHeaders } from "./apiRouting";
import type { ReportStreamEvent } from "./types/forensic";

export interface ReportStreamOptions {
  jobId: string;
  onEvent: (event: ReportStreamEvent) => void;
  onError?: (error: Error) => void;
  signal?: AbortSignal;
}

function parseSseBlock(block: string): ReportStreamEvent | null {
  let event = "message";
  let data = "";
  for (const line of block.split("\n")) {
    if (line.startsWith("event:")) event = line.slice(6).trim();
    else if (line.startsWith("data:")) data += line.slice(5).trim();
  }
  if (!data) return null;
  try {
    return { event: event as ReportStreamEvent["event"], data: JSON.parse(data) };
  } catch {
    return { event: event as ReportStreamEvent["event"], data: { raw: data } };
  }
}

/**
 * Stream report generation progress via SSE with auth + tenant headers.
 * Uses fetch + ReadableStream (EventSource cannot send Authorization).
 */
export async function streamReportGeneration(opts: ReportStreamOptions): Promise<void> {
  const { jobId, onEvent, onError, signal } = opts;
  const headers: Record<string, string> = {
    Accept: "text/event-stream",
    "X-Tenant": tokenStore.tenant(),
    ...serviceHeaders(`/api/jobs/${jobId}/report/stream`),
  };
  const token = tokenStore.access();
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const url = resolveApiUrl(`/api/jobs/${jobId}/report/stream`);

  try {
    const res = await fetch(url, { headers, signal });
    if (!res.ok) {
      throw new Error(`Stream failed: ${res.status} ${res.statusText}`);
    }
    const reader = res.body?.getReader();
    if (!reader) throw new Error("No response body");

    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split("\n\n");
      buffer = parts.pop() ?? "";
      for (const part of parts) {
        const evt = parseSseBlock(part.trim());
        if (evt) onEvent(evt);
      }
    }

    if (buffer.trim()) {
      const evt = parseSseBlock(buffer.trim());
      if (evt) onEvent(evt);
    }
  } catch (err) {
    if (signal?.aborted) return;
    onError?.(err instanceof Error ? err : new Error(String(err)));
  }
}
