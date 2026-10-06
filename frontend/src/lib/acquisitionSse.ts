import { resolveApiUrl, tokenStore } from "./api";
import { serviceHeaders } from "./apiRouting";
import type { AcquisitionRunDetail, AcquisitionRunSummary } from "./types/forensic";

export interface AcquisitionStreamEvent {
  event: "progress" | "done" | "error";
  data: AcquisitionRunSummary | AcquisitionRunDetail | { message: string };
}

export interface AcquisitionStreamOptions {
  runId: string;
  onProgress: (run: AcquisitionRunSummary) => void;
  onDone: (run: AcquisitionRunDetail) => void;
  onError?: (error: Error) => void;
  signal?: AbortSignal;
}

function parseSseBlock(block: string): AcquisitionStreamEvent | null {
  let event = "message";
  let data = "";
  for (const line of block.split("\n")) {
    // Heartbeat comments keep proxies from closing an idle connection during
    // the long quiet stretches of a large pull. They carry no data.
    if (line.startsWith(":")) continue;
    if (line.startsWith("event:")) event = line.slice(6).trim();
    else if (line.startsWith("data:")) data += line.slice(5).trim();
  }
  if (!data) return null;
  try {
    return { event: event as AcquisitionStreamEvent["event"], data: JSON.parse(data) };
  } catch {
    return { event: "error", data: { message: data } };
  }
}

/**
 * Stream acquisition progress via SSE.
 *
 * Detaching from this stream does NOT stop the collection — the run is owned by
 * a background worker on the server. That is the whole point: the examiner can
 * close the tab or lose the network during a multi-hour full-filesystem
 * collection without orphaning the acquisition or losing the outcome.
 *
 * Uses fetch + ReadableStream rather than EventSource, because EventSource
 * cannot send the Authorization and tenant headers this API requires.
 */
export async function streamAcquisition(opts: AcquisitionStreamOptions): Promise<void> {
  const { runId, onProgress, onDone, onError, signal } = opts;

  const headers: Record<string, string> = {
    Accept: "text/event-stream",
    "X-Tenant": tokenStore.tenant(),
    ...serviceHeaders(`/api/acquisition/runs/${runId}/stream`),
  };
  const token = tokenStore.access();
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const url = resolveApiUrl(`/api/acquisition/runs/${runId}/stream`);

  try {
    const res = await fetch(url, { headers, signal });
    if (!res.ok) throw new Error(`Progress stream failed: ${res.status} ${res.statusText}`);

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
        if (!evt) continue;
        if (evt.event === "progress") onProgress(evt.data as AcquisitionRunSummary);
        else if (evt.event === "done") onDone(evt.data as AcquisitionRunDetail);
        else if (evt.event === "error") {
          onError?.(new Error((evt.data as { message: string }).message));
        }
      }
    }

    if (buffer.trim()) {
      const evt = parseSseBlock(buffer.trim());
      if (evt?.event === "done") onDone(evt.data as AcquisitionRunDetail);
    }
  } catch (err) {
    if (signal?.aborted) return;
    onError?.(err instanceof Error ? err : new Error(String(err)));
  }
}
