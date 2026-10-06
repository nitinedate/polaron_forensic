import { useCallback, useEffect, useRef, useState } from "react";

import clsx from "clsx";

import { Pause, Play, Terminal } from "lucide-react";

import { Button, Spinner } from "../ui";

import { ApiError, refreshAccessToken } from "../../lib/api";

import { forensicApi } from "../../lib/forensicApi";
import { formatLogLineTimestamp } from "../../lib/formatDateTime";

import type { ExtractionLog } from "../../lib/types/forensic";
import { sanitizePipelineLabel, stripAxiomBranding } from "../../lib/displayText";



const LEVEL_TONE: Record<string, string> = {

  error: "text-red-400",

  warn: "text-amber-400",

  warning: "text-amber-400",

  info: "text-emerald-400",

  debug: "text-ink-500",

};



const STAGE_TONE: Record<string, string> = {
  artifact_capture: "text-sky-300",
  artifact_inventory: "text-fuchsia-300",
  pipeline: "text-indigo-300",
  virtual_disk: "text-violet-300",
  extract: "text-emerald-300",
  rag_index: "text-amber-300",
  evidence_register: "text-cyan-300",
};



interface ExtractionLogConsoleProps {

  jobId: string;

  autoRefresh?: boolean;

  pollIntervalMs?: number;

  /** Parent-provided logs — disables internal polling when set */

  controlledLogs?: ExtractionLog[];

  controlledLoading?: boolean;

  registering?: boolean;

  onManualRefresh?: () => void;

}



export function ExtractionLogConsole({

  jobId,

  autoRefresh = true,

  pollIntervalMs = 5000,

  controlledLogs,

  controlledLoading,

  registering = false,

  onManualRefresh,

}: ExtractionLogConsoleProps) {

  const isControlled = controlledLogs !== undefined;

  const [logs, setLogs] = useState<ExtractionLog[]>([]);

  const [loading, setLoading] = useState(true);

  const [paused, setPaused] = useState(false);

  const [pollStopped, setPollStopped] = useState(false);

  const scrollRef = useRef<HTMLDivElement>(null);

  const lastTsRef = useRef<string | undefined>();

  const pollBackoffMs = useRef(pollIntervalMs);

  const pollFailures = useRef(0);

  const pollStoppedRef = useRef(pollStopped);

  const pausedRef = useRef(paused);

  pollStoppedRef.current = pollStopped;

  pausedRef.current = paused;



  const displayLogs = isControlled ? controlledLogs : logs;

  const displayLoading = isControlled ? (controlledLoading ?? false) : loading;



  const load = useCallback(async () => {

    if (isControlled) {

      onManualRefresh?.();

      return;

    }

    try {

      const res = await forensicApi.listLogs(jobId, {

        from: lastTsRef.current,

        limit: 200,

      });

      pollFailures.current = 0;

      pollBackoffMs.current = pollIntervalMs;

      setPollStopped(false);

      if (res.items.length > 0) {

        setLogs((prev) => {

          const ids = new Set(prev.map((l) => l.id));

          const merged = [...prev, ...res.items.filter((l) => !ids.has(l.id))];

          return merged.sort((a, b) => a.timestamp.localeCompare(b.timestamp));

        });

        const newest = res.items.reduce(

          (max, item) => (item.timestamp > max ? item.timestamp : max),

          res.items[0].timestamp

        );

        lastTsRef.current = newest;

      }

    } catch (e: unknown) {

      const isUnauthorized = e instanceof ApiError && e.status === 401;

      const isNotFound = e instanceof ApiError && e.status === 404;

      const isBadGateway = e instanceof ApiError && e.status === 502;

      const isRateLimited = e instanceof ApiError && e.status === 429;

      if (isNotFound) {
        setPollStopped(true);
        return;
      }

      if (isUnauthorized && (await refreshAccessToken())) {

        try {

          const res = await forensicApi.listLogs(jobId, {

            from: lastTsRef.current,

            limit: 200,

          });

          pollFailures.current = 0;

          setPollStopped(false);

          if (res.items.length > 0) {

            setLogs((prev) => {

              const ids = new Set(prev.map((l) => l.id));

              const merged = [...prev, ...res.items.filter((l) => !ids.has(l.id))];

              return merged.sort((a, b) => a.timestamp.localeCompare(b.timestamp));

            });

            const newest = res.items.reduce(

              (max, item) => (item.timestamp > max ? item.timestamp : max),

              res.items[0].timestamp

            );

            lastTsRef.current = newest;

          }

          return;

        } catch {

          /* fall through */

        }

      }

      if (isUnauthorized) {

        setPollStopped(true);

        return;

      }

      pollFailures.current += 1;

      if (isBadGateway || isRateLimited) {

        pollBackoffMs.current = Math.min(pollBackoffMs.current * 2, 60_000);

      }

      if (pollFailures.current >= 5) setPollStopped(true);

    } finally {

      setLoading(false);

    }

  }, [jobId, pollIntervalMs, isControlled, onManualRefresh]);



  useEffect(() => {

    if (isControlled) return;

    setLogs([]);

    lastTsRef.current = undefined;

    setPollStopped(false);

    setLoading(true);

    load();

  }, [jobId, load, isControlled]);



  useEffect(() => {

    if (isControlled || !autoRefresh || paused || pollStopped) return;

    let timer: ReturnType<typeof setTimeout>;

    const schedule = () => {

      timer = setTimeout(async () => {

        await load();

        if (!pausedRef.current && !pollStoppedRef.current) schedule();

      }, pollBackoffMs.current);

    };

    schedule();

    return () => clearTimeout(timer);

  }, [autoRefresh, paused, pollStopped, load, isControlled]);



  useEffect(() => {

    if (paused || !scrollRef.current) return;

    scrollRef.current.scrollTo({

      top: scrollRef.current.scrollHeight,

      behavior: "smooth",

    });

  }, [displayLogs, paused]);



  return (

    <div className="flex h-full min-h-0 flex-col overflow-hidden rounded-xl border border-ink-800 bg-ink-950">

      <div className="flex items-center justify-between border-b border-ink-800 px-4 py-2">

        <div className="flex items-center gap-2 text-ink-300">

          <Terminal className="h-4 w-4" />

          <span className="text-xs font-semibold uppercase tracking-wider">Extraction log</span>

          <span className="text-xs text-ink-500">{displayLogs.length} entries</span>

        </div>

        <div className="flex gap-1">

          <Button

            variant="ghost"

            className="!px-2 !py-1 text-ink-400 hover:text-ink-200"

            onClick={() => setPaused((p) => !p)}

          >

            {paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}

          </Button>

          <Button

            variant="ghost"

            className="!px-2 !py-1 text-xs text-ink-400 hover:text-ink-200"

            onClick={load}

          >

            Refresh

          </Button>

        </div>

      </div>

      <div

        ref={scrollRef}

        className="min-h-0 flex-1 overflow-y-auto p-3 font-mono text-xs leading-relaxed"

      >

        {displayLoading && displayLogs.length === 0 ? (

          <Spinner className="py-8" />

        ) : displayLogs.length === 0 ? (

          <p className="text-ink-500">
            {registering
              ? "Registering segments… live log output will appear here."
              : "No log entries yet. Register evidence or start processing to see output."}
          </p>

        ) : (

          displayLogs.map((log) => {

            const isArtifactCapture = log.stage === "artifact_capture";
            const isArtifactInventory = log.stage === "artifact_inventory";
            const agentId = typeof log.metadata?.agent_id === "string" ? log.metadata.agent_id : null;
            const stageTone = STAGE_TONE[log.stage] ?? "text-ink-500";

            return (

            <div

              key={log.id}

              className={clsx(

                "mb-1 flex gap-2",

                isArtifactCapture && "rounded bg-sky-950/40 px-1 py-0.5",
                isArtifactInventory && "rounded bg-fuchsia-950/30 px-1 py-0.5",
                (log.level === "error") && "rounded bg-red-950/50 px-1 py-0.5",
                (log.level === "warn" || log.level === "warning") && "rounded bg-amber-950/40 px-1 py-0.5"

              )}

            >

              <span className="shrink-0 text-ink-600">

                {formatLogLineTimestamp(log.timestamp)}

              </span>

              <span

                className={clsx(

                  "shrink-0 uppercase",

                  isArtifactCapture
                    ? STAGE_TONE.artifact_capture
                    : isArtifactInventory
                      ? STAGE_TONE.artifact_inventory
                      : stageTone

                )}

              >

                [{log.stage}]

              </span>

              {agentId ? (
                <span className="shrink-0 text-[10px] font-semibold uppercase text-cyan-400">[{agentId}]</span>
              ) : null}

              <span className={clsx("shrink-0 uppercase", LEVEL_TONE[log.level] ?? "text-ink-400")}>

                {log.level}

              </span>

              <span
                className={clsx(
                  "text-ink-200",
                  isArtifactCapture && "text-sky-100",
                  isArtifactInventory && "text-fuchsia-100"
                )}
              >

                {sanitizePipelineLabel(stripAxiomBranding(log.message))}

              </span>

            </div>

            );

          })

        )}

      </div>

    </div>

  );

}

