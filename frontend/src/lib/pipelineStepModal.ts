import type { Job } from "./types/forensic";
import { stripAxiomBranding } from "./displayText";
import { AGENT_ORDER, agentOrderForJob, drivesAlreadyMounted, evidenceTransportModeForJob, inferRunningAgentIndex, isMobilePipelineJob, isPipelineFullyComplete } from "./orchestrationStages";

export type PipelineStepStatus = "running" | "error" | "done";

export interface PipelineStepDef {
  id: string;
  title: string;
  runningMessage: string;
  errorMessage: string;
  doneMessage: string;
}

const AGENT_STEP_COPY: Record<string, Pick<PipelineStepDef, "runningMessage" | "errorMessage" | "doneMessage">> = {
  iosagent: {
    runningMessage: "iOS Agent is extracting this iPhone and indexing it for RAG…",
    errorMessage: "iOS Agent could not finish this iPhone. Unlock, Trust This Computer, then Try again.",
    doneMessage: "iOS Agent finished extract and RAG for this iPhone.",
  },
  androidagent: {
    runningMessage: "Android Agent is extracting this phone and indexing it for RAG…",
    errorMessage: "Android Agent could not finish this Android phone. Check USB/MTP, then Try again.",
    doneMessage: "Android Agent finished extract and RAG for this Android phone.",
  },
  drive_mount_agent: {
    runningMessage: "Looking for every attached drive and mounting it in Docker…",
    errorMessage: "Could not mount host drives. Start the host drive helper, then Try again.",
    doneMessage: "All attached drives are mounted. List Folder can run.",
  },
  download_agent: {
    runningMessage: "Download Agent is copying segments from this computer, 5 at a time. Other agents stay stopped.",
    errorMessage: "Download Agent could not finish receiving segments. Try again.",
    doneMessage: "Download Agent finished. Other agents may start.",
  },
  list_folder_agent: {
    runningMessage: "Mounting the selected drive if needed, then listing folder contents…",
    errorMessage: "Error listing folder. Check the path and Try again.",
    doneMessage: "Folder contents listed in extraction log.",
  },
  segments_agent: {
    runningMessage: "Registering disk segments from their current location — no copy…",
    errorMessage: "Error fetching segments. Try again.",
    doneMessage: "All segments received.",
  },
  virtual_disk_agent: {
    runningMessage: "Building virtual disk from E01 segments…",
    errorMessage: "Error building virtual disk. Try again.",
    doneMessage: "Virtual disk ready.",
  },
  extraction_agent: {
    runningMessage: "Extracting artifacts from the disk image…",
    errorMessage: "Error during extraction. Try again.",
    doneMessage: "Extraction complete.",
  },
  materialize_agent: {
    runningMessage: "Registering extracted artifacts…",
    errorMessage: "Error materializing artifacts. Try again.",
    doneMessage: "Artifacts registered.",
  },
  ocr_agent: {
    runningMessage: "OCR on required scans and images (GPU when free)…",
    errorMessage: "Error during OCR. Try again.",
    doneMessage: "OCR enrich complete.",
  },
  parse_agent: {
    runningMessage: "Parsing forensic files…",
    errorMessage: "Error parsing forensic files. Try again.",
    doneMessage: "Forensic files parsed.",
  },
  chunk_agent: {
    runningMessage: "Chunking evidence for RAG…",
    errorMessage: "Error during RAG chunking. Try again.",
    doneMessage: "RAG chunks ready.",
  },
  embed_agent: {
    runningMessage: "Embedding chunks on GPU…",
    errorMessage: "Error during RAG embedding. Try again.",
    doneMessage: "RAG embeddings ready.",
  },
  entity_agent: {
    runningMessage: "Extracting structured entities from parsed evidence…",
    errorMessage: "Error during entity extraction. Try again.",
    doneMessage: "Entities extracted.",
  },
  neo4j_agent: {
    runningMessage: "Syncing artifacts and entities into Neo4j…",
    errorMessage: "Error during Neo4j graph sync. Try again.",
    doneMessage: "Neo4j graph synced.",
  },
  annotation_agent: {
    runningMessage: "Annotating evidence spans for retrieval…",
    errorMessage: "Error during annotation. Try again.",
    doneMessage: "Annotations complete.",
  },
  ontology_agent: {
    runningMessage: "Linking artifacts to the forensic ontology…",
    errorMessage: "Error during ontology linking. Try again.",
    doneMessage: "Ontology linking complete.",
  },
  artifacts_agent: {
    runningMessage: "Counting catalog artifacts…",
    errorMessage: "Error during artifact inventory. Try again.",
    doneMessage: "Artifact inventory complete.",
  },
};

function agentStepDef(agent: { id: string; label: string }): PipelineStepDef {
  return {
    id: agent.id,
    title: agent.label,
    ...(AGENT_STEP_COPY[agent.id] || {
      runningMessage: `${agent.label} is running…`,
      errorMessage: `Error during ${agent.label}. Try again.`,
      doneMessage: `${agent.label} complete.`,
    }),
  };
}

const COMPLETE_STEP: PipelineStepDef = {
  id: "complete",
  title: "Pipeline complete",
  runningMessage: "Finalizing pipeline…",
  errorMessage: "Pipeline did not finish. Try again.",
  doneMessage: "All pipeline agents finished.",
};

/** Full catalog retained for generic callers; job UIs must use pipelineStepDefsForJob(). */
export const PIPELINE_STEP_DEFS: PipelineStepDef[] = [
  ...AGENT_ORDER.map(agentStepDef),
  COMPLETE_STEP,
];

/**
 * Visible modal steps for the actual product. Disk never shows iOS/Android
 * agents; mobile never shows Disk-only mount/download/virtual-disk stages.
 */
export function pipelineStepDefsForJob(
  job: Job | null,
  opts?: { includeClientDownload?: boolean }
): PipelineStepDef[] {
  if (!job) return PIPELINE_STEP_DEFS;
  const agents = [...agentOrderForJob(job)];
  if (opts?.includeClientDownload && !isMobilePipelineJob(job) && !agents.some((a) => a.id === "download_agent")) {
    const download = AGENT_ORDER.find((a) => a.id === "download_agent");
    if (download) {
      const mountIndex = agents.findIndex((a) => a.id === "drive_mount_agent");
      agents.splice(mountIndex >= 0 ? mountIndex + 1 : 0, 0, download);
    }
  }
  return [...agents.map(agentStepDef), COMPLETE_STEP];
}

function stepIndexForAgentIn(defs: PipelineStepDef[], agentId: string): number {
  const index = defs.findIndex((def) => def.id === agentId);
  return index >= 0 ? index : 0;
}

function stepIndexForAgent(job: Job, agentId: string): number {
  return stepIndexForAgentIn(pipelineStepDefsForJob(job), agentId);
}

export interface PipelineStepContext {
  open: boolean;
  stepIndex: number;
  status: PipelineStepStatus;
  detail: string | null;
  completedStepIndexes: number[];
}

function phase3(job: Job) {
  const pp = job.pipeline_progress;
  return {
    phase: pp?.phase ?? "",
    completed: pp?.completed ?? 0,
    total: pp?.total ?? 0,
    label: pp?.label ?? null,
  };
}

function segmentsStepComplete(job: Job): boolean {
  if (job.segment_readiness?.ready) return true;
  return !["created", "registered", "awaiting_segments"].includes(job.status);
}

/** Map job state to the active pipeline step index (0-based). */
export function derivePipelineStepIndex(
  job: Job,
  registering: boolean,
  opts?: { listingFolder?: boolean }
): number {
  const defs = pipelineStepDefsForJob(job);
  const completeIndex = defs.length - 1;

  if (opts?.listingFolder) return stepIndexForAgent(job, "list_folder_agent");
  if (registering) return stepIndexForAgent(job, "segments_agent");

  const status = job.status;
  const { phase, completed, total } = phase3(job);
  const inventoryCountsDone =
    (phase === "artifact_inventory" || phase === "axiom_artifacts") &&
    total > 0 &&
    completed >= total;

  if (phase === "complete" || isPipelineFullyComplete(job)) return completeIndex;
  if (inventoryCountsDone && (status === "indexed" || status === "ready")) {
    return completeIndex;
  }

  // A not-yet-started mobile job begins with its platform owner. A Disk job
  // begins with drive mount/listing and must never surface iOS/Android cards.
  if (["created", "registered", "awaiting_segments"].includes(status) && !job.segment_readiness?.ready) {
    if (isMobilePipelineJob(job)) {
      return 0;
    }
    return drivesAlreadyMounted(job)
      ? stepIndexForAgent(job, "list_folder_agent")
      : stepIndexForAgent(job, "drive_mount_agent");
  }

  const inferred = inferRunningAgentIndex(job);
  if (inferred >= AGENT_ORDER.length) return completeIndex;
  if (inferred >= 0) {
    const agentId = AGENT_ORDER[inferred]?.id;
    if (agentId) {
      const mapped = defs.findIndex((def) => def.id === agentId);
      if (mapped >= 0) return mapped;
    }
  }
  if (job.segment_readiness?.ready) return stepIndexForAgent(job, "virtual_disk_agent");
  return 0;
}

const UPLOAD_FOLDER_ERROR =
  "Still waiting for segment registration. If you attached a new drive, wait for it to mount, choose that folder, then Try again.";

/** Rewrite leftover D: example / paste-path copy so the UI never asks for a mount. */
export function sanitizeRegisterError(message: string | null | undefined): string | null {
  if (!message) return null;
  if (/not found inside Docker|not mounted|missing \/host/i.test(message)) {
    return message;
  }
  if (
    /paste the full windows path|fotrensics_data|segerEx-1|d:\\all\\|d:\\path\\to\\your|go & register|register & start|select disk folder/i.test(
      message
    )
  ) {
    return UPLOAD_FOLDER_ERROR;
  }
  return message;
}

export function derivePipelineStepContext(
  job: Job | null,
  opts: {
    registering: boolean;
    receivingSegmentsStarted: boolean;
    registerError: string | null;
    pipelineError: string | null;
    pipelineErrorStep?: number;
    processRequested: boolean;
    listingFolder?: boolean;
    mountingDrive?: boolean;
    uploading?: boolean;
    uploadDetail?: string | null;
  }
): PipelineStepContext {
  const empty: PipelineStepContext = {
    open: false,
    stepIndex: 0,
    status: "running",
    detail: null,
    completedStepIndexes: [],
  };

  if (!job) return empty;

  const errorText = String(opts.registerError || "");
  const transport = evidenceTransportModeForJob(job);
  const clientTransferContext =
    transport === "client" &&
    (Boolean(opts.uploading) ||
      /download agent|client upload|upload.*segment/i.test(errorText) ||
      String((job.disk_source as { intake?: unknown } | null | undefined)?.intake || "") === "browser_upload");
  const stepDefs = pipelineStepDefsForJob(job, { includeClientDownload: clientTransferContext });
  const stepIndexForVisibleAgent = (agentId: string) => stepIndexForAgentIn(stepDefs, agentId);
  const completedBefore = (index: number) =>
    Array.from({ length: Math.max(0, index) }, (_, i) => i);

  // A live browser upload is success-path progress — never overlay it with a path-register error.
  // Server-attached disks never enter this step; their bytes stay on the forensic server.
  if (opts.uploading && transport !== "server") {
    const stepIndex = stepIndexForVisibleAgent("download_agent");
    return {
      open: true,
      stepIndex,
      status: "running",
      detail: opts.uploadDetail?.trim() || "Uploading evidence files from this computer…",
      completedStepIndexes: completedBefore(stepIndex),
    };
  }

  if (opts.registerError) {
    const errorText = String(opts.registerError || "");
    const agentId =
      transport === "client" && /download agent|client upload|upload.*segment/i.test(errorText)
        ? "download_agent"
        : opts.mountingDrive || /hostdrive|docker mount|mount(?:ing|ed)? drive|forensic server|processed in place|server drives/i.test(errorText)
          ? "drive_mount_agent"
          : opts.listingFolder || /list(?:ing)? folder/i.test(errorText)
            ? "list_folder_agent"
            : "segments_agent";
    const stepIndex = stepIndexForVisibleAgent(agentId);
    return {
      open: true,
      stepIndex,
      status: "error",
      detail: sanitizeRegisterError(opts.registerError),
      completedStepIndexes: completedBefore(stepIndex),
    };
  }

  if (opts.pipelineError) {
    const stepIndex = opts.pipelineErrorStep ?? Math.max(0, derivePipelineStepIndex(job, false));
    return {
      open: true,
      stepIndex,
      status: "error",
      detail: sanitizeRegisterError(opts.pipelineError),
      completedStepIndexes: Array.from({ length: stepIndex }, (_, i) => i),
    };
  }

  if (opts.mountingDrive || opts.listingFolder) {
    const stepIndex = stepIndexForVisibleAgent(
      opts.mountingDrive ? "drive_mount_agent" : "list_folder_agent"
    );
    return {
      open: true,
      stepIndex,
      status: "running",
      detail: opts.mountingDrive
        ? "Mounting the selected drive so Docker can see it. Extraction starts as soon as the folder is visible."
        : null,
      completedStepIndexes: completedBefore(stepIndex),
    };
  }

  if (opts.registering || (opts.receivingSegmentsStarted && !segmentsStepComplete(job))) {
    const stepIndex = stepIndexForVisibleAgent("segments_agent");
    return {
      open: true,
      stepIndex,
      status: "running",
      detail: null,
      completedStepIndexes: completedBefore(stepIndex),
    };
  }

  const pipelineStarted =
    opts.processRequested ||
    opts.receivingSegmentsStarted ||
    job.segment_readiness?.ready ||
    !["created", "awaiting_segments"].includes(job.status);

  if (!pipelineStarted) return empty;

  if (job.status === "failed") {
    const stepIndex = Math.max(0, derivePipelineStepIndex(job, false));
    return {
      open: true,
      stepIndex,
      status: "error",
      detail: sanitizeRegisterError(job.error?.trim() || null),
      completedStepIndexes: Array.from({ length: stepIndex }, (_, i) => i),
    };
  }

  // Normal pipeline progress is shown on the Job Detail left step list —
  // keep this modal closed except for register / fatal error overlays above.
  if (isPipelineFullyComplete(job)) {
    const last = stepDefs.length - 1;
    return {
      open: false,
      stepIndex: last,
      status: "done",
      detail: null,
      completedStepIndexes: Array.from({ length: last + 1 }, (_, i) => i),
    };
  }

  const stepIndex = derivePipelineStepIndex(job, false);
  const completedStepIndexes = Array.from({ length: stepIndex }, (_, i) => i);
  const { label } = phase3(job);

  return {
    open: false,
    stepIndex,
    status: "running",
    detail: label ? stripAxiomBranding(label) : null,
    completedStepIndexes,
  };
}

export function formatElapsed(ms: number): string {
  const totalSec = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  if (h > 0) {
    return `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  }
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}
