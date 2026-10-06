export interface SegmentReadiness {
  ready: boolean;
  has_disk_segments: boolean;
  disk_sets: Array<{
    base_name: string;
    format: string;
    present_segments: number[];
    missing_segments: number[];
    missing_labels: string[];
    range_label: string;
    complete: boolean;
  }>;
  gaps: Array<{
    base_name: string;
    format: string;
    present_segments: number[];
    missing_segments: number[];
    missing_labels: string[];
    range_label: string;
    message: string;
  }>;
  message: string | null;
}

export interface ExtractCoverage {
  interesting_total: number;
  extracted: number;
  pending: number;
  next_batch_size: number;
  batch_cap: number;
}

/** Live Phase 3 stats — baseline Q&A vs background parse/RAG. */
export interface EnrichmentSnapshot {
  /** Forensic parse scope (parsed + pending forensic files). */
  artifacts_total: number;
  artifacts_parsed: number;
  artifacts_pending: number;
  /** All registered files on the job (includes skipped low-value files). */
  files_registered?: number;
  artifacts_skipped?: number;
  rag_chunks: number;
  rag_total?: number;
  rag_pending?: number;
  rag_indexing?: boolean;
  ocr_pending?: number;
  ocr_done?: number;
  baseline_ready: boolean;
  enriching: boolean;
  parse_done?: boolean;
  rag_done?: boolean;
  rag_background_enabled?: boolean;
  rag_embedding_enabled?: boolean;
  background_rag_deferred_for_ocr?: boolean;
}

export interface PipelineProgress {
  phase: string;
  completed: number;
  total: number | null;
  label?: string;
  pending?: number;
  serial_pipeline?: {
    upgrade_required?: boolean;
    version: number;
    serial: boolean;
    max_parallelism: number;
    current_stage: string | null;
    complete: boolean;
    overall_pct: number;
    stages: Array<{
      id: string;
      agent_id: string;
      label: string;
      status: "pending" | "queued" | "running" | "waiting" | "failed" | "done" | "skipped";
      pct: number;
      total: number;
      completed: number;
      failed: number;
      skipped: number;
      attempt: number;
      error: string | null;
      details?: Record<string, unknown>;
      started_at?: string | null;
      completed_at?: string | null;
    }>;
  };
  /** Honest extraction sub-stage. Enumeration intentionally has no denominator. */
  extraction_activity?: {
    subphase?: "enumerating" | "copying" | "finalizing" | string;
    label?: string;
    files_found?: number;
    files_extracted?: number;
    files_total?: number;
    files_remaining?: number;
    bytes_extracted?: number;
    bytes_total?: number | null;
    bytes_remaining?: number | null;
    shards_done?: number;
    shards_total?: number;
  };
  /** Authoritative inventory bar (prewarm 1–18, counting 18–99). */
  inventory_ui_pct?: number;
  inventory_stage?: string;
  orchestration?: {
    agents: Record<
      string,
      {
        state: string;
        pct: number;
        label: string;
        detail?: string;
        started_at?: string;
        finished_at?: string;
        duration_sec?: number;
      }
    >;
    overall_pct: number;
    current_agent_id?: string | null;
    current_agent_label?: string | null;
    current_agent_state?: "running" | "pending" | null;
    sequential?: boolean;
    pipeline_started_at?: string | null;
    total_duration_sec?: number | null;
  };
}

export interface Job {
  id: string;
  type: string;
  status: string;
  domain_pack: string;
  created_by: string | null;
  case_id: string | null;
  progress_pct: number;
  error: string | null;
  segment_readiness?: SegmentReadiness | null;
  pipeline_progress?: PipelineProgress | null;
  extract_coverage?: ExtractCoverage | null;
  enrichment?: EnrichmentSnapshot | null;
  extracted_disk_uri?: string | null;
  disk_source?: {
    mounted?: boolean;
    base_name?: string;
    format?: string;
    mode?: string;
    segments?: number;
    [key: string]: unknown;
  } | null;
  files_total?: number;
  files_extracted?: number;
  bytes_extracted?: number;
  stop_requested?: boolean;
  evidence_count?: number;
  created_at: string;
  updated_at: string;
  /** V45.5: extract worker heartbeat (from its Redis lease); absent when no worker holds the job. */
  worker_liveness?: { alive: boolean; heartbeat_age_sec?: number; pid?: number; reason?: string };
}

export interface JobList {
  items: Job[];
  total: number;
  page: number;
  page_size: number;
}

export interface JobCreate {
  type?: string;
  domain_pack?: string | null;
  case_id?: string | null;
  mobile_os?: string | null;
  source_type?: string | null;
  acquisition_mode?: string | null;
  legal_authority_acknowledged?: boolean;
  evidence_path?: string | null;
}

export interface ProcessResult {
  job_id: string;
  status: string;
  message: string;
}

export interface AgentDefinition {
  id: string;
  name: string;
  description: string;
  stage: string;
  sort_order?: number;
  kind?: "llm" | "pipeline";
  queue?: string;
}

export interface AgentRun {
  id: string;
  agent_id: string;
  parent_run_id: string | null;
  status: string;
  message: string | null;
  started_at: string | null;
  finished_at: string | null;
  latency_ms: number | null;
}

export interface AgentRunList {
  job_id: string;
  items: AgentRun[];
}

export interface AgentInvokeResult {
  agent_id: string;
  run_id: string | null;
  status: string;
  message: string;
  output: Record<string, unknown>;
  thread_id?: string | null;
  latency_ms?: number | null;
}

export interface PipelineHealEvent {
  id: string;
  job_id: string;
  agent: string;
  issue_code: string;
  issue_detail?: string | null;
  stage?: string | null;
  remedy_code?: string | null;
  remedy_detail?: string | null;
  status: string;
  metadata?: Record<string, unknown>;
  created_at?: string | null;
  resolved_at?: string | null;
}

export interface Checkpoint {
  job_id: string;
  file_id: string;
  adapter_name: string | null;
  stage: string | null;
  cursor: number;
  canonical_part: number;
  state_json: Record<string, unknown> | null;
  updated_at: string;
}

export interface ExtractionLog {
  id: string;
  job_id: string;
  file_id: string | null;
  timestamp: string;
  stage: string;
  level: string;
  message: string;
  metadata: Record<string, unknown> | null;
}

export interface LogList {
  items: ExtractionLog[];
  total: number;
}

export type UnifiedLogSourceType = "disk" | "mobile" | "vuln";
export type UnifiedLogOrigin = "inhouse" | "external";

export interface UnifiedLogEntry {
  id: string;
  job_id: string | null;
  source_type: UnifiedLogSourceType;
  source_label: string;
  origin?: UnifiedLogOrigin | string;
  origin_label?: string;
  job_label: string;
  stage: string;
  level: string;
  message: string;
  timestamp: string;
  timestamp_ist: string;
}

export interface UnifiedLogList {
  items: UnifiedLogEntry[];
  total: number;
  page: number;
  page_size: number;
}

export interface UnifiedLogSource {
  id: string;
  source_type: UnifiedLogSourceType;
  source_label: string;
  origin?: UnifiedLogOrigin | string;
  origin_label?: string;
  label: string;
  status?: string | null;
  updated_at?: string | null;
  updated_at_ist?: string | null;
}

export interface CaptureLogEntry {
  timestamp: string;
  timestamp_local?: string | null;
  timezone?: string | null;
  display_timestamp?: string | null;
  event: string;
  message: string | null;
  job_id?: string | null;
  artifact_id?: string | null;
  artifact_type?: string | null;
  title?: string | null;
  source_path?: string | null;
  axiom_category?: string | null;
  axiom_sub_category?: string | null;
  confidence?: number | null;
  storage_uri?: string | null;
  details?: Record<string, unknown> | null;
}

export interface CaptureLogList {
  items: CaptureLogEntry[];
  total: number;
  storage_uri: string | null;
}

export interface EvidenceActivity {
  id: string;
  timestamp: string;
  activity_type: "pipeline" | "artifact";
  stage?: string | null;
  level?: string | null;
  message?: string | null;
  file_name?: string | null;
  source_path?: string | null;
  artifact_type?: string | null;
  axiom_category?: string | null;
  parse_status?: string | null;
  ocr_status?: string | null;
  size_bytes?: number | null;
  sha256?: string | null;
  metadata?: Record<string, unknown> | null;
}

export interface EvidenceSearchResult {
  items: EvidenceActivity[];
  total: number;
  page?: number;
  page_size?: number;
  scope?: "artifacts" | "all";
}

export interface ReportCatalogEntry {
  job_id: string;
  report_run_id: string | null;
  version: string | null;
  created_by: string | null;
  created_by_email: string | null;
  organization: string | null;
  case_type: string | null;
  report_type: string | null;
  job_status: string;
  job_type: string;
  report_status: string;
  sections_completed: number;
  sections_total: number | null;
  export_count: number;
  job_created_at: string | null;
  report_created_at: string | null;
  report_completed_at: string | null;
  duration_ms: number | null;
  report_error: string | null;
}

export interface ReportCatalogList {
  items: ReportCatalogEntry[];
  total: number;
  page: number;
  page_size: number;
}

export interface EvidenceFile {
  id: string;
  job_id: string;
  group_id: string | null;
  relative_path: string | null;
  original_name: string;
  storage_uri: string | null;
  mime_type: string | null;
  sha256: string | null;
  status: string;
  size_bytes: number | null;
  created_at: string;
}

export interface UploadResult {
  accepted: EvidenceFile[];
  skipped: string[];
  message: string | null;
}

export interface ActivityLine {
  id: string;
  timestamp: string;
  level: "info" | "success" | "error" | "warn";
  message: string;
}

export interface UploadProgressState {
  index: number;
  total: number;
  fileName: string;
  filePct: number;
}

export type UploadFileStatus = "queued" | "uploading" | "done" | "skipped" | "failed";

export interface UploadFileItem {
  id: string;
  name: string;
  sizeBytes: number;
  status: UploadFileStatus;
}

export interface JobFileInventory {
  total: number;
  extracted?: number;
  by_status: Record<string, number>;
  total_bytes: number;
  evidence_groups: number;
}

export interface JobDiskIndex {
  file_count: number;
  dir_count: number;
  interesting_file_count: number;
  total_nodes: number;
}

export interface JobArtifactInventory {
  total: number;
  parsed?: number;
  ocr_done?: number;
  by_type: Record<string, number>;
  categories: { category: string; sub_category: string | null; count: number }[];
  category_total: number;
}

export interface JobPipelineInventory {
  checkpoints: number;
  extraction_logs: number;
}

export interface OpenSearchInventory {
  available: boolean;
  artifacts: number;
  chunks: number;
  embeddings: number;
  embedding_coverage_pct: number;
  embedding_providers: Record<string, number>;
  ollama_embeddings: number;
  hash_embeddings: number;
}

export interface RagPipelineInventory {
  artifacts_enriched: number;
  artifacts_annotated?: number;
  postgres_entities?: number;
  chunks_indexed: number;
  encyclopedia_chunks?: number;
  evidence_chunks?: number;
  parsed_artifacts?: number;
  ocr_artifacts?: number;
  embeddings_indexed: number;
  ollama_embeddings: number;
  hash_embeddings: number;
  embedding_coverage_pct: number;
  embedding_device?: string;
  gpu_enabled?: boolean;
  extract_coverage?: ExtractCoverage;
}

export interface ExtractCoverage {
  interesting_total: number;
  extracted: number;
  pending: number;
  next_batch_size: number;
  batch_cap: number;
}

export interface Neo4jInventory {
  available: boolean;
  artifacts: number;
  chunks: number;
  entities: number;
  ontology_nodes: number;
  relationships: number;
  error?: string | null;
}

export interface JobInventory {
  job_id: string;
  job_status: string;
  progress_pct: number;
  generated_at: string;
  artifacts_annotated?: number;
  postgres_entities?: number;
  files: JobFileInventory;
  disk_index: JobDiskIndex;
  artifacts: JobArtifactInventory;
  pipeline: JobPipelineInventory;
  opensearch: OpenSearchInventory;
  rag: RagPipelineInventory;
  neo4j: Neo4jInventory;
  embedding_device?: string;
  gpu_enabled?: boolean;
  extract_coverage?: ExtractCoverage;
}

export interface LocalQueueInventory {
  total: number;
  queued: number;
  uploading: number;
  done: number;
  failed: number;
  skipped: number;
  total_bytes: number;
}

export interface ForensicEntity {
  id: string;
  type: string;
  label: string;
  email?: string;
  role?: string;
  artifact_id?: string;
}

export interface ForensicRelationship {
  type: string;
  from_id: string;
  to_id: string;
  label?: string;
}

export interface ArtifactGraph {
  artifact_id: string;
  entities: ForensicEntity[];
  relationships: ForensicRelationship[];
}

export interface FileTreeSummary {
  total_nodes: number;
  file_count: number;
  dir_count: number;
  interesting_file_count: number;
  truncated?: boolean;
}

export interface FileTreeNode {
  path: string;
  name: string;
  inode?: number;
  type: "file" | "dir";
  interesting?: boolean;
  children?: FileTreeNode[];
}

export interface JobFileTree {
  job_id: string;
  disk_artifact_id: string | null;
  summary: FileTreeSummary;
  nodes: FileTreeNode[];
  root: FileTreeNode | null;
}

export interface Artifact {
  id: string;
  job_id: string;
  file_id: string | null;
  parent_artifact_id: string | null;
  artifact_type: string;
  axiom_category: string;
  axiom_category_label?: string | null;
  axiom_sub_category: string | null;
  title: string | null;
  file_name?: string | null;
  size_bytes?: number | null;
  extension?: string | null;
  source_path: string | null;
  artifact_datetime: string | null;
  preview_uri: string | null;
  storage_uri: string | null;
  metadata: Record<string, unknown> | null;
  tags: string[] | null;
  examiner_comment: string | null;
  parser_version: string | null;
  confidence: number | null;
  created_at: string;
}

export interface ArtifactMediaProperties {
  artifact_id: string;
  job_id: string;
  file_name: string;
  source_path?: string | null;
  sha256?: string | null;
  size_bytes?: number | null;
  content_type?: string | null;
  kind: string;
  extension?: string | null;
  width?: number | null;
  height?: number | null;
  pixels?: number | null;
  duration_seconds?: number | null;
  format?: string | null;
  orientation?: number | null;
  video_codec?: string | null;
  audio_codec?: string | null;
  sample_rate?: number | null;
  channels?: number | null;
  is_deleted?: boolean;
  deleted_at?: string | null;
  probe_source?: string | null;
  probe_error?: string | null;
  downloadable: boolean;
  content_url: string;
}

export interface ArtifactReviewSignal {
  code: string;
  label: string;
  severity: "none" | "info" | "low" | "medium" | "high" | string;
  detail: string;
}

export interface ArtifactReview {
  artifact_id?: string;
  job_id?: string;
  flagged: boolean;
  severity: string;
  signal_count: number;
  signals: ArtifactReviewSignal[];
  disclaimer: string;
}

export interface ArtifactReviewSummary {
  job_id: string;
  total_artifacts: number;
  flagged_total: number;
  candidate_total?: number;
  scanned_candidates?: number;
  by_severity: Record<string, number>;
  items: Array<{
    artifact_id: string;
    file_name?: string | null;
    source_path?: string | null;
    size_bytes?: number | null;
    severity: string;
    signals: ArtifactReviewSignal[];
  }>;
  limited: boolean;
  disclaimer: string;
}

export interface ThreadSummary {
  person_id?: string;
  person_name?: string;
  is_group?: boolean;
  message_count: number;
  current_count: number;
  deleted_count: number;
  media_count: number;
  call_count: number;
  fragment_count: number;
  applications: string[];
  participants: string[];
  participant_count: number;
}

export interface FileForensicsSummary {
  total: number;
  deleted: number;
  photos: number;
  videos: number;
  documents: number;
  audio: number;
  extensionless: number;
  anomalous: number;
  modified: number;
  with_dates: number;
  platforms?: Record<string, number>;
}

export interface ArtifactList {
  items: Artifact[];
  total: number;
  page: number;
  page_size: number;
  /** file | url_visit | whatsapp_message | outlook_message | carved_signature | file_plus_carve | person | person_thread | conversation | conversation_thread | album | album_files */
  evidence_domain?: string | null;
  evidence_label?: string | null;
  /** Active grouping mode when browsing a mobile board family. */
  group_by?: "person" | "conversation" | "album" | string | null;
  /** Selected person_id, conversation_id, or album_id when drilled into a group. */
  group_id?: string | null;
  /** Thread tab filter when viewing a person/conversation. */
  message_filter?: "all" | "current" | "deleted" | "media" | "calls" | string | null;
  /** Person/group header stats for the open thread. */
  thread_summary?: ThreadSummary | null;
  /** File forensics tab filter. */
  file_filter?: string | null;
  /** Deleted/modified/anomalous file tab badge counts. */
  file_summary?: FileForensicsSummary | null;
}

export interface CategoryNode {
  category: string;
  sub_category: string | null;
  count: number;
}

export interface CategoryTree {
  categories: CategoryNode[];
  total: number;
  platform?: string | null;
  /** Artifacts materialized but not yet chunked (RAG in progress). */
  pending_chunk?: number;
}

export interface ArtifactUpdate {
  tags?: string[] | null;
  examiner_comment?: string | null;
}

export interface ArtifactEmailHeaders {
  from?: string;
  to?: string;
  cc?: string;
  bcc?: string;
  subject?: string;
  date?: string;
  message_id?: string;
}

export interface ArtifactEmailAttachment {
  filename: string;
  content_type?: string;
  size?: number;
  part_index?: number;
  artifact_id?: string;
  disposition?: string;
  inline?: boolean;
}

export interface ArtifactPreview {
  artifact_id: string;
  title: string | null;
  artifact_type: string;
  content_type: string;
  body: string;
  body_text?: string;
  body_html?: string;
  encoding?: "base64" | "url" | null;
  content_url?: string | null;
  email?: ArtifactEmailHeaders;
  attachments?: ArtifactEmailAttachment[];
  attachment_count?: number;
  device_name?: string | null;
}

export interface CaseSubject {
  id: string;
  name: string;
  email: string | null;
  role: string | null;
  sort_order: number;
}

export interface CaseSubjectInput {
  name: string;
  email?: string | null;
  role?: string | null;
}

export interface Intake {
  case_id: string;
  case_type: string | null;
  organization: string | null;
  address: string | null;
  evidence_description: string | null;
  seizure_date: string | null;
  background: string | null;
  incident_summary: string | null;
  pre_seizure_consent: string | null;
  evidence_handling: string | null;
  scan_scope_json: Record<string, unknown> | null;
  report_type: string | null;
  objective_ids: string[] | null;
  custom_objectives: CustomObjectiveInput[] | null;
  subjects: CaseSubject[] | null;
  report_ready: boolean;
  missing_fields: string[];
  requesting_agency?: string | null;
  case_number?: string | null;
  examiner_name?: string | null;
  lab_location?: string | null;
  evidence_received_date?: string | null;
  chain_of_custody_ref?: string | null;
  vol18_form_json?: Record<string, unknown> | null;
  forensic_key_status?: Record<string, boolean>;
  whatsapp_key_capture?: WhatsAppKeyCapture;
  updated_at: string;
}

export interface WhatsAppKeyCapture {
  sources: Array<{ source_path: string; source_kind: string; sha256: string; size_bytes: number;
    key_kind: string; key_offset?: number; captured_at: string }>;
  selected_source?: string | null;
  format_validated: boolean;
  backup_match_verified: boolean;
  verified_backup_count?: number;
  legacy_unverified_count?: number;
  blocked_backup_count?: number;
  backup_results?: Array<{ source_path: string; source_sha256?: string; decrypted_sha256?: string;
    state: string; authenticated: boolean; reason?: string; key_source?: string; container?: string; export_state?: string; validation?: string; payload_kind?: string }>;
}

export interface WhatsAppKeyCaptureResult {
  status: string;
  added: number;
  forensic_key_status: Record<string, boolean>;
  whatsapp_key_capture: WhatsAppKeyCapture;
}

export interface ForensicKeysPatch {
  whatsapp_key_hex?: string | null;
  whatsapp_legacy_account?: string | null;
  signal_passphrase?: string | null;
  signal_db_key_hex?: string | null;
  ios_backup_password?: string | null;
  keychain_password?: string | null;
  adb_backup_password?: string | null;
}

export interface IntakePatch {
  case_type?: string | null;
  organization?: string | null;
  address?: string | null;
  evidence_description?: string | null;
  seizure_date?: string | null;
  background?: string | null;
  incident_summary?: string | null;
  pre_seizure_consent?: string | null;
  evidence_handling?: string | null;
  scan_scope_json?: Record<string, unknown> | null;
  report_type?: string | null;
  objective_ids?: string[] | null;
  custom_objectives?: CustomObjectiveInput[] | null;
  subjects?: CaseSubjectInput[] | null;
  forensic_keys?: ForensicKeysPatch | null;
  requesting_agency?: string | null;
  case_number?: string | null;
  examiner_name?: string | null;
  lab_location?: string | null;
  evidence_received_date?: string | null;
  chain_of_custody_ref?: string | null;
  vol18_form_json?: Record<string, unknown> | null;
}

export interface ArtifactCatalogSubcategory {
  key: string;
  label: string;
  critical: boolean;
  in_template?: boolean;
  description?: string | null;
  count?: number;
  prompt_question?: string | null;
  recovery_method?: string | null;
  objective_id?: string | null;
  procedure_id?: string | null;
  observation_focus?: string | null;
  count_domain?: string | null;
  query_key?: string | null;
  query_status?: string | null;
}

export interface ArtifactCatalogSection {
  title: string;
  count?: number;
  subcategories: ArtifactCatalogSubcategory[];
}

export interface ArtifactCatalog {
  sections: ArtifactCatalogSection[];
}

export interface ArtifactGroupArtifact {
  key: string;
  label: string;
  count?: number;
  description?: string;
  enabled?: boolean;
  critical?: boolean;
  prompt_question?: string | null;
  recovery_method?: string | null;
  objective_id?: string | null;
  observation_focus?: string | null;
  count_domain?: string | null;
  query_key?: string | null;
  query_status?: string | null;
}

export interface ArtifactGroup {
  group_name: string;
  group_count?: number;
  group_description?: string | null;
  enabled?: boolean;
  artifacts: ArtifactGroupArtifact[];
}

export interface ArtifactScope {
  enabled_keys: string[];
  groups?: ArtifactGroup[];
  sections: ArtifactCatalogSection[];
  default_critical_keys: string[];
  platform?: string | null;
  axiom_inventory?: {
    platform?: string;
    total?: number;
    completed?: number;
    done?: boolean;
  } | null;
  suggested_investigation_scope?: {
    recommended_headers?: { area_code: string; header_title: string; mandatory?: boolean }[];
    recommended_artifact_ids?: string[];
    recommended_objective_ids?: string[];
  } | null;
  report_template_filtered?: boolean;
  report_template_artifact_count?: number;
  recommended_artifact_ids?: string[];
  report_saved_artifact_ids?: string[];
  report_artifacts_saved_at?: string | null;
}

export interface ArtifactScopeUpdate {
  enabled_keys: string[];
}

export interface ObjectiveProcedureItem {
  key: string;
  procedure_id?: string | null;
  label: string;
  domain?: string | null;
  priority?: string | null;
  critical?: boolean;
  statement?: string | null;
  required_observation_fields?: string | null;
  minimum_corroboration?: string | null;
  limitations?: string | null;
  prompt_question?: string | null;
  procedure_title?: string | null;
  procedure_prompt?: string | null;
  expected_output_fields?: string | null;
}

export interface ObjectiveProcedureSection {
  title: string;
  items: ObjectiveProcedureItem[];
}

export interface CustomExaminationObjective {
  id: string;
  title: string;
  prompt: string;
  procedure?: string | null;
}

export interface ObjectiveProcedureScope {
  enabled_objective_ids: string[];
  custom_objectives?: CustomExaminationObjective[];
  sections: ObjectiveProcedureSection[];
  default_critical_ids: string[];
  total?: number;
}

export interface ObjectiveProcedureScopeUpdate {
  enabled_objective_ids: string[];
  custom_objectives?: CustomExaminationObjective[];
}

export interface ReportStartResult {
  job_id: string;
  status: string;
  message: string;
  report_type?: string | null;
}

export interface ReportTypeOption {
  id: string;
  label: string;
  domain?: string | null;
  default_os?: string[];
  description?: string | null;
}

export interface ReportArtifactMappingItem {
  artifact_id: string;
  artifact_name?: string | null;
  axiom_category?: string | null;
  report_description?: string | null;
  recovery_method?: string | null;
  critical?: boolean;
  primary_objective_id?: string | null;
  mapping_note?: string | null;
  default_enabled?: boolean;
  sort_order?: number;
  axiom_matched?: boolean;
  prompt_question?: string | null;
}

export interface ReportArtifactMappingGroup {
  category: string;
  artifacts: ReportArtifactMappingItem[];
}

export interface ReportArtifactMappingReportType {
  report_type_id: string;
  report_name?: string | null;
  report_domain?: string | null;
  groups: ReportArtifactMappingGroup[];
  artifact_count?: number;
}

export interface ReportArtifactMappingResponse {
  platform: string;
  report_type_filter?: string | null;
  report_types: ReportArtifactMappingReportType[];
  unmapped_template_artifact_ids?: Array<{
    report_type_id: string;
    artifact_id: string;
    artifact_name?: string;
    group_name?: string;
  }>;
}

export interface AxiomArtifactsByGroupResponse {
  platform: string;
  category_filter?: string | null;
  groups: Array<{ category: string; artifacts: Record<string, unknown>[] }>;
  total: number;
}

export interface CaseTypeOption {
  id: string;
  label: string;
  description?: string | null;
  platforms?: string[];
  default_report_type_id?: string | null;
  default_report_type_label?: string | null;
}

export interface ReportObjectiveOption {
  id: string;
  title: string;
  objective: string;
  recommended?: boolean;
  in_template?: boolean;
  report_type?: string | null;
  os_filter?: string[];
  evidence_questions?: string[];
  procedure?: string | null;
  procedure_text?: string | null;
  domain?: string | null;
}

export interface CustomObjectiveInput {
  title: string;
  objective: string;
  procedure?: string | string[] | null;
}

export interface ReportStartPayload {
  report_type?: string;
  objective_ids?: string[] | null;
  custom_objectives?: CustomObjectiveInput[] | null;
  case_meta?: Record<string, unknown> | null;
  recreate?: boolean;
}

export interface ReportSection {
  id: string;
  job_id: string;
  section_key: string;
  structured_json: Record<string, unknown> | null;
  narrative_content: string | null;
  citations: unknown[] | null;
  section_confidence: number | null;
  verification_status: string;
  conflicts: unknown[] | null;
  generator_meta: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

export interface ReportSectionPatch {
  structured_json?: Record<string, unknown> | null;
  narrative_content?: string | null;
  citations?: unknown[] | null;
  verification_status?: string | null;
}

export interface ReportGate {
  cleared: boolean;
  pending: string[];
  needs_review: string[];
  missing_required: string[];
  sections_completed?: number;
  sections_total?: number;
  run_status?: string;
}

export interface HumanFeedback {
  id: string;
  job_id: string;
  section_key: string | null;
  artifact_id: string | null;
  feedback_type: string;
  content: string | null;
  created_by: string | null;
  created_at: string;
}

export interface ReportExport {
  id: string;
  case_id?: string | null;
  job_id: string | null;
  report_run_id?: string | null;
  format: string;
  template?: string | null;
  created_by?: string | null;
  manifest_uri?: string | null;
  sha256: string | null;
  run_status?: string | null;
  run_started_at?: string | null;
  created_at: string;
}

export interface Case {
  id: string;
  job_id: string | null;
  number: string | null;
  title: string | null;
  status: string;
  classification: string | null;
  timezone: string;
  owner_id: string | null;
  authorization_notes: string | null;
  created_at: string;
}

export interface GapMergeCandidate extends Case {
  day_label: "today" | "yesterday" | string;
  has_gap_site?: boolean;
  gap_details?: {
    client_name?: string | null;
    branch_locations?: string | null;
    contact_person?: string | null;
    date_of_visit?: string | null;
    author?: string | null;
    document_version?: string | null;
    num_endpoints?: string | null;
    geographic_locations?: string | null;
  };
}

export interface CaseList {
  items: Case[];
  total: number;
  page: number;
  page_size: number;
}

export interface CaseCreate {
  title?: string | null;
  number?: string | null;
  job_id?: string | null;
  classification?: string | null;
  timezone?: string;
}

export interface CaseUpdate {
  title?: string | null;
  number?: string | null;
  status?: "open" | "closed" | "archived";
  classification?: string | null;
  timezone?: string | null;
  authorization_notes?: string | null;
}

export interface CaseMember {
  case_id: string;
  user_id: string;
  role: string;
}

export interface ChainOfCustodyEntry {
  id: string;
  case_id: string | null;
  evidence_id: string | null;
  handler: string | null;
  action: string;
  reason: string | null;
  location: string | null;
  hash_confirmed: boolean;
  timestamp: string;
}

export interface AuditEvent {
  id: string;
  case_id: string | null;
  user_id: string | null;
  action: string;
  object_type: string | null;
  object_id: string | null;
  request_id: string | null;
  details_json: Record<string, unknown> | null;
  timestamp: string;
}

export interface AuditList {
  items: AuditEvent[];
  total: number;
  page: number;
  page_size: number;
}

export interface ReportStreamEvent {
  event: "progress" | "done" | "section" | "error";
  data: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Live mobile acquisition (UFED 4PC reference architecture)
// ---------------------------------------------------------------------------

export type CollectionMethod =
  | "sim"
  | "memory_card"
  | "logical"
  | "backup"
  | "advanced_logical"
  | "file_system"
  | "full_file_system"
  | "physical";

export interface AcquisitionAdapter {
  name: string;
  os_family: string;
  available: boolean;
  reason: string;
}

export interface AcquisitionAdapterList {
  adapters: AcquisitionAdapter[];
}

export interface DetectedDevice {
  adapter: string;
  device_id: string;
  os_family: string;
  label?: string;
  status?: string;
  connection?: string;
  instance_id?: string;
  attach_host?: string;
}

export interface DetectedDeviceList {
  devices: DetectedDevice[];
  warnings: string[];
  device_count: number;
  host_helper_reachable?: boolean;
  adapters?: AcquisitionAdapter[];
}

export interface AcquisitionDeviceProfile {
  manufacturer: string;
  model: string;
  device_label: string;
  chipset: string;
  serial: string;
  imei: string;
  udid: string;
  os_family: string;
  os_version: string;
  security_patch_level: string;
  build_id: string;
  lock_state: string;
  encryption_state: string;
  connection_mode: string;
  usb_debugging_authorized: boolean;
  pairing_trusted: boolean;
  developer_mode: boolean;
  rooted_or_jailbroken: boolean | null;
  battery_percent: number | null;
  network_isolated: boolean | null;
  sim_present: boolean | null;
  iccid: string;
  imsi: string;
  sd_card_present: boolean | null;
  sd_card_identifier: string;
  tool_version: string;
  license_entitlements: string[];
  required_cable: string;
  unknown_fields: string[];
  observations: string[];
}

export interface AcquisitionCapability {
  capability_label: string;
  supported_methods: CollectionMethod[];
  blocked_methods: Record<string, string>;
  warnings: string[];
  preparation_steps: string[];
}

export interface MethodCoverage {
  method: string;
  meaning: string;
  coverage: string;
  limitations: string;
  deleted_data: string;
  mandatory_caveat: string;
}

export interface AcquisitionPreview {
  ok: boolean;
  device_profile: AcquisitionDeviceProfile;
  capability: AcquisitionCapability;
  preparation_steps: string[];
  method_profiles: Record<string, MethodCoverage>;
}

export interface MethodDecision {
  selected: CollectionMethod | null;
  considered: CollectionMethod[];
  rejected: Record<string, string>;
  rationale: string;
  deeper_available: CollectionMethod[];
}

export interface AcquisitionVerification {
  ok: boolean;
  verified: number;
  mismatched?: string[];
  missing?: string[];
  unexpected?: string[];
  interpretation?: string;
}

export interface AcquisitionResult {
  ok: boolean;
  run_name: string;
  stage_reached: string;
  paths?: Record<string, string>;
  device_profile?: AcquisitionDeviceProfile;
  capability?: AcquisitionCapability;
  method_decision?: MethodDecision;
  preparation_steps?: string[];
  evidence_package?: {
    run_name: string;
    extraction_data: string[];
    collection_log: string | null;
    collection_summary: string | null;
    hash_manifest: string | null;
    complete: boolean;
    [key: string]: unknown;
  };
  acquisition_record?: AcquisitionRecordFields & { output_size?: number; missing_fields?: string[] };
  verification?: AcquisitionVerification;
  coverage_statement?: MethodCoverage;
  limitations?: string[];
  warnings?: string[];
  errors?: string[];
  error?: string;
  audit?: { path: string; event_count: number; by_severity: Record<string, number> };
  chain_of_custody?: CustodyLink[];
}

export interface AcquisitionRecordFields {
  case_id: string;
  evidence_id: string;
  examiner: string;
  legal_authority: string;
  device_make_model: string;
  serial_imei: string;
  collection_method: string;
  start_time: string;
  end_time: string;
  output_path: string;
  output_size: number;
  hash_integrity_value: string;
  warnings_errors: string[];
  missing_fields: string[];
  record_complete: boolean;
  [key: string]: unknown;
}

export interface CustodyLink {
  stage: string;
  actor: string;
  detail: string;
  location: string;
  timestamp_utc: string;
}

export interface AcquisitionStartPayload {
  adapter: string;
  device_id: string;
  case_id: string;
  evidence_id: string;
  legal_authority: string;
  case_root: string;
  objective_methods?: string[];
  authorized_methods?: string[];
  method_override?: string | null;
  cable_adapter_asset_id?: string;
  license_endpoint_id?: string;
  backup_password?: string | null;
  examiner_notes?: string;
  device_condition?: string;
  network_isolated?: boolean | null;
  create_working_copy?: boolean;
  /** Optional IMAP cloud mailboxes (Gmail/Outlook app passwords). */
  cloud_mailboxes?: Array<{
    provider: string;
    address: string;
    secret?: string;
    password?: string;
    app_password?: string;
    host?: string;
    port?: number;
  }>;
}

export interface AcquisitionProgress {
  stage: string;
  item: string;
  detail?: string;
  category?: string;
  bytes_done: number;
  bytes_total: number | null;
  progress_pct: number | null;
  /** ``bytes`` when adapter reported a total; ``estimated`` from stage + volume. */
  progress_mode?: "bytes" | "estimated";
  files_seen: number;
  output_path?: string;
  media_path?: string;
  case_path?: string;
  updated_utc: string;
}

export type AcquisitionRunStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export interface AcquisitionRunSummary {
  run_id: string;
  run_name: string;
  case_id: string;
  evidence_id: string;
  adapter: string;
  device_id: string;
  examiner: string;
  status: AcquisitionRunStatus;
  started_utc: string;
  ended_utc: string | null;
  cancel_requested: boolean;
  progress: AcquisitionProgress;
  error: string | null;
  recovered?: boolean;
  /** Present when this run is a Windows host-helper USB job, not an in-memory Docker run. */
  host_job?: boolean;
  host_job_id?: string;
}

export interface AcquisitionRunDetail extends AcquisitionRunSummary {
  result: AcquisitionResult | null;
}

export interface AcquisitionRunList {
  runs: AcquisitionRunSummary[];
  active_count: number;
}

export interface PriorityEvidenceRecord {
  artifact_id: string; job_artifact_id: string | null; artifact_type: string; state: string;
  timestamp_utc: string | null; data: Record<string, unknown>; forensic: Record<string, unknown>;
  linked_media: { id: string; file_path: string; sha256: string | null; match_basis: string }[];
}
export interface PriorityEvidencePage {
  items: PriorityEvidenceRecord[]; total: number; page: number; families: Record<string, number>;
}
export interface MediaObservationFrame {
  description: string; timestamp_seconds: number | null; frame_sha256: string;
  model: string; signals: { category: string; detail: string; method: string }[];
}
export interface MediaObservation {
  job_artifact_id: string; source_path: string; source_sha256: string; media_kind: string;
  description: string; status: string; flagged: boolean; error: string | null;
  details: { frames?: MediaObservationFrame[]; coverage?: { mode: string; interval_seconds?: number; all_frames_reviewed: boolean; budget_limited?: boolean }; ocr_signals?: { category: string; detail: string; method: string }[] };
}
export interface MediaObservationsPage {
  items: MediaObservation[]; total: number; page: number; reviewed: number; failed: number;
}

export interface SuspiciousActivityCard {
  id: string; job_id: string; job_artifact_id: string | null; category: string;
  source_record_id: string; source_path: string; source_sha256: string | null; timestamp_utc: string | null;
  explanation: string; excerpt?: string; method: string; model?: string; frame_index?: number;
  frame_sha256?: string; timestamp_seconds?: number | null;
  data?: { explanation: string; excerpt?: string; method: string; model?: string; frame_index?: number; frame_sha256?: string; timestamp_seconds?: number | null };
}
export interface SuspiciousActivityPage { items: SuspiciousActivityCard[]; total: number; page: number; note: string }
