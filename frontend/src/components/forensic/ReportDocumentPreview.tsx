import clsx from "clsx";
import { useState, type ReactNode } from "react";

import { stripAxiomBranding } from "../../lib/displayText";
import { A4_PAGE_CLASS, REPORT_FOOTER_SRC, REPORT_HEADER_SRC } from "../../lib/reportA4";
import {
  OPO_PAGE_UNITS,
  TABLE_GAP_UNITS,
  TABLE_PAGE_UNITS,
  artifactItemUnits,
  isNarrativeHeading,
  packAnnexureTables,
  pageVisualCost,
  paginateArtifactItemCosts,
  paginateNarrativeLines,
  paginateOpoCards,
  tableChunkUnits,
  takeOpoCardPrefix,
  visualNarrativeLines,
} from "../../lib/reportPagination";
import { parseMarkdownTables, plainNarrativeLines } from "../../lib/reportTextDiff";
import { EditableReportBody, HumanEditText, ReportEditProvider } from "./ReportEditContext";
import { ReportSectionReview } from "./ReportSectionReview";
import { EvidenceFrame } from "./EvidenceFrame";
import type { SuspiciousActivityCard } from "../../lib/types/forensic";
import type { ReportSection } from "../../lib/types/forensic";

interface AnnexureTable {
  title?: string;
  columns?: string[];
  rows?: string[][];
  continued?: boolean;
  note?: string;
}

type ArtifactGroup = {
  title?: string;
  subcategories?: Array<{ name?: string; usage_count?: number; count?: number; description?: string }>;
};

type ArtifactPageGroup = { group: ArtifactGroup; gi: number; startIndex: number; continued: boolean };

export const REPORT_SECTION_ORDER = [
  "cover_page",
  "table_of_contents",
  "introduction",
  "scope_of_work",
  "tools_used",
  "forensic_imaging",
  "os_information",
  "user_profile_information",
  "artifact_summary",
  "objectives_procedure_observation",
  "suspicious_activity",
  "annexure",
  "final_analysis_summary",
  "appendix",
];

/** Disk page layout with mobile facts in the acquisition and OS positions. */
export const MOBILE_REPORT_SECTION_ORDER = REPORT_SECTION_ORDER.map(key =>
  key === "forensic_imaging" ? "extraction_summary" : key === "os_information" ? "device_information" : key);

export function isMobileReportSections(sections: ReportSection[]): boolean {
  if (sections.some(section => section.section_key === "cover_page" &&
    (section.structured_json?.report_variant === "mobile" || /MOBILE FORENSIC ANALYSIS REPORT/i.test(section.narrative_content ?? "")))) return true;
  const keys = new Set(sections.map(s => s.section_key));
  return keys.has("device_information") && keys.has("extraction_summary") && !keys.has("forensic_imaging");
}

const HIDDEN_REPORT_SECTIONS = new Set(["limitations", "evidence_details"]);

const REPORT_WATERMARK_SRC = "/report/watermark.png";
const REPORT_CONFIDENTIAL_SRC = "/report/confidential-stamp.png";

const DISPLAY_CONTROL_RE = /[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060\ufeff]/g;
const DATEISH_CELL_RE = /^\s*\d{1,4}[/-]\d{1,2}[/-]\d{1,4}(?:\s+\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM)?)?\s*$/i;

function cleanDisplayText(value: unknown): string {
  return String(value ?? "").replace(DISPLAY_CONTROL_RE, "");
}

function displayArtifactGroupTitle(title?: string): string {
  const clean = cleanDisplayText(title).trim();
  if (clean === "Application Usage") return "Application Usages";
  return clean;
}

function wrapFriendlyCell(text: string): string {
  const raw = cleanDisplayText(text);
  const shouldWrap =
    !DATEISH_CELL_RE.test(raw) &&
    (/^https?:\/\//i.test(raw) || /^www\./i.test(raw) || /^[A-Za-z]:[\\/]/.test(raw) || raw.includes("\\") || (raw.split("/").length > 4 && /[A-Za-z]/.test(raw)));
  if (shouldWrap) {
    return raw.replace(/([/?&=._-])/g, "$1\u200b");
  }
  return raw;
}


function coverFromMarkdown(content: string): Record<string, string> {
  const lines = content
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
  let title = "CYBER FORENSIC ANALYSIS REPORT";
  let subject = "";
  let company = "";
  for (const line of lines) {
    if (line.startsWith("# ")) title = line.slice(2).trim();
    else if (line.startsWith("**") && line.endsWith("**")) {
      subject = line.slice(2, -2).replace(/^"|"$/g, "").trim();
    } else if (!line.startsWith("#") && !line.startsWith("|") && !line.startsWith("*")) {
      company = line.replace(/\*\*/g, "").trim();
    }
  }
  return { title, subject, company };
}

function catalogHasItems(catalog: { sections?: ArtifactGroup[] } | null | undefined): boolean {
  return Boolean(catalog?.sections?.some((section) => (section.subcategories ?? []).length > 0));
}

function artifactCatalogFromStructured(structured: Record<string, unknown>): { sections?: ArtifactGroup[] } | null {
  const catalog = structured.catalog as { sections?: ArtifactGroup[] } | undefined;
  if (catalogHasItems(catalog)) return catalog ?? null;
  const categories = structured.categories as
    | Array<{ title?: string; items?: Array<{ label?: string; count?: number; description?: string }> }>
    | undefined;
  if (!categories?.length) return null;
  return {
    sections: categories.map((cat) => ({
      title: cat.title,
      subcategories: (cat.items ?? []).map((item) => ({
        name: item.label,
        count: item.count,
        usage_count: item.count,
        description: item.description,
      })),
    })),
  };
}

/** Rebuild the previous B. ARTIFACTS panel from Report Agent markdown when structured catalog is empty. */
export function artifactCatalogFromMarkdown(content: string): { sections?: ArtifactGroup[] } | null {
  const text = content.replace(/\r\n/g, "\n");
  if (!text.trim() || /Re-run Recreate after extraction/i.test(text)) return null;
  const sections: ArtifactGroup[] = [];
  let current: ArtifactGroup | null = null;
  let pending: { name?: string; count?: number; description?: string } | null = null;

  const flushItem = () => {
    if (!current || !pending?.name) return;
    current.subcategories = current.subcategories ?? [];
    current.subcategories.push({
      name: pending.name,
      count: pending.count ?? 0,
      usage_count: pending.count ?? 0,
      description: pending.description,
    });
    pending = null;
  };

  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const group = line.match(/^#{1,3}\s*(?:\d+\.\s*)?(.+?)\s*:?\s*$/);
    const namedItem = line.match(/^(?:\d+\.\s*)\*\*(.+?)\*\*\s*$/) || line.match(/^\d+\.\s+(.+)$/);
    const count = line.match(/^\*{0,2}Count:\*{0,2}\s*(.+)$/i);
    const desc = line.match(/^\*{0,2}Description:\*{0,2}\s*(.*)$/i);
    if (group && !/^(?:[A-Z]\.\s*)?ARTIFACTS$/i.test(group[1] ?? "")) {
      flushItem();
      if (current) sections.push(current);
      current = { title: (group[1] ?? "Artifacts").replace(/:$/, "").trim(), subcategories: [] };
      continue;
    }
    if (namedItem && current) {
      flushItem();
      pending = { name: (namedItem[1] ?? "").replace(/\*\*/g, "").trim() };
      continue;
    }
    if (count && pending) {
      const parsed = parseInt(String(count[1]).replace(/,/g, ""), 10);
      pending.count = Number.isFinite(parsed) ? parsed : 0;
      continue;
    }
    if (desc && pending) {
      pending.description = desc[1].trim();
    }
  }
  flushItem();
  if (current) sections.push(current);
  return catalogHasItems({ sections }) ? { sections } : null;
}

/** Enrich section with parsed markdown tables / catalog when structured_json is sparse. */
export function enhanceSectionForPreview(section: ReportSection): ReportSection {
  const sj: Record<string, unknown> = { ...(section.structured_json ?? {}) };
  const narrative = section.narrative_content ?? "";

  const parsed = parseMarkdownTables(narrative);
  const existingTables = Array.isArray(sj.tables) ? (sj.tables as AnnexureTable[]) : [];
  const parsedRows = parsed.reduce((sum, table) => sum + table.rows.length, 0);
  const existingRows = existingTables.reduce((sum, table) => sum + (table.rows?.length ?? 0), 0);
  const humanEdited = Boolean(sj.human_edit_baseline);
  if (parsed.length > 0 && (existingTables.length === 0 || humanEdited || parsedRows >= existingRows)) {
    sj.tables = parsed.map((table) => {
      const note = existingTables.find(
        (prev) => (prev.title ?? "").replace(/\s*\(\s*continued\s*\)\s*$/i, "") === (table.title ?? "").replace(/\s*\(\s*continued\s*\)\s*$/i, ""),
      )?.note;
      return {
        title: table.title,
        columns: table.columns,
        rows: table.rows,
        continued: table.continued,
        note,
      };
    });
  }

  if (section.section_key === "artifact_summary") {
    const catalog = artifactCatalogFromStructured(sj) ?? artifactCatalogFromMarkdown(narrative);
    if (catalogHasItems(catalog)) sj.catalog = catalog;
  }

  if (section.section_key === "cover_page" && !sj.title) {
    Object.assign(sj, coverFromMarkdown(narrative));
  }

  return { ...section, structured_json: Object.keys(sj).length ? sj : section.structured_json };
}

function sectionOrderForSections(sections: ReportSection[]): string[] {
  if (isMobileReportSections(sections)) {
    return MOBILE_REPORT_SECTION_ORDER;
  }
  return REPORT_SECTION_ORDER;
}

export function isVisibleReportSection(section: ReportSection, sections?: ReportSection[]): boolean {
  const order = sectionOrderForSections(sections ?? [section]);
  if (HIDDEN_REPORT_SECTIONS.has(section.section_key)) return false;
  if (!order.includes(section.section_key)) {
    const meta = (section.generator_meta ?? {}) as Record<string, unknown>;
    const structured = (section.structured_json ?? {}) as Record<string, unknown>;
    if (meta.objective_id || structured.section) return false;
  }
  return order.includes(section.section_key);
}

export function orderReportSections(sections: ReportSection[]): ReportSection[] {
  const order = sectionOrderForSections(sections);
  const rank = (key: string) => {
    const i = order.indexOf(key);
    return i === -1 ? order.length : i;
  };
  return [...sections].filter((s) => isVisibleReportSection(s, sections)).sort((a, b) => rank(a.section_key) - rank(b.section_key));
}

const REPORT_TOC_ROWS: Array<{ key: string; label: string }> = [
  { key: "introduction", label: "INTRODUCTION" },
  { key: "scope_of_work", label: "SCOPE OF WORK" },
  { key: "tools_used", label: "TOOLS USED" },
  { key: "forensic_imaging", label: "FORENSIC IMAGING" },
  { key: "os_information", label: "A. OPERATING SYSTEM" },
  { key: "user_profile_information", label: "A. OPERATING SYSTEM — User Profile" },
  { key: "artifact_summary", label: "B. ARTIFACTS" },
  { key: "objectives_procedure_observation", label: "C. OBJECTIVE, PROCEDURE & OBSERVATION" },
  { key: "suspicious_activity", label: "SUSPICIOUS ACTIVITY" },
  { key: "annexure", label: "D. ANNEXURE" },
  { key: "final_analysis_summary", label: "E. ANALYSIS SUMMARY" },
  { key: "appendix", label: "F. APPENDIX" },
];

export function computeSectionPageStarts(sections: ReportSection[]): Map<string, number> {
  const ordered = orderReportSections(sections);
  const starts = new Map<string, number>();
  let page = 1;
  for (const section of ordered) {
    starts.set(section.section_key, page);
    page += countPreviewPages(section);
  }
  return starts;
}

function TableOfContentsPreview({ sections }: { sections: ReportSection[] }) {
  const pageStarts = computeSectionPageStarts(sections);
  const mobile = isMobileReportSections(sections);
  const rows = (mobile ? REPORT_TOC_ROWS.map(row => row.key === "forensic_imaging" ? {key: "extraction_summary", label: "EXTRACTION SUMMARY"} : row.key === "os_information" ? {key: "device_information", label: "DEVICE INFORMATION"} : row.key === "user_profile_information" ? {...row,label:"A. DEVICE USER PROFILES"} : row) : REPORT_TOC_ROWS).filter(
    (row) => !HIDDEN_REPORT_SECTIONS.has(row.key),
  );
  return (
    <div className="mt-2">
      <table className="w-full border-0 border-collapse text-[13px] leading-snug">
        <thead>
          <tr className="bg-white text-left text-[12px] font-bold uppercase tracking-wide text-[#082c5c]">
            <th className="w-[72px] border-0 px-3 py-2 font-bold">Sr No</th>
            <th className="border-0 px-3 py-2 font-bold">Description</th>
            <th className="w-[88px] border-0 px-3 py-2 text-right font-bold">Page</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, idx) => (
            <tr key={row.key} className={idx % 2 === 0 ? "bg-[#f3f4f6]" : "bg-white"}>
              <td className="border-0 px-3 py-2.5 align-top font-semibold text-[#111827]">{idx + 1}</td>
              <td className="border-0 px-3 py-2.5 align-top text-[#111827]">{row.label}</td>
              <td className="border-0 px-3 py-2.5 text-right align-top font-semibold tabular-nums text-[#111827]">
                {pageStarts.get(row.key) ?? "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-4 text-[11px] italic text-ink-500">Page numbers follow the live report preview layout.</p>
    </div>
  );
}

function escapeHeadingText(text: string): string {
  return text.replace(/^#{1,6}\s*/, "").replace(/\*\*/g, "").trim();
}

function visibleSectionTitle(section: ReportSection, allSections?: ReportSection[]): string {
  const mobile = allSections ? isMobileReportSections(allSections) : false;
  switch (section.section_key) {
    case "cover_page":
      return mobile ? "MOBILE FORENSIC ANALYSIS REPORT" : "CYBER FORENSIC ANALYSIS REPORT";
    case "table_of_contents":
      return "TABLE OF CONTENTS";
    case "introduction":
      return "INTRODUCTION";
    case "scope_of_work":
      return "SCOPE OF WORK";
    case "tools_used":
      return "TOOLS USED FOR ACQUISITION AND EXTRACTION";
    case "forensic_imaging":
      return "FORENSIC IMAGING";
    case "evidence_details":
      return "EVIDENCE DETAILS";
    case "device_information":
      return "DEVICE INFORMATION";
    case "extraction_summary":
      return "EXTRACTION SUMMARY";
    case "os_information":
      return "A. OPERATING SYSTEM";
    case "user_profile_information":
      return mobile ? "A. DEVICE USER PROFILES" : "A. OPERATING SYSTEM (continued)";
    case "artifact_summary":
      return "B. ARTIFACTS";
    case "objectives_procedure_observation":
      return mobile ? "C. OBJECTIVE, PROCEDURE & OBSERVATION" : "C. OBJECTIVE, PROCEDURE & OBSERVATION";
    case "annexure":
      return "D. ANNEXURE";
    case "final_analysis_summary":
      return "E. ANALYSIS SUMMARY";
    case "appendix":
      return "F. APPENDIX";
    default:
      return section.section_key.replace(/_/g, " ").toUpperCase();
  }
}

function narrativeLines(section: ReportSection): string[] {
  // Annexure tables already carry titles + notes — do not echo markdown previews as italic text.
  if (section.section_key === "annexure") {
    const tables = (section.structured_json?.tables ?? []) as AnnexureTable[];
    if (tables.some((t) => (t.columns?.length ?? 0) > 0)) {
      return [];
    }
  }
  const title = visibleSectionTitle(section).toLowerCase();
  const suppressed = new Set(["target drive details"]);
  const resume = new Set(["terms and condition", "terms and conditions", "digital forensic analyst"]);
  const out: string[] = [];
  let skipping = false;
  for (const raw of (section.narrative_content ?? "").split("\n")) {
    let line = stripAxiomBranding(escapeHeadingText(raw.trim()).replace(/^[-•]\s*/, "").trim());
    if (!line || line.startsWith("|")) continue;
    // Drop standalone italic preview notes (e.g. *Preview — 15 sample URL(s)…*)
    if (/^\*[^*].*\*$/.test(line) || /^preview\s*[—–-]/.test(line.replace(/^\*|\*$/g, "").trim())) {
      continue;
    }
    const key = line.replace(/:$/, "").toLowerCase();
    if (suppressed.has(key)) {
      skipping = true;
      continue;
    }
    if (skipping) {
      if (resume.has(key) || /^[A-F]\.\s/.test(line)) skipping = false;
      else continue;
    }
    if (line && line.toLowerCase() !== title) out.push(line);
  }
  return out;
}

function sectionTables(section: ReportSection): AnnexureTable[] {
  return ((section.structured_json?.tables ?? []) as AnnexureTable[])
    .filter((table) => (table.columns?.length ?? 0) > 0)
    .filter(
      (table) =>
        !(section.section_key === "forensic_imaging" && String(table.title ?? "").trim().toLowerCase() === "target drive details"),
    );
}

type SectionPage = { lines: string[]; tables: AnnexureTable[] };

/** Keep narrative and tables above the letterhead footer; leftover body pulls the next rows. */
function paginateSectionContent(section: ReportSection): SectionPage[] {
  const lines = narrativeLines(section);
  const tables = sectionTables(section);
  const narrativePages = paginateNarrativeLines(lines);
  const packed = packAnnexureTables(tables, TABLE_PAGE_UNITS);

  if (!narrativePages.length && !packed.length) {
    return [{ lines, tables: [] }];
  }
  if (!narrativePages.length) {
    return packed.map((tablePage) => ({ lines: [], tables: tablePage }));
  }
  if (!packed.length) {
    return narrativePages.map((pageLines) => ({ lines: pageLines, tables: [] }));
  }

  const pages: SectionPage[] = narrativePages.map((pageLines) => ({
    lines: pageLines,
    tables: [] as AnnexureTable[],
  }));
  const last = pages[pages.length - 1];
  const leftover = TABLE_PAGE_UNITS - pageVisualCost(last.lines);
  const firstCost = packed[0].reduce(
    (n, chunk, idx) => n + (idx ? TABLE_GAP_UNITS : 0) + tableChunkUnits(chunk),
    0,
  );
  if (firstCost <= leftover) {
    last.tables.push(...packed.shift()!);
  }
  for (const tablePage of packed) {
    pages.push({ lines: [], tables: tablePage });
  }
  return pages.filter((page) => page.lines.length || page.tables.length);
}

function OneStructuredTable({ table }: { table: AnnexureTable }) {
  return (
    <div className="mt-3 break-inside-avoid overflow-visible">
      {table.title && (
        <h4 className="mb-2 text-[14px] font-black uppercase tracking-wide text-[#103b63]">
          {table.title}
          {table.continued ? " (continued)" : ""}
        </h4>
      )}
      {table.note && !table.continued && (
        <p className="mb-2 text-[12px] italic text-ink-600">{table.note}</p>
      )}
      <table className="w-full table-fixed border-collapse text-[11.5px] leading-snug [break-inside:auto]">
        <thead>
          <tr className="bg-[#ffc000] text-black">
            {(table.columns ?? []).map((col) => (
              <th
                key={col}
                className="break-words border border-black px-2 py-2 text-center font-bold [overflow-wrap:break-word] [word-break:break-word]"
              >
                {col}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {(table.rows ?? []).map((row, ri) => (
            <tr key={ri} className={clsx("[break-inside:avoid] [page-break-inside:avoid]", ri % 2 === 0 ? "bg-[#d9e2f3]" : "bg-white")}>
              {(table.columns ?? []).map((_, ci) => (
                <td key={ci} className="border border-black px-2 py-2 align-top [overflow-wrap:break-word] [word-break:break-word]">
                  {wrapFriendlyCell(row[ci] ?? "")}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SectionContentPage({
  sectionTitle,
  pageNo,
  actions,
  lines,
  pages,
}: {
  sectionTitle: string;
  pageNo?: number;
  actions?: ReactNode;
  lines: string[];
  pages: AnnexureTable[];
}) {
  return (
    <ReportPageFrame title={sectionTitle} pageNo={pageNo} actions={actions}>
      <NarrativeBlock lines={lines} />
      {pages.map((tablePage, idx) => (
        <OneStructuredTable key={`${tablePage.title ?? "table"}-${idx}`} table={tablePage} />
      ))}
    </ReportPageFrame>
  );
}

function NarrativeBlock({ lines, limit }: { lines: string[]; limit?: number }) {
  const visible = limit != null ? lines.slice(0, limit) : lines;
  if (visible.length === 0) return null;
  return (
    <div className="mt-4 space-y-2 text-[13px] leading-relaxed text-black">
      {visible.map((line, li) =>
        /^(Objective|Procedure|Observation|Status):?$/i.test(line) ? (
          <p key={li} className="mt-3 font-bold">
            <HumanEditText text={line.replace(/:?$/, ":")} />
          </p>
        ) : /^\d+\.\s/.test(line) ? (
          <p key={li} className="font-bold">
            <HumanEditText text={line} />
          </p>
        ) : (
          <p key={li}>
            <HumanEditText text={line} />
          </p>
        ),
      )}
    </div>
  );
}

function PaginatedTablesPreview({
  section,
  pageStart = 1,
  actions,
}: {
  section: ReportSection;
  pageStart?: number;
  actions?: ReactNode;
}) {
  const pages = paginateSectionContent(section);
  const sectionTitle = visibleSectionTitle(section);

  return (
    <>
      {pages.map((page, idx) => (
        <SectionContentPage
          key={`${section.section_key}-${idx}`}
          sectionTitle={idx === 0 ? sectionTitle : `${sectionTitle} (continued)`}
          pageNo={pageStart + idx}
          actions={idx === pages.length - 1 ? actions : undefined}
          lines={page.lines}
          pages={page.tables}
        />
      ))}
    </>
  );
}

function paginateArtifactGroups(catalog?: { sections?: ArtifactGroup[] }): ArtifactPageGroup[][] {
  const groups = catalog?.sections ?? [];
  const packed = paginateArtifactItemCosts(
    groups.map((group) =>
      (group.subcategories ?? []).map((sub) => artifactItemUnits(sub.description, sub.name)),
    ),
  );
  return packed.map((page) =>
    page.map((chunk) => {
      const group = groups[chunk.groupIndex];
      const subs = (group?.subcategories ?? []).slice(chunk.startIndex, chunk.startIndex + chunk.itemCount);
      return {
        group: { ...(group as ArtifactGroup), subcategories: subs },
        gi: chunk.groupIndex,
        startIndex: chunk.startIndex,
        continued: chunk.continued,
      };
    }),
  );
}

function ArtifactGroupPanel({
  group,
  gi,
  startIndex = 0,
  continued = false,
}: {
  group: ArtifactGroup;
  gi: number;
  startIndex?: number;
  continued?: boolean;
}) {
  const subs = group.subcategories ?? [];
  return (
    <section className="mb-4 last:mb-0">
      <h3 className="mb-2.5 text-[15pt] font-black leading-tight text-[#2f6fb2]">
        {gi + 1}. {displayArtifactGroupTitle(group.title ?? "")}:{continued ? " (continued)" : ""}
      </h3>
      <div className="space-y-3.5 pl-4">
        {subs.map((sub, localIdx) => {
          const count = sub.usage_count ?? sub.count ?? 0;
          const description = cleanDisplayText(sub.description ?? "Artifacts examined during forensic review.");
          return (
            <div key={`${sub.name}-${startIndex + localIdx}`} className="artifact-entry">
              <p className="text-[11pt] font-bold leading-[1.4] text-black">
                {startIndex + localIdx + 1}. {cleanDisplayText(sub.name)}
              </p>
              <p className="text-[11pt] font-bold leading-[1.4] text-black">
                Count: {count < 0 ? "Reviewed" : count}
              </p>
              <p className="text-[11pt] leading-[1.4] text-black">
                <span className="font-bold">Description:</span> {description}
              </p>
            </div>
          );
        })}
      </div>
    </section>
  );
}


function ArtifactReportPages({
  section,
  pageStart = 1,
  actions,
}: {
  section: ReportSection;
  pageStart?: number;
  actions?: ReactNode;
}) {
  const catalog = section.structured_json?.catalog as { sections?: ArtifactGroup[] } | undefined;
  if (!catalog?.sections?.length) {
    return (
      <ReportPageFrame title={visibleSectionTitle(section)} pageNo={pageStart} actions={actions}>
        <NarrativePreview section={section} />
      </ReportPageFrame>
    );
  }
  const pages = paginateArtifactGroups(catalog);
  return (
    <>
      {pages.map((pageGroups, idx) => (
        <ReportPageFrame
          key={`artifact-page-${idx}`}
          title={idx === 0 ? visibleSectionTitle(section) : "B. ARTIFACTS"}
          pageNo={pageStart + idx}
          actions={actions}
        >
          {pageGroups.map((page) => (
            <ArtifactGroupPanel
              key={`${page.group.title}-${page.startIndex}`}
              group={page.group}
              gi={page.gi}
              startIndex={page.startIndex}
              continued={page.continued}
            />
          ))}
        </ReportPageFrame>
      ))}
    </>
  );
}

function isOpoDeviceLine(line: string): boolean {
  const plain = line
    .replace(/^#{1,6}\s*/, "")
    .replace(/^(?:\*\*|__)|(?:\*\*|__)$/g, "")
    .replace(/^[-•]\s*/, "")
    .trim();
  // Section C is a list of examination questions, not a device-banner area. Legacy
  // reports sometimes inserted "Laptop [1]" / "Desktop [1]" between the section
  // heading and objective 1; suppress those labels in every preview/re-export.
  if (/^(?:laptop|desktop|computer|device)(?:\s*\[\d+\])?$/i.test(plain)) return true;
  if (/^ex-\d+$/i.test(plain)) return true;
  if (/\b\d+\s*gb\b/i.test(plain) && /histotech|desktop|laptop|ex-/i.test(plain)) return true;
  return false;
}

function isOpoLabel(line: string, name: "objective" | "procedure" | "observation"): boolean {
  const plain = line.replace(/\*\*/g, "").replace(/:?$/, "").trim().toLowerCase();
  if (plain === name || plain === `${name}s`) return true;
  // Mobile single-block headings: "1. Objective", "2. Procedure", "3. Observations"
  if (name === "objective") return /^\d+\.\s*objective\s*$/i.test(plain);
  if (name === "procedure") return /^\d+\.\s*procedure\s*$/i.test(plain);
  return /^\d+\.\s*observations?\s*$/i.test(plain);
}

/** Mobile template uses ### 1. Objective / ### 2. Procedure / ### 3. Observations — keep as one block. */
function isMobileSingleOpoMarkdown(raw: string): boolean {
  if (!/###\s*1\.\s*Objective/i.test(raw) || !/###\s*2\.\s*Procedure/i.test(raw)) return false;
  // Disk reports use ### N. {catalog title} — never collapse those into one 3-part card.
  if (/###\s+\d+\.\s+(?!(Objective|Procedure|Observations?)\b)/i.test(raw)) return false;
  if (/###\s+[4-9]\./.test(raw) || /###\s+\d{2}\./.test(raw)) return false;
  return true;
}

type MobileOpoParsed = {
  objective: string[];
  procedure: string[];
  observations: string[];
};

function parseMobileOpoMarkdown(raw: string): MobileOpoParsed | null {
  if (!isMobileSingleOpoMarkdown(raw)) return null;
  const chunks = raw.split(/\n(?=###\s+\d+\.\s)/);
  const out: MobileOpoParsed = { objective: [], procedure: [], observations: [] };
  for (const chunk of chunks) {
    const lines = chunk
      .split("\n")
      .map((line) => stripAxiomBranding(escapeHeadingText(line.trim()).replace(/^[-•*]\s*/, "").trim()))
      .filter(
        (line) =>
          line &&
          !line.startsWith("|") &&
          !/^C\. OBJECTIVE/i.test(line) &&
          !/^OBJECTIVE,\s*OBSERVATION/i.test(line) &&
          !isOpoDeviceLine(line),
      );
    if (!lines.length) continue;
    const head = lines[0] ?? "";
    const body = lines.slice(1).filter(Boolean);
    if (isOpoLabel(head, "objective")) out.objective = body;
    else if (isOpoLabel(head, "procedure")) out.procedure = body;
    else if (isOpoLabel(head, "observation")) out.observations = body;
  }
  if (!out.objective.length && !out.procedure.length && !out.observations.length) return null;
  return out;
}

/** UI preview only — hide examiner playbook; keep a short how-we-checked list. */
function isHiddenProcedureDetailLine(line: string): boolean {
  const t = line.trim();
  if (!t) return false;
  if (/^axiom examination procedure/i.test(t)) return true;
  if (/^examination procedure:/i.test(t)) return true;
  if (/^primary evidence sources/i.test(t)) return true;
  if (/^search \/ rag hints/i.test(t)) return true;
  if (/^apply the axiom steps/i.test(t)) return true;
  if (/^\d+\.\s/.test(t)) return true;
  return false;
}

function isMobileOpoCard(card: string[]): boolean {
  const hasNumberedObjective = card.some((l) => /^\d+\.\s*objective\s*$/i.test(l.replace(/\*\*/g, "").replace(/:?$/, "").trim()));
  const hasNumberedProcedure = card.some((l) => /^\d+\.\s*procedure\s*$/i.test(l.replace(/\*\*/g, "").replace(/:?$/, "").trim()));
  return hasNumberedObjective && hasNumberedProcedure;
}

function observationLeaksTechnical(text: string): boolean {
  return /AppData|SoftwareDistribution|LocalCache|\bMSTeams\b|[A-Za-z]:\\|[/\\]Packages[/\\]|NTUSER|USBSTOR|AppxBlockMap|artifact[\s_]records?|(?:^|[\s(])(?:Users|Windows)\/[A-Za-z0-9._-]+|<\?xml|<BlockMap\b|xmlns=|schemas\.microsoft\.com\/appx|\[\s*\{\s*["']text["']\s*:|\b\d[\d,]*\s+(?:file|artifact record)\s+occurrences?\s*\(/i.test(
    text,
  );
}

const SAFE_FILE_ACCESS_OBSERVATION =
  "The files on the computer were used in a regular way. No files were deleted, renamed, or copied in a suspicious manner. Everything matched normal work activity.";

function sanitizeObservationLine(line: string, title: string): string {
  if (!observationLeaksTechnical(line)) return line;
  if (/file access/i.test(title)) return SAFE_FILE_ACCESS_OBSERVATION;
  return "Nothing matching this question was found on the computer. Nothing suspicious was found.";
}

function filterOpoCardForPreview(card: string[]): string[] {
  if (card.length === 0) return card;
  const mobileBlock = isMobileOpoCard(card);
  const out: string[] = [];
  let inProcedure = false;
  let inObservation = false;
  let seenApproach = false;
  let skipDuplicateBlock = false;
  let procedureBodyCount = 0;
  for (let i = 0; i < card.length; i++) {
    const line = card[i];
    if (i === 0) {
      out.push(line);
      continue;
    }
    if (isOpoLabel(line, "objective")) {
      inProcedure = false;
      inObservation = false;
      skipDuplicateBlock = false;
      out.push(line);
      continue;
    }
    if (isOpoLabel(line, "procedure")) {
      inProcedure = true;
      inObservation = false;
      skipDuplicateBlock = false;
      procedureBodyCount = 0;
      out.push(line);
      continue;
    }
    if (isOpoLabel(line, "observation")) {
      inProcedure = false;
      inObservation = true;
      skipDuplicateBlock = false;
      out.push(line);
      continue;
    }
    if (inObservation) {
      const safe = sanitizeObservationLine(line, card[0] ?? "");
      if (out[out.length - 1] !== safe) out.push(safe);
      continue;
    }
    if (inProcedure && !mobileBlock) {
      if (/^examination approach/i.test(line.trim())) {
        if (seenApproach) {
          skipDuplicateBlock = true;
          continue;
        }
        seenApproach = true;
        continue;
      }
      if (skipDuplicateBlock) continue;
      if (/^how to check/i.test(line.trim())) continue;
      if (isHiddenProcedureDetailLine(line)) continue;
      procedureBodyCount += 1;
      // Keep one short narrative plus a few check bullets — never the examiner playbook.
      if (procedureBodyCount > 6) continue;
    }
    out.push(line);
  }
  return out;
}

function opoCardsFromMarkdown(raw: string): string[][] | null {
  if (!/^###\s+\d+\./m.test(raw)) return null;
  // Mobile: never split ### 1/2/3 into separate A4 pages (avoids blank lead + CONTINUED pages).
  if (isMobileSingleOpoMarkdown(raw)) {
    const lines = raw
      .split("\n")
      .map((line) => stripAxiomBranding(escapeHeadingText(line.trim()).replace(/^[-•*]\s*/, "").trim()))
      .filter(
        (line) =>
          line &&
          !line.startsWith("|") &&
          !/^C\. OBJECTIVE/i.test(line) &&
          !/^OBJECTIVE,\s*OBSERVATION/i.test(line) &&
          !isOpoDeviceLine(line),
      );
    return lines.length ? [lines] : null;
  }
  return raw
    .split(/\n(?=###\s+\d+\.\s)/)
    .map((chunk) =>
      chunk
        .split("\n")
        .map((line) => stripAxiomBranding(escapeHeadingText(line.trim()).replace(/^[-•]\s*/, "").trim()))
        .filter((line) => line && !line.startsWith("|") && !/^C\. OBJECTIVE/i.test(line) && !isOpoDeviceLine(line)),
    )
    .filter((card) => card.length > 0);
}

/** True when a numbered line is a procedure step (not a new objective heading). */
function isNumberedProcedureStep(line: string, card: string[]): boolean {
  if (!/^\d+\.\s/.test(line)) return false;
  const stepNum = parseInt(/^(\d+)\./.exec(line)?.[1] ?? "0", 10);
  const hasProcedure = card.some((l) => isOpoLabel(l, "procedure"));
  const hasObservation = card.some((l) => isOpoLabel(l, "observation"));
  if (hasObservation) return false;
  if (hasProcedure) return true;
  if (stepNum >= 2) return true;
  if (stepNum === 1 && card.length > 0 && /^\d+\.\s/.test(card[0] ?? "")) return true;
  return false;
}

function isNewObjectiveLine(line: string, card: string[]): boolean {
  if (!/^\d+\.\s/.test(line)) return false;
  if (card.length === 0) return true;
  if (isNumberedProcedureStep(line, card)) return false;
  return card.some((l) => isOpoLabel(l, "observation"));
}

function opoCards(section: ReportSection): string[][] {
  const fromMarkdown = opoCardsFromMarkdown(section.narrative_content ?? "");
  if (fromMarkdown && fromMarkdown.length > 0) return fromMarkdown;

  const lines = narrativeLines(section).filter(
    (line) => !/^C\. OBJECTIVE/i.test(line) && !isOpoDeviceLine(line),
  );
  const cards: string[][] = [];
  let current: string[] = [];
  for (const line of lines) {
    if (isNewObjectiveLine(line, current)) {
      if (current.length > 0) cards.push(current);
      current = [line];
    } else {
      current.push(line);
    }
  }
  if (current.length > 0) cards.push(current);
  return cards;
}

function isIntroNarrativeNotAddress(line: string): boolean {
  return (
    line.length > 120 ||
    /\b(forensic|examination|requested|device identified|evidence ex-|transferred outside|submitted forensic|conduct cyber forensic)\b/i.test(
      line,
    )
  );
}

function OpoCard({ card, continued = false }: { card: string[]; continued?: boolean }) {
  const previewCard = filterOpoCardForPreview(card);
  let pastObservationLabel = false;
  const mobileBlock = isMobileOpoCard(previewCard);
  // Mobile sample layout: no title-only card header; render 1/2/3 subsections in one flow.
  if (mobileBlock) {
    let mode: "none" | "objective" | "procedure" | "observation" = "none";
    return (
      <div className="mt-1 space-y-2 text-[13px] leading-relaxed text-black">
        {previewCard.map((line, i) => {
          if (isOpoLabel(line, "objective")) {
            mode = "objective";
            return (
              <h4 key={i} className="mt-3 text-[15px] font-bold text-[#082c5c]">
                {line.replace(/\*\*/g, "").replace(/:?$/, "")}
              </h4>
            );
          }
          if (isOpoLabel(line, "procedure")) {
            mode = "procedure";
            return (
              <h4 key={i} className="mt-4 text-[15px] font-bold text-[#082c5c]">
                {line.replace(/\*\*/g, "").replace(/:?$/, "")}
              </h4>
            );
          }
          if (isOpoLabel(line, "observation")) {
            mode = "observation";
            pastObservationLabel = true;
            return (
              <h4 key={i} className="mt-4 text-[15px] font-bold text-[#082c5c]">
                {line.replace(/\*\*/g, "").replace(/:?$/, "")}
              </h4>
            );
          }
          const bullet = mode === "procedure" || mode === "observation";
          return (
            <p key={i} className={pastObservationLabel ? "text-[13px] leading-[1.7]" : undefined}>
              {bullet ? "• " : ""}
              <HumanEditText text={line} />
            </p>
          );
        })}
      </div>
    );
  }
  return (
    <section className="rounded-xl border border-[#c8d3e3] bg-[#fbfdff] p-3.5 shadow-sm">
      <h4 className="mb-3 text-[14px] font-black text-[#082c5c]">
        <HumanEditText text={`${previewCard[0]}${continued ? " (continued)" : ""}`} />
      </h4>
      <div className="space-y-2 text-[12px] leading-relaxed text-black">
        {previewCard.slice(1).map((line, i) => {
          const isLabel = /^(Objective|Procedure|Observation|Status)\**?$|^(\*\*)?(Objective|Procedure|Observation|Status)(\*\*)?$/i.test(
            line.trim(),
          );
          if (isOpoLabel(line, "observation")) pastObservationLabel = true;
          if (isLabel) {
            return (
              <p key={i} className="font-bold">
                <HumanEditText text={line.replace(/\*\*/g, "").replace(/:?$/, ":")} />
              </p>
            );
          }
          return (
            <p
              key={i}
              className={pastObservationLabel ? "text-[13px] leading-[1.7]" : undefined}
            >
              <HumanEditText text={line} />
            </p>
          );
        })}
      </div>
    </section>
  );
}

function splitLongOpoCard(card: string[]): string[][] {
  const filtered = filterOpoCardForPreview(card);
  if (!filtered.length) return [];
  return [filtered];
}

/** Pack Objective + Procedure + Observations onto A4 pages; leftover observations continue. */
function mobileOpoPageCards(parsed: MobileOpoParsed): string[][] {
  const head: string[] = ["1. Objective", ...parsed.objective, "2. Procedure", ...parsed.procedure, "3. Observations"];
  const pages: string[][] = [];
  let used = pageVisualCost(head);
  const firstObs: string[] = [];
  let index = 0;
  while (index < parsed.observations.length) {
    const cost = visualNarrativeLines(parsed.observations[index]);
    if (firstObs.length && used + cost > OPO_PAGE_UNITS) break;
    firstObs.push(parsed.observations[index]);
    used += cost;
    index += 1;
  }
  pages.push([...head, ...firstObs]);
  while (index < parsed.observations.length) {
    const chunk = ["3. Observations", ...parsed.observations.slice(index)];
    const { fit } = takeOpoCardPrefix(chunk, OPO_PAGE_UNITS);
    const taken = Math.max(0, fit.length - 1);
    if (taken === 0) {
      pages.push([parsed.observations[index]]);
      index += 1;
      continue;
    }
    pages.push(fit);
    index += taken;
  }
  return pages.length ? pages : [head];
}

function MobileOpoReportPages({
  section,
  pageStart = 1,
  actions,
  allSections,
}: {
  section: ReportSection;
  pageStart?: number;
  actions?: ReactNode;
  allSections?: ReportSection[];
}) {
  const sectionTitle = visibleSectionTitle(section, allSections);
  const parsed =
    parseMobileOpoMarkdown(section.narrative_content ?? "") ?? {
      objective: [],
      procedure: [],
      observations: [],
    };
  const pages = mobileOpoPageCards(parsed);
  return (
    <>
      {pages.map((card, idx) => (
        <ReportPageFrame
          key={`mobile-opo-page-${idx}`}
          title={idx === 0 ? sectionTitle : `${sectionTitle} (continued)`}
          pageNo={pageStart + idx}
          actions={actions}
        >
          <OpoCard card={card} continued={idx > 0} />
        </ReportPageFrame>
      ))}
    </>
  );
}

function OpoReportPages({
  section,
  pageStart = 1,
  actions,
  allSections,
}: {
  section: ReportSection;
  pageStart?: number;
  actions?: ReactNode;
  allSections?: ReportSection[];
}) {
  const sectionTitle = visibleSectionTitle(section, allSections);
  // Prefer dedicated mobile single-block layout (Objective + Procedure + Findings together).
  const mobileParsed = parseMobileOpoMarkdown(section.narrative_content ?? "");
  if (mobileParsed) {
    return (
      <MobileOpoReportPages
        section={section}
        pageStart={pageStart}
        actions={actions}
        allSections={allSections}
      />
    );
  }
  const cards = opoCards(section).flatMap((card) => splitLongOpoCard(card));
  if (cards.length === 0) {
    return (
      <ReportPageFrame title={sectionTitle} pageNo={pageStart} actions={actions}>
        <NarrativePreview section={section} />
      </ReportPageFrame>
    );
  }
  const pages = paginateOpoCards(cards);
  return (
    <>
      {pages.map((pageCards, idx) => (
        <ReportPageFrame
          key={`opo-page-${idx}`}
          title={idx === 0 ? sectionTitle : `${sectionTitle} (continued)`}
          pageNo={pageStart + idx}
          actions={actions}
        >
          <div className="mt-1 space-y-3">
            {pageCards.map((card, ci) => (
              <OpoCard
                key={`${card[0]}-${ci}`}
                card={card}
                continued={idx > 0 && ci === 0 && pages[idx - 1]?.some((prev) => prev[0] === card[0])}
              />
            ))}
          </div>
        </ReportPageFrame>
      ))}
    </>
  );
}

function NarrativeLinesView({ lines }: { lines: string[] }) {
  if (lines.length === 0) return null;
  return (
    <div className="mt-4 space-y-2 text-[13px] leading-relaxed text-black">
      {lines.map((line, idx) => {
        if (/^(Objective|Procedure|Observation|Status):?$/i.test(line)) {
          return (
            <p key={idx} className="mt-3 font-bold">
              <HumanEditText text={line.replace(/:?$/, ":")} />
            </p>
          );
        }
        if (/^\d+\.\s/.test(line)) {
          return (
            <p key={idx} className="font-bold">
              <HumanEditText text={line} />
            </p>
          );
        }
        if (/^[A-F]\.\s/.test(line) || (isNarrativeHeading(line) && !/[.!?]$/.test(line))) {
          return (
            <h3 key={idx} className="mt-4 text-[15px] font-bold text-[#103b63]">
              <HumanEditText text={line} />
            </h3>
          );
        }
        return (
          <p key={idx}>
            <HumanEditText text={line} />
          </p>
        );
      })}
    </div>
  );
}

function NarrativePreview({ section }: { section: ReportSection }) {
  return <NarrativeLinesView lines={narrativeLines(section)} />;
}

function PaginatedNarrativePages({
  section,
  pageStart = 1,
  actions,
  allSections,
}: {
  section: ReportSection;
  pageStart?: number;
  actions?: ReactNode;
  allSections?: ReportSection[];
}) {
  const sectionTitle = visibleSectionTitle(section, allSections);
  const pages = paginateNarrativeLines(narrativeLines(section));
  return (
    <>
      {pages.map((pageLines, idx) => (
        <ReportPageFrame
          key={`nar-${section.section_key}-${idx}`}
          title={idx === 0 ? sectionTitle : `${sectionTitle} (continued)`}
          pageNo={pageStart + idx}
          actions={idx === pages.length - 1 ? actions : undefined}
        >
          <NarrativeLinesView lines={pageLines} />
        </ReportPageFrame>
      ))}
    </>
  );
}

function introductionLines(section: ReportSection): string[] {
  const title = visibleSectionTitle(section).toLowerCase();
  return (section.narrative_content ?? "")
    .split("\n")
    .map((raw) => stripAxiomBranding(escapeHeadingText(raw.trim()).replace(/^[-•]\s*/, "").trim()))
    .filter((line) => line && !line.startsWith("|") && line.toLowerCase() !== title);
}

function isIntroMarker(line: string, marker: string): boolean {
  return line.replace(/:$/, "").trim().toLowerCase() === marker.toLowerCase();
}

function IntroductionPreview({ section }: { section: ReportSection }) {
  const lines = introductionLines(section);
  const dateLine = lines.find((line) => /^Date:/i.test(line));
  const toIdx = lines.findIndex((line) => isIntroMarker(line, "To") || isIntroMarker(line, "To,"));
  const subjectIdx = lines.findIndex((line) => /^Subject:/i.test(line));
  const dearIdx = lines.findIndex((line) => /^Dear Sir/i.test(line));
  const scopeIdx = lines.findIndex((line) => isIntroMarker(line, "Scope of Work"));
  const termsIdx = lines.findIndex(
    (line) => isIntroMarker(line, "Terms and Condition") || isIntroMarker(line, "Terms and Conditions"),
  );

  const addressEnd = subjectIdx >= 0 ? subjectIdx : dearIdx >= 0 ? dearIdx : lines.length;
  const addressStart = toIdx >= 0 ? toIdx + 1 : 0;
  const addressLines = lines
    .slice(addressStart, addressEnd)
    .filter((line) => line !== dateLine && !isIntroNarrativeNotAddress(line));
  const subjectLine = subjectIdx >= 0 ? lines[subjectIdx] : undefined;

  const salutationEnd = scopeIdx >= 0 ? scopeIdx : termsIdx >= 0 ? termsIdx : lines.length;
  const salutationStart = dearIdx >= 0 ? dearIdx : subjectIdx >= 0 ? subjectIdx + 1 : 0;
  const salutationLines = lines.slice(salutationStart, salutationEnd);

  const scopeEnd = termsIdx >= 0 ? termsIdx : lines.length;
  const scopeLines = scopeIdx >= 0 ? lines.slice(scopeIdx, scopeEnd) : [];

  const termsEnd = lines.length;
  const termsLines = termsIdx >= 0 ? lines.slice(termsIdx, termsEnd) : [];

  const signOffLines = (() => {
    if (termsIdx < 0) return [];
    const afterTerms = lines.slice(termsIdx + 1).filter((line) => !/^\d+\.\s/.test(line));
    const tail = afterTerms.slice(-2).filter(Boolean);
    return tail.length > 0 ? tail : [];
  })();

  return (
    <div className="relative m-0 p-0 text-[14px] leading-[1.45] text-black">
      {dateLine && (
        <p className="mb-[7mm] text-right font-semibold">
          <HumanEditText text={dateLine} />
        </p>
      )}
      <div className="mb-[6mm] space-y-[1mm]">
        <p>To,</p>
        {addressLines.map((line, idx) => (
          <p key={idx}>
            <HumanEditText text={line} />
          </p>
        ))}
      </div>
      {subjectLine && (
        <p className="mb-[7mm] text-center font-normal">
          <span className="font-black">Subject:</span>{" "}
          <HumanEditText text={subjectLine.replace(/^Subject:\s*/i, "")} />
        </p>
      )}
      {salutationLines.length > 0 && (
        <div className="mb-[5mm] space-y-[2mm] text-justify">
          {salutationLines.map((line, idx) => (
            <p key={idx}>
              <HumanEditText text={line} />
            </p>
          ))}
        </div>
      )}
      {scopeLines.length > 0 && (
        <div className="mb-[5mm] space-y-[1.5mm]">
          {scopeLines.map((line, idx) =>
            isIntroMarker(line, "Scope of Work") ? (
              <p key={idx} className="font-bold">
                <HumanEditText text={line} />
              </p>
            ) : /^\d+\.\s/.test(line) ? (
              <p key={idx} className="ml-[4mm]">
                <HumanEditText text={line} />
              </p>
            ) : (
              <p key={idx}>
                <HumanEditText text={line} />
              </p>
            ),
          )}
        </div>
      )}
      {termsLines.length > 0 && (
        <div className="mb-[5mm] space-y-[1.5mm]">
          {termsLines.map((line, idx) => {
            const plain = line.replace(/:$/, "").trim().toLowerCase();
            if (plain === "terms and condition" || plain === "terms and conditions") {
              return (
                <p key={idx} className="font-bold">
                  <HumanEditText text={line} />
                </p>
              );
            }
            if (signOffLines.includes(line)) return null;
            if (/^\d+\.\s/.test(line)) {
              return (
                <p key={idx} className="ml-[4mm]">
                  <HumanEditText text={line} />
                </p>
              );
            }
            return (
              <p key={idx}>
                <HumanEditText text={line} />
              </p>
            );
          })}
        </div>
      )}
      {signOffLines.length > 0 && (
        <div className="mt-[8mm] space-y-[1mm] text-right font-bold">
          {signOffLines.map((line, idx) => (
            <p key={idx}>
              <HumanEditText text={line} />
            </p>
          ))}
        </div>
      )}
    </div>
  );
}

function LetterheadChrome() {
  return (
    <>
      <img src={REPORT_HEADER_SRC} alt="" className="report-a4-letterhead-header" />
      <img src={REPORT_FOOTER_SRC} alt="" className="report-a4-letterhead-footer" />
    </>
  );
}

function ConfidentialStamp() {
  return (
    <img src={REPORT_CONFIDENTIAL_SRC} alt="Confidential" className="report-a4-stamp drop-shadow-sm" />
  );
}

function ReportLogo({ watermark = false }: { watermark?: boolean }) {
  if (!watermark) return null;
  return <img src={REPORT_WATERMARK_SRC} alt="" className="report-a4-watermark" />;
}

function PageNumber({ pageNo }: { pageNo?: number }) {
  if (!pageNo) return null;
  return <div className="report-a4-page-number">Page {pageNo}</div>;
}

function ReportPageFrame({
  title,
  children,
  pageNo,
  actions,
  hideTitle = false,
  editable = true,
}: {
  title?: string;
  children: ReactNode;
  pageNo?: number;
  actions?: ReactNode;
  hideTitle?: boolean;
  editable?: boolean;
}) {
  const centerTitle = /^INTRODUCTION\b/i.test((title ?? "").trim());
  return (
    <>
      <div className={clsx(A4_PAGE_CLASS, "mx-auto flex max-w-full flex-col bg-white font-serif shadow-xl print:shadow-none")}>
        <LetterheadChrome />
        <ConfidentialStamp />
        <ReportLogo watermark />
        <div className={clsx("report-a4-content z-10", centerTitle && "report-a4-content--introduction")}>
          {!hideTitle && title && (
            <h2
              className={clsx(
                "shrink-0 text-[18px] leading-snug font-black uppercase text-[#082c5c] underline decoration-[#082c5c] decoration-2 underline-offset-4",
                centerTitle ? "mt-0 mb-[7mm] text-center" : "mt-2 mb-4",
              )}
            >
              {title}
            </h2>
          )}
          <div className="min-h-0 flex-1 overflow-hidden">
            {editable ? <EditableReportBody>{children}</EditableReportBody> : children}
          </div>
        </div>
        <PageNumber pageNo={pageNo} />
      </div>
      {actions}
    </>
  );
}


function SuspiciousReportPages({ section, pageStart, actions }: {section: ReportSection;pageStart?: number;actions?: ReactNode}) {
  const cards = (section.structured_json?.suspicious_activity ?? []) as SuspiciousActivityCard[];
  if (!cards.length) return <ReportPageFrame title="SUSPICIOUS ACTIVITY" pageNo={pageStart} actions={actions}><NarrativePreview section={section} /></ReportPageFrame>;
  const observations = { ...section, narrative_content: String(section.structured_json?.examiner_observations_md || "### Examiner observations\n\nNo examiner observations recorded."), structured_json: {} };
  return <>{cards.map((card,index) => <ReportPageFrame key={card.id} title="SUSPICIOUS ACTIVITY" pageNo={(pageStart ?? 1)+index} editable={false}>
    <div className="space-y-1 break-all text-[11px] leading-[14px]">
      <p>{String(section.structured_json?.review_note ?? "Source-linked candidates require examiner review.")}</p>
      <EvidenceFrame card={card} />
      <p>Category: {card.category} · pending examiner review</p>
      <p>Source: {card.source_path.slice(0,400)}{card.source_path.length>400 ? " (path excerpt; full path in artifact)" : ""}</p>
      <p>Source SHA256: {card.source_sha256 || "Unavailable"}</p>
      <p>Artifact: {card.job_artifact_id || "Unavailable"}; record: {card.source_record_id}</p>
      <p>Time: {card.timestamp_utc || "Unavailable"}</p>
      <p>Explanation (excerpt): {card.explanation.slice(0,800)}</p>
      <p>Source excerpt: {(card.excerpt ?? "").slice(0,400)}</p>
      <p>Method: {card.method}; model: {card.model || "Not applicable"}</p>
      {card.frame_sha256 && <p>Frame time: {card.timestamp_seconds ?? "Image"}; SHA256: {card.frame_sha256}</p>}
    </div>
  </ReportPageFrame>)}<PaginatedNarrativePages section={observations} pageStart={(pageStart ?? 1)+cards.length} actions={actions} /></>;
}

function ReportPagePreview({
  section,
  pageStart = 1,
  actions,
  allSections,
}: {
  section: ReportSection;
  pageStart?: number;
  actions?: ReactNode;
  allSections?: ReportSection[];
}) {
  const sectionView = enhanceSectionForPreview(section);
  const structured = (sectionView.structured_json ?? {}) as Record<string, unknown>;
  const title = visibleSectionTitle(sectionView, allSections);

  if (sectionView.section_key === "suspicious_activity") return <SuspiciousReportPages section={sectionView} pageStart={pageStart} actions={actions} />;
  if (sectionView.section_key === "cover_page") {
    return (
      <>
        <div
          className={clsx(
            A4_PAGE_CLASS,
            "mx-auto flex max-w-full flex-col bg-white font-serif shadow-xl print:shadow-none",
          )}
        >
          <LetterheadChrome />
          <ConfidentialStamp />
          <ReportLogo watermark />
          <div className="report-a4-content report-a4-content--cover z-10">
            <h1 className="text-[24px] font-black uppercase tracking-wide text-[#062d61]">
              {String(structured.title ?? title)}
            </h1>
            <p className="mt-7 text-2xl font-bold">“{String(structured.subject ?? "")}”</p>
            <p className="mt-7 text-2xl font-bold uppercase">{String(structured.company ?? "")}</p>
          </div>
          <PageNumber pageNo={pageStart} />
        </div>
        {actions}
      </>
    );
  }

  if (sectionView.section_key === "artifact_summary") {
    return <ArtifactReportPages section={sectionView} pageStart={pageStart} actions={actions} />;
  }
  if (sectionView.section_key === "user_profile_information") {
    return <PaginatedTablesPreview section={sectionView} pageStart={pageStart} actions={actions} />;
  }
  if (sectionView.section_key === "objectives_procedure_observation") {
    return <OpoReportPages section={sectionView} pageStart={pageStart} actions={actions} allSections={allSections} />;
  }

  const hasStructuredTables = ((sectionView.structured_json?.tables ?? []) as AnnexureTable[]).some(
    (table) => (table.columns?.length ?? 0) > 0,
  );
  if (sectionView.section_key === "forensic_imaging") {
    return <PaginatedTablesPreview section={sectionView} pageStart={pageStart} actions={actions} />;
  }
  if (sectionView.section_key === "os_information" || (hasStructuredTables && sectionView.section_key !== "introduction")) {
    return <PaginatedTablesPreview section={sectionView} pageStart={pageStart} actions={actions} />;
  }

  if (sectionView.section_key === "introduction") {
    const introPages = paginateNarrativeLines(introductionLines(sectionView));
    if (introPages.length <= 1) {
      return (
        <ReportPageFrame title={title} pageNo={pageStart} actions={actions}>
          <IntroductionPreview section={sectionView} />
        </ReportPageFrame>
      );
    }
    return (
      <>
        {introPages.map((pageLines, idx) => (
          <ReportPageFrame
            key={`intro-${idx}`}
            title={idx === 0 ? title : `${title} (continued)`}
            pageNo={pageStart + idx}
            actions={idx === introPages.length - 1 ? actions : undefined}
          >
            <NarrativeLinesView lines={pageLines} />
          </ReportPageFrame>
        ))}
      </>
    );
  }

  if (sectionView.section_key === "table_of_contents") {
    return (
      <ReportPageFrame title={title} pageNo={pageStart} actions={actions}>
        <TableOfContentsPreview sections={allSections ?? [sectionView]} />
      </ReportPageFrame>
    );
  }

  return (
    <PaginatedNarrativePages
      section={sectionView}
      pageStart={pageStart}
      actions={actions}
      allSections={allSections}
    />
  );
}

export function countPreviewPages(section: ReportSection): number {
  const sectionView = enhanceSectionForPreview(section);
  if (sectionView.section_key === "suspicious_activity") {
    const cards = (sectionView.structured_json?.suspicious_activity ?? []) as unknown[];
    if (cards.length) {
      const observations = { ...sectionView, narrative_content: String(sectionView.structured_json?.examiner_observations_md || "### Examiner observations\n\nNo examiner observations recorded."), structured_json: {} };
      return cards.length + Math.max(1, paginateNarrativeLines(narrativeLines(observations)).length);
    }
  }
  if (sectionView.section_key === "introduction") {
    return Math.max(1, paginateNarrativeLines(introductionLines(sectionView)).length);
  }
  if (sectionView.section_key === "artifact_summary") {
    const catalog = sectionView.structured_json?.catalog as { sections?: ArtifactGroup[] } | undefined;
    if (!catalog?.sections?.length) return 1;
    return Math.max(1, paginateArtifactGroups(catalog).length);
  }
  if (sectionView.section_key === "objectives_procedure_observation") {
    const raw = sectionView.narrative_content ?? "";
    if (isMobileSingleOpoMarkdown(raw)) {
      const parsed = parseMobileOpoMarkdown(raw);
      if (parsed) return Math.max(1, mobileOpoPageCards(parsed).length);
    }
    const cards = opoCards(sectionView).flatMap((card) => splitLongOpoCard(card));
    return Math.max(1, paginateOpoCards(cards).length);
  }
  const hasStructuredTables = ((sectionView.structured_json?.tables ?? []) as AnnexureTable[]).some(
    (table) => (table.columns?.length ?? 0) > 0,
  );
  if (sectionView.section_key === "forensic_imaging") {
    return Math.max(1, paginateSectionContent(sectionView).length);
  }
  if (sectionView.section_key === "os_information" || (hasStructuredTables && sectionView.section_key !== "introduction")) {
    return Math.max(1, paginateSectionContent(sectionView).length);
  }
  if (sectionView.section_key === "user_profile_information") {
    return Math.max(1, paginateSectionContent(sectionView).length);
  }
  if (sectionView.section_key === "annexure") {
    return Math.max(1, paginateSectionContent(sectionView).length);
  }
  return Math.max(1, paginateNarrativeLines(narrativeLines(sectionView)).length);
}

function SectionActionsPanel({
  jobId,
  section,
  onUpdated,
  editing,
  setEditing,
}: {
  jobId: string;
  section: ReportSection;
  onUpdated: (updated: ReportSection) => void;
  editing: boolean;
  setEditing: (value: boolean) => void;
}) {
  return (
    <div className="mx-auto mb-6 mt-4 w-[210mm] max-w-full">
      <ReportSectionReview
        jobId={jobId}
        section={section}
        onUpdated={onUpdated}
        editing={editing}
        setEditing={setEditing}
      />
    </div>
  );
}

export function ReportSectionPagesWithActions({
  section,
  pageStart,
  jobId,
  onUpdated,
  allSections,
}: {
  section: ReportSection;
  pageStart: number;
  jobId: string;
  onUpdated: (updated: ReportSection) => void;
  allSections?: ReportSection[];
}) {
  const [editing, setEditing] = useState(false);
  const sj = (section.structured_json ?? {}) as Record<string, unknown>;
  const baseline = String(sj.human_edit_baseline ?? "").trim();
  const baselineLines = plainNarrativeLines(baseline);
  return (
    <ReportEditProvider editing={editing} baselineLines={baselineLines} sectionKey={section.section_key}>
      <div className="space-y-6">
        <ReportPagePreview
          section={section}
          pageStart={pageStart}
          allSections={allSections}
          actions={
            <SectionActionsPanel
              jobId={jobId}
              section={section}
              onUpdated={onUpdated}
              editing={editing}
              setEditing={setEditing}
            />
          }
        />
      </div>
    </ReportEditProvider>
  );
}
