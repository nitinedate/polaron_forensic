/** Remove third-party forensic-tool vendor branding from user-visible strings. */
export function stripVendorBranding(text: string | null | undefined): string {
  if (!text) return "";
  return text
    .replace(/\s*\(\s*AXIOM\s*\)/gi, "")
    .replace(/\bMagnet\s+AXIOM\b/gi, "Forensic")
    .replace(/\bAXIOM\s+catalog\b/gi, "artifact catalog")
    .replace(/\bAXIOM\s+inventory\b/gi, "artifact inventory")
    .replace(/\bAXIOM\b/gi, "")
    .replace(/\bAxiom-style\b/gi, "")
    .replace(/\bAxiom\b/g, "")
    .replace(/\s{2,}/g, " ")
    .replace(/\s+([,.;:!?—–-])/g, "$1")
    .trim();
}

/** @deprecated Use stripVendorBranding */
export const stripAxiomBranding = stripVendorBranding;

/** Strip internal tuning/config from pipeline agent labels shown in the UI. */
export function sanitizePipelineLabel(text: string | null | undefined): string {
  if (!text) return "";
  let cleaned = stripVendorBranding(text)
    .replace(/\s*\(\s*\d[\d,\s]*\/\s*\d[\d,\s]*\s*overlap\s*\)/gi, "")
    .replace(/\s*\(\s*GPU\s*\)/gi, "")
    .replace(/\s*\(\s*\d+\s*\/\s*\d+\s*overlap\s*\)/gi, "")
    .replace(/\s{2,}/g, " ")
    .trim();

  const lower = cleaned.toLowerCase();
  if (lower.startsWith("rag chunking")) return "RAG chunking";
  if (lower.startsWith("rag embedding")) return "RAG embedding";
  if (lower === "neo4j graph sync") return "Neo4j graph";
  if (lower === "ontology linking") return "Ontology";
  cleaned = cleaned.replace(/\[\s*([^\]]*?)\s*\]/g, (_, inner: string) => `[${inner.trim()}]`);
  return cleaned;
}

/** Short label for pipeline progress summaries (counts only, no duplicate detail). */
export function shortenProgressLabel(label: string | null | undefined, phase?: string | null): string {
  const phaseKey = (phase ?? "").toLowerCase();
  if (phaseKey === "artifact_inventory" || phaseKey === "axiom_artifacts") return "artifact inventory";
  if (phaseKey === "rag") return "RAG indexing";
  if (phaseKey === "parse" || phaseKey === "ocr") return "parsing";
  if (phaseKey === "materialize") return "artifacts registered";
  if (phaseKey === "extract") return "extraction";

  const cleaned = sanitizePipelineLabel(label);
  if (!cleaned) return "processing";
  if (/artifact inventory complete/i.test(cleaned)) return "artifact inventory";
  if (/embed/i.test(cleaned)) return "RAG indexing";
  if (/chunk/i.test(cleaned)) return "RAG indexing";
  if (/parse/i.test(cleaned)) return "parsing";
  if (/materializ/i.test(cleaned)) return "artifacts registered";
  return cleaned.split(/[—–-]/)[0]?.trim() || cleaned;
}
