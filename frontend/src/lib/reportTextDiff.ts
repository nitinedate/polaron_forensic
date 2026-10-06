/** Word-level diff so human edits can be shown in blue on the report page. */

export type DiffOp = "eq" | "ins" | "del";

export type DiffToken = { op: DiffOp; value: string };

export function tokenizeWords(text: string): string[] {
  return (text || "").split(/(\s+)/).filter((t) => t.length > 0);
}

export function diffTokens(original: string, current: string): DiffToken[] {
  const a = tokenizeWords(original);
  const b = tokenizeWords(current);
  const n = a.length;
  const m = b.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const out: DiffToken[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ op: "eq", value: b[j] });
      i += 1;
      j += 1;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      out.push({ op: "del", value: a[i] });
      i += 1;
    } else {
      out.push({ op: "ins", value: b[j] });
      j += 1;
    }
  }
  while (i < n) {
    out.push({ op: "del", value: a[i] });
    i += 1;
  }
  while (j < m) {
    out.push({ op: "ins", value: b[j] });
    j += 1;
  }
  return out;
}

export function closestLine(line: string, originals: string[]): string {
  if (!line) return "";
  if (originals.includes(line)) return line;
  const needle = line.toLowerCase();
  let best = "";
  let bestScore = 0;
  for (const orig of originals) {
    if (!orig) continue;
    if (orig === line) return orig;
    const o = orig.toLowerCase();
    if (needle.startsWith(o.slice(0, Math.min(24, o.length))) || o.startsWith(needle.slice(0, Math.min(24, needle.length)))) {
      const score = Math.min(needle.length, o.length);
      if (score > bestScore) {
        best = orig;
        bestScore = score;
      }
    }
  }
  return best;
}

export function plainNarrativeLines(markdown: string | null | undefined): string[] {
  return (markdown ?? "")
    .split("\n")
    .map((raw) => raw.replace(/^#{1,6}\s*/, "").replace(/\*\*/g, "").replace(/^[-•*]\s*/, "").trim())
    .filter((line) => line && !line.startsWith("|"));
}

export type MarkdownTable = {
  title?: string;
  columns: string[];
  rows: string[][];
  continued?: boolean;
};

function isTableSep(line: string): boolean {
  const s = line.trim();
  return s.startsWith("|") && /^\|[\s\-:|]+\|\s*$/.test(s);
}

function parseTableRow(line: string): string[] {
  return line
    .trim()
    .replace(/^\|/, "")
    .replace(/\|$/, "")
    .split("|")
    .map((c) => c.trim());
}

export function parseMarkdownTables(content: string): MarkdownTable[] {
  const lines = (content || "").replace(/\r\n/g, "\n").split("\n");
  const tables: MarkdownTable[] = [];
  let i = 0;
  let pendingTitle: string | undefined;

  while (i < lines.length) {
    const stripped = lines[i].trim();
    if (stripped.startsWith("### ")) {
      pendingTitle = stripped.slice(4).trim();
      i += 1;
      continue;
    }
    if (stripped.startsWith("|") && i + 1 < lines.length && isTableSep(lines[i + 1])) {
      const header = parseTableRow(stripped);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && lines[i].trim().startsWith("|") && !isTableSep(lines[i])) {
        rows.push(parseTableRow(lines[i]));
        i += 1;
      }
      const continued = /\(\s*continued\s*\)\s*$/i.test(pendingTitle ?? "");
      tables.push({
        title: pendingTitle,
        columns: header,
        rows,
        continued,
      });
      pendingTitle = undefined;
      continue;
    }
    i += 1;
  }
  return tables;
}

function sameColumns(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((cell, idx) => cell === b[idx]);
}

function stripContinued(title?: string): string {
  return (title ?? "").replace(/\s*\(\s*continued\s*\)\s*$/i, "").trim();
}

/** Rejoin table chunks that were split across A4 pages before saving the draft. */
export function mergeContinuedTables(tables: MarkdownTable[]): MarkdownTable[] {
  const out: MarkdownTable[] = [];
  for (const table of tables) {
    const title = stripContinued(table.title);
    const prev = out[out.length - 1];
    const continued =
      Boolean(table.continued) || /\(\s*continued\s*\)\s*$/i.test(table.title ?? "");
    if (prev && sameColumns(prev.columns, table.columns) && (continued || stripContinued(prev.title) === title)) {
      prev.rows = [...prev.rows, ...table.rows];
      continue;
    }
    out.push({
      title: title || undefined,
      columns: [...table.columns],
      rows: table.rows.map((row) => [...row]),
    });
  }
  return out;
}

function serializeTable(table: HTMLElement): string {
  const rows = [...table.querySelectorAll("tr")];
  if (!rows.length) return "";
  const cellsOf = (tr: Element) =>
    [...tr.querySelectorAll("th, td")].map((cell) =>
      (cell.textContent || "").replace(/\|/g, "\\|").replace(/\s+/g, " ").trim(),
    );
  const header = cellsOf(rows[0]);
  if (!header.length) return "";
  const body = rows.slice(1).map(cellsOf);
  return [
    `| ${header.join(" | ")} |`,
    `| ${header.map(() => "---").join(" | ")} |`,
    ...body.map((row) => `| ${row.join(" | ")} |`),
  ].join("\n");
}

function serializeTextBlock(el: HTMLElement): string {
  const text = (el.textContent || "").replace(/\s+/g, " ").trim();
  if (!text) return "";
  const tag = el.tagName;
  const cls = el.className || "";
  const bold = /\bfont-(bold|black)\b/.test(cls);
  if (tag === "H2" || tag === "H3") return `## ${text}`;
  if (tag === "H4") return `### ${text}`;
  if (bold && /^(Objective|Procedure|Observation|Status|Subject|Scope of Work|Terms and Conditions?)\b/i.test(text)) {
    const [label, ...rest] = text.split(":");
    if (rest.length) return `**${label.trim()}:** ${rest.join(":").trim()}`;
    return `**${text.replace(/:$/, "")}**`;
  }
  return text;
}

/** Walk the live page in document order so tables are kept with the surrounding draft. */
export function serializeEditableBody(root: HTMLElement): string {
  const lines: string[] = [];

  const visit = (node: Element) => {
    const el = node as HTMLElement;
    const tag = el.tagName;
    if (tag === "TABLE") {
      const md = serializeTable(el);
      if (md) lines.push(md);
      return;
    }
    if (["P", "H1", "H2", "H3", "H4", "LI"].includes(tag)) {
      const md = serializeTextBlock(el);
      if (md) lines.push(md);
      else if (lines.length > 0 && lines[lines.length - 1] !== "") lines.push("");
      return;
    }
    for (const child of el.children) visit(child);
  };

  for (const child of root.children) visit(child);
  if (!lines.length) return (root.innerText || "").replace(/\u00a0/g, " ").trim();
  return lines.join("\n").trim();
}

export const HUMAN_EDIT_COLOR = "#1d4ed8";
