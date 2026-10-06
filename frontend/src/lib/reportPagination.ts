/**
 * Pack report preview content so each A4 body is filled before the next page starts.
 * A heading stays with the first line of its body; leftover room pulls content forward.
 */

/** Wrapped text lines that fit below the section title and above the footer. */
export const NARRATIVE_PAGE_LINES = 26;
export const NARRATIVE_CHARS_PER_LINE = 88;
/**
 * Section C page budget — lockstep with Report Formation Agent
 * (report_formation_agent.py / opo_page_training v2.1).
 * 78-character wrap matches the on-page card width so leftover body is used
 * instead of inventing empty pages. 34 units fill the A4 body with slack so
 * overflow:hidden never clips a line.
 */
export const OPO_CHARS_PER_LINE = 78;
export const OPO_PAGE_UNITS = 34;
export const OPO_CARD_OVERHEAD_UNITS = 3;
/** Pull a useful prefix of the next O/P/O card when this much body remains. */
export const OPO_MIN_SPLIT_ROOM_UNITS = 6;
/**
 * One A4 body below B. ARTIFACTS after the section title.
 * Each catalog item is the previous panel block: name + count + wrapped description.
 * Units are ~one text line. Leave slack so overflow:hidden never clips Report Agent text.
 */
export const ARTIFACT_PAGE_UNITS = 28;
export const ARTIFACT_GROUP_HEADER_UNITS = 2;
/** Fallback when a description is missing: name, count, one description line. */
export const ARTIFACT_ITEM_UNITS = 4;
export const ARTIFACT_ITEM_GAP_UNITS = 1;
export const ARTIFACT_DESC_CHARS_PER_LINE = 78;
export const TABLE_HEADER_UNITS = 2;
export const TABLE_TITLE_UNITS = 2;
export const TABLE_NOTE_BASE_UNITS = 1;
export const TABLE_NOTE_CHARS_PER_LINE = 78;
export const MIN_TABLE_ROWS_ON_PAGE = 1;
/** Approximate readable characters across the full table width at the report font size. */
export const TABLE_TOTAL_CHARS_PER_LINE = 88;
/**
 * Structured-table budget after the section title — lockstep with Formation Agent
 * v2.4. Overflow:hidden clips anything that enters the footer/page-number band.
 * Missing serials (7 then 9) are worse than leftover white space.
 */
export const TABLE_PAGE_UNITS = 26;
export const TABLE_PACK_SLACK_UNITS = 2;
export const TABLE_GAP_UNITS = 2;
export const TABLE_MIN_SPLIT_ROOM_UNITS = 8;
/** Visible wrap width of a URL cell on a 5-column A4 table (~35mm). */
export const TABLE_URL_CHARS_PER_LINE = 18;
/** Hard cap so a wrapping URL table never walks into the letterhead footer. */
export const TABLE_MAX_URL_ROWS_FIRST = 5;
export const TABLE_MAX_URL_ROWS_CONTINUED = 6;
/** 4-column Objective/Procedure/Observation rows are tall; two is the safe page max. */
export const TABLE_MAX_PROSE_ROWS = 2;
export const TABLE_PROSE_CELL_CHARS = 120;
export const TABLE_MAX_ROW_UNITS = 16;

export function artifactItemUnits(description = "", name = ""): number {
  const nameLines = Math.max(1, Math.ceil(String(name || "Artifact").trim().length / ARTIFACT_DESC_CHARS_PER_LINE));
  const descLines = Math.max(1, Math.ceil(String(description || "").trim().length / ARTIFACT_DESC_CHARS_PER_LINE));
  return nameLines + 1 + descLines + ARTIFACT_ITEM_GAP_UNITS;
}

export function artifactChunkUnits(itemCount: number): number {
  if (itemCount <= 0) return ARTIFACT_GROUP_HEADER_UNITS;
  return ARTIFACT_GROUP_HEADER_UNITS + itemCount * ARTIFACT_ITEM_UNITS;
}

export function artifactChunkCost(itemCosts: number[]): number {
  if (!itemCosts.length) return ARTIFACT_GROUP_HEADER_UNITS;
  return ARTIFACT_GROUP_HEADER_UNITS + itemCosts.reduce((n, cost) => n + cost, 0);
}

const HEADING_RE = /^(Objective|Procedure|Observation|Status):?$/i;
const SECTION_LETTER_RE = /^[A-F]\.\s/;
const NAMED_HEADING_RE =
  /^(Subject|Scope of Work|Terms and Conditions?|Digital Forensic Analyst|Conclusion|Findings?)\b/i;

export function visualNarrativeLines(line: string): number {
  const t = line.trim();
  if (!t) return 0;
  if (HEADING_RE.test(t) || SECTION_LETTER_RE.test(t) || NAMED_HEADING_RE.test(t)) return 1;
  if (/^\d+\.\s/.test(t)) return Math.max(1, Math.ceil(t.length / NARRATIVE_CHARS_PER_LINE));
  return Math.max(1, Math.ceil(t.length / NARRATIVE_CHARS_PER_LINE));
}

export function isNarrativeHeading(line: string): boolean {
  const t = line.trim();
  if (!t) return false;
  if (HEADING_RE.test(t) || SECTION_LETTER_RE.test(t) || NAMED_HEADING_RE.test(t)) return true;
  return false;
}

export function splitIntoSentences(text: string): string[] {
  return (text.match(/[^.!?]+(?:[.!?]+["']?\s*|$)/g) ?? [text])
    .map((s) => s.replace(/\s+/g, " ").trim())
    .filter(Boolean);
}

export function takeFittingPrefix(text: string, maxVisual: number): { fit: string; rest: string } {
  if (maxVisual <= 0) return { fit: "", rest: text };
  if (visualNarrativeLines(text) <= maxVisual) return { fit: text, rest: "" };
  const sentences = splitIntoSentences(text);
  let fit = "";
  let restStart = 0;
  for (let i = 0; i < sentences.length; i++) {
    const next = fit ? `${fit} ${sentences[i]}` : sentences[i];
    if (visualNarrativeLines(next) > maxVisual) {
      restStart = i;
      break;
    }
    fit = next;
    restStart = i + 1;
  }
  const rest = sentences.slice(restStart).join(" ").trim();
  if (!fit && maxVisual >= 1) {
    const room = Math.max(NARRATIVE_CHARS_PER_LINE, maxVisual * NARRATIVE_CHARS_PER_LINE);
    return { fit: text.slice(0, room).trim(), rest: text.slice(room).trim() };
  }
  return { fit, rest };
}

export function pageVisualCost(lines: string[]): number {
  return lines.reduce((n, line) => n + visualNarrativeLines(line), 0);
}

/** Move leading items from the next page while they still fit on the previous page. */
export function pullItemsForward<T>(
  pages: T[][],
  itemCost: (item: T) => number,
  capacity: number,
  canPull: (item: T, dest: T[], remaining: number) => boolean = () => true,
): T[][] {
  const packed = pages.map((page) => [...page]);
  let i = 0;
  while (i < packed.length - 1) {
    if (!packed[i + 1].length) {
      packed.splice(i + 1, 1);
      continue;
    }
    const used = packed[i].reduce((n, item) => n + itemCost(item), 0);
    const remaining = capacity - used;
    const next = packed[i + 1][0];
    const cost = itemCost(next);
    if (cost > 0 && cost <= remaining && canPull(next, packed[i], remaining)) {
      packed[i].push(packed[i + 1].shift() as T);
      continue;
    }
    i += 1;
  }
  return packed.filter((page) => page.length > 0);
}

function stripContinued(line: string): string {
  return line.replace(/\s*\(continued\)\s*$/i, "").trim();
}

/** Fill each A4 page before starting the next. Keep a heading with its body. */
export function paginateNarrativeLines(lines: string[], capacity = NARRATIVE_PAGE_LINES): string[][] {
  const pages: string[][] = [];
  let current: string[] = [];
  let used = 0;
  let lastHeading = "";

  const flush = () => {
    if (current.length) pages.push(current);
    current = [];
    used = 0;
  };

  const push = (line: string, vis = visualNarrativeLines(line)) => {
    current.push(line);
    used += vis;
  };

  const startContinuedPage = () => {
    flush();
    if (lastHeading) push(`${lastHeading} (continued)`, 1);
  };

  for (const raw of lines) {
    if (isNarrativeHeading(raw)) {
      lastHeading = stripContinued(raw);
      if (current.length && used + 2 > capacity) flush();
      push(lastHeading, 1);
      continue;
    }

    let remaining = raw.trim();
    while (remaining) {
      const room = capacity - used;
      const { fit, rest } = takeFittingPrefix(remaining, room);
      if (fit) {
        push(fit);
        remaining = rest;
        continue;
      }
      if (current.length) {
        const orphan = current[current.length - 1];
        if (orphan && isNarrativeHeading(orphan) && !/\(continued\)\s*$/i.test(orphan)) {
          current.pop();
          used = Math.max(0, used - 1);
          flush();
          push(orphan, 1);
        } else {
          startContinuedPage();
        }
      } else {
        startContinuedPage();
      }
    }
  }
  flush();
  if (!pages.length) return [];

  const pulled = pullItemsForward(
    pages,
    visualNarrativeLines,
    capacity,
    (item, dest, remaining) => {
      if (!isNarrativeHeading(item)) return true;
      const headingCost = visualNarrativeLines(item);
      return remaining >= headingCost + 1 || dest.length === 0;
    },
  );

  return pulled.map((page) =>
    page.filter((line, idx) => {
      if (!/\(continued\)\s*$/i.test(line)) return true;
      const base = stripContinued(line).toLowerCase();
      return !page.slice(0, idx).some((prev) => stripContinued(prev).toLowerCase() === base);
    }),
  ).filter((page) => page.length > 0);
}

function isUrlLikeCell(value: string): boolean {
  return /^(?:https?:\/\/|blob:|www\.)/i.test(value.trim());
}

function rowHasUrlCell(row: string[]): boolean {
  return row.some((cell) => isUrlLikeCell(String(cell ?? "")));
}

function rowHasTallProse(row: string[]): boolean {
  return row.some((cell) => String(cell ?? "").replace(/\s+/g, " ").trim().length >= TABLE_PROSE_CELL_CHARS);
}

export function maxManageableTableRows(
  columns: string[] = [],
  rowSample: string[][] = [],
  continued = false,
): number {
  const width = columns.length || (rowSample[0]?.length ?? 0);
  const wrappingUrls = width >= 4 && rowSample.some((row) => rowHasUrlCell(row));
  if (wrappingUrls) return continued ? TABLE_MAX_URL_ROWS_CONTINUED : TABLE_MAX_URL_ROWS_FIRST;
  if (width >= 3 && rowSample.some((row) => rowHasTallProse(row))) return TABLE_MAX_PROSE_ROWS;
  return 14;
}

/**
 * Estimate the vertical cost of a fixed-layout table row.
 *
 * A 5-column URL cell is only ~18 characters wide on A4. Soft-wrap at '/' and
 * cell padding make a typical Social Media row 3-4 units tall. Underestimating
 * that height packs rows 7-8 under the footer; overflow:hidden then hides them
 * while the next page starts at 9.
 */
export function tableRowUnits(row: string[], columns: string[] = []): number {
  const columnCount = Math.max(1, columns.length || row.length || 1);
  const charsPerColumn = Math.max(14, Math.floor(TABLE_TOTAL_CHARS_PER_LINE / columnCount));
  let wrappedLines = 1;
  const cells = row.length ? row : [""];
  cells.forEach((raw) => {
    const value = String(raw ?? "").replace(/\s+/g, " ").trim();
    const width = isUrlLikeCell(value)
      ? Math.min(TABLE_URL_CHARS_PER_LINE, charsPerColumn)
      : charsPerColumn;
    const lineCount = Math.max(1, Math.ceil(Math.max(1, value.length) / width));
    wrappedLines = Math.max(wrappedLines, lineCount);
  });
  const padding = wrappedLines >= 2 ? 1 : 0;
  return Math.max(1, Math.min(TABLE_MAX_ROW_UNITS, wrappedLines + padding));
}

export function tableChunkChromeUnits(
  title: string | undefined,
  note: string | undefined,
  continued: boolean,
): number {
  let units = TABLE_HEADER_UNITS;
  if ((title ?? "").trim()) units += TABLE_TITLE_UNITS;
  if (!continued && (note ?? "").trim()) {
    units += TABLE_NOTE_BASE_UNITS + Math.ceil(String(note).length / TABLE_NOTE_CHARS_PER_LINE);
  }
  return units;
}

export type AnnexureTableSource = {
  title?: string;
  columns?: string[];
  rows?: string[][];
  note?: string;
};

export type PackedAnnexureChunk = {
  title?: string;
  columns?: string[];
  rows: string[][];
  continued: boolean;
  note?: string;
};

export function tableChunkUnits(chunk: PackedAnnexureChunk): number {
  const chrome = tableChunkChromeUnits(chunk.title, chunk.note, chunk.continued);
  return chrome + (chunk.rows ?? []).reduce((n, row) => n + tableRowUnits(row, chunk.columns ?? []), 0);
}

function pageTableUnits(chunks: PackedAnnexureChunk[]): number {
  return chunks.reduce((n, chunk, idx) => n + (idx ? TABLE_GAP_UNITS : 0) + tableChunkUnits(chunk), 0);
}

export function annexurePagesCoverSource(
  tables: AnnexureTableSource[],
  pages: PackedAnnexureChunk[][],
): boolean {
  const source = tables.flatMap((table) =>
    (table.rows ?? []).map((row) => JSON.stringify([table.title ?? "", row])),
  );
  const packed = pages.flat().flatMap((chunk) =>
    (chunk.rows ?? []).map((row) => JSON.stringify([chunk.title ?? "", row])),
  );
  return source.length === packed.length && source.every((row, idx) => row === packed[idx]);
}

/** Serial numbers that the packer skipped or dropped. Empty means every row is present in order. */
export function missingAnnexureRows(
  tables: AnnexureTableSource[],
  pages: PackedAnnexureChunk[][],
): string[] {
  const missing: string[] = [];
  if (!annexurePagesCoverSource(tables, pages)) {
    for (const table of tables) {
      const source = table.rows ?? [];
      const packed = pages
        .flat()
        .filter((chunk) => (chunk.title ?? "") === (table.title ?? ""))
        .flatMap((chunk) => chunk.rows ?? []);
      source.forEach((row, idx) => {
        const key = JSON.stringify(row);
        if (!packed.some((have) => JSON.stringify(have) === key)) {
          missing.push(`${table.title ?? "table"} row ${row[0] ?? idx + 1}`);
        }
      });
      if (!missing.length && packed.length !== source.length) {
        missing.push(`${table.title ?? "table"} row-count ${packed.length} != ${source.length}`);
      }
    }
  }
  return missing;
}

function compactAnnexurePages(
  pages: PackedAnnexureChunk[][],
  capacity: number,
): PackedAnnexureChunk[][] {
  const packed = pages.map((page) => page.map((chunk) => ({ ...chunk, rows: [...(chunk.rows ?? [])] })));
  let i = 0;
  while (i < packed.length - 1) {
    if (!packed[i + 1].length) {
      packed.splice(i + 1, 1);
      continue;
    }
    const dest = packed[i];
    let room = capacity - pageTableUnits(dest);
    const next = packed[i + 1][0];
    const destLast = dest[dest.length - 1];
    const sameTable = Boolean(
      destLast && next && (destLast.title ?? "") === (next.title ?? "") && next.continued,
    );

    if (sameTable && next.rows.length) {
      const cap = maxManageableTableRows(destLast.columns ?? [], destLast.rows, destLast.continued);
      let pulled = 0;
      while (pulled < next.rows.length && destLast.rows.length + pulled < cap) {
        const cost = tableRowUnits(next.rows[pulled], next.columns ?? []);
        if (cost > room) break;
        destLast.rows.push(next.rows[pulled]);
        room -= cost;
        pulled += 1;
      }
      if (pulled) {
        next.rows = next.rows.slice(pulled);
        if (!next.rows.length) {
          packed[i + 1].shift();
          continue;
        }
      }
      i += 1;
      continue;
    }

    const nextCost = (dest.length ? TABLE_GAP_UNITS : 0) + tableChunkUnits(next);
    if (nextCost > 0 && nextCost <= room) {
      dest.push(packed[i + 1].shift() as PackedAnnexureChunk);
      continue;
    }

    if (room >= TABLE_MIN_SPLIT_ROOM_UNITS && next.rows.length) {
      const chrome = tableChunkChromeUnits(next.title, next.note, next.continued);
      const gap = dest.length ? TABLE_GAP_UNITS : 0;
      const first = tableRowUnits(next.rows[0], next.columns ?? []);
      const cap = maxManageableTableRows(next.columns ?? [], next.rows, next.continued);
      if (gap + chrome + first <= room) {
        let take = 0;
        let rowCost = 0;
        while (take < next.rows.length && take < cap) {
          const cost = tableRowUnits(next.rows[take], next.columns ?? []);
          if (gap + chrome + rowCost + cost > room) break;
          rowCost += cost;
          take += 1;
        }
        if (take >= 1) {
          dest.push({
            ...next,
            rows: next.rows.slice(0, take),
          });
          next.rows = next.rows.slice(take);
          next.continued = true;
          next.note = undefined;
          if (!next.rows.length) packed[i + 1].shift();
          continue;
        }
      }
    }
    i += 1;
  }
  return packed.filter((page) => page.length > 0);
}

/** Pack annexure tables onto A4 pages. Leftover body pulls the next rows/table. */
export function packAnnexureTables(
  tables: AnnexureTableSource[],
  capacity = TABLE_PAGE_UNITS,
): PackedAnnexureChunk[][] {
  const budget = Math.max(8, capacity - TABLE_PACK_SLACK_UNITS);
  const pages: PackedAnnexureChunk[][] = [];
  let current: PackedAnnexureChunk[] = [];
  let used = 0;

  const flush = () => {
    if (current.length) pages.push(current);
    current = [];
    used = 0;
  };

  for (const table of tables) {
    const rows = table.rows ?? [];
    const columns = table.columns ?? [];
    let offset = 0;
    let continued = false;

    if (rows.length === 0) {
      const chrome = tableChunkChromeUnits(table.title, table.note, continued);
      const gap = current.length ? TABLE_GAP_UNITS : 0;
      if (current.length && used + gap + chrome > budget) flush();
      const emptyGap = current.length ? TABLE_GAP_UNITS : 0;
      current.push({
        title: table.title,
        columns,
        rows: [],
        continued,
        note: table.note,
      });
      used += emptyGap + chrome;
      continue;
    }

    while (offset < rows.length) {
      const remainingRows = rows.slice(offset);
      const chrome = tableChunkChromeUnits(table.title, continued ? undefined : table.note, continued);
      const gap = current.length ? TABLE_GAP_UNITS : 0;
      const firstCost = tableRowUnits(remainingRows[0], columns);
      if (current.length && gap + chrome + firstCost > budget - used) {
        flush();
        continue;
      }

      const startChrome = chrome + (current.length ? TABLE_GAP_UNITS : 0);
      const cap = maxManageableTableRows(columns, remainingRows, continued);
      let take = 0;
      let rowCost = 0;
      while (take < remainingRows.length && take < cap) {
        const cost = tableRowUnits(remainingRows[take], columns);
        if (startChrome + rowCost + cost > budget - used) break;
        rowCost += cost;
        take += 1;
      }
      if (take <= 0) {
        if (current.length) {
          flush();
          continue;
        }
        take = 1;
        rowCost = tableRowUnits(remainingRows[0], columns);
      }

      current.push({
        title: table.title,
        columns,
        rows: remainingRows.slice(0, take),
        continued,
        note: continued ? undefined : table.note,
      });
      used += startChrome + rowCost;
      offset += take;
      continued = true;
      if (offset < rows.length) flush();
    }
  }
  if (current.length) pages.push(current);

  const packed = compactAnnexurePages(pages.filter((page) => page.length > 0), budget);
  if (annexurePagesCoverSource(tables, packed) && missingAnnexureRows(tables, packed).length === 0) {
    return packed;
  }
  const fallback = pages.filter((page) => page.length > 0);
  if (annexurePagesCoverSource(tables, fallback) && missingAnnexureRows(tables, fallback).length === 0) {
    return fallback;
  }
  return tables
    .filter((table) => (table.rows ?? []).length || (table.columns?.length ?? 0) > 0)
    .flatMap((table) => {
      const rows = table.rows ?? [];
      if (!rows.length) {
        return [[{ title: table.title, columns: table.columns ?? [], rows: [], continued: false, note: table.note }]];
      }
      return rows.map((row, idx) => [
        {
          title: table.title,
          columns: table.columns ?? [],
          rows: [row],
          continued: idx > 0,
          note: idx > 0 ? undefined : table.note,
        },
      ]);
    });
}

export function opoLineUnits(line: string): number {
  const t = line.trim();
  if (!t) return 0;
  return Math.max(1, Math.ceil(t.length / OPO_CHARS_PER_LINE));
}

export function opoCardUnits(card: string[]): number {
  const total = card.reduce((n, line) => n + opoLineUnits(line), 0);
  // Border, padding, title margin and inter-card spacing consume real vertical space.
  // Modelling that overhead lets us safely pull the next complete panel forward
  // instead of using the old overly-conservative one-card-per-page behaviour.
  return Math.max(1, total + OPO_CARD_OVERHEAD_UNITS);
}

function isOpoSectionLabel(line: string): boolean {
  return /^(?:\*\*)?(Objective|Procedure|Observation|Status)(?:\*\*)?:?$/i.test(line.trim());
}

export function takeOpoCardPrefix(card: string[], maxUnits: number): { fit: string[]; rest: string[] } {
  if (card.length === 0) return { fit: [], rest: [] };
  if (opoCardUnits(card) <= maxUnits) return { fit: card, rest: [] };
  const title = card[0] ?? "";
  const fit: string[] = [];
  let used = OPO_CARD_OVERHEAD_UNITS;
  for (let i = 0; i < card.length; i++) {
    const cost = opoLineUnits(card[i]);
    if (fit.length && used + cost > maxUnits) {
      if (cost >= maxUnits - OPO_CARD_OVERHEAD_UNITS - 2) {
        fit.push(card[i]);
        const restHuge = card.slice(i + 1);
        return { fit, rest: restHuge.length ? [title, ...restHuge] : [] };
      }
      const restBody = card.slice(i);
      // Never leave Objective/Procedure/Observation as the last line of a page.
      // Move the label with its first body line to the continuation page.
      if (fit.length > 1 && isOpoSectionLabel(fit[fit.length - 1]) && restBody.length) {
        const orphanLabel = fit.pop() as string;
        restBody.unshift(orphanLabel);
      }
      return { fit, rest: restBody.length ? [title, ...restBody] : [] };
    }
    fit.push(card[i]);
    used += cost;
  }
  return { fit, rest: [] };
}

function opoPrefixIsUseful(fit: string[]): boolean {
  if (fit.length < 3) return false;
  return fit.slice(1).some((line) => line.trim() && !isOpoSectionLabel(line));
}

export function opoPagesCoverSource(cards: string[][], pages: string[][][]): boolean {
  const seen = new Set(
    pages
      .flat(2)
      .map((line) => String(line ?? "").replace(/\s*\(continued\)\s*$/i, "").trim())
      .filter(Boolean),
  );
  return cards.every((card) => card.every((line) => !line.trim() || seen.has(line.trim())));
}

/** Pack OPO cards onto pages.
 *
 * Rules:
 *  - Keep a complete card on the current page whenever it fits.
 *  - If a complete next card does not fit but substantial room remains, place a
 *    meaningful prefix there and continue it on the next page.
 *  - If the gap is small, move the card intact instead of creating tiny fragments.
 *  - Oversized cards are split only as required by physical A4 capacity.
 *  - Never create an orphan continuation containing only the repeated title.
 */
export function paginateOpoCards(cards: string[][], capacity = OPO_PAGE_UNITS): string[][][] {
  const pages: string[][][] = [];
  let current: string[][] = [];
  let used = 0;

  const flush = () => {
    if (current.length) pages.push(current);
    current = [];
    used = 0;
  };

  for (const card of cards) {
    const cost = opoCardUnits(card);
    if (cost <= 0) continue;

    const room = capacity - used;
    if (cost <= room) {
      current.push(card);
      used += cost;
      continue;
    }

    // When a meaningful part of the next panel can use the remaining page body,
    // pull that prefix forward.  This is the report-space optimisation visible
    // in the reference layout: do not leave half a page blank merely because
    // the complete next panel is slightly too tall.  Tiny gaps are still left
    // alone so the report does not become excessively fragmented.
    let remaining = card;
    if (current.length && room >= OPO_MIN_SPLIT_ROOM_UNITS) {
      const { fit, rest } = takeOpoCardPrefix(remaining, room);
      if (opoPrefixIsUseful(fit) && rest.length) {
        current.push(fit);
        remaining = rest;
        flush();
      } else {
        flush();
      }
    } else if (current.length) {
      flush();
    }

    // If the untouched card fits on a fresh page, keep it whole.
    if (remaining.length && opoCardUnits(remaining) <= capacity) {
      current.push(remaining);
      used = opoCardUnits(remaining);
      continue;
    }

    // Oversized remainder: split only as required by physical A4 capacity.
    while (remaining.length) {
      const prevLen = remaining.length;
      const { fit, rest } = takeOpoCardPrefix(remaining, capacity);
      if (rest.length && rest.length >= prevLen && fit.length === remaining.slice(0, fit.length).length) {
        current.push(remaining);
        remaining = [];
        flush();
        break;
      }
      if (!fit.length) {
        current.push(remaining);
        remaining = [];
        flush();
        break;
      }
      current.push(fit);
      used = opoCardUnits(fit);
      remaining = rest;
      if (remaining.length) flush();
    }
  }
  if (current.length) pages.push(current);
  const packed = pullItemsForward(
    pages.filter((page) => page.length > 0),
    (card) => opoCardUnits(card),
    capacity,
  ).filter((page) => page.length > 0);
  if (!opoPagesCoverSource(cards, packed)) {
    return pages.filter((page) => page.length > 0);
  }
  return packed;
}

export type ArtifactPageChunk = {
  groupIndex: number;
  startIndex: number;
  itemCount: number;
  continued: boolean;
};

/** Pack artifact groups onto A4 pages using each item's real name/count/description height.
 * Keep a complete group on this page only when it still fits. Otherwise start the next
 * group (or continue leftover items) on a new page so Report Agent text is never clipped.
 */
export function paginateArtifactItemCosts(
  groupItemCosts: number[][],
  capacity = ARTIFACT_PAGE_UNITS,
): ArtifactPageChunk[][] {
  const pages: ArtifactPageChunk[][] = [];
  let current: ArtifactPageChunk[] = [];
  let used = 0;

  const flush = () => {
    if (current.length) pages.push(current);
    current = [];
    used = 0;
  };

  const remaining = () => capacity - used;

  groupItemCosts.forEach((itemCosts, groupIndex) => {
    const total = itemCosts.length;
    if (total === 0) {
      if (current.length && remaining() < ARTIFACT_GROUP_HEADER_UNITS) flush();
      current.push({ groupIndex, startIndex: 0, itemCount: 0, continued: false });
      used += ARTIFACT_GROUP_HEADER_UNITS;
      return;
    }

    let startIndex = 0;
    while (startIndex < total) {
      const leftCosts = itemCosts.slice(startIndex);
      const fullCost = artifactChunkCost(leftCosts);
      if (fullCost <= remaining()) {
        current.push({
          groupIndex,
          startIndex,
          itemCount: leftCosts.length,
          continued: startIndex > 0,
        });
        used += fullCost;
        startIndex = total;
        continue;
      }

      const firstItem = leftCosts[0] ?? ARTIFACT_ITEM_UNITS;
      if (current.length && remaining() < ARTIFACT_GROUP_HEADER_UNITS + firstItem) {
        flush();
        continue;
      }

      let take = 0;
      let takeCost = ARTIFACT_GROUP_HEADER_UNITS;
      while (take < leftCosts.length && takeCost + leftCosts[take] <= remaining()) {
        takeCost += leftCosts[take];
        take += 1;
      }
      if (take <= 0) {
        if (current.length) {
          flush();
          continue;
        }
        current.push({
          groupIndex,
          startIndex,
          itemCount: 1,
          continued: startIndex > 0,
        });
        used += artifactChunkCost(leftCosts.slice(0, 1));
        startIndex += 1;
        if (startIndex < total) flush();
        continue;
      }

      current.push({
        groupIndex,
        startIndex,
        itemCount: take,
        continued: startIndex > 0,
      });
      used += takeCost;
      startIndex += take;
    }
  });

  if (current.length) pages.push(current);

  return pullItemsForward(
    pages.length ? pages : [[]],
    (chunk) => {
      const costs = groupItemCosts[chunk.groupIndex] ?? [];
      return artifactChunkCost(costs.slice(chunk.startIndex, chunk.startIndex + chunk.itemCount));
    },
    capacity,
  ).filter((page) => page.length > 0);
}

/** Pack groups from item counts only (uniform fallback height). */
export function paginateArtifactItemCounts(
  itemCounts: number[],
  capacity = ARTIFACT_PAGE_UNITS,
): ArtifactPageChunk[][] {
  return paginateArtifactItemCosts(
    itemCounts.map((count) => Array.from({ length: Math.max(0, count) }, () => ARTIFACT_ITEM_UNITS)),
    capacity,
  );
}
