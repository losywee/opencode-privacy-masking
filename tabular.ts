/**
 * Tabular masking: CSV / TSV / Markdown-table / XLSX routing and column policy.
 * Zero dependencies: CSV/TSV/MD are parsed in-house; XLSX is read by parsing
 * the OOXML zip (stored + deflate entries, sharedStrings + inline strings).
 *
 * Canonical home is the repo root (`tabular.ts`); `privacy-masking/tabular.ts`
 * is a symlink to it, mirroring the other modules.
 */

export type TableFormat = "csv" | "tsv" | "md" | "xlsx";

export interface TableData {
  format: TableFormat;
  /** First row = header when the source had one, else Column 1..N labels. */
  headers: string[];
  rows: string[][];
  /** True when the source text had no header row (headers were synthesized). */
  headerless: boolean;
}

export interface TabularConfig {
  enabled: boolean;
  /** File extensions that route into the table pipeline (lowercase, with dot). */
  extensions: string[];
  /** Max bytes of a table payload/file to mask (larger => returned unchanged). */
  maxBytes: number;
  /** Max rows to scan per table (later rows pass through unchanged). */
  maxRows: number;
  /** Max columns to scan per row (later cells pass through unchanged). */
  maxColumns: number;
  /**
   * Column policy. Keys are matched case-insensitively against the header
   * (exact first, then substring). Values: "mask" (whole-cell mask),
   * "rules" (default: run regex/SLM masking inside the cell), "keep".
   */
  columns: Record<string, "mask" | "rules" | "keep">;
  /**
   * Header-name hints. A column whose header contains any of these hints
   * (case-insensitive) is whole-cell masked when no explicit column entry
   * matches. Mirrors the .env sensitive-key list.
   */
  sensitiveHints: string[];
  /** Mask whole cell when the header itself matches a sensitive hint. */
  maskHeaderMatchedCells: boolean;
}

export const DEFAULT_TABULAR_CONFIG: TabularConfig = {
  enabled: true,
  extensions: [".csv", ".tsv", ".tab", ".md", ".markdown", ".xlsx", ".xlsm"],
  maxBytes: 512 * 1024,
  maxRows: 5000,
  maxColumns: 100,
  columns: {},
  sensitiveHints: [
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "auth",
    "credential",
    "ssn",
    "social",
    "credit",
    "card",
    "bank",
    "iban",
    "phone",
    "mobile",
    "email",
    "address",
    "salary",
  ],
  maskHeaderMatchedCells: true,
};

const DEFAULT_SENSITIVE_HINTS = DEFAULT_TABULAR_CONFIG.sensitiveHints;

/** Case-insensitive substring test for normalized hints. */
function headerMatchesHint(header: string, hint: string): boolean {
  return header.toLowerCase().includes(hint.toLowerCase());
}

/**
 * Resolve the policy for a column: explicit config key first (exact, then
 * substring, case-insensitive), then sensitive-hint whole-cell masking.
 */
export function resolveColumnPolicy(
  header: string,
  cfg: Pick<TabularConfig, "columns" | "sensitiveHints" | "maskHeaderMatchedCells">,
  defaultSensitiveHints: readonly string[] = DEFAULT_SENSITIVE_HINTS
): "mask" | "rules" | "keep" {
  const name = (header || "").trim();
  const lower = name.toLowerCase();
  if (lower) {
    for (const [key, mode] of Object.entries(cfg.columns || {})) {
      if (key.toLowerCase() === lower) return mode;
    }
    for (const [key, mode] of Object.entries(cfg.columns || {})) {
      if (key && lower.includes(key.toLowerCase())) return mode;
    }
  }
  if (cfg.maskHeaderMatchedCells !== false && lower) {
    const hints =
      cfg.sensitiveHints && cfg.sensitiveHints.length > 0
        ? cfg.sensitiveHints
        : defaultSensitiveHints;
    for (const hint of hints) {
      if (hint && headerMatchesHint(name, hint)) return "mask";
    }
  }
  return "rules";
}

/**
 * Heuristic: does this text look like a table? Used to auto-route tool
 * outputs / message text that has no filename. Requires a header row plus
 * at least one data row with a consistent column count.
 */
export function detectTableFormat(text: string): TableFormat | null {
  if (!text || text.length < 8) return null;
  const sample = text.slice(0, 64 * 1024);
  const lines = sample.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length < 2) return null;
  if (isMarkdownTable(lines)) return "md";
  const first = lines[0];
  const commaCount = (first.match(/,/g) || []).length;
  const tabCount = (first.match(/\t/g) || []).length;
  const delimiter = tabCount > commaCount && tabCount >= 1 ? "\t" : commaCount >= 1 ? "," : null;
  if (!delimiter) return null;
  const widths = lines.slice(0, Math.min(lines.length, 10)).map((l) => splitDelimited(l, delimiter).length);
  const headerWidth = widths[0];
  if (headerWidth < 2) return null;
  let consistent = 0;
  for (let i = 1; i < widths.length; i++) {
    if (widths[i] === headerWidth) consistent++;
    else if (Math.abs(widths[i] - headerWidth) > 1) return null;
  }
  return consistent >= 1 ? (delimiter === "\t" ? "tsv" : "csv") : null;
}

function isMarkdownTable(lines: string[]): boolean {
  if (lines.length < 2) return false;
  const delim = lines[1].trim();
  if (!delim.includes("|") || !delim.includes("-")) return false;
  if (!/^\|?[\s|:.-]+\|?$/.test(delim)) return false;
  return lines[0].includes("|") && lines.length >= 3;
}

function splitDelimited(line: string, delimiter: string): string[] {
  if (delimiter === "\t") return line.split("\t");
  return parseCsvLine(line, ",");
}

/**
 * Minimal RFC-4180 CSV line parser: quoted fields, "" escapes, commas in quotes.
 */
export function parseCsvLine(line: string, delimiter = ","): string[] {
  const out: string[] = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQuotes) {
      if (c === '"') {
        if (line[i + 1] === '"') {
          cur += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        cur += c;
      }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === delimiter) {
      out.push(cur);
      cur = "";
    } else {
      cur += c;
    }
  }
  out.push(cur);
  return out;
}

/** Parse a full CSV/TSV document (handles multi-line quoted fields). */
export function parseDelimited(text: string, delimiter: "," | "\t"): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cur = "";
  let inQuotes = false;
  const pushCell = () => {
    row.push(cur);
    cur = "";
  };
  const pushRow = () => {
    pushCell();
    // Skip the phantom trailing row from a final newline.
    if (!(row.length === 1 && row[0] === "")) rows.push(row);
    row = [];
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          cur += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        cur += c;
      }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === delimiter) {
      pushCell();
    } else if (c === "\r") {
      if (text[i + 1] === "\n") i++;
      pushRow();
    } else if (c === "\n") {
      pushRow();
    } else {
      cur += c;
    }
  }
  pushCell();
  if (!(row.length === 1 && row[0] === "")) rows.push(row);
  return rows;
}

function csvNeedsQuote(cell: string, delimiter: string): boolean {
  return (
    cell.includes('"') ||
    cell.includes("\n") ||
    cell.includes("\r") ||
    cell.includes(delimiter)
  );
}

function escapeCsvCell(cell: string, delimiter: "," | "\t"): string {
  if (delimiter === "\t") {
    // TSV: strip structural chars so a masked value can't break columns.
    return cell.replace(/[\t\r\n]+/g, " ");
  }
  if (!csvNeedsQuote(cell, delimiter)) return cell;
  return `"${cell.replace(/"/g, '""')}"`;
}

/** Serialize rows back to CSV/TSV text (LF endings). */
export function serializeDelimited(rows: string[][], delimiter: "," | "\t"): string {
  return rows.map((r) => r.map((c) => escapeCsvCell(c, delimiter)).join(delimiter)).join("\n");
}

function splitMarkdownRow(line: string): string[] {
  let s = line.trim();
  if (s.startsWith("|")) s = s.slice(1);
  if (s.endsWith("|")) s = s.slice(0, -1);
  return s.split("|").map((c) => c.trim());
}

/** Parse a GitHub-flavored Markdown table (header + delimiter + body). */
export function parseMarkdownTable(text: string): string[][] {
  const lines = text.split(/\r?\n/);
  let start = 0;
  while (start < lines.length && lines[start].trim() === "") start++;
  const rows: string[][] = [];
  for (let i = start; i < lines.length; i++) {
    if (!lines[i].includes("|")) break;
    // Skip the alignment/delimiter row (index 1 relative to start).
    if (i === start + 1 && /^\|?[\s|:.-]+\|?$/.test(lines[i].trim())) continue;
    rows.push(splitMarkdownRow(lines[i]));
    if (rows.length === 1) continue;
  }
  return rows;
}

/** Serialize rows back to a Markdown table (pads cells; keeps alignment simple). */
export function serializeMarkdownTable(headers: string[], rows: string[][]): string {
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => (r[i] ?? "").length))
  );
  const pad = (s: string, w: number) => s + " ".repeat(Math.max(0, w - s.length));
  const line = (cells: string[]) =>
    `| ${cells.map((c, i) => pad(c, widths[i] ?? c.length)).join(" | ")} |`;
  const delim = `| ${widths.map((w) => "-".repeat(Math.max(3, w))).join(" | ")} |`;
  return [line(headers), delim, ...rows.map((r) => line(headers.map((_, i) => r[i] ?? "")))].join("\n");
}

export function parseTableText(text: string, format: TableFormat): TableData {
  let rows: string[][];
  if (format === "tsv") rows = parseDelimited(text, "\t");
  else if (format === "md") rows = parseMarkdownTable(text);
  else rows = parseDelimited(text, ",");
  if (rows.length === 0) return { format, headers: [], rows: [], headerless: true };
  const width = Math.max(...rows.map((r) => r.length));
  const normalized = rows.map((r) =>
    r.length < width ? [...r, ...Array(width - r.length).fill("")] : r.slice(0, width)
  );
  const looksHeaderless = normalized.length > 1 && looksDataRow(normalized[0]);
  if (looksHeaderless) {
    return {
      format,
      headers: Array.from({ length: width }, (_, i) => `Column ${i + 1}`),
      rows: normalized,
      headerless: true,
    };
  }
  const [header, ...body] = normalized;
  return { format, headers: header, rows: body, headerless: false };
}

const DATA_CELL_RE = /^[\d\s$€£¥₹.,()%+/-]*$|^\d{4}-\d{2}-\d{2}/;

/** A row of numbers/dates/empties is data, not a header. */
function looksDataRow(row: string[]): boolean {
  let data = 0;
  let words = 0;
  for (const cell of row) {
    const c = cell.trim();
    if (!c) continue;
    if (DATA_CELL_RE.test(c)) data++;
    else if (/[A-Za-z]{2,}/.test(c)) words++;
  }
  return data > 0 && words === 0;
}

export function serializeTable(table: TableData, rows: string[][]): string {
  if (table.format === "tsv") return serializeDelimited([table.headers, ...rows].slice(table.headerless ? 1 : 0), "\t");
  if (table.format === "md") return serializeMarkdownTable(table.headers, table.headerless ? rows.slice(1) : rows);
  return serializeDelimited(table.headerless ? rows : [table.headers, ...rows], ",");
}

// ---------------------------------------------------------------------------
// XLSX: minimal OOXML reader (sharedStrings + first sheet, inline strings).
// ---------------------------------------------------------------------------

const ZIP_LOCAL_HEADER = 0x04034b50;
const ZIP_CENTRAL_HEADER = 0x02014b50;
const ZIP_EOCD = 0x06054b50;

interface ZipEntry {
  name: string;
  data: Buffer;
}

/** CRC-32 (IEEE) for building the masked XLSX we write back. */
function crc32(buf: Buffer): number {
  let table = (crc32 as any)._table as Int32Array | undefined;
  if (!table) {
    table = new Int32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      table[n] = c;
    }
    (crc32 as any)._table = table;
  }
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) crc = table[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

/** Parse a zip archive (stored + deflate), enough for OOXML workbooks. */
export function parseZip(buf: Buffer): Map<string, Buffer> {
  const out = new Map<string, Buffer>();
  // Walk central directory when present; fall back to local headers.
  const eocd = findSignature(buf, ZIP_EOCD);
  if (eocd >= 0) {
    const count = buf.readUInt16LE(eocd + 10);
    let ptr = buf.readUInt32LE(eocd + 16);
    for (let i = 0; i < count; i++) {
      if (buf.readUInt32LE(ptr) !== ZIP_CENTRAL_HEADER) break;
      const method = buf.readUInt16LE(ptr + 10);
      const compSize = buf.readUInt32LE(ptr + 24);
      const nameLen = buf.readUInt16LE(ptr + 28);
      const extraLen = buf.readUInt16LE(ptr + 30);
      const commentLen = buf.readUInt16LE(ptr + 32);
      const headerOffset = buf.readUInt32LE(ptr + 42);
      const name = buf.toString("utf8", ptr + 46, ptr + 46 + nameLen);
      const data = extractFileData(buf, headerOffset, compSize, method);
      if (data && !name.endsWith("/")) out.set(name, data);
      ptr += 46 + nameLen + extraLen + commentLen;
    }
    if (out.size > 0) return out;
  }
  // Fallback: linear scan of local file headers.
  let ptr = 0;
  while (ptr + 30 <= buf.length) {
    if (buf.readUInt32LE(ptr) !== ZIP_LOCAL_HEADER) {
      ptr++;
      continue;
    }
    const method = buf.readUInt16LE(ptr + 8);
    const compSize = buf.readUInt32LE(ptr + 18);
    const nameLen = buf.readUInt16LE(ptr + 26);
    const extraLen = buf.readUInt16LE(ptr + 28);
    const name = buf.toString("utf8", ptr + 30, ptr + 30 + nameLen);
    const dataStart = ptr + 30 + nameLen + extraLen;
    const data = extractFileData(buf, ptr, compSize, method, dataStart);
    if (data && !name.endsWith("/")) out.set(name, data);
    ptr = dataStart + compSize;
  }
  return out;
}

function findSignature(buf: Buffer, sig: number): number {
  const min = Math.max(0, buf.length - 22 - 65536);
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === sig) return i;
  }
  return -1;
}

function extractFileData(
  buf: Buffer,
  headerOffset: number,
  compSize: number,
  method: number,
  dataStart?: number
): Buffer | null {
  try {
    let start = dataStart;
    if (start === undefined) {
      const nameLen = buf.readUInt16LE(headerOffset + 26);
      const extraLen = buf.readUInt16LE(headerOffset + 28);
      start = headerOffset + 30 + nameLen + extraLen;
    }
    const raw = buf.subarray(start, start + compSize);
    if (method === 0) return Buffer.from(raw);
    if (method === 8) {
      const { inflateRawSync } = require("node:zlib") as typeof import("node:zlib");
      return Buffer.from(inflateRawSync(raw));
    }
    return null;
  } catch {
    return null;
  }
}

/** Build a minimal stored (uncompressed) zip for the masked workbook. */
export function buildZip(files: Map<string, Buffer>): Buffer {
  const chunks: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const [name, data] of files) {
    const nameBuf = Buffer.from(name, "utf8");
    const crc = crc32(data);
    const local = Buffer.alloc(30 + nameBuf.length);
    local.writeUInt32LE(ZIP_LOCAL_HEADER, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6); // flags (no data descriptor, UTF-8 off — names are ASCII)
    local.writeUInt16LE(0, 8); // stored
    local.writeUInt16LE(0, 10); // time
    local.writeUInt16LE(0, 12); // date
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28);
    nameBuf.copy(local, 30);
    chunks.push(local, data);

    const cen = Buffer.alloc(46 + nameBuf.length);
    cen.writeUInt32LE(ZIP_CENTRAL_HEADER, 0);
    cen.writeUInt16LE(20, 4); // version made by
    cen.writeUInt16LE(20, 6); // version needed
    cen.writeUInt16LE(0, 8);
    cen.writeUInt16LE(0, 10); // stored
    cen.writeUInt16LE(0, 12);
    cen.writeUInt16LE(0, 14);
    cen.writeUInt32LE(crc, 16);
    cen.writeUInt32LE(data.length, 20);
    cen.writeUInt32LE(data.length, 24);
    cen.writeUInt16LE(nameBuf.length, 26);
    cen.writeUInt16LE(0, 28);
    cen.writeUInt16LE(0, 30);
    cen.writeUInt16LE(0, 32);
    cen.writeUInt16LE(0, 34);
    cen.writeUInt32LE(0, 36);
    cen.writeUInt32LE(offset, 38);
    nameBuf.copy(cen, 42);
    central.push(cen);
    offset += local.length + data.length;
  }
  const centralDir = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(ZIP_EOCD, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(files.size, 8);
  end.writeUInt16LE(files.size, 10);
  end.writeUInt32LE(centralDir.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);
  return Buffer.concat([...chunks, centralDir, end]);
}

function decodeXmlEntities(s: string): string {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

function encodeXmlEntities(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** Extract ordered shared strings from xl/sharedStrings.xml. */
export function parseSharedStrings(xml: string): string[] {
  const out: string[] = [];
  const siRe = /<si>([\s\S]*?)<\/si>/g;
  let m: RegExpExecArray | null;
  while ((m = siRe.exec(xml)) !== null) {
    const tRe = /<t(?:\s[^>]*)?>([\s\S]*?)<\/t>/g;
    let text = "";
    let t: RegExpExecArray | null;
    while ((t = tRe.exec(m[1])) !== null) text += decodeXmlEntities(t[1]);
    out.push(text);
  }
  return out;
}

export function serializeSharedStrings(strings: string[]): string {
  const items = strings
    .map((s) => `<si><t xml:space="preserve">${encodeXmlEntities(s)}</t></si>`)
    .join("");
  return (
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" ` +
    `count="${strings.length}" uniqueCount="${strings.length}">${items}</sst>`
  );
}

export interface SheetCell {
  ref: string; // e.g. "B2"
  row: number; // 1-based
  col: number; // 1-based
  type: string; // "s" shared, "inlineStr", "str", "" numeric, ...
  value: string; // raw <v> text or inline <t> text
}

/** Column letters (A, AB) -> 1-based column number. */
export function colLettersToNumber(letters: string): number {
  let n = 0;
  for (const ch of letters.toUpperCase()) n = n * 26 + (ch.charCodeAt(0) - 64);
  return n;
}

export function colNumberToLetters(n: number): string {
  let s = "";
  while (n > 0) {
    const r = (n - 1) % 26;
    s = String.fromCharCode(65 + r) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

function refToRowCol(ref: string): { row: number; col: number } | null {
  const m = /^([A-Za-z]+)(\d+)$/.exec(ref);
  if (!m) return null;
  return { row: parseInt(m[2], 10), col: colLettersToNumber(m[1]) };
}

/** Parse <c> cells from a worksheet XML (shared + inline strings). */
export function parseSheetCells(xml: string): SheetCell[] {
  const cells: SheetCell[] = [];
  const cRe = /<c\b([^>]*)>([\s\S]*?)<\/c>|<c\b([^>]*)\/>/g;
  let m: RegExpExecArray | null;
  while ((m = cRe.exec(xml)) !== null) {
    const attrs = m[1] ?? m[3] ?? "";
    const inner = m[2] ?? "";
    const refM = /r="([A-Za-z]+\d+)"/.exec(attrs);
    if (!refM) continue;
    const rc = refToRowCol(refM[1]);
    if (!rc) continue;
    const tM = /t="([^"]*)"/.exec(attrs);
    const type = tM ? tM[1] : "";
    let value = "";
    if (type === "inlineStr") {
      const t = /<t(?:\s[^>]*)?>([\s\S]*?)<\/t>/.exec(inner);
      value = t ? decodeXmlEntities(t[1]) : "";
    } else {
      const v = /<v>([\s\S]*?)<\/v>/.exec(inner);
      value = v ? v[1].trim() : "";
    }
    cells.push({ ref: refM[1], row: rc.row, col: rc.col, type, value });
  }
  return cells.sort((a, b) => a.row - b.row || a.col - b.col);
}

/**
 * Read the first worksheet of an XLSX buffer into a TableData.
 * Only string cells (shared/inline) participate; numbers/dates pass through.
 */
export function parseXlsx(buf: Buffer): TableData | null {
  let files: Map<string, Buffer>;
  try {
    files = parseZip(buf);
  } catch {
    return null;
  }
  const sheetNames = [...files.keys()].filter((n) => /^xl\/worksheets\/sheet\d+\.xml$/.test(n)).sort();
  if (sheetNames.length === 0) return null;
  const sheetXml = files.get(sheetNames[0])!.toString("utf8");
  let shared: string[] = [];
  const sharedXml = files.get("xl/sharedStrings.xml");
  if (sharedXml) {
    try {
      shared = parseSharedStrings(sharedXml.toString("utf8"));
    } catch {
      shared = [];
    }
  }
  const cells = parseSheetCells(sheetXml);
  if (cells.length === 0) return { format: "xlsx", headers: [], rows: [], headerless: true };
  const maxRow = Math.max(...cells.map((c) => c.row));
  const maxCol = Math.max(...cells.map((c) => c.col));
  if (maxRow < 1 || maxCol < 1) return { format: "xlsx", headers: [], rows: [], headerless: true };
  const grid: string[][] = Array.from({ length: maxRow }, () => Array(maxCol).fill(""));
  for (const c of cells) {
    let text = "";
    if (c.type === "s") {
      const idx = parseInt(c.value, 10);
      text = Number.isFinite(idx) && idx >= 0 && idx < shared.length ? shared[idx] : "";
    } else if (c.type === "inlineStr" || c.type === "str") {
      text = c.value;
    } else {
      continue; // numeric/bool/date/formula result — leave untouched
    }
    grid[c.row - 1][c.col - 1] = text;
  }
  // Trim trailing empty rows/cols (sparse sheets).
  while (grid.length > 0 && grid[grid.length - 1].every((c) => c === "")) grid.pop();
  let width = Math.max(0, ...grid.map((r) => r.length));
  while (width > 0 && grid.every((r) => (r[width - 1] ?? "") === "")) width--;
  const trimmed = grid.map((r) => r.slice(0, width));
  if (trimmed.length === 0 || width === 0)
    return { format: "xlsx", headers: [], rows: [], headerless: true };
  const looksHeaderless = trimmed.length > 1 && looksDataRow(trimmed[0]);
  if (looksHeaderless) {
    return {
      format: "xlsx",
      headers: Array.from({ length: width }, (_, i) => `Column ${i + 1}`),
      rows: trimmed,
      headerless: true,
    };
  }
  const [header, ...body] = trimmed;
  return { format: "xlsx", headers: header, rows: body, headerless: false };
}

/**
 * Rewrite the first worksheet with masked strings. New masked values are
 * appended to sharedStrings (original entries untouched); inline strings are
 * rewritten in place. Returns the new XLSX bytes, or null if not an XLSX.
 */
export function buildMaskedXlsx(
  original: Buffer,
  maskCell: (header: string, value: string, rowIdx: number, colIdx: number) => string | null
): Buffer | null {
  let files: Map<string, Buffer>;
  try {
    files = parseZip(original);
  } catch {
    return null;
  }
  const sheetNames = [...files.keys()].filter((n) => /^xl\/worksheets\/sheet\d+\.xml$/.test(n)).sort();
  if (sheetNames.length === 0) return null;
  const sheetName = sheetNames[0];
  const sheetXml = files.get(sheetName)!.toString("utf8");
  let shared: string[] = [];
  const sharedXml = files.get("xl/sharedStrings.xml");
  if (sharedXml) {
    try {
      shared = parseSharedStrings(sharedXml.toString("utf8"));
    } catch {
      shared = [];
    }
  }
  const cells = parseSheetCells(sheetXml);
  if (cells.length === 0) return null;
  const maxRow = Math.max(...cells.map((c) => c.row));
  const maxCol = Math.max(...cells.map((c) => c.col));
  const grid: (string | null)[][] = Array.from({ length: maxRow }, () => Array(maxCol).fill(null));
  const cellType: string[][] = Array.from({ length: maxRow }, () => Array(maxCol).fill(""));
  for (const c of cells) {
    let text: string | null = null;
    if (c.type === "s") {
      const idx = parseInt(c.value, 10);
      text = Number.isFinite(idx) && idx >= 0 && idx < shared.length ? shared[idx] : "";
    } else if (c.type === "inlineStr" || c.type === "str") {
      text = c.value;
    } else {
      continue;
    }
    grid[c.row - 1][c.col - 1] = text ?? "";
    cellType[c.row - 1][c.col - 1] = c.type;
  }
  const width = maxCol;
  const headerRow = grid[0] ?? [];
  const headerless = grid.length > 1 && looksDataRow((headerRow as string[]).map((c) => c ?? ""));
  const headers = headerless
    ? Array.from({ length: width }, (_, i) => `Column ${i + 1}`)
    : (headerRow as string[]).map((c) => c ?? "");
  const startRow = headerless ? 0 : 1;

  // Replacement map: "row,col" -> shared-string index (for s cells) or literal (inline).
  const sharedIndex = new Map<string, number>(shared.map((s, i) => [s, i]));
  const replacements = new Map<string, { sharedIdx?: number; literal?: string }>();
  for (let r = startRow; r < grid.length; r++) {
    for (let c = 0; c < width; c++) {
      const val = grid[r]?.[c];
      if (val === null || val === undefined || val === "") continue;
      const masked = maskCell(headers[c] ?? `Column ${c + 1}`, val, r, c);
      if (masked === null || masked === val) continue;
      let idx = sharedIndex.get(masked);
      if (idx === undefined) {
        idx = shared.length;
        shared.push(masked);
        sharedIndex.set(masked, idx);
      }
      replacements.set(`${r},${c}`, { sharedIdx: idx });
    }
  }
  if (replacements.size === 0) return null; // nothing to change — keep original bytes

  const newSheetXml = sheetXml.replace(
    /<c\b([^>]*)>([\s\S]*?)<\/c>|<c\b([^>]*)\/>/g,
    (whole, attrs: string, inner: string, selfAttrs: string) => {
      const a = attrs ?? selfAttrs ?? "";
      const refM = /r="([A-Za-z]+\d+)"/.exec(a);
      if (!refM) return whole;
      const rc = refToRowCol(refM[1]);
      if (!rc) return whole;
      const rep = replacements.get(`${rc.row - 1},${rc.col - 1}`);
      if (rep?.sharedIdx === undefined) return whole;
      const tM = /t="([^"]*)"/.exec(a);
      const type = tM ? tM[1] : "";
      const newAttrs = type
        ? a.replace(/t="[^"]*"/, 't="s"')
        : `${a} t="s"`;
      return `<c ${newAttrs.trim()}><v>${rep.sharedIdx}</v></c>`;
    }
  );
  files.set(sheetName, Buffer.from(newSheetXml, "utf8"));
  files.set("xl/sharedStrings.xml", Buffer.from(serializeSharedStrings(shared), "utf8"));
  // Content-Types must list sharedStrings (normally already does; add if missing).
  const ctName = "[Content_Types].xml";
  const ct = files.get(ctName)?.toString("utf8");
  if (ct && !ct.includes("sharedStrings.xml")) {
    files.set(
      ctName,
      Buffer.from(
        ct.replace(
          "</Types>",
          `<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/></Types>`
        ),
        "utf8"
      )
    );
  }
  return buildZip(files);
}

/** Route a filename to a table format (null = not a table file). */
export function formatForExtension(filePath: string): TableFormat | null {
  const lower = filePath.toLowerCase();
  if (lower.endsWith(".csv")) return "csv";
  if (lower.endsWith(".tsv") || lower.endsWith(".tab")) return "tsv";
  if (lower.endsWith(".md") || lower.endsWith(".markdown")) return "md";
  if (lower.endsWith(".xlsx") || lower.endsWith(".xlsm")) return "xlsx";
  return null;
}

/** XLSX magic bytes (PK.. + [Content_Types].xml nearby) vs legacy OLE .xls. */
export function looksLikeXlsx(buf: Buffer): boolean {
  if (buf.length < 4 || buf[0] !== 0x50 || buf[1] !== 0x4b) return false;
  const head = buf.subarray(0, Math.min(buf.length, 4096)).toString("latin1");
  if (head.includes("[Content_Types].xml")) return true;
  // Fallback: any sheet/shared-string part name implies OOXML workbook.
  return head.includes("xl/worksheets") || head.includes("xl/sharedStrings.xml");
}

/** Legacy OLE .xls (cannot safely rewrite) — detect to refuse loudly. */
export function looksLikeLegacyXls(buf: Buffer, filePath?: string): boolean {
  if (typeof filePath === "string" && filePath.toLowerCase().endsWith(".xls")) return true;
  return (
    buf.length >= 8 &&
    buf[0] === 0xd0 &&
    buf[1] === 0xcf &&
    buf[2] === 0x11 &&
    buf[3] === 0xe0 &&
    buf[4] === 0xa1 &&
    buf[5] === 0xb1 &&
    buf[6] === 0x1a &&
    buf[7] === 0xe1
  );
}
