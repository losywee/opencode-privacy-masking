/**
 * Core RedactStore engine: O((P+F) log P) interval exclusion, Sticky Masking,
 * and single-pass O(N) restoration.
 * Place inside: `.opencode/plugins/privacy-masking/store.ts`
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import type { MaskingConfig, Span } from "./config";
import {
  hmacBase32,
  hostStandInOf,
  ipStandInOf,
  loadOrCreateHmacKey,
  sha256,
} from "./crypto";
import { LocalModelDetector } from "./local-model";
import { EXISTING_TOKEN_RE, isRealBase64DataUrl, RULES } from "./rules";
import {
  buildMaskedXlsx,
  detectTableFormat,
  formatForExtension,
  looksLikeLegacyXls,
  looksLikeXlsx,
  markdownTableCoversText,
  parseTableText,
  parseXlsxSheets,
  resolveColumnPolicy,
  serializeTable,
  type TableData,
  type TableFormat,
} from "./tabular";

interface Interval {
  start: number;
  end: number;
}

/**
 * Coarse character class for exact-term boundary checks. Neighbors in the
 * same class as the term's edge character indicate a longer token (e.g. an
 * alphanumeric neighbor next to an alphanumeric edge, or a `.`/`@` neighbor
 * next to a `.`/`@` edge in IPs and emails).
 */
function charClass(c: string): string {
  if (/[A-Za-z0-9_]/.test(c)) return "word";
  if (c === "-" || c === ".") return "sep";
  if (c === "@") return "at";
  return "other";
}

export class RedactStore {
  private readonly key: Buffer;
  public readonly config: MaskingConfig;
  private readonly detector: LocalModelDetector;
  private readonly placeholderToReal = new Map<string, string>();
  private readonly realToPlaceholder = new Map<string, string>();
  // Learned exact terms. Bounded like the other maps: FIFO eviction at
  // maxMemoryValues so long sessions cannot grow memory without limit.
  private readonly knownValues = new Map<string, string>();
  private readonly envSecrets = new Set<string>();

  // Sticky Masking: maps rawHash -> frozenMaskedOutput, and tracks already-masked hashes
  private readonly stickyByRawHash = new Map<string, string>();
  private readonly stickyMaskedHashes = new Set<string>();
  public hasMaskedAny = false;

  constructor(config: MaskingConfig, projectDir?: string) {
    this.key = loadOrCreateHmacKey();
    this.config = config;
    this.detector = new LocalModelDetector(config.localModel);
    if (config.scanDotEnv && projectDir) {
      this.loadEnvFiles(projectDir);
    }
    for (const w of config.words) {
      if (w.trim().length > 0) this.envSecrets.add(w);
    }
  }

  private loadEnvFiles(projectDir: string): void {
    const SENSITIVE_KEY_RE = /key|secret|token|password|passwd|auth|cred|dsn|private|cert|sign/i;
    for (const file of this.config.envFiles) {
      const fullPath = join(projectDir, file);
      if (!existsSync(fullPath)) continue;
      try {
        const content = readFileSync(fullPath, "utf8");
        for (const rawLine of content.split(/\r?\n/)) {
          const line = rawLine.trim();
          if (!line || line.startsWith("#")) continue;
          const eqIdx = line.indexOf("=");
          if (eqIdx <= 0) continue;
          const key = line.slice(0, eqIdx).trim();
          let val = line.slice(eqIdx + 1).trim();
          if (
            (val.startsWith('"') && val.endsWith('"')) ||
            (val.startsWith("'") && val.endsWith("'"))
          ) {
            val = val.slice(1, -1);
          }
          if (
            val.length >= this.config.minEnvValueLength &&
            !this.isAllowed(val) &&
            (SENSITIVE_KEY_RE.test(key) ||
              (!/^(true|false|development|production|staging|test|local|verbose|debug|info|warn|error)$/i.test(val) &&
                val.length >= 16))
          ) {
            this.envSecrets.add(val);
          }
        }
      } catch {
        // Ignore unreadable .env files
      }
    }
  }

  private isAllowed(value: string): boolean {
    return this.config.allow.some((a) => a === value);
  }

  /**
   * Pre-computes sorted intervals of existing placeholders and stand-ins once per text
   * so overlap checks run in O(log P) via binary search (mirrors magpie Issue #4766).
   */
  private extractExistingIntervals(text: string): Interval[] {
    const intervals: Interval[] = [];
    EXISTING_TOKEN_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = EXISTING_TOKEN_RE.exec(text)) !== null) {
      intervals.push({ start: m.index, end: m.index + m[0].length });
    }
    return intervals;
  }

  private overlapsIntervals(intervals: Interval[], start: number, end: number): boolean {
    let lo = 0;
    let hi = intervals.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      const iv = intervals[mid];
      if (end <= iv.start) {
        hi = mid - 1;
      } else if (start >= iv.end) {
        lo = mid + 1;
      } else {
        return true;
      }
    }
    return false;
  }

  private hasOddLeadingBackslashes(text: string, start: number): boolean {
    let count = 0;
    for (let i = start - 1; i >= 0 && text[i] === "\\"; i--) {
      count++;
    }
    return count % 2 === 1;
  }

  private makePlaceholder(kind: string, value: string): string {
    const existing = this.realToPlaceholder.get(value);
    if (existing) {
      const real = this.placeholderToReal.get(existing);
      if (real !== undefined) {
        this.placeholderToReal.delete(existing);
        this.placeholderToReal.set(existing, real);
      }
      return existing;
    }
    let placeholder: string;
    if (this.config.preserveShape && kind === "IP") {
      let host = ipStandInOf(this.key, value);
      let attempts = 0;
      let hostByte = Number(host.split(".")[3]) || 1;
      while (
        this.placeholderToReal.has(host) &&
        this.placeholderToReal.get(host) !== value &&
        attempts < 253
      ) {
        hostByte = (hostByte % 253) + 1;
        host = `203.0.113.${hostByte}`;
        attempts++;
      }
      if (
        this.placeholderToReal.has(host) &&
        this.placeholderToReal.get(host) !== value
      ) {
        const hash = hmacBase32(this.key, kind, value, 8);
        placeholder = `{{${kind}_${hash}}}`;
      } else {
        placeholder = host;
      }
    } else if (this.config.preserveShape && kind === "IPV6") {
      let host = this.makeIpv6StandIn(value);
      if (
        this.placeholderToReal.has(host) &&
        this.placeholderToReal.get(host) !== value
      ) {
        // Documentation-range collision is near-impossible (2^64 space);
        // fall back to an opaque placeholder rather than corrupting a mapping.
        const hash = hmacBase32(this.key, kind, value, 8);
        placeholder = `{{${kind}_${hash}}}`;
      } else {
        placeholder = host;
      }
    } else if (this.config.preserveShape && kind === "HOSTNAME") {
      let host = hostStandInOf(this.key, value);
      if (
        this.placeholderToReal.has(host) &&
        this.placeholderToReal.get(host) !== value
      ) {
        const hash = hmacBase32(this.key, kind, value, 8);
        placeholder = `{{${kind}_${hash}}}`;
      } else {
        placeholder = host;
      }
    } else {
      const hash = hmacBase32(this.key, kind, value, 8);
      placeholder = `{{${kind}_${hash}}}`;
    }

    if (this.placeholderToReal.size >= this.config.maxMemoryValues) {
      const oldestKey = this.placeholderToReal.keys().next().value;
      if (oldestKey) {
        const oldestVal = this.placeholderToReal.get(oldestKey);
        this.placeholderToReal.delete(oldestKey);
        if (oldestVal) this.realToPlaceholder.delete(oldestVal);
      }
    }
    this.placeholderToReal.set(placeholder, value);
    this.realToPlaceholder.set(value, placeholder);
    return placeholder;
  }

  /**
   * Deterministic stand-in for IPv6: maps the full address into the
   * documentation range `2001:db8::/32` so masked logs keep their shape
   * (colon groups, scope suffix) while remaining non-routable.
   * Emits a full 8-hextet address (2001:db8 + 6 derived groups = 128 bits)
   * so standard validators (net.isIPv6, inet_pton) accept it.
   */
  private makeIpv6StandIn(value: string): string {
    const scopeIdx = value.indexOf("%");
    const scope = scopeIdx !== -1 ? value.slice(scopeIdx) : "";
    const addr = scopeIdx !== -1 ? value.slice(0, scopeIdx) : value;
    const hex = sha256(`IPV6\0${addr.toLowerCase()}`);
    const groups = [
      hex.slice(0, 4),
      hex.slice(4, 8),
      hex.slice(8, 12),
      hex.slice(12, 16),
      hex.slice(16, 20),
      hex.slice(20, 24),
    ];
    return `2001:db8:${groups.join(":")}${scope}`;
  }

  private collectRuleSpans(text: string, asJsonText: boolean, existing: Interval[]): Span[] {
    const spans: Span[] = [];

    for (const rule of RULES) {
      if (rule.category === "secret" && !this.config.secrets) continue;
      if (rule.category === "personal" && !this.config.personal) continue;

      rule.re.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = rule.re.exec(text)) !== null) {
        const value = rule.group ? match[rule.group] : match[0];
        if (!value) continue;
        let start: number;
        let end: number;
        const indices = (match as any).indices;
        if (rule.group && indices?.[rule.group]) {
          [start, end] = indices[rule.group];
        } else if (rule.group) {
          let searchFrom = 0;
          if (rule.group === 2 && match[1]) {
            const g1Idx = match[0].indexOf(match[1]);
            if (g1Idx !== -1) searchFrom = g1Idx + match[1].length;
          }
          const relIdx = match[0].indexOf(value, searchFrom);
          start = match.index + (relIdx !== -1 ? relIdx : match[0].indexOf(value));
          end = start + value.length;
        } else {
          start = match.index;
          end = start + value.length;
        }

        if (this.isAllowed(value)) continue;
        if (this.overlapsIntervals(existing, start, end)) continue;
        if (asJsonText && this.hasOddLeadingBackslashes(text, start)) continue;
        if (rule.validate && !rule.validate(value, text, start)) continue;

        const shouldLearn = rule.learn ? rule.learn(value, text, start) : true;
        spans.push({
          start,
          end,
          kind: rule.kind,
          value,
          placeholder: this.makePlaceholder(rule.kind, value),
          learn: shouldLearn,
        });
      }
    }

    const exactTerms = new Map<string, string>();
    for (const s of this.envSecrets) exactTerms.set(s, "SECRET");
    for (const [val, kind] of this.knownValues) exactTerms.set(val, kind);

    for (const [val, kind] of exactTerms) {
      if (val.length < 4 || this.isAllowed(val)) continue;
      let idx = 0;
      while ((idx = text.indexOf(val, idx)) !== -1) {
        const end = idx + val.length;
        // Boundary check on BOTH sides for every term, not just
        // alphanumeric ones: "198.51.100.4" must not match inside
        // "198.51.100.42", and "user@example.com" must not match inside
        // "superuser@example.com". A neighbor char of the same class as the
        // term's edge char means we are inside a longer token.
        let wordBoundary = true;
        const first = val[0];
        const last = val[val.length - 1];
        const before = idx > 0 ? text[idx - 1] : "";
        const after = end < text.length ? text[end] : "";
        if (before && charClass(before) === charClass(first)) wordBoundary = false;
        else if (after && charClass(after) === charClass(last)) wordBoundary = false;
        if (
          wordBoundary &&
          !this.overlapsIntervals(existing, idx, end) &&
          !(asJsonText && this.hasOddLeadingBackslashes(text, idx))
        ) {
          spans.push({
            start: idx,
            end,
            kind,
            value: val,
            placeholder: this.makePlaceholder(kind, val),
            learn: false,
          });
        }
        idx = end;
      }
    }

    return spans;
  }

  private applySpans(text: string, spans: Span[]): string {
    if (spans.length === 0) return text;

    spans.sort((a, b) => a.start - b.start || b.end - a.end);
    const chosen: Span[] = [];
    let cursor = 0;
    for (const s of spans) {
      if (s.start < cursor) continue;
      chosen.push(s);
      cursor = s.end;
      if (s.learn) this.learnValue(s.value, s.kind);
      this.hasMaskedAny = true;
    }

    let result = "";
    let pos = 0;
    for (const s of chosen) {
      result += text.slice(pos, s.start) + s.placeholder;
      pos = s.end;
    }
    result += text.slice(pos);
    return result;
  }

  /** Learned exact term with FIFO eviction at maxMemoryValues. */
  private learnValue(value: string, kind: string): void {
    if (this.knownValues.has(value)) {
      this.knownValues.delete(value);
      this.knownValues.set(value, kind);
      return;
    }
    if (this.knownValues.size >= this.config.maxMemoryValues) {
      const oldest = this.knownValues.keys().next().value;
      if (oldest !== undefined) this.knownValues.delete(oldest);
    }
    this.knownValues.set(value, kind);
  }

  private recordSticky(rawHash: string, maskedText: string): void {
    if (!this.config.localModel.sticky) return;
    if (this.stickyByRawHash.size >= this.config.maxMemoryValues) {
      const oldest = this.stickyByRawHash.keys().next().value;
      if (oldest) {
        const oldMasked = this.stickyByRawHash.get(oldest);
        if (oldMasked) this.stickyMaskedHashes.delete(sha256(oldMasked));
        this.stickyByRawHash.delete(oldest);
      }
    }
    this.stickyByRawHash.set(rawHash, maskedText);
    this.stickyMaskedHashes.add(sha256(maskedText));
  }

  public async maskAsync(
    text: string,
    asJsonText = false,
    turnDeadline = Date.now() + this.config.localModel.timeoutMs
  ): Promise<string> {
    if (!text || text.length < 4 || isRealBase64DataUrl(text)) return text;

    // Auto-route table-shaped text (CSV/TSV/Markdown tables pasted into chat
    // or returned by tools) into the column-aware pipeline. Byte cap doubles
    // as a cost guard AND a correctness guard: above it, text passes through
    // 100% unchanged, so oversized tables are never partially masked.
    // NOTE: the cap is enforced BEFORE sticky lookup so large tables can
    // never be served a partially-masked cached copy either.
    const byteLen = Buffer.byteLength(text, "utf8");
    if (byteLen > this.config.tabular.maxBytes) return text;
    if (this.config.tabular.enabled) {
      const tableFormat = detectTableFormat(text);
      if (tableFormat && tableFormat !== "xlsx") {
        const routed = await this.maskTableTextAsync(text, tableFormat, turnDeadline);
        if (routed !== null) return routed;
        // Fall through to scalar masking when the table parse yields nothing.
      }
    }

    const rawHash = sha256(text);
    if (this.config.localModel.sticky) {
      // If text is already the frozen masked output or was previously masked from rawHash, return as-is
      if (this.stickyMaskedHashes.has(rawHash)) return text;
      const frozen = this.stickyByRawHash.get(rawHash);
      if (frozen !== undefined) return frozen;
    }

    const existingIntervals = this.extractExistingIntervals(text);
    const ruleSpans = this.collectRuleSpans(text, asJsonText, existingIntervals);
    const ruleMasked = this.applySpans(text, ruleSpans);

    if (
      !this.config.personal ||
      !this.config.localModel.enabled ||
      Date.now() >= turnDeadline
    ) {
      this.recordSticky(rawHash, ruleMasked);
      return ruleMasked;
    }

    const modelHits = await this.detector.findSpans(ruleMasked, turnDeadline);
    if (modelHits.length === 0) {
      this.recordSticky(rawHash, ruleMasked);
      return ruleMasked;
    }

    const postRuleIntervals = this.extractExistingIntervals(ruleMasked);
    const modelSpans: Span[] = [];
    for (const hit of modelHits) {
      const value = ruleMasked.slice(hit.start, hit.end);
      if (!value || this.isAllowed(value)) continue;
      if (this.overlapsIntervals(postRuleIntervals, hit.start, hit.end)) continue;
      if (asJsonText && this.hasOddLeadingBackslashes(ruleMasked, hit.start)) continue;
      modelSpans.push({
        start: hit.start,
        end: hit.end,
        kind: hit.kind,
        value,
        placeholder: this.makePlaceholder(hit.kind, value),
        learn: true,
      });
    }

    const finalMasked = this.applySpans(ruleMasked, modelSpans);
    this.recordSticky(rawHash, finalMasked);
    return finalMasked;
  }

  // ------------------------------------------------------------------
  // Tabular masking: column-aware CSV/TSV/Markdown/XLSX pipeline.
  // ------------------------------------------------------------------

  /**
   * Mask one table cell according to its column policy, reusing the exact
   * same primitive the scalar pipeline uses (maskAsync). "mask" forces a
   * whole-cell placeholder even when no rule fires (e.g. a name no regex or
   * SLM run would catch); "rules" runs normal masking; "keep" skips.
   */
  private async maskTableCellAsync(
    header: string,
    value: string,
    turnDeadline: number
  ): Promise<string> {
    if (!value) return value;
    // Exact learned secrets (sticky .env / seen values) always win, even in
    // "keep" columns: a real secret must never pass through because its
    // column header looked innocent.
    const exactHit = this.findExactTerm(value);
    if (exactHit) {
      const placeholder = this.makePlaceholder(exactHit.kind, value);
      this.learnValue(value, exactHit.kind);
      this.hasMaskedAny = true;
      return placeholder;
    }
    const policy = resolveColumnPolicy(header, this.config.tabular);
    if (policy === "keep") return value;
    // "mask" AND "rules" both run the scalar rule/SLM pipeline first, so
    // emails, secrets, and IPs in body cells are masked even when the column
    // header is generic ("Column 1") or the table was auto-detected. "mask"
    // additionally forces a whole-cell placeholder when no rule fires.
    const viaRules = await this.maskCellRulesAsync(value, turnDeadline);
    if (viaRules !== value) return viaRules;
    if (policy === "rules") return value;
    if (this.isAllowed(value)) return value;
    // "mask": force a whole-cell placeholder even when no rule fires
    // (e.g. a name no regex or SLM run would catch). Structured values keep
    // shape (203.0.113.x, *.example) via maskCellRulesAsync above.
    const kind = this.kindForWholeCell(header, value);
    const placeholder = this.makePlaceholder(kind, value);
    this.learnValue(value, kind);
    this.hasMaskedAny = true;
    return placeholder;
  }

  /**
   * Whole-value exact-term lookup (mirrors the boundary logic in
   * collectRuleSpans): returns the kind when the ENTIRE cell value is a
   * known secret, so masks apply even in "keep" columns or "rules" cells
   * no regex would fire on.
   */
  private findExactTerm(value: string): { kind: string } | null {
    if (value.length < 4 || this.isAllowed(value)) return null;
    if (this.envSecrets.has(value)) return { kind: "SECRET" };
    const kind = this.knownValues.get(value);
    return kind ? { kind } : null;
  }

  /** Scalar-equivalent masking for a single cell without table re-routing. */
  private async maskCellRulesAsync(value: string, turnDeadline: number): Promise<string> {
    if (!value || value.length < 4 || isRealBase64DataUrl(value)) return value;
    const rawHash = sha256(`cell\0${value}`);
    if (this.config.localModel.sticky) {
      const frozen = this.stickyByRawHash.get(rawHash);
      if (frozen !== undefined) return frozen;
    }
    // A cell that IS an already-masked placeholder/stand-in must pass through
    // untouched: extractExistingIntervals SKIPS rule spans overlapping it,
    // but collectRuleSpans would still learn the raw secret into knownValues
    // via exactTerms on the NEXT call. Short-circuit before any learning.
    // (The scalar maskAsync path cannot hit this: its overlap check happens
    // before learning too, but cells bypass it since each cell is masked in
    // isolation with no knowledge of sibling cells' placeholders.)
    if (this.placeholderToReal.has(value)) return value;
    const existing = this.extractExistingIntervals(value);
    if (existing.length > 0 && existing.some((iv) => iv.start === 0 && iv.end === value.length)) {
      return value;
    }
    const spans = this.collectRuleSpans(value, false, existing);
    const ruleMasked = this.applySpans(value, spans);
    if (
      !this.config.personal ||
      !this.config.localModel.enabled ||
      Date.now() >= turnDeadline
    ) {
      this.recordSticky(rawHash, ruleMasked);
      return ruleMasked;
    }
    const hits = await this.detector.findSpans(ruleMasked, turnDeadline);
    if (hits.length === 0) {
      this.recordSticky(rawHash, ruleMasked);
      return ruleMasked;
    }
    const postIntervals = this.extractExistingIntervals(ruleMasked);
    const modelSpans: Span[] = [];
    for (const hit of hits) {
      const hitValue = ruleMasked.slice(hit.start, hit.end);
      if (!hitValue || this.isAllowed(hitValue)) continue;
      if (this.overlapsIntervals(postIntervals, hit.start, hit.end)) continue;
      modelSpans.push({
        start: hit.start,
        end: hit.end,
        kind: hit.kind,
        value: hitValue,
        placeholder: this.makePlaceholder(hit.kind, hitValue),
        learn: true,
      });
    }
    const finalMasked = this.applySpans(ruleMasked, modelSpans);
    this.recordSticky(rawHash, finalMasked);
    return finalMasked;
  }

  private kindForWholeCell(header: string, value: string): string {
    const h = header.toLowerCase();
    if (/e-?mail/.test(h) || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return "EMAIL";
    if (/phone|mobile|tel/.test(h)) return "PHONE";
    if (/ip\b|address\b/.test(h) === false && /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/.test(value)) return "IP";
    return "COLUMN";
  }

  /**
   * Mask parsed table rows cell-by-cell. Async (rules + SLM per cell) but
   * bounded: maxRows x maxColumns, plus the shared per-turn deadline.
   */
  public async maskTableAsync(table: TableData, turnDeadline = Date.now() + this.config.localModel.timeoutMs): Promise<string[][]> {
    const maxRows = Math.min(table.rows.length, this.config.tabular.maxRows);
    const out: string[][] = [];
    for (let r = 0; r < table.rows.length; r++) {
      const row = table.rows[r];
      if (r >= maxRows) {
        out.push([...row]);
        continue;
      }
      const masked: string[] = [];
      const width = Math.min(row.length, this.config.tabular.maxColumns);
      for (let c = 0; c < row.length; c++) {
        if (c >= width || Date.now() >= turnDeadline) {
          masked.push(row[c]);
          continue;
        }
        const header = table.headers[c] ?? `Column ${c + 1}`;
        masked.push(await this.maskTableCellAsync(header, row[c], turnDeadline));
      }
      out.push(masked);
    }
    return out;
  }

  /**
   * Parse + mask table text, returning the serialized masked text or null
   * when the input does not actually parse as a table.
   */
  public async maskTableTextAsync(
    text: string,
    format?: TableFormat,
    turnDeadline = Date.now() + this.config.localModel.timeoutMs
  ): Promise<string | null> {
    const fmt = format ?? detectTableFormat(text);
    if (!fmt || fmt === "xlsx") return null;
    let table: TableData;
    try {
      table = parseTableText(text, fmt);
    } catch {
      return null;
    }
    if (table.rows.length === 0) return null;
    // Markdown serialization rebuilds only the table: if the table does not
    // span the whole input, fall back to scalar masking so surrounding prose
    // is preserved instead of silently dropped.
    if (fmt === "md" && !markdownTableCoversText(text, table)) return null;
    // Defense in depth: headers are emitted verbatim by serializeTable, so
    // scrub them with scalar rules. A misclassified header row carrying a
    // secret/email would otherwise leak in cleartext to the upstream LLM.
    const maskedHeaders: string[] = [];
    for (const h of table.headers) {
      maskedHeaders.push(await this.maskCellRulesAsync(h, turnDeadline));
    }
    const maskedRows = await this.maskTableAsync(table, turnDeadline);
    return serializeTable({ ...table, headers: maskedHeaders }, maskedRows);
  }

  /**
   * Mask a table file on disk. CSV/TSV/MD come back as text; XLSX comes back
   * as rewritten workbook bytes (base64 when asText is set). Returns null
   * when the file is not a supported table (caller falls back to scalar
   * masking). Throws on legacy OLE .xls, which cannot be safely rewritten.
   */
  public async maskFileAsync(
    filePath: string,
    turnDeadline = Date.now() + this.config.localModel.timeoutMs
  ): Promise<{ text?: string; bytes?: Buffer; format: TableFormat } | null> {
    // Legacy .xls is refused even when tabular routing is disabled: a loud
    // error beats silently passing an unmaskable binary blob to the LLM.
    if (filePath.toLowerCase().endsWith(".xls") && !filePath.toLowerCase().endsWith(".xlsx")) {
      let probe: Buffer | null = null;
      try {
        probe = readFileSync(filePath);
      } catch {
        probe = null;
      }
      if (probe && looksLikeLegacyXls(probe, filePath)) {
        throw new Error(
          `Legacy OLE .xls is not supported for masking (${filePath}); convert to .xlsx first.`
        );
      }
    }
    if (!this.config.tabular.enabled) return null;
    const format = formatForExtension(filePath);
    if (!format) return null;
    let raw: Buffer;
    try {
      raw = readFileSync(filePath);
    } catch {
      return null;
    }
    if (raw.length === 0 || raw.length > this.config.tabular.maxBytes) return null;
    if (format === "xlsx") {
      // Refuse legacy OLE .xls by content OR by misleading extension.
      if (looksLikeLegacyXls(raw, filePath)) {
        throw new Error(
          `Legacy OLE .xls is not supported for masking (${filePath}); convert to .xlsx first.`
        );
      }
      if (!looksLikeXlsx(raw)) return null;
      const sheets = parseXlsxSheets(raw);
      if (!sheets || sheets.every((s) => s.table.rows.length === 0)) return null;
      const masked = await this.rewriteXlsxWithRows(raw, turnDeadline);
      if (!masked) return null;
      return { bytes: masked, format };
    }
    const text = raw.toString("utf8");
    const masked = await this.maskTableTextAsync(text, format, turnDeadline);
    if (masked === null) return null;
    return { text: masked, format };
  }

  /**
   * Rewrite XLSX via maskCell callbacks (header-aware, ALL sheets).
   * Masks every sheet row-by-row with that sheet's own headers instead of
   * reusing sheet 1's rows, so sheet 2+ never inherits sheet 1's policy.
   */
  private async rewriteXlsxWithRows(
    original: Buffer,
    turnDeadline: number
  ): Promise<Buffer | null> {
    const sheets = parseXlsxSheets(original);
    if (!sheets) return null;
    // Pre-mask all sheets (async, honors per-turn deadline) before the sync rewrite.
    const maskedBySheet = new Map<string, Map<string, string>>();
    for (const { name, table } of sheets) {
      const maskedRows = await this.maskTableAsync(table, turnDeadline);
      const byOriginal = new Map<string, string>();
      const dataRows = table.headerless ? table.rows : table.rows;
      for (let r = 0; r < dataRows.length && r < maskedRows.length; r++) {
        const origRow = dataRows[r];
        const maskedRow = maskedRows[r];
        for (let c = 0; c < origRow.length && c < maskedRow.length; c++) {
          if (origRow[c] !== "" && maskedRow[c] !== origRow[c] && !byOriginal.has(origRow[c])) {
            byOriginal.set(origRow[c], maskedRow[c]);
          }
        }
      }
      maskedBySheet.set(name, byOriginal);
    }
    // Rewrite: match each cell against ITS OWN sheet's mapping, routed by
    // the sheetName buildMaskedXlsx passes to the callback. A value masked
    // on one sheet but unmasked on another (different column policy) must
    // NOT leak across sheets.
    const result = buildMaskedXlsx(original, (_header, value, _r, _c, sheetName) => {
      const map = maskedBySheet.get(sheetName);
      return map?.get(value) ?? null;
    });
    return result;
  }

  public async maskDeepAsync(
    value: unknown,
    asJsonText: boolean,
    turnDeadline: number
  ): Promise<unknown> {
    if (typeof value === "string") {
      return this.maskAsync(value, asJsonText, turnDeadline);
    }
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        value[i] = await this.maskDeepAsync(value[i], asJsonText, turnDeadline);
      }
      return value;
    }
    if (value && typeof value === "object") {
      const obj = value as Record<string, unknown>;
      for (const k of Object.keys(obj)) {
        obj[k] = await this.maskDeepAsync(obj[k], asJsonText, turnDeadline);
      }
      return obj;
    }
    return value;
  }

  /**
   * Single-pass O(N) restoration using `EXISTING_TOKEN_RE` and `Map.get()`.
   */
  public restore(text: string): string {
    if (!text || this.placeholderToReal.size === 0) return text;
    return text.replace(EXISTING_TOKEN_RE, (match) => {
      const real = this.placeholderToReal.get(match);
      if (real !== undefined) {
        this.placeholderToReal.delete(match);
        this.placeholderToReal.set(match, real);
        return real;
      }
      return match;
    });
  }

  public restoreDeep(value: unknown): unknown {
    if (typeof value === "string") {
      return this.restore(value);
    }
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        value[i] = this.restoreDeep(value[i]);
      }
      return value;
    }
    if (value && typeof value === "object") {
      const obj = value as Record<string, unknown>;
      for (const k of Object.keys(obj)) {
        obj[k] = this.restoreDeep(obj[k]);
      }
      return obj;
    }
    return value;
  }
}