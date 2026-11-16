/**
 * Local model PII detector, single-flight scheduler, and SHA-256 LRU cache.
 * Place inside: `.opencode/plugins/privacy-masking/local-model.ts`
 */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { CachedSpan, LocalModelConfig } from "./config";
import { getConfigDir, sha256 } from "./crypto";

const CODE_STOPWORDS = new Set([
  "true",
  "false",
  "null",
  "undefined",
  "void",
  "main",
  "index",
  "const",
  "function",
  "return",
  "import",
  "export",
  "string",
  "number",
  "boolean",
  "object",
  "admin",
  "root",
  "user",
  "test",
  "localhost",
]);

/**
 * Extracts the first balanced {...} JSON object from model output.
 * Prefers fenced ```json blocks (which greedy /\{[\s\S]*\}/ gets wrong
 * when the model emits prose + JSON + trailing text), then scans for the
 * first balanced brace run while respecting strings/escapes. Returns null
 * (no backoff) when no balanced object exists so one malformed reply does
 * not disable PII detection for a minute.
 */
function extractJsonObject(raw: string): { items?: Array<{ text?: string; kind?: string }> } | null {
  const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)```/);
  const candidates = fenced ? [fenced[1].trim(), raw] : [raw];
  for (const text of candidates) {
    const start = text.indexOf('{');
    if (start === -1) continue;
    let depth = 0;
    let inString = false;
    for (let i = start; i < text.length; i++) {
      const c = text[i];
      if (inString) {
        if (c === '\\') i++;
        else if (c === '"') inString = false;
        continue;
      }
      if (c === '"') inString = true;
      else if (c === '{') depth++;
      else if (c === '}') {
        depth--;
        if (depth === 0) {
          try {
            return JSON.parse(text.slice(start, i + 1));
          } catch {
            break; // try next candidate
          }
        }
      }
    }
  }
  return null;
}

class LocalPiiCache {
  private readonly cachePath: string;
  private readonly maxEntries = 10000;
  private readonly map = new Map<string, CachedSpan[]>();
  private saveTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(modelName: string) {
    const safeModel = modelName.replace(/[^a-zA-Z0-9._-]/g, "_");
    this.cachePath = join(getConfigDir(), `privacy-masking-cache-${safeModel}.json`);
    this.load();
  }

  private load(): void {
    try {
      if (!existsSync(this.cachePath)) return;
      const raw = JSON.parse(readFileSync(this.cachePath, "utf8")) as Record<string, CachedSpan[]>;
      for (const [k, v] of Object.entries(raw)) {
        if (Array.isArray(v)) this.map.set(k, v);
      }
    } catch {
      // Rebuildable cache; ignore corrupt file
    }
  }

  public get(hash: string): CachedSpan[] | undefined {
    const val = this.map.get(hash);
    if (val !== undefined) {
      this.map.delete(hash);
      this.map.set(hash, val);
    }
    return val;
  }

  public set(hash: string, spans: CachedSpan[]): void {
    if (this.map.size >= this.maxEntries) {
      const oldest = this.map.keys().next().value;
      if (oldest) this.map.delete(oldest);
    }
    this.map.set(hash, spans);
    this.saveSoon();
  }

  private saveSoon(): void {
    if (this.saveTimer) clearTimeout(this.saveTimer);
    this.saveTimer = setTimeout(() => {
      try {
        const dir = getConfigDir();
        mkdirSync(dir, { recursive: true });
        const obj: Record<string, CachedSpan[]> = {};
        for (const [k, v] of this.map) obj[k] = v;
        const tmpPath = `${this.cachePath}.tmp.${process.pid}`;
        writeFileSync(tmpPath, JSON.stringify(obj), { mode: 0o600 });
        renameSync(tmpPath, this.cachePath);
      } catch {
        // Non-fatal
      }
    }, 2000);
    if (this.saveTimer && typeof (this.saveTimer as any).unref === "function") {
      (this.saveTimer as any).unref();
    }
  }
}

export class LocalModelDetector {
  private readonly cfg: LocalModelConfig;
  private readonly cache: LocalPiiCache;
  private backoffUntil = 0;
  private queue: Promise<void> = Promise.resolve();

  constructor(cfg: LocalModelConfig) {
    this.cfg = cfg;
    this.cache = new LocalPiiCache(cfg.model);
  }

  private splitChunks(text: string): Array<{ offset: number; chunk: string }> {
    const out: Array<{ offset: number; chunk: string }> = [];
    let offset = 0;
    while (offset < text.length) {
      let end = Math.min(offset + this.cfg.chunkSize, text.length);
      if (end < text.length) {
        const nl = text.lastIndexOf("\n", end);
        if (nl > offset + this.cfg.chunkSize / 2) end = nl + 1;
      }
      out.push({ offset, chunk: text.slice(offset, end) });
      offset = end;
    }
    return out;
  }

  /**
   * Serializes inference calls so concurrent hooks do not stampede the local model server
   * (mirrors magpie's guardTurn / srv.mu single-flight scheduling).
   */
  private runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.queue.then(fn, fn);
    this.queue = next.then(
      () => undefined,
      () => undefined
    );
    return next;
  }

  public async findSpans(text: string, turnDeadline: number): Promise<CachedSpan[]> {
    if (!this.cfg.enabled || text.trim().length < 6) return [];

    const chunks = this.splitChunks(text);
    const allSpans: CachedSpan[] = [];

    for (const { offset, chunk } of chunks) {
      const hash = sha256(chunk);
      const cached = this.cache.get(hash);
      if (cached) {
        for (const s of cached) {
          allSpans.push({ start: offset + s.start, end: offset + s.end, kind: s.kind });
        }
        continue;
      }

      if (!this.cfg.strict && Date.now() < this.backoffUntil) {
        continue;
      }

      const remainingMs = turnDeadline - Date.now();
      if (remainingMs <= 50) {
        if (this.cfg.strict) {
          throw new Error(`Local masking model timed out (${this.cfg.timeoutMs}ms budget exceeded)`);
        }
        break;
      }

      const detected = await this.runExclusive(() => {
        const left = turnDeadline - Date.now();
        if (left <= 50) {
          if (this.cfg.strict) {
            throw new Error(`Local masking model timed out (${this.cfg.timeoutMs}ms budget exceeded)`);
          }
          return Promise.resolve(null);
        }
        return this.inferChunk(chunk, left);
      });

      if (detected !== null) {
        this.cache.set(hash, detected);
        for (const s of detected) {
          allSpans.push({ start: offset + s.start, end: offset + s.end, kind: s.kind });
        }
      }
    }

    return allSpans;
  }

  private isValidEntitySubstring(chunk: string, sub: string, index: number): boolean {    const trimmed = sub.trim();
    if (trimmed.length < 2) return false;
    if (CODE_STOPWORDS.has(trimmed.toLowerCase())) return false;

    // For pure ASCII words, require at least 3 chars and whole-word boundaries
    if (/^[A-Za-z0-9_-]+$/.test(trimmed)) {
      if (trimmed.length < 3) return false;
      const before = index > 0 ? chunk[index - 1] : "";
      const after = chunk[index + sub.length] ?? "";
      if (/[A-Za-z0-9_-]/.test(before) || /[A-Za-z0-9_-]/.test(after)) {
        return false;
      }
    }
    return true;
  }

  private async inferChunk(chunk: string, timeoutMs: number): Promise<CachedSpan[] | null> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(this.cfg.endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: controller.signal,
        body: JSON.stringify({
          model: this.cfg.model,
          temperature: 0,
          messages: [
            {
              role: "system",
              content:
                'Extract personal names (NAME), physical street addresses (ADDRESS), and sensitive personal IDs (ID) from the user text. Return ONLY a JSON object: {"items":[{"text":"exact substring","kind":"NAME|ADDRESS|ID"}]}. Never extract programming keywords, variable names, file paths, URLs, or {{...}} placeholders.',
            },
            { role: "user", content: chunk },
          ],
        }),
      });

      if (!res.ok) {
        if (this.cfg.strict) throw new Error(`Local model HTTP ${res.status}`);
        // Back off on transient server errors, not on client errors (4xx = bad request).
        if (res.status >= 500 || res.status === 429) {
          this.backoffUntil = Date.now() + 60_000;
        }
        return null;
      }

      const data = (await res.json()) as {
        choices?: Array<{ message?: { content?: string } }>;
      };
      const rawContent = data.choices?.[0]?.message?.content?.trim() || "";
      const parsed = extractJsonObject(rawContent);
      if (!parsed) return [];
      if (!Array.isArray(parsed.items)) return [];

      const spans: CachedSpan[] = [];
      for (const item of parsed.items) {
        if (!item.text || item.text.length < 2) continue;
        const kind = (item.kind || "PII").toUpperCase().replace(/[^A-Z0-9_]/g, "");
        let idx = 0;
        while ((idx = chunk.indexOf(item.text, idx)) !== -1) {
          if (this.isValidEntitySubstring(chunk, item.text, idx)) {
            spans.push({ start: idx, end: idx + item.text.length, kind });
          }
          idx += item.text.length;
        }
      }
      return spans;
    } catch (err) {
      if (this.cfg.strict) throw err;
      // Only back off on network/timeout/abort failures. Parse failures and
      // empty results are handled above with `return []`, so reaching here
      // means the request itself failed (ECONNREFUSED, timeout, 5xx, ...).
      const msg = err instanceof Error ? err.message : String(err);
      if (
        /abort|timeout|timed out|ECONNREFUSED|ENOTFOUND|EHOSTUNREACH|ENETUNREACH|ECONNRESET|EPIPE|fetch failed|network|HTTP\s*[5]\d\d|HTTP\s*429/i.test(
          msg
        )
      ) {
        this.backoffUntil = Date.now() + 60_000;
      }
      return null;
    } finally {
      clearTimeout(timer);
    }
  }
}