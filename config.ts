/**
 * Configuration & shared types for the OpenCode Privacy Masking Plugin.
 * Place inside: `.opencode/plugins/privacy-masking/config.ts`
 *
 * Configuration precedence (later overrides earlier):
 *   1. Built-in defaults
 *   2. Global `~/.config/opencode/privacy-masking.json` & `~/.config/opencode/opencode.json`
 *   3. Project `.opencode/privacy-masking.json` & `<project>/opencode.json`
 *   4. Environment variables (`OPENCODE_MASKING_*`)
 *   5. Programmatic `overrides` passed to `loadConfig()`
 */

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export interface LocalModelConfig {
  enabled: boolean;
  endpoint: string;
  model: string;
  timeoutMs: number; // Per-turn total budget (default 2000ms, mirrors magpie's defaultWait)
  strict: boolean; // Fail closed on model failure instead of falling back to rules
  chunkSize: number; // 12 KB chunks (mirrors magpie's chunkSize = 12 << 10)
  sticky: boolean; // Freeze already-sent message masks to preserve upstream Prompt Cache
}

export type TabularColumnMode = "mask" | "rules" | "keep";

export interface TabularConfig {
  enabled: boolean;
  extensions: string[];
  maxBytes: number; // Max table payload/file bytes to process (larger => unchanged)
  maxRows: number; // Max rows scanned per table (later rows pass through)
  maxColumns: number; // Max columns scanned per row
  columns: Record<string, TabularColumnMode>;
  sensitiveHints: string[];
  maskHeaderMatchedCells: boolean;
}

export interface MaskingConfig {
  secrets: boolean;
  personal: boolean;
  preserveShape: boolean; // Map public IPs -> 203.0.113.x and hostnames -> *.example
  scanDotEnv: boolean;
  envFiles: string[];
  minEnvValueLength: number;
  words: string[];
  allow: string[];
  maxMemoryValues: number;
  tabular: TabularConfig;
  /** Alias: explicit column policy for CSV/Excel masking (merged into tabular.columns). */
  excelColumns?: Record<string, TabularColumnMode>;
  localModel: LocalModelConfig;
}

export interface Rule {
  kind: string;
  category: "secret" | "personal";
  re: RegExp;
  group?: number;
  validate?: (match: string, fullText: string, start: number) => boolean;
  learn?: (match: string, fullText: string, start: number) => boolean;
}

export interface Span {
  start: number;
  end: number;
  kind: string;
  value: string;
  placeholder: string;
  learn: boolean;
}

export interface CachedSpan {
  start: number;
  end: number;
  kind: string;
}

const DEFAULT_ALLOW = ["localhost", "127.0.0.1", "0.0.0.0"];

export const DEFAULT_TABULAR: TabularConfig = {
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

function asTabularMode(v: unknown): TabularColumnMode | null {
  if (v === "mask" || v === "rules" || v === "keep") return v;
  return null;
}

/** Normalize a raw tabular/excelColumns config fragment from JSON or env. */
export function normalizeTabularConfig(raw: unknown): Partial<TabularConfig> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const r = raw as Record<string, unknown>;
  const out: Partial<TabularConfig> = {};
  if (typeof r.enabled === "boolean") out.enabled = r.enabled;
  if (Array.isArray(r.extensions)) {
    const exts = r.extensions
      .filter((e): e is string => typeof e === "string")
      .map((e) => (e.startsWith(".") ? e.toLowerCase() : `.${e.toLowerCase()}`));
    if (exts.length > 0) out.extensions = exts;
  }
  if (typeof r.maxBytes === "number" && Number.isFinite(r.maxBytes) && r.maxBytes > 0)
    out.maxBytes = Math.floor(r.maxBytes);
  if (typeof r.maxRows === "number" && Number.isFinite(r.maxRows) && r.maxRows > 0)
    out.maxRows = Math.floor(r.maxRows);
  if (typeof r.maxColumns === "number" && Number.isFinite(r.maxColumns) && r.maxColumns > 0)
    out.maxColumns = Math.floor(r.maxColumns);
  if (r.columns && typeof r.columns === "object" && !Array.isArray(r.columns)) {
    const cols: Record<string, TabularColumnMode> = {};
    for (const [k, v] of Object.entries(r.columns as Record<string, unknown>)) {
      const mode = asTabularMode(typeof v === "string" ? v.toLowerCase() : v);
      if (k && mode) cols[k] = mode;
    }
    out.columns = cols;
  }
  if (Array.isArray(r.sensitiveHints)) {
    const hints = r.sensitiveHints.filter((h): h is string => typeof h === "string" && h.length > 0);
    out.sensitiveHints = hints;
  }
  if (typeof r.maskHeaderMatchedCells === "boolean") out.maskHeaderMatchedCells = r.maskHeaderMatchedCells;
  return out;
}

function normalizeExcelColumns(raw: unknown): Record<string, TabularColumnMode> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const cols: Record<string, TabularColumnMode> = {};
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    const mode = asTabularMode(typeof v === "string" ? v.toLowerCase() : v);
    if (k && mode) cols[k] = mode;
  }
  return cols;
}

function stripJsonComments(raw: string): string {
  // String-aware: track in-string state so `//` inside URLs or values
  // (e.g. "endpoint": "http://127.0.0.1:11434/...") is preserved,
  // while whole-line, trailing, and /* */ comments are removed.
  // Handles escaped quotes (\") so strings with escapes don't desync.
  // Also strips JSONC trailing commas (`,}` / `,]`) so standard .jsonc
  // configs parse instead of failing silently with a SyntaxError.
  let out = "";
  let inString = false;
  let inLineComment = false;
  let inBlockComment = false;
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    const next = raw[i + 1] ?? "";
    if (inLineComment) {
      if (c === "\n") {
        inLineComment = false;
        out += c;
      }
      continue;
    }
    if (inBlockComment) {
      if (c === "*" && next === "/") {
        inBlockComment = false;
        i++; // skip closing /
      }
      continue;
    }
    if (inString) {
      out += c;
      if (c === "\\") {
        // Preserve the escaped char verbatim so \" doesn't end the string.
        if (i + 1 < raw.length) out += raw[++i];
      } else if (c === '"') {
        inString = false;
      }
      continue;
    }
    if (c === '"') {
      inString = true;
      out += c;
      } else if (c === "/" && next === "/") {
      inLineComment = true;
      i++; // skip second /
      } else if (c === "/" && next === "*") {
      inBlockComment = true;
      i++; // skip *
      } else {
      out += c;
      }
  }
  // Strip trailing commas outside strings: `,}` -> `}`, `,]` -> `]`.
  let stripped = "";
  inString = false;
  for (let i = 0; i < out.length; i++) {
    const c = out[i];
    if (inString) {
      stripped += c;
      if (c === "\\" && i + 1 < out.length) stripped += out[++i];
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') {
      inString = true;
      stripped += c;
      continue;
    }
    if (c === ",") {
      let j = i + 1;
      while (j < out.length && /\s/.test(out[j])) j++;
      if (out[j] === "}" || out[j] === "]") continue; // drop trailing comma
    }
    stripped += c;
    }
  return stripped;
}

function readJsonFile(filePath: string): Record<string, unknown> | null {
  try {
    if (!existsSync(filePath)) return null;
    const text = stripJsonComments(readFileSync(filePath, "utf8"));
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function extractFromOpencodeJson(filePath: string): {
  options?: Partial<MaskingConfig>;
  env?: Record<string, string>;
} {
  const data = readJsonFile(filePath);
  if (!data) return {};

  const env =
    data.env && typeof data.env === "object"
      ? (data.env as Record<string, string>)
      : undefined;

  const pluginConfig =
    data.plugin_config && typeof data.plugin_config === "object"
      ? (data.plugin_config as Record<string, unknown>)["privacy-masking"]
      : undefined;

  const direct = data.privacyMasking ?? pluginConfig;
  const options =
    direct && typeof direct === "object" ? (direct as Partial<MaskingConfig>) : undefined;

  return { options, env };
}

export function loadConfig(
  projectDir?: string,
  overrides?: Partial<MaskingConfig>
): MaskingConfig {
  const globalDir = join(homedir(), ".config", "opencode");

  // 1. Read optional JSON/JSONC files (global -> project)
  const globalDedicated = readJsonFile(
    join(globalDir, "privacy-masking.json")
  ) as Partial<MaskingConfig> | null;
  const globalOc = extractFromOpencodeJson(join(globalDir, "opencode.json"));

  const projectDedicated = projectDir
    ? ((readJsonFile(
        join(projectDir, ".opencode", "privacy-masking.json")
      ) ??
        readJsonFile(
          join(projectDir, "privacy-masking.json")
        )) as Partial<MaskingConfig> | null)
    : null;
  const projectOc = projectDir
    ? extractFromOpencodeJson(join(projectDir, "opencode.json"))
    : {};

  const projectDotOpencodeOc = projectDir
    ? extractFromOpencodeJson(join(projectDir, ".opencode", "opencode.json"))
    : {};

  const mergedEnv: Record<string, string | undefined> = {
    ...globalOc.env,
    ...projectOc.env,
    ...projectDotOpencodeOc.env,
    ...process.env,
  };

  const fileCfg: Partial<MaskingConfig> = {
    ...globalDedicated,
    ...globalOc.options,
    ...projectDedicated,
    ...projectOc.options,
    ...projectDotOpencodeOc.options,
  };

  const fileLocal: Partial<LocalModelConfig> = {
    ...globalDedicated?.localModel,
    ...globalOc.options?.localModel,
    ...projectDedicated?.localModel,
    ...projectOc.options?.localModel,
    ...projectDotOpencodeOc.options?.localModel,
  };

  const strict =
    mergedEnv.OPENCODE_MASKING_STRICT !== undefined
      ? mergedEnv.OPENCODE_MASKING_STRICT === "1"
      : (fileLocal.strict ?? false);

  const defaultTimeout = strict ? 15_000 : 2_000;

  const allowFile =
    fileCfg.allow ??
    globalOc.options?.allow ??
    projectDedicated?.allow ??
    projectOc.options?.allow ??
    projectDotOpencodeOc.options?.allow;
  // Union (not overwrite): project allow entries add to defaults such as
  // "localhost" instead of silently dropping them.
  const allow = allowFile ? Array.from(new Set([...DEFAULT_ALLOW, ...allowFile])) : [...DEFAULT_ALLOW];

  // --- Tabular (CSV/Excel) config: file layers then env, then programmatic ---
  const fileTabular: Partial<TabularConfig> = {
    ...normalizeTabularConfig(globalDedicated?.tabular),
    ...normalizeTabularConfig(globalOc.options?.tabular),
    ...normalizeTabularConfig(projectDedicated?.tabular),
    ...normalizeTabularConfig(projectOc.options?.tabular),
    ...normalizeTabularConfig(projectDotOpencodeOc.options?.tabular),
  };
  const fileExcelColumns: Record<string, TabularColumnMode> = {
    ...normalizeExcelColumns(globalDedicated?.excelColumns),
    ...normalizeExcelColumns(globalOc.options?.excelColumns),
    ...normalizeExcelColumns(projectDedicated?.excelColumns),
    ...normalizeExcelColumns(projectOc.options?.excelColumns),
    ...normalizeExcelColumns(projectDotOpencodeOc.options?.excelColumns),
  };

  // OPENCODE_MASKING_TABULAR / OPENCODE_MASKING_EXCEL_COLUMNS accept inline JSON.
  // OPENCODE_MASKING_TABULAR=0 disables table routing entirely.
  let envTabular: Partial<TabularConfig> = {};
  if (mergedEnv.OPENCODE_MASKING_TABULAR !== undefined) {
    if (mergedEnv.OPENCODE_MASKING_TABULAR === "0" || mergedEnv.OPENCODE_MASKING_TABULAR === "false") {
      envTabular = { enabled: false };
    } else if (mergedEnv.OPENCODE_MASKING_TABULAR !== "1" && mergedEnv.OPENCODE_MASKING_TABULAR !== "true") {
      try {
        envTabular = normalizeTabularConfig(JSON.parse(mergedEnv.OPENCODE_MASKING_TABULAR));
      } catch {
        envTabular = {};
      }
    }
  }
  let envExcelColumns: Record<string, TabularColumnMode> = {};
  if (mergedEnv.OPENCODE_MASKING_EXCEL_COLUMNS) {
    try {
      envExcelColumns = normalizeExcelColumns(JSON.parse(mergedEnv.OPENCODE_MASKING_EXCEL_COLUMNS));
    } catch {
      envExcelColumns = {};
    }
  }

  const tabular: TabularConfig = {
    ...DEFAULT_TABULAR,
    ...fileTabular,
    ...envTabular,
    columns: {
      ...fileTabular.columns,
      ...fileExcelColumns,
      ...envTabular.columns,
      ...envExcelColumns,
      ...overrides?.tabular?.columns,
      ...overrides?.excelColumns,
    },
    ...(overrides?.tabular ?? {}),
    // Re-apply merged columns: overrides.tabular must not wipe excelColumns alias entries.
    columns: {
      ...fileTabular.columns,
      ...fileExcelColumns,
      ...envTabular.columns,
      ...envExcelColumns,
      ...overrides?.tabular?.columns,
      ...overrides?.excelColumns,
    },
  };

  return {
    secrets: fileCfg.secrets ?? true,
    personal: fileCfg.personal ?? true,
    preserveShape: fileCfg.preserveShape ?? true,
    scanDotEnv: fileCfg.scanDotEnv ?? true,
    envFiles: fileCfg.envFiles ?? [".env", ".env.local", ".env.production"],
    minEnvValueLength: fileCfg.minEnvValueLength ?? 8,
    words: fileCfg.words ?? [],
    allow,
    maxMemoryValues: fileCfg.maxMemoryValues ?? 4096,
    tabular,
    excelColumns: { ...tabular.columns },
    ...overrides,
    // Keep tabular merged even when overrides spread above overwrote it.
    tabular: { ...tabular, ...(overrides?.tabular ?? {}), columns: { ...tabular.columns, ...overrides?.tabular?.columns, ...overrides?.excelColumns } },
    localModel: {
      enabled:
        mergedEnv.OPENCODE_MASKING_MODEL !== undefined
          ? mergedEnv.OPENCODE_MASKING_MODEL !== "0"
          : (fileLocal.enabled ?? true),
      endpoint:
        mergedEnv.OPENCODE_MASKING_URL ||
        fileLocal.endpoint ||
        "http://127.0.0.1:11434/v1/chat/completions",
      model:
        mergedEnv.OPENCODE_MASKING_MODEL_NAME ||
        fileLocal.model ||
        "qwen2.5:1.5b",
      timeoutMs:
        Number(mergedEnv.OPENCODE_MASKING_TIMEOUT_MS) ||
        fileLocal.timeoutMs ||
        defaultTimeout,
      strict,
      chunkSize: fileLocal.chunkSize ?? 12 * 1024,
      sticky:
        mergedEnv.OPENCODE_MASKING_STICKY !== undefined
          ? mergedEnv.OPENCODE_MASKING_STICKY !== "0"
          : (fileLocal.sticky ?? true),
      ...overrides?.localModel,
    },
  };
}