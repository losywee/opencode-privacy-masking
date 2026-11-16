/**
 * Pattern rules and structural guards (secrets, personal data, hostnames, data URLs).
 * Place inside: `.opencode/plugins/privacy-masking/rules.ts`
 */

import type { Rule } from "./config";
import { Buffer } from "node:buffer";

/**
 * Matches standard placeholders `{{KIND_xxxxxxxx}}`, IP stand-ins `203.0.113.x`,
 * and hostname stand-ins `xxxxxxxx.example`.
 */
export const EXISTING_TOKEN_RE =
  /\{\{[A-Z0-9_]+_[a-z2-7]{8}\}\}|2001:db8(?::[A-Fa-f0-9]{1,4}){4}(?:%[A-Za-z0-9._-]+)?|(?<![A-Za-z0-9_.-])(?:203\.0\.113\.\d{1,3}|[a-z]{8}\.example)(?![A-Za-z0-9_.-])/g;

/**
 * Returns true only when `text` is an actual base64-encoded media data URL
 * (and NOT an SSE `data: {...}` line or plain text starting with `data:`).
 * Mirrors magpie Issue #5651.
 */
export function isRealBase64DataUrl(text: string): boolean {
  return /^data:[a-zA-Z0-9.+/-]*;base64,[A-Za-z0-9+/=\r\n]+$/.test(text.trim());
}

function hostOk(host: string): boolean {
  const lower = host.toLowerCase();
  if (
    lower === "localhost" ||
    lower.endsWith(".local") ||
    lower.endsWith(".example") ||
    lower.endsWith(".invalid") ||
    lower.endsWith(".internal") ||
    lower.endsWith(".test") ||
    lower.endsWith(".localhost") ||
    lower === "github.com" ||
    lower === "gitlab.com" ||
    lower === "bitbucket.org"
  ) {
    return false;
  }
  // Ignore pure IPv4 addresses (handled by IP rule)
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(lower)) return false;
  return lower.includes(".");
}

export const RULES: Rule[] = [
  {
    kind: "PRIVATE_KEY",
    category: "secret",
    re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
  },
  {
    kind: "API_KEY",
    category: "secret",
    re: /\b(?:[a-z]{2,4}_sk_|sk-(?:ant-|proj-|or-|svcacct-|admin-)?)[A-Za-z0-9_-]{20,}\b/g,
    validate: (m) => /\d/.test(m) && /[A-Za-z]/.test(m),
  },
  {
    kind: "GITHUB_TOKEN",
    category: "secret",
    re: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,
  },
  {
    kind: "AWS_KEY",
    category: "secret",
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    kind: "JWT",
    category: "secret",
    re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  },
  {
    kind: "PASSWORD",
    category: "secret",
    re: /[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^:\s/@]+):([^@\s/]+)@[^\s/]+/gd,
    group: 2,
    learn: (m, full, start) => {
      // Do not learn placeholder DSNs where password === username (Issue #3365)
      const prefix = full.slice(Math.max(0, start - 64), start);
      const userMatch = prefix.match(/\/\/([^:\s/@]+):$/);
      return !(userMatch && userMatch[1] === m);
    },
  },
  {
    kind: "SECRET",
    category: "secret",
    re: /(?:^|[\s,{'"`(\["])([\w.-]*?(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|private[_-]?key|client[_-]?secret|token[_-]?signing[_-]?key)[\w.-]*)['"`]?\s*[:=]\s*['"`]?([A-Za-z0-9_./+=\-!@#$%^*~?]{12,})['"`]?/gid,
    group: 2,
    validate: (m) => {
      // Skip RFC 3339 timestamps (Issue #5002), semver strings, and owner/repo paths (Issue #3365)
      if (/^\d{4}-\d{2}-\d{2}T\d{2}/.test(m)) return false;
      if (/^\d+\.\d+\.\d+/.test(m)) return false;
      if (/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(m) && !/\d{4,}/.test(m)) return false;
      return /\d/.test(m) && /[A-Za-z]/.test(m);
    },
  },
  {
    kind: "BEARER",
    category: "secret",
    re: /\bBearer\s+([A-Za-z0-9_.\-~+/=]{12,})(?![A-Za-z0-9_.\-~+/=])/gd,
    group: 1,
    validate: (m) => /\d/.test(m) && /[A-Za-z]/.test(m),
  },
  {
    kind: "BASIC_AUTH",
    category: "secret",
    re: /\bBasic\s+([A-Za-z0-9+/=]{8,})(?![A-Za-z0-9+/=])/gd,
    group: 1,
    validate: (m) => {
      // Must base64-decode to printable "user:password" form, otherwise
      // prose like "Basic authentication is required" would false-positive.
      if (m.length < 8) return false;
      try {
        const decoded = Buffer.from(m, "base64").toString("utf8");
        return decoded.includes(":") && decoded.length >= 3 && /^[\x20-\x7e]+$/.test(decoded);
      } catch {
        return false;
      }
    },
  },
  {
    kind: "QUERY_SECRET",
    category: "secret",
    re: /[?&#]([\w.-]*?(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|private[_-]?key|client[_-]?secret|api[_-]?token|session[_-]?id|token|secret)[\w.-]*)=([^&#\s'";,]+)/gid,
    group: 2,
    validate: (m) => m.length >= 8 && /\d/.test(m) && /[A-Za-z]/.test(m),
  },
  {
    kind: "HOSTNAME",
    category: "personal",
    // Matches ssh targets (`ssh user@host` or `HostName host.domain`) for .example stand-ins (Issue #4063)
    re: /(?:(?:\bssh\s+(?:-[^\s]+\s+)*[A-Za-z0-9._-]+@)|(?:\bHostName\s+))([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b/gd,
    group: 1,
    validate: (m) => hostOk(m),
  },
  {
    kind: "IPV6",
    category: "personal",
    // Full and ::-compressed IPv6 (requires at least 2 colons to avoid matching times/MACs).
    re: /(?<![A-Za-z0-9:_.])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![A-Za-z0-9:_.])/g,
    validate: (m) => {
      if ((m.match(/:/g) || []).length < 2) return false;
      // Skip loopback, link-local, docs range already stand-in, bare :: (often a placeholder).
      if (m === "::1" || m === "::") return false;
      const lower = m.toLowerCase();
      if (lower.startsWith("fe80:") || lower.startsWith("2001:db8:")) return false;
      return true;
    },
  },
  {
    kind: "EMAIL",
    category: "personal",
    re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    validate: (m, full, start) => {
      const lower = m.toLowerCase();
      if (
        lower.endsWith(".local") ||
        lower.endsWith(".example") ||
        lower.endsWith(".invalid") ||
        lower.endsWith(".png") ||
        lower.endsWith(".jpg") ||
        lower.endsWith(".svg")
      ) {
        return false;
      }
      // Skip path-adjacent systemd unit names like /user/demo@web.service (Issue #3629)
      const before = start > 0 ? full[start - 1] : "";
      const after = full[start + m.length] ?? "";
      if (before === "/" || after === "/") return false;
      // Skip URI user:password@host (handled by PASSWORD rule)
      const prefix = full.slice(Math.max(0, start - 128), start);
      if (/[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^:\s/@]+:$/.test(prefix)) return false;
      // Skip matches triggered by ssh user@host (handled by HOSTNAME rule)
      if (/\bssh\s+(?:-[^\s]+\s+)*$/.test(prefix)) return false;
      return true;
    },
  },
  {
    kind: "PHONE",
    category: "personal",
    re: /(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)|(?<!\d)(?:\+?81[- ]?|0)[789]0[- ]\d{4}[- ]\d{4}(?!\d)|(?<!\d)(?:\+?1[-. ]?)?\(?[2-9]\d{2}\)?[-. ]\d{3}[-. ]\d{4}(?!\d)/g,
    validate: (m, full, start) => {
      // Guard against bare 11-digit JSON numbers like {"swap_free_bytes": 13800138000} (Issue #3629)
      const before = full.slice(Math.max(0, start - 24), start);
      if (/":\s*$/.test(before)) return false;
      return true;
    },
  },
  {
    kind: "IP",
    category: "personal",
    re: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
    validate: (m) => {
      if (
        m.startsWith("203.0.113.") ||
        m.startsWith("127.") ||
        m.startsWith("10.") ||
        m.startsWith("192.168.") ||
        m.startsWith("169.254.") ||
        m === "0.0.0.0"
      ) {
        return false;
      }
      // Skip RFC 1918 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
      if (m.startsWith("172.")) {
        const secondOctet = Number(m.split(".")[1]);
        if (secondOctet >= 16 && secondOctet <= 31) return false;
      }
      return true;
    },
  },
];