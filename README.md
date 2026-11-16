# OpenCode Privacy Masking Plugin

A high-performance, bidirectional privacy and secret masking plugin for [OpenCode](https://opencode.ai). Protects sensitive credentials, tokens, PII, internal hostnames, and IP addresses from leaking into upstream LLM prompts, while guaranteeing transparent, in-place $O(N)$ restoration before local tool execution.

---

## Features

- **Bidirectional Redaction & Restoration**: Replaces secrets and personal data with deterministic HMAC-derived placeholders (`{{KIND_xxxxxxxx}}`) or RFC-compliant stand-ins before sending to the model, and restores original values before tools (`bash`, `read`, `write`, `edit`) execute locally.
- **Shape-Preserving RFC Stand-ins**:
  - **IPv4**: Maps public IPs to RFC 5737 `203.0.113.x` (TEST-NET-3) with linear probing collision resolution and HMAC fallback.
  - **IPv6**: Maps IPv6 addresses into RFC 3849 `2001:db8::/32` documentation prefixes, preserving scope suffixes (`%eth0`).
  - **Hostnames**: Maps internal hosts and SSH targets to RFC 2606 `*.example` domains.
- **Upstream Prompt Cache Preservation**:
  - Injects `SYSTEM_NOTICE` unconditionally on Turn 1 to prevent invalidating provider prompt caches mid-session.
  - Sticky masking memoizes previously masked content by SHA-256 hash so re-sent messages remain identical byte-for-byte.
- **Local Small Language Model (SLM) Fallback**:
  - Connects to local endpoints (Ollama, vLLM, Qwen2.5) for semantic PII detection (names, physical addresses, personal IDs).
  - Balanced-brace JSON parser extracts structured items even amidst surrounding conversational prose or markdown code blocks.
  - Single-flight serial scheduler avoids concurrency stampedes against local GPUs/CPUs.
  - SHA-256 disk cache with `.unref()` timers avoids hanging Node.js CLI process termination.
- **Tabular & Spreadsheet Support (Zero Dependencies)**:
  - Native parser and serializer for CSV, TSV, Markdown tables, and XLSX (OOXML zip + sharedStrings/inline XML).
  - Granular column policies (`mask`, `rules`, `keep`) with case-insensitive sensitive header hints (`password`, `token`, `secret`, `ssn`, etc.).
  - Bounded resource safeguards: byte size limits, row/column caps, and rejection of legacy binary `.xls` files.
- **Strict False-Positive Protections**:
  - Preserves RFC 3339 timestamps, semver tags, JSON numbers, and RFC 1918 private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`).
  - Validates `Basic` authentication by testing base64 decodability to printable `user:password` pairs, avoiding false positives on sentences like *"Basic authentication is required"*.

---

## Architecture & Hook Lifecycle

```
[User Input / Session History]
           │
           ▼
[experimental.chat.messages.transform]  ───► Masks secrets, PII, IPs, tool errors
           │
[experimental.chat.system.transform]    ───► Ensures static Turn 1 system guidance
           │
           ▼
    (Upstream LLM)
           │
           ▼
  [tool.execute.before]                 ───► Restores {{...}} & stand-ins -> real values
           │
     (Local Tool)
           │
           ▼
  [tool.execute.after]                  ───► Scrubs secrets from stdout/stderr/title
           │
[experimental.text.complete]            ───► Restores placeholders in user-facing text
```

---

## Directory Layout

```
.
├── .opencode/
│   └── plugins/
│       ├── privacy-masking.ts     -> ../../privacy-masking.ts (Entrypoint)
│       └── privacy-masking        -> ../../privacy-masking    (Supporting modules)
├── config.ts                      # Configuration parsing & comment-safe JSONC loader
├── crypto.ts                      # HMAC key store, base32 encoding & RFC stand-in generators
├── rules.ts                       # High-speed RegExp rules (/gd hasIndices) & validators
├── store.ts                       # RedactStore, interval exclusion, sticky cache & O(N) restore
├── local-model.ts                 # Local SLM PII detector, single-flight queue & LRU cache
├── tabular.ts                     # Zero-dependency CSV/TSV/Markdown/XLSX masking engine
├── privacy-masking.ts             # Canonical plugin hook entrypoint
├── privacy-masking.json           # Project-level masking configuration
├── opencode.json                  # OpenCode environment & runtime settings
├── register-hooks.mjs             # Node.js ESM TypeScript loader hook registration
├── ts-resolver.mjs                # TypeScript module resolution hook for tests
└── test_privacy_masking.ts        # Unit and integration test suite
```

---

## Built-in Masking Rules

| Kind | Target / Pattern | Replacement Format | Validation / Guard |
| :--- | :--- | :--- | :--- |
| `PRIVATE_KEY` | `-----BEGIN * PRIVATE KEY-----` | `{{PRIVATE_KEY_xxxxxxxx}}` | Standard PEM bounds |
| `API_KEY` | OpenAI (`sk-...`), Anthropic (`sk-ant-...`), OpenCode | `{{API_KEY_xxxxxxxx}}` | Length $\ge 20$, alphanumeric |
| `GITHUB_TOKEN`| `ghp_...`, `github_pat_...` | `{{GITHUB_TOKEN_xxxxxxxx}}` | Character set & prefix check |
| `AWS_KEY` | `AKIA...`, `ASIA...` | `{{AWS_KEY_xxxxxxxx}}` | 20-character uppercase |
| `JWT` | `eyJ...` (3-part dot separated) | `{{JWT_xxxxxxxx}}` | Base64 URL character sets |
| `PASSWORD` | `proto://user:password@host` | `proto://user:{{PASSWORD_...}}@host` | Uses regex `/gd` indices; never masks username |
| `SECRET` | Keys: `api_key`, `secret`, `password`, `token` | `key: "{{SECRET_xxxxxxxx}}"` | Excludes timestamps & semver |
| `BEARER` | `Authorization: Bearer <token>` | `Bearer {{BEARER_xxxxxxxx}}` | Minimum 12 chars, alphanumeric |
| `BASIC_AUTH` | `Authorization: Basic <base64>` | `Basic {{BASIC_AUTH_xxxxxxxx}}` | Validates printable ASCII `user:pass` |
| `QUERY_SECRET`| URL query parameters (`?key=...&token=...`) | `?key={{QUERY_SECRET_xxxxxxxx}}` | URL boundary safe |
| `HOSTNAME` | SSH targets and `HostName` directives | `[a-z]{8}.example` | RFC 2606 `.example` domain |
| `IP` | Public IPv4 addresses | `203.0.113.x` | RFC 5737 TEST-NET-3; ignores RFC 1918 private |
| `IPV6` | Public IPv6 addresses | `2001:db8:xxxx:xxxx:xxxx:xxxx` | RFC 3849 doc range; ignores `::1`, `fe80::` |
| `EMAIL` | Email addresses | `{{EMAIL_xxxxxxxx}}` | Excludes systemd units and SSH commands |
| `PHONE` | International (E.164), CN (+86), JP (+81), US/NANP | `{{PHONE_xxxxxxxx}}` | Excludes JSON numbers (timestamps/ports) |

---

## Configuration

Configuration is loaded and merged with the following precedence (highest overrides lowest):

1. Programmatic overrides
2. Environment variables (`OPENCODE_MASKING_*`)
3. Project `.opencode/privacy-masking.json` or `privacy-masking.json`
4. Project `opencode.json` (`env` and `privacyMasking` sections)
5. Global `~/.config/opencode/privacy-masking.json` & `opencode.json`
6. Built-in defaults

### Example `privacy-masking.json`

```jsonc
{
  "secrets": true,
  "personal": true,
  "preserveShape": true,
  "words": [
    "internal-codename",
    "project-atlas"
  ],
  "allow": [
    "localhost",
    "127.0.0.1",
    "public-api.mycompany.com"
  ],
  "maxMemoryValues": 4096,
  "tabular": {
    "enabled": true,
    "maxBytes": 524288,
    "maxRows": 5000,
    "maxColumns": 100,
    "columns": {
      "user_email": "mask",
      "ip_address": "mask",
      "public_notes": "rules"
    }
  },
  "localModel": {
    "enabled": true,
    "endpoint": "http://127.0.0.1:11434/v1/chat/completions",
    "model": "qwen2.5:1.5b",
    "timeoutMs": 2000,
    "strict": false,
    "sticky": true
  }
}
```

### Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `OPENCODE_MASKING_MODEL` | `1` | Enable (`1`) or disable (`0`) local SLM inference |
| `OPENCODE_MASKING_URL` | `http://127.0.0.1:11434/v1/chat/completions` | Local model OpenAI-compatible chat completions endpoint |
| `OPENCODE_MASKING_MODEL_NAME` | `qwen2.5:1.5b` | Model identifier passed in the request body |
| `OPENCODE_MASKING_TIMEOUT_MS` | `2000` | Per-turn execution budget for local SLM detection |
| `OPENCODE_MASKING_STRICT` | `0` | Fail closed (`1`) if local model times out or errors |
| `OPENCODE_MASKING_STICKY` | `1` | Freeze masked outputs to maintain prompt cache |
| `OPENCODE_MASKING_TABULAR` | `1` | Enable (`1` or JSON config) or disable (`0`) tabular parsing |
| `OPENCODE_MASKING_EXCEL_COLUMNS` | `{}` | JSON map of column masking rules for spreadsheets |

---

## Testing & Verification

Run the test suite using Node.js with the included TypeScript loader hooks:

```bash
node --import ./register-hooks.mjs --test test_privacy_masking.ts
```

Verify OpenCode plugin discovery and startup performance:

```bash
# Check resolved plugin configuration
opencode debug config

# Check startup latency
opencode debug startup
```

---

## Security & Reliability Design Principles

1. **Exact Offset Targeting (`/gd`)**: Regex replacements use V8 `match.indices` capture offsets rather than `indexOf`, ensuring passwords with substrings common to usernames are never swapped or leaked.
2. **Deterministic & Collision-Free**: HMAC keys (`~/.config/opencode/privacy-masking.key`) ensure consistent stand-ins across turns with zero persistent secret exposure. Linear probing prevents IP address overwrites.
3. **Fail-Safe String Parsing**: State-machine JSON comment stripping ignores `//` sequences inside string literals (e.g., URLs like `http://localhost`).
4. **Non-Blocking Execution**: Background file timers in the cache manager call `.unref()` so CLI commands terminate cleanly without artificial 2-second hangs.
