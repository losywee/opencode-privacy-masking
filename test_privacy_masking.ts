import test from "node:test";
import assert from "node:assert";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig } from "./config.ts";
import { RedactStore } from "./store.ts";
import { PrivacyMaskingPlugin } from "./privacy-masking.ts";

test("Header, query-string, JSON-shaped and env-style secrets are masked", async () => {
  const config = loadConfig(".", {
    localModel: { enabled: false } as any,
  });
  const store = new RedactStore(config);

  const cases: Array<[string, RegExp]> = [
    ['{"password": "hunter2Secret123"}', /\{"password": "\{\{SECRET_[a-z2-7]{8}\}\}"\}/],
    ["https://api.example.com/data?api_key=Abcdef1234567890&x=1", /api_key=\{\{QUERY_SECRET_[a-z2-7]{8}\}\}&x=1/],
    ["x-api-key: Abcdef1234567890abcdef", /x-api-key: \{\{SECRET_[a-z2-7]{8}\}\}/],
    ["Authorization: Bearer abcdef1234567890ABCDEF", /Bearer \{\{BEARER_[a-z2-7]{8}\}\}/],
    ["Authorization: Basic dXNlcjpzdXBlcl9zZWNyZXQxMjM=", /Basic \{\{BASIC_AUTH_[a-z2-7]{8}\}\}/],
    ["db_password=hunter2!@#Secret99", /db_password=\{\{SECRET_[a-z2-7]{8}\}\}/],
  ];
  for (const [text, pattern] of cases) {
    const masked = await store.maskAsync(text);
    assert.match(masked, pattern, `expected masking for: ${text}`);
    assert.strictEqual(store.restore(masked), text, "restoration must be exact");
  }
});

test("False-positive guards hold (timestamps, prose, doc ranges, allow-list)", async () => {
  const config = loadConfig(".", {
    localModel: { enabled: false } as any,
  });
  const store = new RedactStore(config);

  const keep = [
    "2024-01-15T10:30:00Z started",
    "version 1.2.3 released",
    '"created_at": "2024-01-15T10:30:00Z"',
    "Basic authentication is required",
    "The token bucket refills every minute",
    '{"swap_free_bytes": 13800138000}',
    "2001:db8:abcd:0012::0 is our doc example",
    "Contact demo@example.com for help",
  ];
  for (const text of keep) {
    assert.strictEqual(await store.maskAsync(text), text, `must not mask: ${text}`);
  }
});

test("Real IPv6 addresses map to 2001:db8::/32 stand-ins", async () => {
  const config = loadConfig(".", {
    preserveShape: true,
    localModel: { enabled: false } as any,
  });
  const store = new RedactStore(config);

  const text = "server 2001:4860:4860::8888 up";
  const masked = await store.maskAsync(text);
  assert.match(masked, /server 2001:db8:[0-9a-f]{4}(:[0-9a-f]{4}){3} up/);
  assert.strictEqual(store.restore(masked), text);

  // Loopback, link-local and doc-range addresses stay untouched
  for (const ip of ["::1", "fe80::1", "2001:db8::1"]) {
    assert.strictEqual(await store.maskAsync(`ping ${ip} now`), `ping ${ip} now`);
  }
});

test("Group offset calculation - PASSWORD rule masks password, not username", async () => {
  const config = loadConfig(".", {
    localModel: { enabled: false } as any,
  });
  const store = new RedactStore(config);

  const text = "Database url: postgres://admin:admin@localhost:5432/mydb";
  const masked = await store.maskAsync(text);

  // The username "admin" must remain intact right after "postgres://"
  assert.match(masked, /postgres:\/\/admin:\{\{PASSWORD_[a-z2-7]{8}\}\}@localhost:5432\/mydb/);

  // Restoration recovers the exact original text
  const restored = store.restore(masked);
  assert.strictEqual(restored, text);
});

test("Group offset calculation - SECRET rule with matching characters in key", async () => {
  const config = loadConfig(".", {
    localModel: { enabled: false } as any,
  });
  const store = new RedactStore(config);

  const text = 'api_key: "api_key_secret_value_12345"';
  const masked = await store.maskAsync(text);

  assert.match(masked, /api_key: "\{\{SECRET_[a-z2-7]{8}\}\}"/);
  const restored = store.restore(masked);
  assert.strictEqual(restored, text);
});

test("IP stand-in collision resolution", async () => {
  const config = loadConfig(".", {
    preserveShape: true,
    localModel: { enabled: false } as any,
  });
  const store = new RedactStore(config);

  // Mask 40 distinct IP addresses
  const originalIps: string[] = [];
  const maskedIps: string[] = [];
  for (let i = 1; i <= 40; i++) {
    const ip = `198.51.100.${i}`;
    originalIps.push(ip);
    const masked = await store.maskAsync(ip);
    maskedIps.push(masked);
  }

  // Verify all 40 are unique in the masked mapping (no collision overwrite)
  const uniqueMasks = new Set(maskedIps);
  assert.strictEqual(uniqueMasks.size, 40, "All 40 distinct IPs must have distinct stand-ins/placeholders");

  // Verify full restoration of all 40 IPs
  for (let i = 0; i < 40; i++) {
    const restored = store.restore(maskedIps[i]);
    assert.strictEqual(restored, originalIps[i]);
  }
});

test("Private IP ranges are preserved unmasked", async () => {
  const config = loadConfig(".", {
    preserveShape: true,
    localModel: { enabled: false } as any,
  });
  const store = new RedactStore(config);

  // RFC 1918 10.x, 192.168.x, 172.16-31.x, link-local 169.254.x
  const privateIps = [
    "10.0.1.5",
    "192.168.1.1",
    "172.16.0.10",
    "172.24.1.1",
    "172.31.255.254",
    "169.254.169.254",
    "127.0.0.1",
  ];

  for (const ip of privateIps) {
    const masked = await store.maskAsync(ip);
    assert.strictEqual(masked, ip, `Private IP ${ip} should not be masked`);
  }

  // Public 172.x addresses (e.g. 172.15.x or 172.32.x) should be masked
  const public172 = "172.32.0.1";
  const maskedPublic = await store.maskAsync(public172);
  assert.notStrictEqual(maskedPublic, public172, "Public IP 172.32.0.1 should be masked");
});

test("JSON comment stripping handles inline and block comments incl. URLs", () => {
  // Write a real JSONC file so stripJsonComments + readJsonFile are exercised
  // end-to-end (regression: naive // stripping corrupts http:// URLs).
  const dir = mkdtempSync(join(tmpdir(), "masking-jsonc-"));
  try {
    writeFileSync(
      join(dir, "privacy-masking.json"),
      `{
        /* block comment */
        "secrets": true, // inline comment
        "personal": false,
        "localModel": {
          "endpoint": "http://127.0.0.1:11434/v1/chat/completions", // keep // in URL
          "model": "qwen2.5:1.5b"
        }
      }
      `
    );
    const config = loadConfig(dir);
    assert.strictEqual(config.secrets, true);
    assert.strictEqual(config.personal, false);
    assert.strictEqual(config.localModel.endpoint, "http://127.0.0.1:11434/v1/chat/completions");
    assert.strictEqual(config.localModel.model, "qwen2.5:1.5b");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Project allow-list unions with defaults (localhost preserved)", () => {
  const dir = mkdtempSync(join(tmpdir(), "masking-allow-"));
  try {
    writeFileSync(
      join(dir, "privacy-masking.json"),
      `{"allow": ["demo@example.com"]}`
    );
    const config = loadConfig(dir);
    assert.ok(config.allow.includes("demo@example.com"), "project entry kept");
    assert.ok(config.allow.includes("localhost"), "default localhost preserved");
    assert.ok(config.allow.includes("127.0.0.1"), "default 127.0.0.1 preserved");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Word boundaries prevent substring pollution on exact terms", async () => {
  const config = loadConfig(".", {
    words: ["admin"],
    localModel: { enabled: false } as any,
  });
  const store = new RedactStore(config);

  const text = "The administrator granted permissions to admin yesterday.";
  const masked = await store.maskAsync(text);

  assert.ok(masked.includes("administrator"), "administrator should not be partially masked");
  assert.match(masked, /to \{\{SECRET_[a-z2-7]{8}\}\} yesterday/);

  const restored = store.restore(masked);
  assert.strictEqual(restored, text);
});

test("Sticky cache eviction bounded by maxMemoryValues", async () => {
  const config = loadConfig(".", {
    maxMemoryValues: 10,
    localModel: { enabled: false, sticky: true } as any,
  });
  const store = new RedactStore(config);

  // Generate 25 distinct masked texts to verify no unbounded memory growth
  for (let i = 0; i < 25; i++) {
    await store.maskAsync(`Unique input line #${i} with sk-proj-1234567890abcdef${i}`);
  }

  // Access private stickyByRawHash and stickyMaskedHashes via casting to verify size
  const stickyMap = (store as any).stickyByRawHash as Map<string, string>;
  const stickySet = (store as any).stickyMaskedHashes as Set<string>;

  assert.ok(stickyMap.size <= 10, `stickyByRawHash size ${stickyMap.size} must be <= 10`);
  assert.ok(stickySet.size <= 25, `stickyMaskedHashes size ${stickySet.size} must be pruned`);
});

test("Plugin hook integration", async () => {
  const plugin = await PrivacyMaskingPlugin({ directory: "." } as any);

  // 1. System notice is unconditionally present
  const sysOutput: { system: string[] } = { system: ["You are a helpful assistant."] };
  await (plugin as any)["experimental.chat.system.transform"]({}, sysOutput);
  assert.strictEqual(sysOutput.system.length, 2);
  assert.ok(sysOutput.system[1].includes("Privacy masking is active"));

  // 2. Chat messages transform masks text, tool output, and tool error
  const msgOutput: { messages: any[] } = {
    messages: [
      {
        parts: [
          { type: "text", text: "Here is my key: sk-ant-api03-abcdef1234567890abcdef1234567890" },
          {
            type: "tool",
            state: {
              status: "error",
              error: "Connection failed for user postgres://user:secretpass12345@db.example.com",
              output: "Found ghp_1234567890abcdefghijklmnopqrstuv in log",
              input: { query: "sk-proj-abcdef1234567890abcdef1234567890" },
            },
          },
        ],
      },
    ],
  };

  await (plugin as any)["experimental.chat.messages.transform"]({}, msgOutput);
  const part0 = msgOutput.messages[0].parts[0];
  const part1 = msgOutput.messages[0].parts[1];

  assert.match(part0.text, /\{\{API_KEY_[a-z2-7]{8}\}\}/);
  assert.match(part1.state.output, /\{\{GITHUB_TOKEN_[a-z2-7]{8}\}\}/);
  assert.match(part1.state.error, /\{\{PASSWORD_[a-z2-7]{8}\}\}/);
  assert.match(part1.state.input.query, /\{\{API_KEY_[a-z2-7]{8}\}\}/);

  // 3. Tool execute before restores args
  const toolArgs = { args: { apiKey: part0.text.match(/\{\{API_KEY_[a-z2-7]{8}\}\}/)![0] } };
  await (plugin as any)["tool.execute.before"]({}, toolArgs);
  assert.strictEqual(toolArgs.args.apiKey, "sk-ant-api03-abcdef1234567890abcdef1234567890");

  // 4. Text complete restores text shown to user
  const textOutput = { text: `Used ${part0.text.match(/\{\{API_KEY_[a-z2-7]{8}\}\}/)![0]} successfully.` };
  await (plugin as any)["experimental.text.complete"]({}, textOutput);
  assert.strictEqual(textOutput.text, "Used sk-ant-api03-abcdef1234567890abcdef1234567890 successfully.");
});

test("Tabular: CSV auto-route masks cells per column, keeps shape", async () => {
  const config = loadConfig(".", { localModel: { enabled: false } as any });
  const store = new RedactStore(config);
  const text = "name,email,ip\nAlice,alice@example.org,8.8.8.8\nBob,bob@example.org,1.1.1.1";
  const masked = await store.maskAsync(text);
  const lines = masked.split("\n");
  assert.strictEqual(lines[0], "name,email,ip");
  assert.match(lines[1], /^Alice,\{\{EMAIL_[a-z2-7]{8}\}\},203\.0\.113\.\d{1,3}$/);
  assert.match(lines[2], /^Bob,\{\{EMAIL_[a-z2-7]{8}\}\},203\.0\.113\.\d{1,3}$/);
  // Full round-trip: placeholders restore to the exact original CSV
  assert.strictEqual(store.restore(masked), text);
});

test("Tabular: quoted commas and TSV/Markdown tables survive round-trip", async () => {
  const config = loadConfig(".", { localModel: { enabled: false } as any });
  const store = new RedactStore(config);

  const csv = 'name,email\n"Doe, John",john@example.org\n';
  const maskedCsv = await store.maskAsync(csv);
  assert.match(maskedCsv, /^name,email\n"Doe, John",\{\{EMAIL_[a-z2-7]{8}\}\}$/);
  assert.strictEqual(store.restore(maskedCsv), 'name,email\n"Doe, John",john@example.org');

  const tsv = "a\tb\n1\talice@example.org\n";
  assert.match(await store.maskAsync(tsv), /^a\tb\n1\t\{\{EMAIL_[a-z2-7]{8}\}\}$/);

  const md = "| name | email |\n|---|---|\n| Al | alice@example.org |";
  const maskedMd = await store.maskAsync(md);
  assert.ok(maskedMd.includes("{{EMAIL_"), "markdown email cell must mask");
  assert.ok(maskedMd.includes("|"), "markdown table shape preserved");

  // Prose is untouched by the table router
  const prose = "hello world this is just prose";
  assert.strictEqual(await store.maskAsync(prose), prose);
});

test("Tabular: excelColumns alias + sensitive-header hints", async () => {
  const config = loadConfig(".", {
    localModel: { enabled: false },
    excelColumns: { ssn: "mask", notes: "keep" },
  } as any);
  assert.strictEqual(config.tabular.columns.ssn, "mask");
  assert.strictEqual(config.body ?? undefined, undefined);
  const store = new RedactStore(config);
  const masked = await store.maskAsync("name,ssn,notes\nAlice,123-45-6789,hello\n");
  const row = masked.split("\n")[1];
  assert.match(row, /^Alice,\{\{[A-Z0-9_]+_[a-z2-7]{8}\}\},hello$/);

  // Header-hint masking: a password column masks even odd values no rule fires on
  const store2 = new RedactStore(loadConfig(".", { localModel: { enabled: false } as any }));
  const masked2 = await store2.maskAsync("user,password\nbob,Xy!9z\n");
  assert.match(masked2.split("\n")[1], /^bob,\{\{[A-Z0-9_]+_[a-z2-7]{8}\}\}$/);
  assert.strictEqual(store2.restore(masked2), "user,password\nbob,Xy!9z");
  assert.strictEqual(masked2.split("\n")[0], "user,password", "header row preserved");
});

test("Tabular: XLSX round-trip preserves workbook, masks strings", async () => {
  const { buildZip, serializeSharedStrings, parseXlsx } = await import("./tabular.ts");
  const config = loadConfig(".", { localModel: { enabled: false } as any });
  const store = new RedactStore(config);

  const shared = ["name", "email", "Alice", "alice@example.org", "Bob", "bob@example.org"];
  const cell = (ref: string, s: number) => `<c r="${ref}" t="s"><v>${s}</v></c>`;
  const sheet =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>` +
    `<row r="1">${cell("A1", 0)}${cell("B1", 1)}</row>` +
    `<row r="2">${cell("A2", 2)}${cell("B2", 3)}</row>` +
    `<row r="3">${cell("A3", 4)}${cell("B3", 5)}</row>` +
    `</sheetData></worksheet>`;
  const xlsx = buildZip(
    new Map([
      ["[Content_Types].xml", Buffer.from(`<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/></Types>`)],
      ["xl/workbook.xml", Buffer.from(`<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>`)],
      ["xl/worksheets/sheet1.xml", Buffer.from(sheet)],
      ["xl/sharedStrings.xml", Buffer.from(serializeSharedStrings(shared))],
    ])
  );
  const dir = mkdtempSync(join(tmpdir(), "masking-xlsx-"));
  try {
    const file = join(dir, "data.xlsx");
    writeFileSync(file, xlsx);
    const res = await store.maskFileAsync(file);
    assert.ok(res && res.format === "xlsx" && res.bytes && res.bytes.length > 0);
    const reparsed = parseXlsx(res.bytes!);
    assert.deepStrictEqual(reparsed!.headers, ["name", "email"]);
    assert.match(reparsed!.rows[0][1], /^\{\{EMAIL_[a-z2-7]{8}\}\}$/);
    assert.match(reparsed!.rows[1][1], /^\{\{EMAIL_[a-z2-7]{8}\}\}$/);
    // Original shared strings untouched in the masked copy's mapping
    assert.strictEqual(store.restore(reparsed!.rows[0][1]), "alice@example.org");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("IPv6: MAC addresses, clock times and ratios are not masked", async () => {
  const config = loadConfig(".", { localModel: { enabled: false } as any });
  const store = new RedactStore(config);

  const keep = [
    "adapter aa:bb:cc:dd:ee:ff is down",
    "started at 12:34:56 yesterday",
    "meet at 10:30 tomorrow",
    "ratio 1:2:3 holds",
  ];
  for (const text of keep) {
    assert.strictEqual(await store.maskAsync(text), text, `must not mask: ${text}`);
  }

  // Real IPv6 (full + compressed) still masks and restores
  for (const ip of ["2001:4860:4860::8888", "fe80::1:2:3:4:5", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"]) {
    if (ip.startsWith("fe80:")) {
      assert.strictEqual(await store.maskAsync(`ping ${ip}`), `ping ${ip}`);
      continue;
    }
    const masked = await store.maskAsync(`ping ${ip} now`);
    assert.ok(masked.includes("2001:db8:"), `must mask ${ip}: ${masked}`);
    assert.strictEqual(store.restore(masked), `ping ${ip} now`);
  }
  // Over-long group chains are not valid IPv6
  assert.strictEqual(
    await store.maskAsync("see 1:2:3:4:5:6::7:8:9:10:11:12 here"),
    "see 1:2:3:4:5:6::7:8:9:10:11:12 here"
  );
});

test("Tabular: markdown table+prose falls back to scalar (no data loss)", async () => {
  const config = loadConfig(".", { localModel: { enabled: false } as any });
  const store = new RedactStore(config);

  const mixed = "| name | email |\n|---|---|\n| Al | alice@example.org |\nSome trailing note here";
  const masked = await store.maskAsync(mixed);
  assert.ok(masked.includes("Some trailing note here"), `trailing prose must survive: ${masked}`);
  assert.ok(masked.includes("{{EMAIL_"), "email in table+prose must still mask via scalar path");
  assert.strictEqual(store.restore(masked), mixed);

  // Pure table still routes through the table pipeline (padded re-serialization)
  const pure = "| name | email |\n|---|---|\n| Al | alice@example.org |";
  const maskedPure = await store.maskAsync(pure);
  assert.ok(maskedPure.includes("{{EMAIL_"), `pure table must mask: ${maskedPure}`);
  assert.ok(maskedPure.includes("|"), "markdown shape preserved");
  // Restore recovers the email; padding normalization means exact text differs
  assert.ok(store.restore(maskedPure).includes("alice@example.org"));
});

test("Tabular: headerless markdown table keeps every data row", async () => {
  const config = loadConfig(".", { localModel: { enabled: false } as any });
  const store = new RedactStore(config);

  const md = "| 123 | 456 |\n|---|---|\n| Al | alice@example.org |";
  const masked = await store.maskAsync(md);
  // Both data rows must survive (old code dropped the first via rows.slice(1))
  assert.ok(masked.includes("123"), `first data row must survive: ${masked}`);
  assert.ok(masked.includes("{{EMAIL_"), "email cell must mask");
  assert.ok(masked.includes("456"), `second column of first row must survive: ${masked}`);
  // Restore recovers all original values (padding is normalized by design)
  const restored = store.restore(masked);
  assert.ok(restored.includes("123") && restored.includes("456"), `numbers survive: ${restored}`);
  assert.ok(restored.includes("alice@example.org"), `email restores: ${restored}`);
  assert.ok(restored.includes("Al"), `name cell survives: ${restored}`);
});

test("Tabular: multi-sheet XLSX masks every sheet with its own headers", async () => {
  const { buildZip, serializeSharedStrings, parseXlsxSheets } = await import("./tabular.ts");
  const config = loadConfig(".", { localModel: { enabled: false } as any });
  const store = new RedactStore(config);

  // Sheet1 headers: name,email. Sheet2 headers: name,notes. Sheet 2 must be
  // masked with its OWN headers (old code reused sheet 1's rows, leaking or
  // mis-masking sheet 2+).
  const shared = ["name", "email", "notes", "Alice", "alice@example.org"];
  const cell = (ref: string, s: number) => `<c r="${ref}" t="s"><v>${s}</v></c>`;
  const mkSheet = (headers: [number, number], row: [number, number]) =>
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>` +
    `<row r="1">${cell("A1", headers[0])}${cell("B1", headers[1])}</row>` +
    `<row r="2">${cell("A2", row[0])}${cell("B2", row[1])}</row>` +
    `</sheetData></worksheet>`;
  const xlsx = buildZip(
    new Map([
      ["[Content_Types].xml", Buffer.from(`<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/xl/worksheets/sheet1.xml" ContentType="w"/><Override PartName="/xl/worksheets/sheet2.xml" ContentType="w"/><Override PartName="/xl/sharedStrings.xml" ContentType="s"/></Types>`)],
      ["xl/worksheets/sheet1.xml", Buffer.from(mkSheet([0, 1], [3, 4]))],
      ["xl/worksheets/sheet2.xml", Buffer.from(mkSheet([0, 2], [3, 4]))],
      ["xl/sharedStrings.xml", Buffer.from(serializeSharedStrings(shared))],
    ])
  );
  const dir = mkdtempSync(join(tmpdir(), "masking-xlsx-multi-"));
  try {
    const file = join(dir, "two.xlsx");
    writeFileSync(file, xlsx);
    const res = await store.maskFileAsync(file);
    assert.ok(res && res.format === "xlsx" && res.bytes && res.bytes.length > 0);
    const sheets = parseXlsxSheets(res.bytes!);
    assert.ok(sheets && sheets.length === 2, "both sheets must parse");
    assert.deepStrictEqual(sheets[0].table.headers, ["name", "email"]);
    assert.deepStrictEqual(sheets[1].table.headers, ["name", "notes"]);
    // Sheet1 email cell masked with sheet1's headers
    assert.match(sheets[0].table.rows[0][1], /^\{\{EMAIL_[a-z2-7]{8}\}\}$/, `sheet1 masked: ${sheets[0].table.rows[0]}`);
    // Sheet2: no raw email survives anywhere
    for (const row of sheets[1].table.rows) {
      assert.ok(!row.some((c) => c === "alice@example.org"), `sheet2 leak: ${row}`);
    }
    // Round-trip: every masked value restores
    for (const sh of sheets) {
      for (const row of sh.table.rows) {
        for (const c of row) {
          const restored = store.restore(c);
          assert.ok(restored === c || shared.includes(restored) || c === "", `restorable: ${c}`);
        }
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("knownValues is bounded by maxMemoryValues", async () => {
  const config = loadConfig(".", {
    maxMemoryValues: 10,
    localModel: { enabled: false } as any,
  });
  const store = new RedactStore(config);
  for (let i = 0; i < 25; i++) {
    await store.maskAsync(`api_key=Abcdefgh12345678_${String(i).padStart(3, "0")}`);
  }
  const known = (store as any).knownValues as Map<string, string>;
  assert.ok(known.size <= 10, `knownValues size ${known.size} must be <= 10`);
});

test("Tabular: limits and legacy .xls refusal", async () => {
  const { writeFileSync: writeSync } = await import("node:fs");
  const config = loadConfig(".", {
    localModel: { enabled: false },
    tabular: { maxBytes: 32 },
  } as any);
  const store = new RedactStore(config);
  const dir = mkdtempSync(join(tmpdir(), "masking-xls-"));
  try {
    const legacy = join(dir, "old.xls");
    writeSync(legacy, Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, 0, 0]));
    await assert.rejects(store.maskFileAsync(legacy), /Legacy OLE/);
    // Unknown extension => null fallback for scalar masking
    const txt = join(dir, "notes.txt");
    writeSync(txt, "just prose");
    assert.strictEqual(await store.maskFileAsync(txt), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Tabular: byte cap returns oversized tables unchanged", async () => {
  const { writeFileSync: writeSync2 } = await import("node:fs");
  const config = loadConfig(".", {
    localModel: { enabled: false },
    tabular: { maxBytes: 64 },
  } as any);
  const store = new RedactStore(config);
  // 64-byte cap: 11-row table (~300 bytes) must pass through 100% unchanged
  const big = "name,email\n" + "a@b.co,12345678901234567890\n".repeat(10);
  assert.ok(Buffer.byteLength(big, "utf8") > 64, "fixture must exceed the cap");
  assert.strictEqual(await store.maskAsync(big), big);
  // Small table under the cap still masks
  const small = await store.maskAsync("name,email\nAl,alice@example.org\n");
  assert.ok(small.includes("{{EMAIL_"), "under-cap table must mask");
  // Same cap applies to maskFileAsync
  const dir = mkdtempSync(join(tmpdir(), "masking-cap-"));
  try {
    const csv = join(dir, "big.csv");
    writeSync2(csv, big);
    assert.strictEqual(await store.maskFileAsync(csv), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
