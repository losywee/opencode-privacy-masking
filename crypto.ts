/**
 * HMAC key management, deterministic placeholders, and RFC stand-ins.
 * Place inside: `.opencode/plugins/privacy-masking/crypto.ts`
 */

import { createHash, createHmac, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

export function getConfigDir(): string {
  return join(homedir(), ".config", "opencode");
}

export function loadOrCreateHmacKey(): Buffer {
  const configDir = getConfigDir();
  const keyPath = join(configDir, "privacy-masking.key");
  try {
    if (existsSync(keyPath)) {
      const raw = readFileSync(keyPath);
      if (raw.length >= 32) return raw;
    }
    mkdirSync(configDir, { recursive: true });
    const key = randomBytes(32);
    writeFileSync(keyPath, key, { mode: 0o600 });
    chmodSync(keyPath, 0o600);
    return key;
  } catch {
    return randomBytes(32);
  }
}

export function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

export function hmacBase32(key: Buffer, kind: string, value: string, length = 8): string {
  const digest = createHmac("sha256", key).update(`${kind}\0${value}`).digest();
  let out = "";
  let bits = 0;
  let buffer = 0;
  for (const byte of digest) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5 && out.length < length) {
      bits -= 5;
      out += BASE32_ALPHABET[(buffer >> bits) & 31];
    }
    if (out.length >= length) break;
  }
  return out;
}

/**
 * Generates an 8-letter deterministic RFC 2606 `.example` hostname stand-in.
 */
export function hostStandInOf(key: Buffer, host: string): string {
  const digest = createHmac("sha256", key).update(`HOST\0${host.toLowerCase()}`).digest();
  let label = "";
  for (let i = 0; i < 8; i++) {
    label += String.fromCharCode(97 + (digest[i] % 26));
  }
  return `${label}.example`;
}

/**
 * Generates a deterministic RFC 5737 TEST-NET-3 (`203.0.113.x`) IP stand-in.
 */
export function ipStandInOf(key: Buffer, ip: string): string {
  const digest = createHmac("sha256", key).update(`IP\0${ip}`).digest();
  const hostByte = (digest[0] % 253) + 1;
  return `203.0.113.${hostByte}`;
}