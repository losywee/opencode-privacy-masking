/**
 * OpenCode Privacy Masking Plugin — Entrypoint
 *
 * Directory layout inside `.opencode/plugins/` (or `~/.config/opencode/plugins/`):
 *   plugins/
 *   ├── privacy-masking.ts             <-- Only top-level file auto-discovered by OpenCode
 *   └── privacy-masking/
 *       ├── config.ts                  <-- Configuration & types (reads opencode.json & privacy-masking.json)
 *       ├── crypto.ts                  <-- HMAC key, base32 placeholders & RFC stand-ins
 *       ├── rules.ts                   <-- Built-in regex rules & structural guards
 *       ├── local-model.ts             <-- Single-flight local LLM client & SHA-256 LRU cache
 *       └── store.ts                   <-- RedactStore, Sticky Masking & O(N) restoration
 */

import type { Plugin } from "@opencode-ai/plugin";
import { loadConfig } from "./config";
import { RedactStore } from "./store";

const SYSTEM_NOTICE =
  "Privacy masking is active. Placeholders like {{SECRET_...}} or stand-ins (203.0.113.x, *.example) represent real values that are automatically restored locally before tool execution. Use them verbatim in tool calls and responses without asking the user for the original values.";

export const PrivacyMaskingPlugin: Plugin = async (ctx) => {
  const config = loadConfig(ctx.directory);
  const store = new RedactStore(config, ctx.directory);

  return {
    // 1. Scrub chat messages in-place before sending to the upstream LLM.
    //    Processes newest messages first under a single per-turn deadline (mirrors pii.Bounded).
    "experimental.chat.messages.transform": async (_input, output) => {
      if (!Array.isArray(output.messages) || output.messages.length === 0) return;

      const turnDeadline = Date.now() + store.config.localModel.timeoutMs;
      for (let i = output.messages.length - 1; i >= 0; i--) {
        const msg = output.messages[i];
        if (!msg || !Array.isArray(msg.parts)) continue;

        for (let j = msg.parts.length - 1; j >= 0; j--) {
          const part = msg.parts[j];
          if (!part) continue;

          if (part.type === "text" && typeof part.text === "string") {
            part.text = await store.maskAsync(part.text, false, turnDeadline);
          } else if (part.type === "tool" && part.state) {
            if (typeof part.state.output === "string") {
              part.state.output = await store.maskAsync(part.state.output, false, turnDeadline);
            }
            if (typeof part.state.error === "string") {
              part.state.error = await store.maskAsync(part.state.error, false, turnDeadline);
            }
            if (part.state.input && typeof part.state.input === "object") {
              await store.maskDeepAsync(part.state.input, true, turnDeadline);
            } else if (typeof part.state.input === "string") {
              part.state.input = await store.maskAsync(part.state.input, true, turnDeadline);
            }
          }
        }
      }
    },

    // 2. Inject system prompt instruction to guide LLM on placeholders without busting prompt cache.
    "experimental.chat.system.transform": async (_input, output) => {
      if (!Array.isArray(output.system)) return;
      if (!output.system.includes(SYSTEM_NOTICE)) {
        output.system.push(SYSTEM_NOTICE);
      }
    },

    // 3. Restore real values in-place inside tool arguments before local execution.
    "tool.execute.before": async (_input, output) => {
      if (output.args && typeof output.args === "object") {
        store.restoreDeep(output.args);
      }
    },

    // 4. Scrub secrets from tool outputs right after execution.
    "tool.execute.after": async (_input, output) => {
      const turnDeadline = Date.now() + store.config.localModel.timeoutMs;
      if (typeof output.output === "string") {
        output.output = await store.maskAsync(output.output, false, turnDeadline);
      }
      if (typeof output.title === "string") {
        output.title = await store.maskAsync(output.title, false, turnDeadline);
      }
      if (typeof (output as any).error === "string") {
        (output as any).error = await store.maskAsync((output as any).error, false, turnDeadline);
      }
    },

    // 5. Restore placeholders in finalized assistant response text shown to the user.
    "experimental.text.complete": async (_input, output) => {
      if (typeof output.text === "string") {
        output.text = store.restore(output.text);
      }
    },
  };
};

export default PrivacyMaskingPlugin;