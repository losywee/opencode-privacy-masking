import { existsSync } from "node:fs";
import { resolve as pathResolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export async function resolve(specifier, context, nextResolve) {
  try {
    return await nextResolve(specifier, context);
  } catch (err) {
    if (specifier.startsWith(".") && context.parentURL) {
      const parentDir = pathResolve(fileURLToPath(context.parentURL), "..");
      const target = pathResolve(parentDir, specifier);
      if (existsSync(target + ".ts")) {
        return { url: pathToFileURL(target + ".ts").href, shortCircuit: true };
      }
      if (existsSync(pathResolve(target, "index.ts"))) {
        return { url: pathToFileURL(pathResolve(target, "index.ts")).href, shortCircuit: true };
      }
    }
    throw err;
  }
}
