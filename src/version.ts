import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** Version from package.json (searched upwards: works from src/ and from dist/src/). */
export function relayVersion(): string {
  let dir = path.dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 4; i++) {
    try {
      const pkg = JSON.parse(readFileSync(path.join(dir, "package.json"), "utf8")) as {
        name?: string;
        version?: string;
      };
      if (pkg.name === "flowplan-push" && typeof pkg.version === "string") return pkg.version;
    } catch {
      // keep searching
    }
    dir = path.dirname(dir);
  }
  return "unknown";
}
