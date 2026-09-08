import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

/**
 * 07-02 scoped upstream CSS is generated deterministically from the immutable
 * originals. Re-running the generator must reproduce the committed files
 * byte-for-byte, and every emitted selector must stay inside its .up-* scope
 * so upstream presentation cannot leak into the internal UI.
 */
const repoRoot = resolve(fileURLToPath(import.meta.url), "../../../..");
const cssDir = resolve(repoRoot, "web", "src", "app", "upstream-css");

const SCOPES = ["up-main", "up-start", "up-quiz", "up-photo", "up-etc"] as const;

test("regenerating the scoped upstream CSS is byte-for-byte deterministic", () => {
  const before = Object.fromEntries(
    SCOPES.map((scope) => [scope, readFileSync(resolve(cssDir, `${scope}.css`)).toString("utf8")]),
  );
  execFileSync("python3", ["scripts/namespace_upstream_css.py"], { cwd: repoRoot });
  for (const scope of SCOPES) {
    const after = readFileSync(resolve(cssDir, `${scope}.css`)).toString("utf8");
    expect(after, `${scope}.css must regenerate identically`).toBe(before[scope]);
  }
});

test.for(SCOPES as unknown as string[])(
  "%s.css keeps every selector inside the page scope",
  (scope) => {
    const css = readFileSync(resolve(cssDir, `${scope}` + ".css")).toString("utf8");
    const selectorLines = css
      .split("\n")
      .map((line) => line.trim())
      .filter(
        (line) =>
          line.length > 0 &&
          !line.startsWith("@keyframes") &&
          !line.startsWith("@-webkit-keyframes") &&
          !line.startsWith("@media") &&
          line !== "}" &&
          !line.endsWith("{") &&
          line.includes("{"),
      );
    expect(selectorLines.length).toBeGreaterThan(10);
    for (const line of selectorLines) {
      const selector = line.slice(0, line.indexOf("{"));
      for (const compound of selector.split(",")) {
        const trimmed = compound.trim();
        const inScope = trimmed === `.${scope}` || trimmed.startsWith(`.${scope} `) || trimmed === `.${scope},`;
        expect(inScope, `selector out of scope: ${trimmed}`).toBe(true);
      }
    }
  },
);
