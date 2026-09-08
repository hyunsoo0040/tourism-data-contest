import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

/**
 * 07-02 authority boundary: the built web app must not import, execute, or
 * reconstruct the upstream JS as any kind of authority, and must not carry
 * hidden upstream fetch/XHR code. The vendored originals stay fixtures-only.
 */
const repoRoot = resolve(fileURLToPath(import.meta.url), "../../../..");
const srcDir = resolve(repoRoot, "web", "src");

function* walk(dir: string): Generator<string> {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = resolve(dir, entry.name);
    if (entry.isDirectory()) yield* walk(full);
    else if (/\.(ts|tsx|css)$/.test(entry.name) && !entry.name.endsWith(".test.ts") && !entry.name.endsWith(".test.tsx")) {
      yield full;
    }
  }
}

test("web source never imports or embeds the upstream behavior scripts", () => {
  const forbidden = [
    /from\s+["'][^"']*메인페이지\.js["']/,
    /import\(\s*["'][^"']*메인페이지\.js/,
    /<script[^>]*메인페이지\.js/,
    /from\s+["'][^"']*기타\.js["']/,
    /import\(\s*["'][^"']*기타\.js/,
    /<script[^>]*기타\.js/,
    /XMLHttpRequest/,
    /\.send\(\)/,
    /new WebSocket\(/,
    /eval\(/,
  ];
  for (const file of walk(srcDir)) {
    if (file.includes(`${"upstream-css"}`)) continue; // generated CSS only
    const text = readFileSync(file, "utf8");
    for (const pattern of forbidden) {
      expect(pattern.test(text), `${file} matches forbidden pattern ${pattern}`).toBe(false);
    }
  }
});

test("web source never references upstream host or non-relative upstream fetch", () => {
  for (const file of walk(srcDir)) {
    if (file.includes("upstream-css")) continue;
    const text = readFileSync(file, "utf8");
    expect(/hyunsoo0040/.test(text), `${file} references the upstream repository`).toBe(false);
    expect(/Backend\/ItDaServer/.test(text), `${file} references the upstream backend`).toBe(false);
  }
});

test("the only upstream localStorage key use is the presentation-only preselection read", () => {
  const main = readFileSync(resolve(srcDir, "app", "upstream", "UpstreamMainPage.tsx"), "utf8");
  expect(main).toContain("itdaTravelPreference");
  // It is a read-only preselection: no writes to that key anywhere in src.
  for (const file of walk(srcDir)) {
    if (file.includes("upstream-css")) continue;
    const text = readFileSync(file, "utf8");
    if (text.includes("itdaTravelPreference")) {
      expect(/setItem\(\s*"itdaTravelPreference"|setItem\(`itdaTravelPreference`/.test(text)).toBe(false);
    }
  }
});
