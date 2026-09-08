import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

import provenance from "../../../fixtures/upstream-ui/provenance.json";

/**
 * 07-02 vendored-original integrity: every manifest entry must exist under
 * fixtures/upstream-ui/original/ and match the frozen SHA-256 and byte count
 * byte-for-byte. This is the deterministic local verification of the
 * authorized upstream sources; a mismatch fails closed.
 */
const repoRoot = resolve(fileURLToPath(import.meta.url), "../../../..");
const originalsDir = resolve(repoRoot, "fixtures", "upstream-ui", "original");

test("provenance manifest freezes the authorized upstream commit", () => {
  expect(provenance.upstream.repository).toBe("hyunsoo0040/tourism-data-contest");
  expect(provenance.upstream.commit).toBe("d3f2ac2aa7ed866a753b4916b6f9544b22ae0611");
  expect(provenance.authorization.status).toBe("user-confirmed-authorization");
  expect(provenance.authorization.upstream_license).toBeNull();
  expect(provenance.files).toHaveLength(13);
});

test.for(provenance.files as ReadonlyArray<{ upstream_path: string; sha256: string; bytes: number }>)(
  "vendored original matches the frozen hash: $upstream_path",
  (entry) => {
    const bytes = readFileSync(resolve(originalsDir, entry.upstream_path));
    expect(bytes.byteLength).toBe(entry.bytes);
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(entry.sha256);
  },
);

test("excluded upstream content is not vendored", () => {
  const excludedPaths = provenance.excluded.map((entry) => entry.upstream_path);
  expect(excludedPaths).toEqual([
    "Backend/ItDaServer.java",
    "『2026 관광데이터 활용 공모전』 제안서_connector(김현수).pdf",
    "README.md",
    "tmp/",
  ]);
});
