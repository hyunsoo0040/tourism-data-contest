import { expect, test, type APIResponse } from "@playwright/test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ProfileReleaseConsole,
  normalizeRollbackReason,
  profileReleaseSurfaceContract,
  type ProfileReleaseBuildInput,
  type ProfileReleaseMutation,
} from "../src/features/evaluation/ProfileReleaseConsole";
import type { ProfileReleaseBuildOutcome } from "../src/features/evaluation/api";

type Fixture = {
  assignment: { assignment_id: string };
  rubric: {
    ordered_attribute_ids: string[];
    subattributes: Array<{ attribute_id: string; label_ko: string }>;
  };
  forbidden_canaries: string[];
};

type RuntimeFixture = {
  synthetic_only: true;
  assignment: {
    assignment_id: string;
    rubric_version: string;
    source_snapshot_version: string;
  };
  sources: Array<{ source_id: string; lane: "DESCRIPTION" | "ODII"; text_ko: string }>;
  evidence_items: Array<{
    evidence_id: string;
    source_id: string;
    lane: "DESCRIPTION" | "ODII";
    dedup_cluster_id: string;
  }>;
  release: {
    candidate_release_sha256: string;
    active_release_sha256: string;
    status: string;
  };
};

const ATTRIBUTE_IDS = ["H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "R1", "R2", "R3", "R4"];

const fixture = JSON.parse(
  readFileSync(
    resolve(dirname(fileURLToPath(import.meta.url)), "../../fixtures/synthetic/phase3/labeling.json"),
    "utf8",
  ),
) as Fixture;

const evaluatorPath = "/internal/evaluator/assignments/synthetic-runtime-assignment-alpha";
const operatorPath = "/internal/operator/assignments/synthetic-runtime-assignment-alpha";
const adjudicatorPath = "/internal/adjudicator/assignments/synthetic-runtime-assignment-alpha";
const evidenceReviewPath = "/internal/profile-releases/builder/evidence-review";

type RuntimeRole =
  | "EVALUATOR_A"
  | "EVALUATOR_B"
  | "EVALUATOR_C"
  | "ADJUDICATOR"
  | "BUILDER"
  | "APPROVER";

const RELEASE_HASH = "a".repeat(64);

function profileReleaseBuildInput(): ProfileReleaseBuildInput {
  return {
    canonical_lineage_sha256: "1".repeat(64),
    candidate_run_sha256: "4".repeat(64),
    cohort: Array.from({ length: 24 }, (_, index) => ({
      accepted_review_set_sha256: syntheticHash(`accepted-review-${index}`),
      candidate_manifest_sha256: syntheticHash(`candidate-manifest-${index}`),
      description_lane: "READY" as const,
      evidence_ready: true,
      label_export_sha256: syntheticHash(`label-export-${index}`),
      label_ready: true,
      odii_lane: "READY" as const,
      place_ref: `synthetic-place-${String(index + 1).padStart(2, "0")}`,
      profile_sha256: index.toString(16).padStart(64, "0"),
      reviewed_evidence_manifest_sha256: syntheticHash(`reviewed-evidence-${index}`),
      rights_sha256: syntheticHash(`rights-${index}`),
      rights_ready: true,
      source_sha256: syntheticHash(`source-${index}`),
    })),
    dev_lineage_sha256: "2".repeat(64),
    label_freeze_sha256: "5".repeat(64),
    profile_schema_sha256: "3".repeat(64),
    reviewed_manifest_sha256: "6".repeat(64),
    release_id: "synthetic-profile-release-console",
    rights_manifest_sha256: "7".repeat(64),
    schema_version: "itda.profile-release-candidate.v1",
    source_manifest_sha256: "8".repeat(64),
  };
}

function syntheticHash(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function linkedProfileReleaseBuildInput(releaseId: string): ProfileReleaseBuildInput {
  const labelFreezeSha256 = syntheticHash("synthetic-label-freeze");
  const candidateRunSha256 = syntheticHash("synthetic-candidate-run");
  const candidateManifestSha256 = syntheticHash("synthetic-candidate-manifest");
  const reviewedManifestSha256 = syntheticHash("synthetic-reviewed-evidence-manifest");
  const acceptedReviewSetSha256 = syntheticHash("synthetic-accepted-review-set");
  const rightsManifestSha256 = syntheticHash("synthetic-rights-manifest");
  const sourceManifestSha256 = syntheticHash("synthetic-source-manifest");
  return {
    candidate_run_sha256: candidateRunSha256,
    canonical_lineage_sha256: syntheticHash("synthetic-canonical-lineage"),
    code_sha256: syntheticHash("synthetic-code"),
    cohort: Array.from({ length: 24 }, (_, index) => ({
      accepted_review_set_sha256: acceptedReviewSetSha256,
      candidate_manifest_sha256: candidateManifestSha256,
      description_lane: "READY" as const,
      evidence_ready: true,
      label_export_sha256: labelFreezeSha256,
      label_ready: true,
      odii_lane: index === 23 ? ("MISSING" as const) : ("READY" as const),
      place_ref: `synthetic-dev-place-${String(index + 1).padStart(2, "0")}`,
      profile_sha256: syntheticHash(`${releaseId}:profile:${index}`),
      reviewed_evidence_manifest_sha256: reviewedManifestSha256,
      rights_ready: true,
      rights_sha256: rightsManifestSha256,
      source_sha256: sourceManifestSha256,
    })),
    config_sha256: syntheticHash("synthetic-config"),
    dev_lineage_sha256: syntheticHash("synthetic-dev-lineage"),
    label_freeze_sha256: labelFreezeSha256,
    profile_schema_sha256: syntheticHash("synthetic-profile-schema"),
    release_id: releaseId,
    reviewed_manifest_sha256: reviewedManifestSha256,
    rights_manifest_sha256: rightsManifestSha256,
    source_manifest_sha256: sourceManifestSha256,
    schema_version: "itda.profile-release-candidate.v1",
  };
}

function releaseMutation(state: ProfileReleaseMutation["state"]): ProfileReleaseMutation {
  return {
    completion: state === "ACTIVE" ? "MUTATION_COMMITTED" : null,
    receipt_sha256: state === "BUILT_UNAPPROVED" ? null : "c".repeat(64),
    release_sha256: RELEASE_HASH,
    state,
  };
}

test("profile release console keeps builder, approver, and activator stages distinct", () => {
  expect(typeof ProfileReleaseConsole).toBe("function");
  expect(profileReleaseBuildInput().cohort).toHaveLength(24);
  const builder = profileReleaseSurfaceContract(
    "builder",
    releaseMutation("BUILT_UNAPPROVED"),
  );
  const approver = profileReleaseSurfaceContract(
    "approver",
    releaseMutation("APPROVED_INACTIVE"),
  );
  const activator = profileReleaseSurfaceContract("activator", releaseMutation("ACTIVE"));

  expect(builder.state).toBe("BUILT_UNAPPROVED");
  expect(builder.actions).toEqual(["불변 release 후보 만들기"]);
  expect(builder.actions).not.toContain("정확한 release 승인하기");
  expect(approver.state).toBe("APPROVED_INACTIVE");
  expect(approver.actions).toEqual(["정확한 release 승인하기"]);
  expect(approver.actions).not.toContain("승인된 release 활성화하기");
  expect(activator.state).toBe("ACTIVE");
  expect(activator.actions).toEqual([
    "승인된 release 활성화하기",
    "이전 active release로 되돌리기",
  ]);
  for (const surface of [builder, approver, activator]) {
    expect(surface.release_sha256).toBe(RELEASE_HASH);
    expect(JSON.stringify(surface)).not.toMatch(/approver[_ -]?identity|capability|token/i);
  }
  expect(normalizeRollbackReason("  합성 rollback 사유  ")).toBe("합성 rollback 사유");
  expect(normalizeRollbackReason("   ")).toBeNull();
  expect(normalizeRollbackReason("가".repeat(301))).toBeNull();
});

test("profile release routed browser journey reconciles build and activation before success", async ({
  page,
}, testInfo) => {
  const capabilities = {
    approver: runtimeCapability("APPROVER"),
    builder: runtimeCapability("BUILDER"),
  };
  let browserCapability = capabilities.builder;
  let rawBuildNonce = "";
  let rawTransitionNonce = "";
  let committedBuild: ProfileReleaseBuildOutcome | null = null;
  const networkBodies: string[] = [];
  const requestUrls: string[] = [];

  await page.unroute("**/*");
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (
      (url.protocol === "http:" || url.protocol === "https:") &&
      !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)
    ) {
      if (url.hostname.endsWith("fonts.googleapis.com") || url.hostname === "fonts.gstatic.com") {
        await route.abort();
        return;
      }
      throw new Error("non-loopback browser request blocked");
    }
    const internal = url.pathname.startsWith("/internal/evaluation");
    if (internal) {
      const response = await route.fetch({
        headers: {
          ...route.request().headers(),
          "X-ITDA-Phase3-Capability": browserCapability,
        },
      });
      await route.fulfill({
        body: await response.body(),
        headers: response.headers(),
        status: response.status(),
      });
      return;
    }
    await route.continue();
  });
  await page.route(
    "**/internal/evaluation/profile-releases/build-drafts/build",
    async (route) => {
      const body = route.request().postDataJSON() as { draft_ref: string };
      expect(body.draft_ref).toMatch(/^[A-Za-z0-9_-]{43}$/);
      const forwarded = await route.fetch({
        headers: {
          ...route.request().headers(),
          "X-ITDA-Phase3-Capability": capabilities.builder,
        },
      });
      const forwardedBody = await forwarded.text();
      expect(forwarded.status(), forwardedBody).toBe(201);
      committedBuild = JSON.parse(forwardedBody) as ProfileReleaseBuildOutcome;
      expect(committedBuild.nonce_sha256).toBe(syntheticHash(rawBuildNonce));
      await route.abort("failed");
    },
    { times: 1 },
  );
  page.on("request", (request) => {
    requestUrls.push(request.url());
    if (request.url().endsWith("/profile-releases/build-drafts")) {
      rawBuildNonce = (
        request.postDataJSON() as { reconciliation_nonce: string }
      ).reconciliation_nonce;
    }
    if (request.url().endsWith("/activate")) {
      rawTransitionNonce = (request.postDataJSON() as { nonce: string }).nonce;
    }
  });
  page.on("response", async (response) => {
    const url = new URL(response.url());
    if (url.pathname.startsWith("/internal/evaluation")) {
      networkBodies.push(await response.text().catch(() => ""));
    }
  });

  const buildInput = linkedProfileReleaseBuildInput(
    `synthetic-profile-release-browser-${runtimeAttemptRef(testInfo)}`,
  );
  await page.goto("/internal/profile-releases/builder");
  await page.getByLabel("검토된 release 후보 JSON").setInputFiles({
    buffer: Buffer.from(JSON.stringify(buildInput), "utf8"),
    mimeType: "application/json",
    name: "reviewed-release-candidate.json",
  });
  await page.getByRole("button", { name: "보호 draft 준비하기" }).click();
  const builderHeading = page.getByRole("heading", {
    level: 1,
    name: "DEV profile release 후보",
  });
  await expect(builderHeading).toBeFocused();
  expect(rawBuildNonce).toMatch(/^[0-9a-f]{64}$/);
  await expect(page.getByRole("button", { name: "불변 release 후보 만들기" })).toBeVisible();
  await page.getByRole("button", { name: "불변 release 후보 만들기" }).click();
  await expect(page.getByText("BUILT_UNAPPROVED · 후보 생성됨, 독립 승인 전")).toBeVisible();
  expect(rawBuildNonce).toMatch(/^[0-9a-f]{64}$/);
  expect(committedBuild).not.toBeNull();
  const releaseSha256 = committedBuild!.release_sha256;

  browserCapability = capabilities.approver;
  await page.goto("/internal/profile-releases/approver");
  await expect(page.getByRole("heading", { name: "DEV profile release 후보" })).toBeFocused();
  await expect(page.getByText("BUILT_UNAPPROVED · 후보 생성됨, 독립 승인 전")).toHaveCount(0);
  await page.getByLabel("승인할 full release SHA-256").fill(releaseSha256);
  await page.getByRole("button", { name: "Exact release 상태 확인" }).click();
  await expect(page.getByText("BUILT_UNAPPROVED · 후보 생성됨, 독립 승인 전")).toBeVisible();
  await page.getByRole("button", { name: "정확한 release 승인하기" }).click();
  await expect(page.getByText("APPROVED_INACTIVE · 독립 승인됨, 아직 비활성")).toBeVisible();
  await expect(page.getByText(/approver receipt/)).toBeVisible();

  await page.goto("/internal/profile-releases/activator");
  await expect(page.getByRole("heading", { name: "DEV profile release 후보" })).toBeFocused();
  await page.getByLabel("전환할 full release SHA-256").fill(releaseSha256);
  await page.getByRole("button", { name: "Exact release 상태 확인" }).click();
  await expect(page.getByText("APPROVED_INACTIVE · 독립 승인됨, 아직 비활성")).toBeVisible();
  await page
    .getByLabel("새 세션에만 적용되는 pointer 전환임을 확인했습니다")
    .check();
  await page.getByRole("button", { name: "승인된 release 활성화하기" }).click();
  await expect(page.getByText("ACTIVE · 현재 active release")).toBeVisible();
  await expect(page.getByText(/ACTIVATE receipt, active pointer/)).toBeVisible();
  expect(rawTransitionNonce).toMatch(/^[0-9a-f]{64}$/);

  const browserSurface = JSON.stringify(
    await page.evaluate(() => ({
      html: document.documentElement.outerHTML,
      historyState: window.history.state,
      localStorage: { ...window.localStorage },
      sessionStorage: { ...window.sessionStorage },
    })),
  );
  const reachableHistoryStates: unknown[] = [
    await page.evaluate(() => window.history.state),
  ];
  await page.goBack();
  await expect(page.getByRole("heading", { name: "DEV profile release 후보" })).toBeFocused();
  reachableHistoryStates.push(await page.evaluate(() => window.history.state));
  await page.goBack();
  await expect(page.getByRole("heading", { name: "DEV profile release 후보" })).toBeFocused();
  reachableHistoryStates.push(await page.evaluate(() => window.history.state));
  await page.goForward();
  reachableHistoryStates.push(await page.evaluate(() => window.history.state));
  await page.goForward();
  reachableHistoryStates.push(await page.evaluate(() => window.history.state));
  const historySurface = JSON.stringify(reachableHistoryStates);
  expect(historySurface).not.toMatch(/buildInput|cohort|place_ref|profile_sha256/);
  for (const canary of [
    rawBuildNonce,
    rawTransitionNonce,
    ...Object.values(capabilities),
    "BLIND",
    "authority_token",
    "private_runtime_path",
  ]) {
    expect(browserSurface).not.toContain(canary);
    expect(historySurface).not.toContain(canary);
    expect(networkBodies.join("\n")).not.toContain(canary);
    expect(requestUrls.join("\n")).not.toContain(canary);
  }
  await page.unrouteAll({ behavior: "wait" });
});

test("routed rollback dialog preserves old and new session pins", async ({ page }) => {
  const oldSessionRef = "synthetic-routed-old-session";
  const newSessionRef = "synthetic-routed-new-session";
  const oldPin = {
    pin_sha256: syntheticHash("synthetic-routed-old-pin"),
    pinned_at: "2026-08-06T07:00:00Z",
    release_sha256: "b".repeat(64),
    session_ref: oldSessionRef,
  };
  const newPin = {
    pin_sha256: syntheticHash("synthetic-routed-new-pin"),
    pinned_at: "2026-08-06T07:01:00Z",
    release_sha256: "a".repeat(64),
    session_ref: newSessionRef,
  };
  let currentRelease = newPin.release_sha256;
  let rollbackRequests = 0;
  const pinMethods: string[] = [];
  let releaseRejectedRollback: (() => void) | undefined;
  const rejectedRollbackGate = new Promise<void>((resolve) => {
    releaseRejectedRollback = resolve;
  });

  await page.route("**/internal/evaluation/profile-releases/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const respond = (body: object, status = 200) =>
      route.fulfill({
        body: JSON.stringify(body),
        contentType: "application/json",
        status,
      });
    if (path.endsWith("/active-pointer")) {
      await respond({
        active_release_sha256: currentRelease,
        receipt_sha256: "e".repeat(64),
        state: "ACTIVE",
      });
      return;
    }
    if (path.endsWith(`/sessions/${oldSessionRef}/pin`)) {
      pinMethods.push(request.method());
      await respond(oldPin);
      return;
    }
    if (path.endsWith(`/sessions/${newSessionRef}/pin`)) {
      pinMethods.push(request.method());
      await respond(newPin);
      return;
    }
    if (path.includes("transition-receipts")) {
      const nonceSha256 = path.split("/").at(-1)!;
      await respond({
        action: "ROLLBACK",
        binding_sha256: "d".repeat(64),
        completion: "MUTATION_COMMITTED",
        expected_current_sha256: newPin.release_sha256,
        nonce_sha256: nonceSha256,
        outcome: "COMMITTED",
        previous_release_sha256: newPin.release_sha256,
        receipt_sha256: "e".repeat(64),
        release_sha256: oldPin.release_sha256,
      });
      return;
    }
    if (path.endsWith("/rollback")) {
      rollbackRequests += 1;
      if (rollbackRequests === 1) {
        await rejectedRollbackGate;
        await respond({ detail: "합성 rollback 거부" }, 422);
        return;
      }
      currentRelease = oldPin.release_sha256;
      await respond({
        completion: "MUTATION_COMMITTED",
        receipt_sha256: "e".repeat(64),
        release_sha256: oldPin.release_sha256,
        state: "ACTIVE",
      });
      return;
    }
    const releaseSha256 = path.split("/").at(-2) === "profile-releases"
      ? path.split("/").at(-1)!
      : path.split("/").at(-2)!;
    if (path.endsWith("/state")) {
      const isActive = releaseSha256 === currentRelease;
      await respond({
        lifecycle_head_receipt_sha256: "e".repeat(64),
        provenance_kind: isActive ? "TRANSITION" : "APPROVAL",
        provenance_receipt_sha256: "e".repeat(64),
        release_sha256: releaseSha256,
        state: isActive ? "ACTIVE" : "APPROVED_INACTIVE",
      });
      return;
    }
    await respond({ detail: "unexpected synthetic route" }, 404);
  });

  await page.goto("/internal/profile-releases/activator");
  await page.getByLabel("기존 세션 reference").fill(oldSessionRef);
  await page.getByRole("button", { name: "기존 세션 pin 확인" }).click();
  await expect(page.getByText(oldPin.pin_sha256)).toBeVisible();
  await page.getByLabel("신규 세션 reference").fill(newSessionRef);
  await page.getByRole("button", { name: "신규 세션 pin 확인" }).click();
  await expect(page.getByText(newPin.pin_sha256)).toBeVisible();
  await page.getByLabel("전환할 full release SHA-256").fill(oldPin.release_sha256);
  await page.getByRole("button", { name: "Exact release 상태 확인" }).click();
  await page.getByLabel("Rollback 사유 (trimmed 1..300자)").fill("합성 호환 release 복구");
  await page
    .getByLabel("새 세션에만 적용되는 pointer 전환임을 확인했습니다")
    .check();
  const trigger = page.getByRole("button", { name: "이전 active release로 되돌리기" });
  await trigger.click();
  expect(rollbackRequests).toBe(0);
  const rollbackDialog = page.getByRole("dialog", { name: "이 release로 rollback할까요?" });
  const safeRollbackAction = page.getByRole("button", { name: "현재 release 유지하기" });
  await expect(safeRollbackAction).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(trigger).toBeFocused();
  await trigger.click();
  await safeRollbackAction.click();
  await expect(trigger).toBeFocused();
  await trigger.click();

  // Playwright cannot drive Chromium's browser chrome zoom. Reducing the CSS viewport
  // from a 1280px reference to 640px faithfully exercises 200% zoom reflow/media queries.
  for (const width of [320, 640]) {
    await page.setViewportSize({ width, height: 720 });
    await expect(rollbackDialog).toBeVisible();
    expect(await page.evaluate(() => window.innerWidth)).toBe(width);
    expect(await page.evaluate(() => matchMedia("(max-width: 768px)").matches)).toBe(true);
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= document.documentElement.clientWidth,
      ),
    ).toBe(true);
    for (const locator of [
      page.locator("main.evaluator-shell"),
      page.locator(".hash-block"),
      rollbackDialog,
    ]) {
      const count = await locator.count();
      for (let index = 0; index < count; index += 1) {
        const bounds = await locator.nth(index).boundingBox();
        expect(bounds).not.toBeNull();
        expect(bounds!.x).toBeGreaterThanOrEqual(0);
        expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(width + 0.5);
      }
    }
  }
  await page.setViewportSize({ width: 1280, height: 720 });
  const confirmRollback = page.getByRole("button", { name: "호환 release로 rollback하기" });
  await confirmRollback.click();
  await expect.poll(() => rollbackRequests).toBe(1);
  await expect(rollbackDialog).toHaveAttribute("aria-busy", "true");
  await expect(rollbackDialog).toBeFocused();
  await expect(safeRollbackAction).toBeDisabled();
  await expect(confirmRollback).toBeDisabled();
  await page.keyboard.press("Tab");
  await expect(rollbackDialog).toBeFocused();
  await page.keyboard.press("Shift+Tab");
  await expect(rollbackDialog).toBeFocused();
  releaseRejectedRollback?.();
  const rollbackError = rollbackDialog.getByRole("alert");
  await expect(rollbackError).toContainText("Rollback 결과");
  await expect(rollbackError).toBeFocused();
  await expect(page.getByRole("alert")).toHaveCount(1);
  await page.keyboard.press("Shift+Tab");
  await expect(confirmRollback).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(safeRollbackAction).toBeFocused();
  await safeRollbackAction.click();
  await expect(rollbackDialog).toBeHidden();
  await expect(trigger).toBeFocused();
  await expect(page.getByRole("alert")).toHaveCount(0);
  await trigger.click();
  await confirmRollback.click();
  await expect(page.getByText(/old\/new session pin을 모두 확인했습니다/)).toBeVisible();
  expect(rollbackRequests).toBe(2);
  expect(pinMethods).toEqual(["GET", "GET", "GET", "GET"]);
  await expect(page.getByText(oldPin.pin_sha256)).toBeVisible();
  await expect(page.getByText(newPin.pin_sha256)).toBeVisible();
});

test("profile release synthetic lifecycle preserves exact authority, CAS, rollback, and pins", async ({
  request,
}, testInfo) => {
  const capabilities = {
    approver: runtimeCapability("APPROVER"),
    builder: runtimeCapability("BUILDER"),
  };
  const observedBodies: string[] = [];
  const observedUrls: string[] = [];
  const call = async (
    capability: string,
    path: string,
    data?: object,
  ) => {
    observedUrls.push(path);
    const response = await request.post(path, {
      data,
      headers: { "X-ITDA-Phase3-Capability": capability },
    });
    observedBodies.push(data === undefined ? "" : JSON.stringify(data));
    observedBodies.push(await response.text());
    return response;
  };
  const runSuffix = runtimeAttemptRef(testInfo);
  const scoped = (value: string) => `${value}-${runSuffix}`;
  const releaseAInput = linkedProfileReleaseBuildInput(scoped("synthetic-profile-release-a"));
  const releaseBInput = linkedProfileReleaseBuildInput(scoped("synthetic-profile-release-b"));
  const buildNonceA = syntheticHash(scoped("build-release-a"));
  const buildNonceB = syntheticHash(scoped("build-release-b"));

  const approverCannotBuild = await call(
    capabilities.approver,
    "/internal/evaluation/profile-releases/build",
    { ...releaseAInput, reconciliation_nonce: syntheticHash(scoped("approver-cannot-build")) },
  );
  expect(approverCannotBuild.status()).toBe(403);

  const builtA = await call(
    capabilities.builder,
    "/internal/evaluation/profile-releases/build",
    { ...releaseAInput, reconciliation_nonce: buildNonceA },
  );
  const builtB = await call(
    capabilities.builder,
    "/internal/evaluation/profile-releases/build",
    { ...releaseBInput, reconciliation_nonce: buildNonceB },
  );
  expect(builtA.status()).toBe(201);
  expect(builtB.status()).toBe(201);
  const candidateA = (await builtA.json()) as ProfileReleaseMutation;
  const candidateB = (await builtB.json()) as ProfileReleaseMutation;
  expect(candidateA.state).toBe("BUILT_UNAPPROVED");
  expect(candidateB.state).toBe("BUILT_UNAPPROVED");
  expect(candidateA.release_sha256).toMatch(/^[a-f0-9]{64}$/);
  expect(candidateB.release_sha256).toMatch(/^[a-f0-9]{64}$/);
  expect(candidateA.release_sha256).not.toBe(candidateB.release_sha256);
  expect(releaseAInput.reviewed_manifest_sha256).toBe(
    releaseAInput.cohort[0]!.reviewed_evidence_manifest_sha256,
  );

  const inertRawShapeFixture = syntheticHash(scoped("inert-nonce-shape-never-mutated"));
  expect(inertRawShapeFixture).not.toBe(buildNonceA);
  expect(inertRawShapeFixture).not.toBe(buildNonceB);
  const rawBuildLookupPath =
    `/internal/evaluation/profile-releases/build-receipts/by-nonce/${inertRawShapeFixture}`;
  observedUrls.push(rawBuildLookupPath);
  const rawBuildLookup = await request.get(
    rawBuildLookupPath,
    { headers: { "X-ITDA-Phase3-Capability": capabilities.builder } },
  );
  expect(rawBuildLookup.status()).toBe(404);
  const buildNonceDigestA = syntheticHash(buildNonceA);
  const committedBuildLookupPath =
    `/internal/evaluation/profile-releases/build-receipts/by-nonce/${buildNonceDigestA}`;
  observedUrls.push(committedBuildLookupPath);
  const committedBuildLookup = await request.get(
    committedBuildLookupPath,
    { headers: { "X-ITDA-Phase3-Capability": capabilities.builder } },
  );
  expect(committedBuildLookup.status()).toBe(200);
  expect((await committedBuildLookup.json()).release_sha256).toBe(
    candidateA.release_sha256,
  );

  const builderCannotApprove = await call(
    capabilities.builder,
    `/internal/evaluation/profile-releases/${candidateA.release_sha256}/approve`,
  );
  expect(builderCannotApprove.status()).toBe(403);

  const approvedA = await call(
    capabilities.approver,
    `/internal/evaluation/profile-releases/${candidateA.release_sha256}/approve`,
  );
  const approvedB = await call(
    capabilities.approver,
    `/internal/evaluation/profile-releases/${candidateB.release_sha256}/approve`,
  );
  expect(approvedA.status()).toBe(200);
  expect(approvedB.status()).toBe(200);
  const approvalA = (await approvedA.json()) as ProfileReleaseMutation;
  const approvalB = (await approvedB.json()) as ProfileReleaseMutation;
  expect(approvalA.state).toBe("APPROVED_INACTIVE");
  expect(approvalB.state).toBe("APPROVED_INACTIVE");
  expect(approvalA.receipt_sha256).toMatch(/^[a-f0-9]{64}$/);
  expect(approvalB.receipt_sha256).toMatch(/^[a-f0-9]{64}$/);

  const pointerBeforeActivation = await request.get(
    "/internal/evaluation/profile-releases/active-pointer",
    { headers: { "X-ITDA-Phase3-Capability": capabilities.approver } },
  );
  expect(pointerBeforeActivation.status()).toBe(200);
  const initialActiveSha256 = (await pointerBeforeActivation.json()).active_release_sha256 as
    | string
    | null;
  const winningActivationNonce = syntheticHash(scoped("activate-a-winner-one"));
  const winningActivation = await call(
    capabilities.approver,
    `/internal/evaluation/profile-releases/${candidateA.release_sha256}/activate`,
    {
      expected_current_sha256: initialActiveSha256,
      nonce: winningActivationNonce,
    },
  );
  expect(winningActivation.status()).toBe(200);
  const activeA = (await winningActivation.json()) as ProfileReleaseMutation;
  expect(activeA.state).toBe("ACTIVE");
  expect(activeA.completion).toBe("MUTATION_COMMITTED");
  expect(activeA.receipt_sha256).toMatch(/^[a-f0-9]{64}$/);

  const rawTransitionLookupPath =
    `/internal/evaluation/profile-releases/transition-receipts/by-nonce/${inertRawShapeFixture}`;
  observedUrls.push(rawTransitionLookupPath);
  const rawTransitionLookup = await request.get(
    rawTransitionLookupPath,
    { headers: { "X-ITDA-Phase3-Capability": capabilities.approver } },
  );
  expect(rawTransitionLookup.status()).toBe(404);
  const transitionNonceDigest = syntheticHash(winningActivationNonce);
  const committedTransitionLookupPath =
    `/internal/evaluation/profile-releases/transition-receipts/by-nonce/${transitionNonceDigest}`;
  observedUrls.push(committedTransitionLookupPath);
  const committedTransitionLookup = await request.get(
    committedTransitionLookupPath,
    { headers: { "X-ITDA-Phase3-Capability": capabilities.approver } },
  );
  expect(committedTransitionLookup.status()).toBe(200);
  expect((await committedTransitionLookup.json()).action).toBe("ACTIVATE");

  const concurrentLoser = await call(
    capabilities.approver,
    `/internal/evaluation/profile-releases/${candidateA.release_sha256}/activate`,
    {
      expected_current_sha256: initialActiveSha256,
      nonce: syntheticHash(scoped("activate-a-concurrent-loser")),
    },
  );
  expect(concurrentLoser.status()).toBe(409);

  const replay = await call(
    capabilities.approver,
    `/internal/evaluation/profile-releases/${candidateA.release_sha256}/activate`,
    {
      expected_current_sha256: initialActiveSha256,
      nonce: winningActivationNonce,
    },
  );
  expect(replay.status()).toBe(200);
  expect(((await replay.json()) as ProfileReleaseMutation).completion).toBe(
    "RELOOKUP_CONFIRMED",
  );

  const oldSession = await call(
    capabilities.builder,
    `/internal/evaluation/profile-releases/sessions/${scoped("synthetic-session-before-activation")}/pin`,
  );
  const oldResult = await call(
    capabilities.builder,
    `/internal/evaluation/profile-releases/results/${scoped("synthetic-result-before-activation")}/pin`,
  );
  expect((await oldSession.json()).release_sha256).toBe(candidateA.release_sha256);
  expect((await oldResult.json()).release_sha256).toBe(candidateA.release_sha256);

  const staleActivation = await call(
    capabilities.approver,
    `/internal/evaluation/profile-releases/${candidateB.release_sha256}/activate`,
    {
      expected_current_sha256: initialActiveSha256,
      nonce: syntheticHash(scoped("activate-b-stale")),
    },
  );
  expect(staleActivation.status()).toBe(409);

  const activatedB = await call(
    capabilities.approver,
    `/internal/evaluation/profile-releases/${candidateB.release_sha256}/activate`,
    {
      expected_current_sha256: candidateA.release_sha256,
      nonce: syntheticHash(scoped("activate-b-current")),
    },
  );
  expect(activatedB.status()).toBe(200);
  expect(((await activatedB.json()) as ProfileReleaseMutation).state).toBe("ACTIVE");

  const newSession = await call(
    capabilities.builder,
    `/internal/evaluation/profile-releases/sessions/${scoped("synthetic-session-after-activation")}/pin`,
  );
  expect((await newSession.json()).release_sha256).toBe(candidateB.release_sha256);
  const oldSessionAgain = await call(
    capabilities.builder,
    `/internal/evaluation/profile-releases/sessions/${scoped("synthetic-session-before-activation")}/pin`,
  );
  expect((await oldSessionAgain.json()).release_sha256).toBe(candidateA.release_sha256);

  const invalidReason = await call(
    capabilities.approver,
    `/internal/evaluation/profile-releases/${candidateA.release_sha256}/rollback`,
    {
      expected_current_sha256: candidateB.release_sha256,
      nonce: syntheticHash(scoped("rollback-invalid-reason")),
      reason: "   ",
    },
  );
  expect(invalidReason.status()).toBe(409);

  const rolledBack = await call(
    capabilities.approver,
    `/internal/evaluation/profile-releases/${candidateA.release_sha256}/rollback`,
    {
      expected_current_sha256: candidateB.release_sha256,
      nonce: syntheticHash(scoped("rollback-compatible-a")),
      reason: "  합성 호환 release 복구 검증  ",
    },
  );
  expect(rolledBack.status()).toBe(200);
  const rollbackReceipt = (await rolledBack.json()) as ProfileReleaseMutation;
  expect(rollbackReceipt.state).toBe("ACTIVE");
  expect(rollbackReceipt.release_sha256).toBe(candidateA.release_sha256);
  expect(rollbackReceipt.receipt_sha256).toMatch(/^[a-f0-9]{64}$/);

  const postRollbackSession = await call(
    capabilities.builder,
    `/internal/evaluation/profile-releases/sessions/${scoped("synthetic-session-after-rollback")}/pin`,
  );
  expect((await postRollbackSession.json()).release_sha256).toBe(candidateA.release_sha256);
  const pinnedBStillB = await call(
    capabilities.builder,
    `/internal/evaluation/profile-releases/sessions/${scoped("synthetic-session-after-activation")}/pin`,
  );
  expect((await pinnedBStillB.json()).release_sha256).toBe(candidateB.release_sha256);
  for (const canary of [
    ...Object.values(capabilities),
    "BLIND",
    "traveler_data",
    "private_runtime_path",
    "authority_token",
  ]) {
    expect(observedBodies.join("\n")).not.toContain(canary);
  }
  for (const rawMutationNonce of [buildNonceA, buildNonceB, winningActivationNonce]) {
    expect(observedUrls.join("\n")).not.toContain(rawMutationNonce);
  }
  console.log(
    `profile release synthetic candidate ${candidateA.release_sha256} state=${candidateA.state}; final=${rollbackReceipt.release_sha256} state=${rollbackReceipt.state}`,
  );
});

function runtimeCapability(role: RuntimeRole): string {
  const value = process.env[`ITDA_E2E_PHASE3_${role}_CAPABILITY`];
  expect(value).toBeTruthy();
  return value!;
}

function runtimeAttemptRef(testInfo: {
  repeatEachIndex: number;
  retry: number;
  workerIndex: number;
}): string {
  return `r${testInfo.retry}-e${testInfo.repeatEachIndex}-w${testInfo.workerIndex}`;
}

function runtimeSubmission(
  runtimeFixture: RuntimeFixture,
  roleIndex: number,
  primaryAxis: "HISTORY_TRADITION" | "EMOTION_IMAGE" | "REST_IMMERSION" | null,
) {
  const description = runtimeFixture.evidence_items.find((item) => item.lane === "DESCRIPTION")!;
  const odii = runtimeFixture.evidence_items.find((item) => item.lane === "ODII")!;
  const evidence = (item: typeof description, options: { absence?: boolean } = {}) => ({
    complete_context: options.absence ?? false,
    concordance_key: "synthetic-runtime-concordance-a",
    dedup_cluster_id: item.dedup_cluster_id,
    direct: true,
    evidence_id: item.evidence_id,
    lane: item.lane,
    source_id: item.source_id,
    supports_absence: options.absence ?? false,
  });
  return {
    assignment_id: runtimeFixture.assignment.assignment_id,
    rubric_version: runtimeFixture.assignment.rubric_version,
    source_snapshot_version: runtimeFixture.assignment.source_snapshot_version,
    primary_axis: primaryAxis,
    submitted_at: `2026-08-04T01:0${roleIndex}:00+00:00`,
    judgments: ATTRIBUTE_IDS.map((attribute_id) => ({
      attribute_id,
      score: attribute_id === "H1" ? [0, 2, 4][roleIndex] : 2,
      unknown_reason: null,
      unknown_note: null,
      evidence:
        attribute_id !== "H1"
          ? []
          : roleIndex === 0
            ? [evidence(description, { absence: true })]
            : roleIndex === 2
              ? [evidence(description), evidence(odii)]
              : [],
    })),
  };
}

test.beforeEach(async ({ page }) => {
  const capability = process.env.ITDA_E2E_PHASE3_EVALUATOR_A_CAPABILITY;
  expect(capability).toBeTruthy();
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (
      (url.protocol === "http:" || url.protocol === "https:") &&
      !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)
    ) {
      if (url.hostname.endsWith("fonts.googleapis.com") || url.hostname === "fonts.gstatic.com") {
        await route.abort();
        return;
      }
      throw new Error("non-loopback browser request blocked");
    }
    const isEvaluatorRequest =
      url.pathname.startsWith("/internal/evaluation") ||
      url.pathname.startsWith("/internal/test-support/phase3");
    await route.continue({
      headers: isEvaluatorRequest
        ? {
            ...route.request().headers(),
            "X-ITDA-Phase3-Capability": capability!,
          }
        : route.request().headers(),
    });
  });
});

test("isolated evaluator submits one synthetic immutable revision through UI, API, and database", async ({
  page,
}) => {
  const capability = process.env.ITDA_E2E_PHASE3_EVALUATOR_A_CAPABILITY!;
  const evaluatorRequests: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname.startsWith("/internal/evaluation")) evaluatorRequests.push(url.pathname);
  });
  await page.goto(evaluatorPath);

  const heading = page.getByRole("heading", { level: 1, name: "독립 평가를 시작합니다" });
  await expect(heading).toBeVisible();
  await expect(heading).toBeFocused();

  const source = page.getByRole("region", { name: "공식 근거" });
  const firstField = page.getByRole("group", { name: fixture.rubric.subattributes[0].label_ko });
  await expect(source).toBeVisible();
  await expect(firstField).toBeVisible();
  expect(
    await source.evaluate((node, field) =>
      Boolean(node.compareDocumentPosition(field as Node) & Node.DOCUMENT_POSITION_FOLLOWING),
    await firstField.elementHandle()),
  ).toBe(true);

  const legends = await page.locator("fieldset.attribute-score-field > legend").allTextContents();
  expect(legends).toEqual(fixture.rubric.subattributes.map((item) => item.label_ko));

  for (const [index, spec] of fixture.rubric.subattributes.entries()) {
    const field = page.getByRole("group", { name: spec.label_ko });
    if (index === 0) {
      await field.getByRole("radio", { name: "판단 불가" }).check();
      await field.getByLabel("판단 불가 사유").selectOption("NO_EVIDENCE");
      await field.getByLabel("판단 불가 설명").fill("가");
    } else {
      await field.getByRole("radio", { name: index === 1 ? /^0,/ : index === 2 ? /^3,/ : /^2,/ }).check();
      if (index === 1) {
        await field.getByRole("checkbox", { name: /synthetic-desc-direct-a$/ }).check();
      }
      if (index === 2) {
        await field.getByRole("checkbox", { name: /synthetic-desc-direct-b/ }).check();
      }
    }
  }

  const postResponse = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      response.url().endsWith("/internal/evaluation/revisions"),
  );
  await page.getByRole("button", { name: "평가 revision 제출하기" }).click();
  await page.getByRole("button", { name: "불변 revision 제출하기" }).click();
  const response = await postResponse;
  expect(response.status()).toBe(201);
  const receipt = (await response.json()) as {
    revision_sha256: string;
    receipt_sha256: string;
    evaluator_principal: string;
    revision: {
      parent_revision_sha256: string | null;
      correction_reason: string | null;
    };
  };
  expect(Object.keys(receipt).sort()).toEqual(
    ["created_at", "evaluator_principal", "receipt_sha256", "revision", "revision_sha256"].sort(),
  );
  expect(receipt.revision_sha256).toMatch(/^[a-f0-9]{64}$/);
  expect(receipt.receipt_sha256).toMatch(/^[a-f0-9]{64}$/);
  expect(receipt.revision.parent_revision_sha256).toBeNull();
  expect(receipt.revision.correction_reason).toBeNull();

  const persisted = await page.request.get(
    `/internal/evaluation/revisions/${receipt.revision_sha256}/receipt`,
    { headers: { "X-ITDA-Phase3-Capability": capability } },
  );
  expect(persisted.status()).toBe(200);
  expect(await persisted.json()).toEqual(receipt);
  await expect(page.getByRole("heading", { name: "제출 완료" })).toBeFocused();

  await page.getByRole("button", { name: "수정 revision 만들기" }).click();
  const firstCorrectionField = page.getByRole("group", {
    name: fixture.rubric.subattributes[0].label_ko,
  });
  await firstCorrectionField.getByRole("radio", { name: /^2,/ }).click();
  await expect(
    page.getByRole("alertdialog", { name: "판단 불가 내용을 지울까요?" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "내용 지우고 2점 선택하기" }).click();
  await page.getByLabel("수정 사유").fill("첫 제출의 판단 불가 항목을 직접 근거로 보완함");

  let persistedSuccessor: typeof receipt | null = null;
  await page.route("**/internal/evaluation/revisions/*/corrections", async (route) => {
    const forwarded = await route.fetch({
      headers: {
        ...route.request().headers(),
        "X-ITDA-Phase3-Capability": capability,
      },
    });
    expect(forwarded.status()).toBe(201);
    persistedSuccessor = (await forwarded.json()) as typeof receipt;
    await route.abort("failed");
  });
  await page.getByRole("button", { name: "수정 내용 검토하기" }).click();
  const recoveryLookup = page.waitForResponse(
    (candidate) =>
      candidate.request().method() === "GET" &&
      candidate.url().endsWith("/internal/evaluation/revisions/own-chain"),
  );
  await page.getByRole("button", { name: "수정 successor 제출하기" }).click();
  expect((await recoveryLookup).status()).toBe(200);
  await expect(page.getByRole("heading", { name: "수정 revision 제출 완료" })).toBeFocused();
  expect(persistedSuccessor).not.toBeNull();
  const successor = persistedSuccessor!;
  expect(successor.revision.parent_revision_sha256).toBe(receipt.revision_sha256);
  expect(successor.revision.correction_reason).toBe("첫 제출의 판단 불가 항목을 직접 근거로 보완함");

  const predecessorAfterCorrection = await page.request.get(
    `/internal/evaluation/revisions/${receipt.revision_sha256}/receipt`,
    { headers: { "X-ITDA-Phase3-Capability": capability } },
  );
  expect(await predecessorAfterCorrection.json()).toEqual(receipt);
  const successorLookup = await page.request.get(
    `/internal/evaluation/revisions/${successor.revision_sha256}/receipt`,
    { headers: { "X-ITDA-Phase3-Capability": capability } },
  );
  expect(await successorLookup.json()).toEqual(successor);
  expect(evaluatorRequests.some((path) => path.includes("accepted-head"))).toBe(false);
  await expect(page.getByRole("button", { name: /accepted|채택|선택/ })).toHaveCount(0);

  const browserSurface = JSON.stringify(
    await page.evaluate(() => ({
      html: document.documentElement.outerHTML,
      localStorage: { ...window.localStorage },
      sessionStorage: { ...window.sessionStorage },
    })),
  );
  for (const canary of fixture.forbidden_canaries) {
    expect(browserSurface).not.toContain(canary);
  }
  expect(page.url()).toMatch(/\/internal\/evaluator\/assignments\/synthetic-runtime-assignment-alpha$/);
});

test("isolated evaluator unknown boundaries, score-present exclusivity, and both score-four branches fail closed", async ({
  page,
}) => {
  await page.goto(evaluatorPath);
  await expect(page.getByRole("heading", { level: 1, name: "독립 평가를 시작합니다" })).toBeVisible();
  const field = page.getByRole("group", { name: fixture.rubric.subattributes[0].label_ko });

  await field.getByRole("radio", { name: "판단 불가" }).check();
  await field.getByLabel("판단 불가 사유").selectOption("NO_EVIDENCE");
  const note = field.getByLabel("판단 불가 설명");
  for (const valid of ["가", "가".repeat(300)]) {
    await note.fill(valid);
    await expect(field.getByRole("alert")).toHaveCount(0);
  }
  for (const invalid of ["", "가".repeat(301)]) {
    await note.fill(invalid);
    await expect(field.getByRole("alert")).toBeVisible();
  }

  await note.fill("합성 판단 불가 설명");
  await field.getByRole("radio", { name: /^2,/ }).click();
  await expect(
    page.getByRole("alertdialog", { name: "판단 불가 내용을 지울까요?" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "내용 지우고 2점 선택하기" }).click();
  await expect(field.getByLabel("판단 불가 사유")).toHaveCount(0);
  await expect(field.getByLabel("판단 불가 설명")).toHaveCount(0);

  await field.getByRole("radio", { name: /^4,/ }).check();
  await field.getByRole("checkbox", { name: /synthetic-desc-direct-a$/ }).check();
  await field.getByRole("checkbox", { name: /synthetic-desc-direct-a-copy/ }).check();
  await expect(field.getByRole("alert")).toContainText("서로 다른 직접 근거");
  await field.getByRole("checkbox", { name: /synthetic-desc-direct-a-copy/ }).uncheck();
  await field.getByRole("checkbox", { name: /synthetic-desc-direct-b/ }).check();
  await expect(field.getByRole("alert")).toHaveCount(0);
  await field.getByRole("checkbox", { name: /synthetic-desc-direct-b/ }).uncheck();
  await field.getByRole("checkbox", { name: /synthetic-odii-direct-a/ }).check();
  await expect(field.getByRole("alert")).toHaveCount(0);
  await field.getByRole("checkbox", { name: /synthetic-odii-direct-a/ }).uncheck();
  await field.getByRole("checkbox", { name: /synthetic-odii-discordant/ }).check();
  await expect(field.getByRole("alert")).toContainText("일치 근거");
});

test("isolated evaluator keeps 320px and 200% CSS viewport equivalents usable", async ({
  page,
}) => {
  await page.setViewportSize({ width: 320, height: 568 });
  await page.goto(evaluatorPath);
  await expect(page.getByRole("heading", { level: 1, name: "독립 평가를 시작합니다" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
  for (const control of await page.getByRole("button").all()) {
    expect((await control.boundingBox())?.height ?? 0).toBeGreaterThanOrEqual(44);
  }

  // A 640px CSS viewport is the reflow/media-query equivalent of 200% browser zoom
  // on the 1280px desktop reference used by this Chromium gate.
  await page.setViewportSize({ width: 640, height: 720 });
  expect(await page.evaluate(() => window.innerWidth)).toBe(640);
  expect(await page.evaluate(() => matchMedia("(max-width: 768px)").matches)).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(
    await page.evaluate(() => document.documentElement.clientWidth),
  );
});

test("real stale head remains stale across attempts", async ({ request }, testInfo) => {
  const attemptRef = runtimeAttemptRef(testInfo);
  const attemptAssignmentId = `synthetic-runtime-assignment-alpha-${attemptRef}`;
  const capabilities = {
    evaluatorA: runtimeCapability("EVALUATOR_A"),
    evaluatorB: runtimeCapability("EVALUATOR_B"),
    evaluatorC: runtimeCapability("EVALUATOR_C"),
    adjudicator: runtimeCapability("ADJUDICATOR"),
    builder: runtimeCapability("BUILDER"),
  };
  const observedBodies: string[] = [];
  const recordBody = async (response: APIResponse) => {
    const body = await response.text();
    observedBodies.push(body);
    return body;
  };

  const fixtureResponse = await request.get(
    `/internal/test-support/phase3/fixture?attempt=${attemptRef}`,
    { headers: { "X-ITDA-Phase3-Capability": capabilities.evaluatorA } },
  );
  expect(fixtureResponse.status()).toBe(200);
  const runtimeFixture = JSON.parse(await recordBody(fixtureResponse)) as RuntimeFixture;
  expect(runtimeFixture.assignment.assignment_id).toBe(attemptAssignmentId);

  const roles = [
    [capabilities.evaluatorA, "HISTORY_TRADITION"],
    [capabilities.evaluatorB, "EMOTION_IMAGE"],
    [capabilities.evaluatorC, "REST_IMMERSION"],
  ] as const;
  const receipts: Array<{ revision_sha256: string }> = [];
  for (const [index, [capability, primaryAxis]] of roles.entries()) {
    const response = await request.post("/internal/evaluation/revisions", {
      headers: { "X-ITDA-Phase3-Capability": capability },
      data: runtimeSubmission(runtimeFixture, index, primaryAxis),
    });
    expect(response.status()).toBe(201);
    receipts.push(JSON.parse(await recordBody(response)) as { revision_sha256: string });
  }

  const operatorDeniedProjection = await request.get(
    `/internal/evaluation/assignments/${attemptAssignmentId}/adjudication-projection`,
    { headers: { "X-ITDA-Phase3-Capability": capabilities.builder } },
  );
  expect(operatorDeniedProjection.status()).toBe(403);
  await recordBody(operatorDeniedProjection);
  const evaluatorDeniedSelection = await request.post(
    `/internal/evaluation/revisions/${receipts[0]!.revision_sha256}/accepted-head`,
    {
      headers: { "X-ITDA-Phase3-Capability": capabilities.evaluatorA },
      data: { expected_chain_sha256: "a".repeat(64), reason: "forbidden" },
    },
  );
  expect(evaluatorDeniedSelection.status()).toBe(403);
  await recordBody(evaluatorDeniedSelection);

  const projectionResponse = await request.get(
    `/internal/evaluation/assignments/${attemptAssignmentId}/adjudication-projection`,
    { headers: { "X-ITDA-Phase3-Capability": capabilities.adjudicator } },
  );
  expect(projectionResponse.status()).toBe(200);
  const projection = JSON.parse(await recordBody(projectionResponse)) as {
    chains: Array<{
      chain_sha256: string;
      tip_revision_sha256: string;
      revisions: Array<{ revision_sha256: string }>;
    }>;
  };
  const staleChain = projection.chains.find((chain) =>
    chain.revisions.some(
      (revision) => revision.revision_sha256 === receipts[0]!.revision_sha256,
    ),
  );
  expect(staleChain).toBeDefined();

  const correctionResponse = await request.post(
    `/internal/evaluation/revisions/${receipts[0]!.revision_sha256}/corrections`,
    {
      headers: { "X-ITDA-Phase3-Capability": capabilities.evaluatorA },
      data: {
        ...runtimeSubmission(runtimeFixture, 0, "HISTORY_TRADITION"),
        correction_reason: "현재 tip을 바꾸는 합성 correction",
        submitted_at: "2026-08-04T01:30:00+00:00",
      },
    },
  );
  expect(correctionResponse.status()).toBe(201);
  await recordBody(correctionResponse);

  const staleResponse = await request.post(
    `/internal/evaluation/revisions/${staleChain!.tip_revision_sha256}/accepted-head`,
    {
      headers: { "X-ITDA-Phase3-Capability": capabilities.adjudicator },
      data: {
        expected_chain_sha256: staleChain!.chain_sha256,
        reason: "stale projection 거부 확인",
      },
    },
  );
  expect(staleResponse.status()).toBe(409);
  await recordBody(staleResponse);

  for (const canary of [
    ...fixture.forbidden_canaries,
    ...Object.values(capabilities),
    "BLIND",
    "private_runtime_path",
  ]) {
    expect(observedBodies.join("\n")).not.toContain(canary);
  }
});

test("adjudication and label freeze: routed freeze receipt parents reviewed candidate", async ({
  page,
}) => {
  test.setTimeout(90_000);
  const capabilities = {
    evaluatorA: runtimeCapability("EVALUATOR_A"),
    evaluatorB: runtimeCapability("EVALUATOR_B"),
    evaluatorC: runtimeCapability("EVALUATOR_C"),
    adjudicator: runtimeCapability("ADJUDICATOR"),
    builder: runtimeCapability("BUILDER"),
  };
  let browserCapability = capabilities.evaluatorA;
  const networkBodies: string[] = [];
  const browserErrors: string[] = [];

  await page.unroute("**/*");
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (
      (url.protocol === "http:" || url.protocol === "https:") &&
      !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)
    ) {
      if (url.hostname.endsWith("fonts.googleapis.com") || url.hostname === "fonts.gstatic.com") {
        await route.abort();
        return;
      }
      throw new Error("non-loopback browser request blocked");
    }
    const internal =
      url.pathname.startsWith("/internal/evaluation") ||
      url.pathname.startsWith("/internal/test-support/phase3");
    await route.continue({
      headers: internal
        ? {
            ...route.request().headers(),
            "X-ITDA-Phase3-Capability": browserCapability,
          }
        : route.request().headers(),
    });
  });
  page.on("response", async (response) => {
    if (new URL(response.url()).pathname.startsWith("/internal/evaluation")) {
      networkBodies.push(await response.text().catch(() => ""));
    }
  });
  page.on("pageerror", (error) => browserErrors.push(error.message));

  const fixtureResponse = await page.request.get("/internal/test-support/phase3/fixture", {
    headers: { "X-ITDA-Phase3-Capability": capabilities.evaluatorA },
  });
  expect(fixtureResponse.status()).toBe(200);
  const runtimeFixture = (await fixtureResponse.json()) as RuntimeFixture;
  const roles = [
    [capabilities.evaluatorA, "HISTORY_TRADITION"],
    [capabilities.evaluatorB, "EMOTION_IMAGE"],
    [capabilities.evaluatorC, "REST_IMMERSION"],
  ] as const;
  const receipts: Array<{ revision_sha256: string; revision: Record<string, unknown> }> = [];
  for (const [index, [capability, primaryAxis]] of roles.entries()) {
    const response = await page.request.post("/internal/evaluation/revisions", {
      headers: { "X-ITDA-Phase3-Capability": capability },
      data: runtimeSubmission(runtimeFixture, index, primaryAxis),
    });
    expect(response.status()).toBe(201);
    receipts.push(await response.json());
  }

  const operatorDeniedProjection = await page.request.get(
    `/internal/evaluation/assignments/${runtimeFixture.assignment.assignment_id}/adjudication-projection`,
    { headers: { "X-ITDA-Phase3-Capability": capabilities.builder } },
  );
  expect(operatorDeniedProjection.status()).toBe(403);
  const evaluatorDeniedSelection = await page.request.post(
    `/internal/evaluation/revisions/${receipts[0]!.revision_sha256}/accepted-head`,
    {
      headers: { "X-ITDA-Phase3-Capability": capabilities.evaluatorA },
      data: { expected_chain_sha256: "a".repeat(64), reason: "forbidden" },
    },
  );
  expect(evaluatorDeniedSelection.status()).toBe(403);

  browserCapability = capabilities.builder;
  await page.goto(operatorPath);
  await expect(page.getByRole("heading", { name: "독립 제출 상태" })).toBeFocused();
  await expect(page.getByRole("list", { name: "평가자 제출 상태" }).getByRole("listitem")).toHaveCount(3);
  await expect(page.getByText("공식 근거")).toHaveCount(0);
  await expect(page.getByRole("button", { name: /accepted revision 선택/ })).toHaveCount(0);

  browserCapability = capabilities.adjudicator;
  await page.goto(adjudicatorPath);
  await expect(page.getByRole("heading", { name: "익명 revision 재검토" })).toBeFocused();
  await expect(page.getByRole("region", { name: "공식 근거 원문" })).toBeVisible();
  await expect(page.getByRole("article", { name: "평가자 A revision chain" })).toBeVisible();

  const projectionBeforeCorrectionResponse = await page.request.get(
    `/internal/evaluation/assignments/${runtimeFixture.assignment.assignment_id}/adjudication-projection`,
    { headers: { "X-ITDA-Phase3-Capability": capabilities.adjudicator } },
  );
  expect(projectionBeforeCorrectionResponse.status()).toBe(200);
  const projectionBeforeCorrection = (await projectionBeforeCorrectionResponse.json()) as {
    chains: Array<{
      chain_sha256: string;
      tip_revision_sha256: string;
      revisions: Array<{ revision_sha256: string }>;
    }>;
  };
  const staleChainIndex = projectionBeforeCorrection.chains.findIndex((chain) =>
    chain.revisions.some(
      (revision) => revision.revision_sha256 === receipts[0]!.revision_sha256,
    ),
  );
  expect(staleChainIndex).toBeGreaterThanOrEqual(0);
  const staleChain = projectionBeforeCorrection.chains[staleChainIndex]!;
  const staleEvaluatorLabel = `평가자 ${String.fromCharCode(65 + staleChainIndex)}`;
  const evaluatorACorrection = {
    ...runtimeSubmission(runtimeFixture, 0, "HISTORY_TRADITION"),
    correction_reason: "현재 tip을 바꾸는 합성 correction",
    submitted_at: "2026-08-04T01:30:00+00:00",
  };
  const correction = await page.request.post(
    `/internal/evaluation/revisions/${receipts[0]!.revision_sha256}/corrections`,
    {
      headers: { "X-ITDA-Phase3-Capability": capabilities.evaluatorA },
      data: evaluatorACorrection,
    },
  );
  expect(correction.status()).toBe(201);
  const canonicalStaleResponse = await page.request.post(
    `/internal/evaluation/revisions/${staleChain.tip_revision_sha256}/accepted-head`,
    {
      headers: { "X-ITDA-Phase3-Capability": capabilities.adjudicator },
      data: {
        expected_chain_sha256: staleChain.chain_sha256,
        reason: "stale projection 거부 확인",
      },
    },
  );
  expect(canonicalStaleResponse.status()).toBe(409);

  await page.route(
    "**/accepted-head",
    async (route) => {
      await route.fulfill({
        body: JSON.stringify({ detail: "stale accepted-head projection" }),
        contentType: "application/json",
        status: 409,
      });
    },
    { times: 1 },
  );
  await page
    .getByRole("button", { name: `${staleEvaluatorLabel} accepted revision 선택` })
    .click();
  await expect(page.getByRole("alert")).toContainText("최신 projection");
  await expect(
    page.getByRole("button", { name: `${staleEvaluatorLabel} accepted revision 선택` }),
  ).toBeVisible();

  const evaluatorBCorrection = {
    ...runtimeSubmission(runtimeFixture, 1, null),
    correction_reason: "주 경험축 근거 부족을 null로 보존",
    submitted_at: "2026-08-04T01:31:00+00:00",
  };
  const nullPrimaryCorrection = await page.request.post(
    `/internal/evaluation/revisions/${receipts[1]!.revision_sha256}/corrections`,
    {
      headers: { "X-ITDA-Phase3-Capability": capabilities.evaluatorB },
      data: evaluatorBCorrection,
    },
  );
  expect(nullPrimaryCorrection.status()).toBe(201);
  await page.getByRole("button", { name: "최신 projection 다시 확인하기" }).click();
  await expect(page.getByText("주 경험축 근거 부족을 null로 보존")).toBeVisible();

  for (const label of ["평가자 A", "평가자 B", "평가자 C"]) {
    await page.getByRole("button", { name: `${label} accepted revision 선택` }).click();
    await expect(page.getByRole("article", { name: `${label} revision chain` })).toContainText(
      "accepted revision 선택됨",
    );
  }
  await expect(page.getByText("점수 범위 차이 2 이상")).toBeVisible();
  await expect(page.getByText("주유형 판단 누락")).toBeVisible();
  await expect(page.getByText("주유형 판단 전원 불일치")).toHaveCount(0);
  for (const primaryAxis of ["HISTORY_TRADITION", "EMOTION_IMAGE", "REST_IMMERSION"]) {
    await expect(page.getByText(primaryAxis, { exact: true }).first()).toBeVisible();
  }

  await page.getByRole("button", { name: "재검토 목록 생성하기" }).click();
  const aggregateBlocked = page.waitForResponse(
    (response) => response.url().endsWith("/aggregate") && response.status() === 409,
  );
  await page.getByRole("button", { name: "조정 결과 revision 게시하기" }).click();
  await aggregateBlocked;
  await expect(page.getByRole("alert")).toContainText("재검토 사유");

  const triggerRows = page.getByRole("list", { name: "재검토 사유" }).getByRole("listitem");
  for (let index = 0; index < (await triggerRows.count()); index += 1) {
    const row = triggerRows.nth(index);
    await row.getByRole("textbox", { name: "해결 사유" }).fill("공식 원문과 세 revision을 대조해 해결함");
    await row.getByRole("button", { name: "재검토 사유 해결" }).click();
  }
  const aggregateResponse = page.waitForResponse(
    (response) => response.url().endsWith("/aggregate") && response.status() === 200,
  );
  await page.getByRole("button", { name: "조정 결과 revision 게시하기" }).click();
  const labelExport = (await (await aggregateResponse).json()) as { export_sha256: string };
  await expect(page.getByRole("heading", { name: "불변 label export 생성됨" })).toBeFocused();

  browserCapability = capabilities.builder;
  await page.goto(operatorPath);
  await expect(page.getByText(runtimeFixture.sources[0]!.text_ko)).toHaveCount(0);
  await page.getByLabel("Label export SHA-256").fill(labelExport.export_sha256);
  await page.getByLabel("Rubric SHA-256").fill("1".repeat(64));
  await page.getByLabel("Source root SHA-256").fill("2".repeat(64));
  await page.getByLabel("DEV lineage SHA-256").fill("3".repeat(64));
  let freezeAttempts = 0;
  let releaseRejectedFreeze: (() => void) | undefined;
  const rejectedFreezeGate = new Promise<void>((resolve) => {
    releaseRejectedFreeze = resolve;
  });
  await page.route("**/internal/evaluation/freeze", async (route) => {
    freezeAttempts += 1;
    if (freezeAttempts === 1) {
      await rejectedFreezeGate;
      await route.fulfill({
        body: JSON.stringify({ detail: "합성 freeze 거부" }),
        contentType: "application/json",
        status: 422,
      });
      return;
    }
    await route.fallback({
      headers: {
        ...route.request().headers(),
        "X-ITDA-Phase3-Capability": browserCapability,
      },
    });
  });
  await page.getByRole("button", { name: "독립 라벨 동결하기" }).click();
  const freezeDialog = page.getByRole("dialog", { name: "현재 독립 라벨 집합을 동결할까요?" });
  await expect(freezeDialog).toBeVisible();
  const freezeTrigger = page.getByRole("button", { name: "독립 라벨 동결하기" });
  await expect(page.getByRole("button", { name: "아직 동결하지 않기" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(freezeTrigger).toBeFocused();
  await freezeTrigger.click();
  await page.getByRole("button", { name: "아직 동결하지 않기" }).click();
  await expect(freezeTrigger).toBeFocused();
  await freezeTrigger.click();
  const confirmFreeze = page.getByRole("button", { name: "정확한 라벨 집합 동결하기" });
  await confirmFreeze.click();
  await expect.poll(() => freezeAttempts).toBe(1);
  await expect(freezeDialog).toHaveAttribute("aria-busy", "true");
  await expect(freezeDialog).toBeFocused();
  await expect(confirmFreeze).toBeDisabled();
  await page.keyboard.press("Tab");
  await expect(freezeDialog).toBeFocused();
  releaseRejectedFreeze?.();
  const freezeError = freezeDialog.getByRole("alert");
  await expect(freezeError).not.toHaveText("");
  await expect(freezeError).toBeFocused();
  await expect(page.getByRole("alert")).toHaveCount(1);
  await page.keyboard.press("Escape");
  await expect(freezeDialog).toBeHidden();
  await expect(freezeTrigger).toBeFocused();
  await expect(page.getByRole("alert")).toHaveCount(0);
  await freezeTrigger.click();
  await expect(page.getByRole("button", { name: "아직 동결하지 않기" })).toBeFocused();
  const freezeResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith("/internal/evaluation/freeze") && response.status() === 200,
  );
  await confirmFreeze.click();
  const frozen = await freezeResponse;
  expect(frozen.status()).toBe(200);
  const freezeReceipt = (await frozen.json()) as { receipt_sha256: string; status: string };
  expect(freezeReceipt.status).toBe("APPROVED_FROZEN");
  await expect(page.getByRole("heading", { name: "독립 라벨 동결 영수증" })).toBeFocused();
  await expect(page.getByText(freezeReceipt.receipt_sha256)).toBeVisible();

  let candidateResponse: Awaited<ReturnType<typeof page.request.get>> | null = null;
  await expect
    .poll(
      async () => {
        try {
          const response = await page.request.get(
            "/internal/evaluation/evidence-review/candidates",
            { headers: { "X-ITDA-Phase3-Capability": capabilities.builder } },
          );
          if (response.status() === 200) candidateResponse = response;
          return response.status();
        } catch {
          return 0;
        }
      },
      { timeout: 30_000 },
    )
    .toBe(200);
  expect(candidateResponse).not.toBeNull();
  const candidateQueue = (await candidateResponse!.json()) as {
    candidate_manifest_sha256: string;
    provenance: { freeze_receipt_sha256: string };
  };
  expect(candidateQueue.provenance.freeze_receipt_sha256).toBe(
    freezeReceipt.receipt_sha256,
  );

  browserCapability = capabilities.builder;
  await page.setViewportSize({ width: 320, height: 568 });
  await page.goto(evidenceReviewPath);
  await expect(
    page.getByRole("heading", { level: 1, name: "Description/Odii 근거 검수" }),
  ).toBeFocused();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= document.documentElement.clientWidth,
    ),
  ).toBe(true);
  await page.setViewportSize({ width: 640, height: 720 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= document.documentElement.clientWidth,
    ),
  ).toBe(true);
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.getByRole("button", { name: "관련 근거로 승인" }).first().click();
  await page
    .getByRole("button", { name: "현재 review를 accepted head로 선택" })
    .first()
    .click();
  const reviewedResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith("/internal/evaluation/evidence-review/finalize") &&
      response.status() === 201,
  );
  await page.getByRole("button", { name: "현재 lane 검수 완료하기" }).click();
  const reviewedManifest = (await (await reviewedResponse).json()) as {
    manifest_sha256: string;
    candidate_manifest_sha256: string;
  };
  expect(reviewedManifest.candidate_manifest_sha256).toBe(
    candidateQueue.candidate_manifest_sha256,
  );
  await expect(
    page.getByRole("heading", { name: "불변 reviewed-evidence manifest 생성됨" }),
  ).toBeFocused();
  await expect(page.getByText(reviewedManifest.manifest_sha256)).toBeVisible();

  const draftResponse = await page.request.post(
    "/internal/test-support/phase3/profile-release-build-draft",
    {
      headers: { "X-ITDA-Phase3-Capability": capabilities.builder },
      data: { reviewed_evidence_manifest_sha256: reviewedManifest.manifest_sha256 },
    },
  );
  expect(draftResponse.status(), await draftResponse.text()).toBe(201);
  const buildDraft = (await draftResponse.json()) as {
    draft_ref: string;
    expires_at: string;
    nonce_sha256: string;
  };
  expect(buildDraft.draft_ref).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(buildDraft.nonce_sha256).toMatch(/^[a-f0-9]{64}$/);

  await page.goto("/internal/profile-releases/builder");
  await page.evaluate((draft) => {
    window.history.replaceState(
      { ...(window.history.state ?? {}), usr: { buildDraft: draft } },
      "",
      window.location.href,
    );
  }, buildDraft);
  await page.reload();
  await expect(
    page.getByRole("heading", { level: 1, name: "DEV profile release 후보" }),
  ).toBeFocused();
  const buildResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith("/internal/evaluation/profile-releases/build-drafts/build") &&
      response.status() === 201,
  );
  await page.getByRole("button", { name: "불변 release 후보 만들기" }).click();
  const buildReceipt = (await (await buildResponse).json()) as {
    receipt_sha256: string;
    release_sha256: string;
    state: string;
  };
  expect(buildReceipt.receipt_sha256).toMatch(/^[a-f0-9]{64}$/);
  expect(buildReceipt.release_sha256).toMatch(/^[a-f0-9]{64}$/);
  expect(buildReceipt.state).toBe("BUILT_UNAPPROVED");
  await expect(page.getByText("BUILT_UNAPPROVED · 후보 생성됨, 독립 승인 전")).toBeVisible();

  const browserSurface = JSON.stringify(
    await page.evaluate(() => ({
      html: document.documentElement.outerHTML,
      localStorage: { ...window.localStorage },
      sessionStorage: { ...window.sessionStorage },
    })),
  );
  const screenshotBytes = (await page.screenshot()).toString("utf8");
  for (const canary of [
    ...fixture.forbidden_canaries,
    ...Object.values(capabilities),
    "model_output",
    "BLIND",
  ]) {
    expect(browserSurface).not.toContain(canary);
    expect(networkBodies.join("\n")).not.toContain(canary);
    expect(browserErrors.join("\n")).not.toContain(canary);
    expect(screenshotBytes).not.toContain(canary);
  }
});

test("canonical evaluator receipt runtime", async ({ request }) => {
  const capability = process.env.ITDA_E2E_PHASE3_EVALUATOR_C_CAPABILITY;
  expect(capability).toBeTruthy();
  const headers = { "X-ITDA-Phase3-Capability": capability! };

  const fixtureResponse = await request.get("/internal/test-support/phase3/fixture", {
    headers,
  });
  expect(fixtureResponse.status()).toBe(200);
  const runtimeFixture = (await fixtureResponse.json()) as RuntimeFixture;
  expect(runtimeFixture.synthetic_only).toBe(true);

  const submission = {
    assignment_id: runtimeFixture.assignment.assignment_id,
    rubric_version: runtimeFixture.assignment.rubric_version,
    source_snapshot_version: runtimeFixture.assignment.source_snapshot_version,
    primary_axis: "HISTORY_TRADITION",
    submitted_at: "2026-08-04T00:00:00+00:00",
    judgments: ATTRIBUTE_IDS.map((attribute_id) => ({
      attribute_id,
      score: 2,
      unknown_reason: null,
      unknown_note: null,
      evidence: [],
    })),
  };

  const created = await request.post("/internal/evaluation/revisions", {
    headers,
    data: submission,
  });
  expect(created.status()).toBe(201);
  const receipt = await created.json();
  expect(Object.keys(receipt).sort()).toEqual(
    ["created_at", "evaluator_principal", "receipt_sha256", "revision", "revision_sha256"].sort(),
  );
  expect(receipt.evaluator_principal).toMatch(/^itda_label_evaluator_c_run_[a-z0-9_]+$/);
  expect(receipt.evaluator_principal).not.toContain(capability);

  const persisted = await request.get(
    `/internal/evaluation/revisions/${receipt.revision_sha256}/receipt`,
    { headers },
  );
  expect(persisted.status()).toBe(200);
  expect(await persisted.json()).toEqual(receipt);

  const replay = await request.post("/internal/evaluation/revisions", {
    headers,
    data: submission,
  });
  expect(replay.status()).toBe(201);
  expect(await replay.json()).toEqual(receipt);

  const revoked = await request.post("/internal/test-support/phase3/revoke-self", {
    headers,
  });
  expect(revoked.status()).toBe(204);
  const denied = await request.get(
    `/internal/evaluation/revisions/${receipt.revision_sha256}/receipt`,
    { headers },
  );
  expect(denied.status()).toBe(401);
  expect(await denied.text()).not.toContain(capability);
});

test("isolated evaluator clears forbidden-role DOM and storage state", async ({ page }) => {
  const capability = process.env.ITDA_E2E_PHASE3_EVALUATOR_A_CAPABILITY!;
  await page.goto(evaluatorPath);
  await expect(page.getByRole("heading", { level: 1, name: "독립 평가를 시작합니다" })).toBeVisible();

  const revoked = await page.request.post("/internal/test-support/phase3/revoke-self", {
    headers: { "X-ITDA-Phase3-Capability": capability },
  });
  expect(revoked.status()).toBe(204);
  await page.reload();
  await expect(page.getByText("이 역할은 이 자료를 볼 수 없습니다.")).toBeVisible();
  await expect(page.getByText("합성 전용 평가 초안")).toHaveCount(0);
  expect(await page.evaluate(() => window.localStorage.length + window.sessionStorage.length)).toBe(0);
});
