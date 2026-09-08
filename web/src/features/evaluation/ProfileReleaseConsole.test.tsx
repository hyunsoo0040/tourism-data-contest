import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

import {
  ProfileReleaseConsole,
  sha256Ascii,
  type ProfileReleaseBuildInput,
  type ProfileReleaseMutation,
} from "./ProfileReleaseConsole";
import {
  createProfileReleaseClient,
  type ProfileReleaseActivePointerProjection,
  type ProfileReleaseBuildDraftReference,
  type ProfileReleaseBuildOutcome,
  type ProfileReleasePinProjection,
  type ProfileReleaseStateProjection,
  type ProfileReleaseTransitionOutcome,
} from "./api";

const TARGET_SHA256 = "a".repeat(64);
const PREVIOUS_SHA256 = "b".repeat(64);
const BUILD_RECEIPT_SHA256 = "c".repeat(64);
const BINDING_SHA256 = "d".repeat(64);
const CURRENT_LIFECYCLE_RECEIPT_SHA256 = "e".repeat(64);
const REPLACEMENT_TRANSITION_RECEIPT_SHA256 = "f".repeat(64);
const STATE_COPY_FOR_TEST = {
  ACTIVE: "ACTIVE · 현재 active release",
  APPROVED_INACTIVE: "APPROVED_INACTIVE · 독립 승인됨, 아직 비활성",
} as const;

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    headers: { "Content-Type": "application/json" },
    status,
  });
}

function unknown(
  action: "BUILD" | "APPROVE" | "ACTIVATE" | "ROLLBACK",
  lookupPath: string,
): Response {
  return json(
    { detail: { action, lookup_path: lookupPath, outcome: "UNKNOWN" } },
    503,
  );
}

function retryableAbort(
  action: "BUILD" | "APPROVE" | "ACTIVATE" | "ROLLBACK",
): Response {
  return json({ detail: { action, outcome: "RETRYABLE_ABORT" } }, 503);
}

function buildUnavailable(retryPath: string): Response {
  return json(
    { detail: { action: "BUILD", outcome: "BUILD_UNAVAILABLE", retry_path: retryPath } },
    503,
  );
}

function cleanupUnknown(nonceSha256: string): Response {
  return json(
    {
      detail: {
        action: "BUILD",
        lookup_path:
          `/internal/evaluation/profile-releases/build-receipts/by-nonce/${nonceSha256}`,
        outcome: "DRAFT_CLEANUP_UNKNOWN",
        retry_path: "/internal/evaluation/profile-releases/build-drafts/build",
      },
    },
    503,
  );
}

function pointer(activeReleaseSha256: string | null): ProfileReleaseActivePointerProjection {
  return activeReleaseSha256 === null
    ? { active_release_sha256: null, receipt_sha256: null, state: null }
    : {
        active_release_sha256: activeReleaseSha256,
        receipt_sha256: CURRENT_LIFECYCLE_RECEIPT_SHA256,
        state: "ACTIVE",
      };
}

function state(
  releaseSha256: string,
  releaseState: ProfileReleaseStateProjection["state"],
): ProfileReleaseStateProjection {
  return {
    lifecycle_head_receipt_sha256:
      releaseState === "BUILT_UNAPPROVED"
        ? null
        : CURRENT_LIFECYCLE_RECEIPT_SHA256,
    provenance_kind:
      releaseState === "BUILT_UNAPPROVED"
        ? "BUILD"
        : releaseState === "APPROVED_INACTIVE"
          ? "APPROVAL"
          : "TRANSITION",
    provenance_receipt_sha256:
      releaseState === "BUILT_UNAPPROVED"
        ? BUILD_RECEIPT_SHA256
        : CURRENT_LIFECYCLE_RECEIPT_SHA256,
    release_sha256: releaseSha256,
    state: releaseState,
  };
}

function buildInput(): ProfileReleaseBuildInput {
  return {
    canonical_lineage_sha256: "1".repeat(64),
    candidate_run_sha256: "4".repeat(64),
    cohort: Array.from({ length: 24 }, (_, index) => ({
      accepted_review_set_sha256: (index + 100).toString(16).padStart(64, "0"),
      candidate_manifest_sha256: (index + 200).toString(16).padStart(64, "0"),
      description_lane: "READY" as const,
      evidence_ready: true,
      label_export_sha256: (index + 300).toString(16).padStart(64, "0"),
      label_ready: true,
      odii_lane: "READY" as const,
      place_ref: `synthetic-place-${index}`,
      profile_sha256: index.toString(16).padStart(64, "0"),
      reviewed_evidence_manifest_sha256: (index + 400)
        .toString(16)
        .padStart(64, "0"),
      rights_sha256: (index + 500).toString(16).padStart(64, "0"),
      rights_ready: true,
      source_sha256: (index + 600).toString(16).padStart(64, "0"),
    })),
    dev_lineage_sha256: "2".repeat(64),
    label_freeze_sha256: "5".repeat(64),
    profile_schema_sha256: "3".repeat(64),
    reviewed_manifest_sha256: "6".repeat(64),
    release_id: "synthetic-console-release",
    rights_manifest_sha256: "7".repeat(64),
    schema_version: "itda.profile-release-candidate.v1",
    source_manifest_sha256: "8".repeat(64),
  };
}

function buildDraft(): ProfileReleaseBuildDraftReference {
  return {
    draft_ref: "R".repeat(43),
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    nonce_sha256: "4".repeat(64),
  };
}

function mutation(
  releaseSha256: string,
  releaseState: ProfileReleaseMutation["state"],
): ProfileReleaseMutation {
  return {
    completion: releaseState === "ACTIVE" ? "MUTATION_COMMITTED" : null,
    receipt_sha256:
      releaseState === "BUILT_UNAPPROVED"
        ? null
        : CURRENT_LIFECYCLE_RECEIPT_SHA256,
    release_sha256: releaseSha256,
    state: releaseState,
  };
}

describe("profile release generated client", () => {
  it("uses all four generated-response-typed authoritative GET operations", async () => {
    const buildOutcome: ProfileReleaseBuildOutcome = {
      binding_sha256: BINDING_SHA256,
      completion: "MUTATION_COMMITTED",
      nonce_sha256: "4".repeat(64),
      outcome: "COMMITTED",
      receipt_sha256: BUILD_RECEIPT_SHA256,
      release_sha256: TARGET_SHA256,
      state: "BUILT_UNAPPROVED",
    };
    const transitionOutcome: ProfileReleaseTransitionOutcome = {
      action: "ACTIVATE",
      binding_sha256: BINDING_SHA256,
      completion: "MUTATION_COMMITTED",
      expected_current_sha256: PREVIOUS_SHA256,
      nonce_sha256: "5".repeat(64),
      outcome: "COMMITTED",
      previous_release_sha256: PREVIOUS_SHA256,
      receipt_sha256: CURRENT_LIFECYCLE_RECEIPT_SHA256,
      release_sha256: TARGET_SHA256,
    };
    const requests: string[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      requests.push(path);
      if (path.includes("build-receipts")) return json(buildOutcome);
      if (path.endsWith("active-pointer")) return json(pointer(TARGET_SHA256));
      if (path.includes("transition-receipts")) return json(transitionOutcome);
      return json(state(TARGET_SHA256, "ACTIVE"));
    });
    const client = createProfileReleaseClient({ fetchImpl: fetchImpl as typeof fetch });

    expect(await client.getProfileReleaseBuildOutcomeByNonce("4".repeat(64))).toEqual(
      buildOutcome,
    );
    expect(await client.getProfileReleaseActivePointer()).toEqual(pointer(TARGET_SHA256));
    expect(await client.getProfileReleaseState(TARGET_SHA256)).toEqual(
      state(TARGET_SHA256, "ACTIVE"),
    );
    expect(await client.getProfileReleaseTransitionOutcomeByNonce("5".repeat(64))).toEqual(
      transitionOutcome,
    );
    expect(requests).toEqual([
      `/internal/evaluation/profile-releases/build-receipts/by-nonce/${"4".repeat(64)}`,
      "/internal/evaluation/profile-releases/active-pointer",
      `/internal/evaluation/profile-releases/${TARGET_SHA256}/state`,
      `/internal/evaluation/profile-releases/transition-receipts/by-nonce/${"5".repeat(64)}`,
    ]);
  });

  it("rejects every impossible lifecycle provenance combination at the client boundary", async () => {
    const invalidStates: ProfileReleaseStateProjection[] = [
      { ...state(TARGET_SHA256, "BUILT_UNAPPROVED"), provenance_kind: "APPROVAL" },
      {
        ...state(TARGET_SHA256, "APPROVED_INACTIVE"),
        lifecycle_head_receipt_sha256: null,
      },
      { ...state(TARGET_SHA256, "ACTIVE"), provenance_kind: "APPROVAL" },
      {
        ...state(TARGET_SHA256, "ACTIVE"),
        lifecycle_head_receipt_sha256: "f".repeat(64),
      },
    ];
    for (const invalidState of invalidStates) {
      const client = createProfileReleaseClient({
        fetchImpl: vi.fn(async () => json(invalidState)) as typeof fetch,
      });
      await expect(client.getProfileReleaseState(TARGET_SHA256)).rejects.toMatchObject({
        name: "EvaluatorApiError",
      });
    }
  });

  it("rejects impossible transition CAS relationships at the client boundary", async () => {
    const invalidOutcomes: ProfileReleaseTransitionOutcome[] = [
      {
        action: "ACTIVATE",
        binding_sha256: BINDING_SHA256,
        completion: "RELOOKUP_CONFIRMED",
        expected_current_sha256: PREVIOUS_SHA256,
        nonce_sha256: "5".repeat(64),
        outcome: "COMMITTED",
        previous_release_sha256: TARGET_SHA256,
        receipt_sha256: CURRENT_LIFECYCLE_RECEIPT_SHA256,
        release_sha256: TARGET_SHA256,
      },
      {
        action: "ROLLBACK",
        binding_sha256: BINDING_SHA256,
        completion: "RELOOKUP_CONFIRMED",
        expected_current_sha256: null,
        nonce_sha256: "5".repeat(64),
        outcome: "COMMITTED",
        previous_release_sha256: null,
        receipt_sha256: CURRENT_LIFECYCLE_RECEIPT_SHA256,
        release_sha256: TARGET_SHA256,
      },
    ];
    for (const invalidOutcome of invalidOutcomes) {
      const client = createProfileReleaseClient({
        fetchImpl: vi.fn(async () => json(invalidOutcome)) as typeof fetch,
      });
      await expect(
        client.getProfileReleaseTransitionOutcomeByNonce("5".repeat(64)),
      ).rejects.toMatchObject({ name: "EvaluatorApiError" });
    }
  });

  it("fails closed when a 503 UNKNOWN action or lookup path is not exact", async () => {
    const client = createProfileReleaseClient({
      fetchImpl: vi.fn(async () =>
        unknown(
          "ROLLBACK",
          `/internal/evaluation/profile-releases/build-receipts/by-nonce/${"4".repeat(64)}`,
        ),
      ) as typeof fetch,
    });
    await expect(
      client.build({ ...buildInput(), reconciliation_nonce: "4".repeat(64) }),
    ).rejects.toMatchObject({ name: "EvaluatorApiError", status: 503 });
  });

  it("rejects every structured 503 outcome that belongs to another operation", async () => {
    type Operation =
      | "direct-build"
      | "draft-build"
      | "approve"
      | "activate"
      | "rollback";
    const nonceSha256 = "4".repeat(64);
    const buildLookup =
      `/internal/evaluation/profile-releases/build-receipts/by-nonce/${nonceSha256}`;
    const transitionLookup =
      `/internal/evaluation/profile-releases/transition-receipts/by-nonce/${nonceSha256}`;
    const stateLookup =
      `/internal/evaluation/profile-releases/${TARGET_SHA256}/state`;
    const variants: ReadonlyArray<{
      name: string;
      allowed: readonly Operation[];
      response: () => Response;
    }> = [
      {
        name: "unknown-build",
        allowed: ["direct-build", "draft-build"],
        response: () => unknown("BUILD", buildLookup),
      },
      {
        name: "unknown-approve",
        allowed: ["approve"],
        response: () => unknown("APPROVE", stateLookup),
      },
      {
        name: "unknown-activate",
        allowed: ["activate"],
        response: () => unknown("ACTIVATE", transitionLookup),
      },
      {
        name: "unknown-rollback",
        allowed: ["rollback"],
        response: () => unknown("ROLLBACK", transitionLookup),
      },
      {
        name: "retry-build",
        allowed: ["direct-build", "draft-build"],
        response: () => retryableAbort("BUILD"),
      },
      {
        name: "retry-approve",
        allowed: ["approve"],
        response: () => retryableAbort("APPROVE"),
      },
      {
        name: "retry-activate",
        allowed: ["activate"],
        response: () => retryableAbort("ACTIVATE"),
      },
      {
        name: "retry-rollback",
        allowed: ["rollback"],
        response: () => retryableAbort("ROLLBACK"),
      },
      {
        name: "unavailable-direct",
        allowed: ["direct-build"],
        response: () => buildUnavailable("/internal/evaluation/profile-releases/build"),
      },
      {
        name: "unavailable-draft",
        allowed: ["draft-build"],
        response: () =>
          buildUnavailable(
            "/internal/evaluation/profile-releases/build-drafts/build",
          ),
      },
      {
        name: "cleanup-draft",
        allowed: ["draft-build"],
        response: () => cleanupUnknown(nonceSha256),
      },
    ];
    const operations: Operation[] = [
      "direct-build",
      "draft-build",
      "approve",
      "activate",
      "rollback",
    ];
    for (const operation of operations) {
      for (const variant of variants) {
        if (variant.allowed.includes(operation)) continue;
        const client = createProfileReleaseClient({
          fetchImpl: vi.fn(async () => variant.response()) as typeof fetch,
        });
        const request =
          operation === "direct-build"
            ? client.build({ ...buildInput(), reconciliation_nonce: nonceSha256 })
            : operation === "draft-build"
              ? client.buildDraft(
                  { draft_ref: "R".repeat(43), nonce_sha256: nonceSha256 },
                  nonceSha256,
                )
              : operation === "approve"
                ? client.approve(TARGET_SHA256)
                : operation === "activate"
                  ? client.activate(TARGET_SHA256, {
                      expected_current_sha256: null,
                      nonce: nonceSha256,
                    })
                  : client.rollback(TARGET_SHA256, {
                      expected_current_sha256: PREVIOUS_SHA256,
                      nonce: nonceSha256,
                      reason: "합성 복구",
                    });
        await expect(
          request,
          `${operation} accepted ${variant.name}`,
        ).rejects.toMatchObject({
            name: "EvaluatorApiError",
            status: 503,
          });
      }
    }
  });

  it("keeps transport loss distinct from an explicit typed 503", async () => {
    const client = createProfileReleaseClient({
      fetchImpl: vi.fn(async () => {
        throw new TypeError("synthetic transport loss");
      }) as typeof fetch,
    });
    await expect(
      client.build({ ...buildInput(), reconciliation_nonce: "4".repeat(64) }),
    ).rejects.toMatchObject({ name: "EvaluatorApiError", status: null });
  });

  it("keeps retryable abort, pre-build unavailable, and proven cleanup uncertainty distinct", async () => {
    const nonceSha256 = "4".repeat(64);
    const proof: ProfileReleaseBuildOutcome = {
      binding_sha256: BINDING_SHA256,
      completion: "RELOOKUP_CONFIRMED",
      nonce_sha256: nonceSha256,
      outcome: "COMMITTED",
      receipt_sha256: BUILD_RECEIPT_SHA256,
      release_sha256: TARGET_SHA256,
      state: "BUILT_UNAPPROVED",
    };
    const retryClient = createProfileReleaseClient({
      fetchImpl: vi.fn(async () => retryableAbort("BUILD")) as typeof fetch,
    });
    await expect(
      retryClient.build({ ...buildInput(), reconciliation_nonce: "4".repeat(64) }),
    ).rejects.toMatchObject({
      action: "BUILD",
      name: "ProfileReleaseRetryableAbortError",
    });

    const retryPath = "/internal/evaluation/profile-releases/build-drafts/build";
    const unavailableClient = createProfileReleaseClient({
      fetchImpl: vi.fn(async () => buildUnavailable(retryPath)) as typeof fetch,
    });
    await expect(
      unavailableClient.buildDraft(
        { draft_ref: "R".repeat(43), nonce_sha256: nonceSha256 },
        nonceSha256,
      ),
    ).rejects.toMatchObject({
      name: "ProfileReleaseBuildUnavailableError",
      retryPath,
    });

    const cleanupFetch = vi
      .fn()
      .mockResolvedValueOnce(cleanupUnknown(nonceSha256))
      .mockResolvedValueOnce(json(proof));
    const cleanupClient = createProfileReleaseClient({
      fetchImpl: cleanupFetch as typeof fetch,
    });
    await expect(
      cleanupClient.buildDraft(
        { draft_ref: "R".repeat(43), nonce_sha256: nonceSha256 },
        nonceSha256,
      ),
    ).rejects.toMatchObject({
      name: "ProfileReleaseDraftCleanupUnknownError",
      outcome: "DRAFT_CLEANUP_UNKNOWN",
      provenBuild: proof,
    });
  });

  it.each([
    ["lookup 404", () => json({ detail: "not found" }, 404)],
    ["read 503", () => json({ detail: "temporarily unavailable" }, 503)],
    ["transport loss", () => new TypeError("synthetic lookup transport loss")],
  ] as const)(
    "preserves cleanup uncertainty when %s prevents BUILD proof",
    async (_name, failure) => {
      const nonceSha256 = "4".repeat(64);
      const fetchImpl = vi.fn(async () => {
        if (fetchImpl.mock.calls.length === 1) return cleanupUnknown(nonceSha256);
        const result = failure();
        if (result instanceof Error) throw result;
        return result;
      });
      const client = createProfileReleaseClient({
        fetchImpl: fetchImpl as typeof fetch,
      });
      await expect(
        client.buildDraft(
          { draft_ref: "R".repeat(43), nonce_sha256: nonceSha256 },
          nonceSha256,
        ),
      ).rejects.toMatchObject({
        name: "ProfileReleaseDraftCleanupUnknownError",
        outcome: "DRAFT_CLEANUP_UNKNOWN",
        provenBuild: null,
      });
    },
  );
});

describe("ProfileReleaseConsole", () => {
  it("initializes from active-pointer and exact-state reads", async () => {
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) =>
      String(input).endsWith("active-pointer")
        ? json(pointer(TARGET_SHA256))
        : json(state(TARGET_SHA256, "ACTIVE")),
    );

    render(<ProfileReleaseConsole fetchImpl={fetchImpl as typeof fetch} role="activator" />);

    expect(await screen.findByText("ACTIVE · 현재 active release")).toBeTruthy();
    expect(screen.getAllByText(TARGET_SHA256).length).toBeGreaterThan(0);
    expect(fetchImpl.mock.calls.map(([input]) => String(input))).toEqual([
      "/internal/evaluation/profile-releases/active-pointer",
      `/internal/evaluation/profile-releases/${TARGET_SHA256}/state`,
    ]);
  });

  it("recovers a lost build response only with Web Crypto nonce digest and no optimistic success", async () => {
    let resolveState: ((response: Response) => void) | undefined;
    const stateResponse = new Promise<Response>((resolve) => {
      resolveState = resolve;
    });
    const requests: string[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      requests.push(path);
      if (path.endsWith("active-pointer")) return json(pointer(null));
      if (path.endsWith("/build-drafts/build")) {
        expect(JSON.parse(String(init?.body))).toEqual({
          draft_ref: buildDraft().draft_ref,
          nonce_sha256: buildDraft().nonce_sha256,
        });
        return unknown(
          "BUILD",
          `/internal/evaluation/profile-releases/build-receipts/by-nonce/${buildDraft().nonce_sha256}`,
        );
      }
      if (path.includes("build-receipts")) {
        expect(path).toBe(
          `/internal/evaluation/profile-releases/build-receipts/by-nonce/${buildDraft().nonce_sha256}`,
        );
        return json({
          binding_sha256: BINDING_SHA256,
          completion: "RELOOKUP_CONFIRMED",
          nonce_sha256: buildDraft().nonce_sha256,
          outcome: "COMMITTED",
          receipt_sha256: BUILD_RECEIPT_SHA256,
          release_sha256: TARGET_SHA256,
          state: "BUILT_UNAPPROVED",
        } satisfies ProfileReleaseBuildOutcome);
      }
      return stateResponse;
    });

    render(
      <ProfileReleaseConsole
        buildDraft={buildDraft()}
        fetchImpl={fetchImpl as typeof fetch}
        role="builder"
      />,
    );
    await waitFor(() => expect(fetchImpl).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole("button", { name: "불변 release 후보 만들기" }));
    await waitFor(() =>
      expect(requests).toContain(
        "/internal/evaluation/profile-releases/build-drafts/build",
      ),
    );
    expect(screen.queryByText("BUILT_UNAPPROVED · 후보 생성됨, 독립 승인 전")).toBeNull();
    resolveState?.(json(state(TARGET_SHA256, "BUILT_UNAPPROVED")));

    expect(
      await screen.findByText("BUILT_UNAPPROVED · 후보 생성됨, 독립 승인 전"),
    ).toBeTruthy();
    expect(document.documentElement.outerHTML).not.toContain("synthetic-place-");
    expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain(
      "synthetic-place-",
    );
  });

  it.each([
    ["typed 503 after approval", "APPROVED_INACTIVE", true],
    ["transport loss after activation", "ACTIVE", false],
  ] as const)(
    "keeps immutable BUILD proof separate from current lifecycle: %s",
    async (_scenario, currentState, typed503) => {
      const draft = buildDraft();
      let buildAttempts = 0;
      const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
        const path = String(input);
        if (path.endsWith("active-pointer")) return json(pointer(null));
        if (path.endsWith("/build-drafts/build")) {
          buildAttempts += 1;
          if (typed503) {
            return unknown(
              "BUILD",
              `/internal/evaluation/profile-releases/build-receipts/by-nonce/${draft.nonce_sha256}`,
            );
          }
          throw new TypeError("synthetic committed response loss");
        }
        if (path.includes("build-receipts")) {
          return json({
            binding_sha256: BINDING_SHA256,
            completion: "RELOOKUP_CONFIRMED",
            nonce_sha256: draft.nonce_sha256,
            outcome: "COMMITTED",
            receipt_sha256: BUILD_RECEIPT_SHA256,
            release_sha256: TARGET_SHA256,
            state: "BUILT_UNAPPROVED",
          } satisfies ProfileReleaseBuildOutcome);
        }
        if (path.endsWith("/state")) return json(state(TARGET_SHA256, currentState));
        throw new Error(`unexpected request: ${path}`);
      });
      render(
        <ProfileReleaseConsole
          buildDraft={draft}
          fetchImpl={fetchImpl as typeof fetch}
          role="builder"
        />,
      );
      await waitFor(() => expect(fetchImpl).toHaveBeenCalledTimes(1));
      fireEvent.click(screen.getByRole("button", { name: "불변 release 후보 만들기" }));
      expect(await screen.findByText(STATE_COPY_FOR_TEST[currentState])).toBeTruthy();
      expect(screen.getByText(new RegExp(`현재 lifecycle 상태는 ${currentState}`))).toBeTruthy();
      const lifecycleBlock = screen
        .getByText("Current lifecycle receipt SHA-256")
        .closest("div");
      expect(lifecycleBlock?.textContent).toContain(
        CURRENT_LIFECYCLE_RECEIPT_SHA256,
      );
      expect(lifecycleBlock?.textContent).not.toContain(BUILD_RECEIPT_SHA256);
      expect(buildAttempts).toBe(1);
    },
  );

  it("preserves proven BUILD identity when protected draft cleanup remains unknown", async () => {
    const draft = buildDraft();
    const proof: ProfileReleaseBuildOutcome = {
      binding_sha256: BINDING_SHA256,
      completion: "RELOOKUP_CONFIRMED",
      nonce_sha256: draft.nonce_sha256,
      outcome: "COMMITTED",
      receipt_sha256: BUILD_RECEIPT_SHA256,
      release_sha256: TARGET_SHA256,
      state: "BUILT_UNAPPROVED",
    };
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith("active-pointer")) return json(pointer(null));
      if (path.endsWith("/build-drafts/build")) {
        return cleanupUnknown(draft.nonce_sha256);
      }
      if (path.includes("build-receipts")) return json(proof);
      if (path.endsWith("/state")) {
        return json(state(TARGET_SHA256, "BUILT_UNAPPROVED"));
      }
      throw new Error(`unexpected request: ${path}`);
    });
    render(
      <ProfileReleaseConsole
        buildDraft={draft}
        fetchImpl={fetchImpl as typeof fetch}
        role="builder"
      />,
    );
    await waitFor(() => expect(fetchImpl).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole("button", { name: "불변 release 후보 만들기" }));
    expect(
      await screen.findByText(/보호 draft 정리는 아직 확인되지 않았습니다/),
    ).toBeTruthy();
    expect(screen.getAllByText(TARGET_SHA256).length).toBeGreaterThan(0);
    expect(screen.getAllByText(BUILD_RECEIPT_SHA256).length).toBeGreaterThan(0);
    expect(document.body.textContent).not.toContain("Build 결과는 UNKNOWN");
  });

  it.each([
    ["lifecycle 404", () => json({ detail: "not found" }, 404)],
    ["lifecycle 503", () => json({ detail: "temporarily unavailable" }, 503)],
    ["lifecycle transport loss", () => new TypeError("synthetic lifecycle transport loss")],
  ] as const)(
    "keeps proven BUILD and cleanup uncertainty when %s follows receipt proof",
    async (_name, failure) => {
      const draft = buildDraft();
      const proof: ProfileReleaseBuildOutcome = {
        binding_sha256: BINDING_SHA256,
        completion: "RELOOKUP_CONFIRMED",
        nonce_sha256: draft.nonce_sha256,
        outcome: "COMMITTED",
        receipt_sha256: BUILD_RECEIPT_SHA256,
        release_sha256: TARGET_SHA256,
        state: "BUILT_UNAPPROVED",
      };
      const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
        const path = String(input);
        if (path.endsWith("active-pointer")) return json(pointer(null));
        if (path.endsWith("/build-drafts/build")) {
          return cleanupUnknown(draft.nonce_sha256);
        }
        if (path.includes("build-receipts")) return json(proof);
        if (path.endsWith("/state")) {
          const result = failure();
          if (result instanceof Error) throw result;
          return result;
        }
        throw new Error(`unexpected request: ${path}`);
      });
      render(
        <ProfileReleaseConsole
          buildDraft={draft}
          fetchImpl={fetchImpl as typeof fetch}
          role="builder"
        />,
      );
      await waitFor(() => expect(fetchImpl).toHaveBeenCalledTimes(1));
      fireEvent.click(screen.getByRole("button", { name: "불변 release 후보 만들기" }));

      expect(await screen.findByText("현재 lifecycle 조회 불가")).toBeTruthy();
      expect(screen.getByText(/현재 lifecycle 조회는 unavailable입니다/)).toBeTruthy();
      expect(screen.getByText(/보호 draft 정리는 아직 확인되지 않았습니다/)).toBeTruthy();
      expect(screen.getAllByText(TARGET_SHA256).length).toBeGreaterThan(0);
      expect(screen.getAllByText(BUILD_RECEIPT_SHA256).length).toBeGreaterThan(0);
      expect(document.body.textContent).not.toContain("Build 결과는 UNKNOWN");
    },
  );

  it.each([
    ["lifecycle 404", () => json({ detail: "not found" }, 404)],
    ["lifecycle 503", () => json({ detail: "temporarily unavailable" }, 503)],
    ["lifecycle transport loss", () => new TypeError("synthetic lifecycle transport loss")],
  ] as const)(
    "rejects mismatched BUILD nonce before %s can present immutable proof",
    async (_name, lifecycleFailure) => {
      const draft = buildDraft();
      const mismatchedProof: ProfileReleaseBuildOutcome = {
        binding_sha256: BINDING_SHA256,
        completion: "RELOOKUP_CONFIRMED",
        nonce_sha256: "5".repeat(64),
        outcome: "COMMITTED",
        receipt_sha256: BUILD_RECEIPT_SHA256,
        release_sha256: TARGET_SHA256,
        state: "BUILT_UNAPPROVED",
      };
      const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
        const path = String(input);
        if (path.endsWith("active-pointer")) return json(pointer(null));
        if (path.endsWith("/build-drafts/build")) {
          return cleanupUnknown(draft.nonce_sha256);
        }
        if (path.includes("build-receipts")) return json(mismatchedProof);
        if (path.endsWith("/state")) {
          const result = lifecycleFailure();
          if (result instanceof Error) throw result;
          return result;
        }
        throw new Error(`unexpected request: ${path}`);
      });
      render(
        <ProfileReleaseConsole
          buildDraft={draft}
          fetchImpl={fetchImpl as typeof fetch}
          role="builder"
        />,
      );
      await waitFor(() => expect(fetchImpl).toHaveBeenCalledTimes(1));
      fireEvent.click(screen.getByRole("button", { name: "불변 release 후보 만들기" }));

      expect(
        await screen.findByText(
          /Build 응답을 nonce digest receipt로 조정하지 못했습니다/,
        ),
      ).toBeTruthy();
      expect(document.body.textContent).not.toContain("불변 BUILD receipt는 확인했습니다");
      expect(document.body.textContent).not.toContain(TARGET_SHA256);
      expect(document.body.textContent).not.toContain(BUILD_RECEIPT_SHA256);
      expect(
        fetchImpl.mock.calls.some(([input]) => String(input).endsWith("/state")),
      ).toBe(false);
    },
  );

  it.each([
    ["lookup 404", () => json({ detail: "not found" }, 404)],
    ["read 503", () => json({ detail: "temporarily unavailable" }, 503)],
    ["transport loss", () => new TypeError("synthetic lookup transport loss")],
  ] as const)("keeps cleanup-specific guidance when %s prevents proof", async (
    _name,
    failure,
  ) => {
    const draft = buildDraft();
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith("active-pointer")) return json(pointer(null));
      if (path.endsWith("/build-drafts/build")) return cleanupUnknown(draft.nonce_sha256);
      if (path.includes("build-receipts")) {
        const result = failure();
        if (result instanceof Error) throw result;
        return result;
      }
      throw new Error(`unexpected request: ${path}`);
    });
    render(
      <ProfileReleaseConsole
        buildDraft={draft}
        fetchImpl={fetchImpl as typeof fetch}
        role="builder"
      />,
    );
    await waitFor(() => expect(fetchImpl).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole("button", { name: "불변 release 후보 만들기" }));
    expect(
      await screen.findByText(
        /보호 draft 정리 결과는 여전히 불확실하며 BUILD receipt는 아직 확인되지 않았습니다/,
      ),
    ).toBeTruthy();
    expect(document.body.textContent).not.toContain("불변 BUILD receipt는 확인했습니다");
    expect(document.body.textContent).not.toContain("Build 결과는 UNKNOWN");
  });

  it("renders BUILD retryable abort as safe retry rather than UNKNOWN", async () => {
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) =>
      String(input).endsWith("active-pointer")
        ? json(pointer(null))
        : retryableAbort("BUILD"),
    );
    render(
      <ProfileReleaseConsole
        buildDraft={buildDraft()}
        fetchImpl={fetchImpl as typeof fetch}
        role="builder"
      />,
    );
    await waitFor(() => expect(fetchImpl).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole("button", { name: "불변 release 후보 만들기" }));
    expect(await screen.findByText(/BUILD는 커밋 전에 안전하게 중단되었습니다/)).toBeTruthy();
    expect(document.body.textContent).not.toContain("Build 결과는 UNKNOWN");
  });

  it("reconciles an explicit approval 503 through exact approval provenance", async () => {
    let stateReads = 0;
    const lookupPath =
      `/internal/evaluation/profile-releases/${TARGET_SHA256}/state`;
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith("active-pointer")) return json(pointer(null));
      if (path === lookupPath) {
        stateReads += 1;
        return json(
          state(
            TARGET_SHA256,
            stateReads < 3 ? "BUILT_UNAPPROVED" : "APPROVED_INACTIVE",
          ),
        );
      }
      if (path.endsWith("/approve")) return unknown("APPROVE", lookupPath);
      throw new Error(`unexpected request: ${path}`);
    });

    render(
      <ProfileReleaseConsole
        fetchImpl={fetchImpl as typeof fetch}
        release={mutation(TARGET_SHA256, "BUILT_UNAPPROVED")}
        role="approver"
      />,
    );
    await screen.findByText("BUILT_UNAPPROVED · 후보 생성됨, 독립 승인 전");
    fireEvent.change(screen.getByLabelText("승인할 full release SHA-256"), {
      target: { value: TARGET_SHA256 },
    });
    fireEvent.click(screen.getByRole("button", { name: "정확한 release 승인하기" }));

    expect(
      await screen.findByText("APPROVED_INACTIVE · 독립 승인됨, 아직 비활성"),
    ).toBeTruthy();
    expect(screen.getByText(/approver receipt/)).toBeTruthy();
  });

  it("recovers uncertain activation through digest receipt, pointer, and exact state", async () => {
    let rawNonce = "";
    let pointerReads = 0;
    const requests: string[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      requests.push(path);
      if (path.endsWith("active-pointer")) {
        pointerReads += 1;
        return json(pointer(pointerReads === 1 ? PREVIOUS_SHA256 : TARGET_SHA256));
      }
      if (path.endsWith(`/${TARGET_SHA256}/state`)) {
        return json(state(TARGET_SHA256, pointerReads === 1 ? "APPROVED_INACTIVE" : "ACTIVE"));
      }
      if (path.endsWith("/activate")) {
        rawNonce = (JSON.parse(String(init?.body)) as { nonce: string }).nonce;
        return unknown(
          "ACTIVATE",
          `/internal/evaluation/profile-releases/transition-receipts/by-nonce/${await sha256Ascii(rawNonce)}`,
        );
      }
      if (path.includes("transition-receipts")) {
        const nonceSha256 = await sha256Ascii(rawNonce);
        expect(path).toBe(
          `/internal/evaluation/profile-releases/transition-receipts/by-nonce/${nonceSha256}`,
        );
        expect(path).not.toContain(rawNonce);
        return json({
          action: "ACTIVATE",
          binding_sha256: BINDING_SHA256,
          completion: "RELOOKUP_CONFIRMED",
          expected_current_sha256: PREVIOUS_SHA256,
          nonce_sha256: nonceSha256,
          outcome: "COMMITTED",
          previous_release_sha256: PREVIOUS_SHA256,
          receipt_sha256: CURRENT_LIFECYCLE_RECEIPT_SHA256,
          release_sha256: TARGET_SHA256,
        } satisfies ProfileReleaseTransitionOutcome);
      }
      throw new Error(`unexpected request: ${path}`);
    });

    render(
      <ProfileReleaseConsole
        fetchImpl={fetchImpl as typeof fetch}
        release={mutation(TARGET_SHA256, "APPROVED_INACTIVE")}
        role="activator"
      />,
    );
    expect(
      await screen.findByText("APPROVED_INACTIVE · 독립 승인됨, 아직 비활성"),
    ).toBeTruthy();
    fireEvent.change(screen.getByLabelText("전환할 full release SHA-256"), {
      target: { value: TARGET_SHA256 },
    });
    fireEvent.click(
      screen.getByLabelText("새 세션에만 적용되는 pointer 전환임을 확인했습니다"),
    );
    fireEvent.click(screen.getByRole("button", { name: "승인된 release 활성화하기" }));

    expect(await screen.findByText("ACTIVE · 현재 active release")).toBeTruthy();
    expect(screen.getByText(/ACTIVATE receipt, active pointer/)).toBeTruthy();
    expect(document.documentElement.outerHTML).not.toContain(rawNonce);
    expect(requests.filter((path) => path.includes(rawNonce))).toEqual([]);
  });

  it("keeps rollback nonce separate and reconciles a lost response by digest only", async () => {
    const oldSessionRef = "synthetic-lost-response-session-before-rollback";
    const newSessionRef = "synthetic-lost-response-session-after-rollback";
    const pinnedAt = "2026-08-06T07:00:00Z";
    const oldPin = {
      pin_sha256: "3".repeat(64),
      pinned_at: pinnedAt,
      release_sha256: PREVIOUS_SHA256,
      session_ref: oldSessionRef,
    } satisfies ProfileReleasePinProjection;
    const newPin = {
      pin_sha256: "4".repeat(64),
      pinned_at: pinnedAt,
      release_sha256: TARGET_SHA256,
      session_ref: newSessionRef,
    } satisfies ProfileReleasePinProjection;
    let rawNonce = "";
    let pointerReads = 0;
    const requests: string[] = [];
    const pinReads = new Map<string, number>();
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      requests.push(path);
      if (path.endsWith("active-pointer")) {
        pointerReads += 1;
        return json(pointer(pointerReads === 1 ? TARGET_SHA256 : PREVIOUS_SHA256));
      }
      if (path.endsWith(`/${PREVIOUS_SHA256}/state`)) {
        return json(
          state(
            PREVIOUS_SHA256,
            pointerReads === 1 ? "APPROVED_INACTIVE" : "ACTIVE",
          ),
        );
      }
      if (path.endsWith(`/sessions/${oldSessionRef}/pin`)) {
        pinReads.set(oldSessionRef, (pinReads.get(oldSessionRef) ?? 0) + 1);
        return json(oldPin);
      }
      if (path.endsWith(`/sessions/${newSessionRef}/pin`)) {
        pinReads.set(newSessionRef, (pinReads.get(newSessionRef) ?? 0) + 1);
        return json(newPin);
      }
      if (path.endsWith("/rollback")) {
        rawNonce = (JSON.parse(String(init?.body)) as { nonce: string }).nonce;
        return unknown(
          "ROLLBACK",
          `/internal/evaluation/profile-releases/transition-receipts/by-nonce/${await sha256Ascii(rawNonce)}`,
        );
      }
      if (path.includes("transition-receipts")) {
        const nonceSha256 = await sha256Ascii(rawNonce);
        expect(path).toBe(
          `/internal/evaluation/profile-releases/transition-receipts/by-nonce/${nonceSha256}`,
        );
        expect(path).not.toContain(rawNonce);
        return json({
          action: "ROLLBACK",
          binding_sha256: BINDING_SHA256,
          completion: "RELOOKUP_CONFIRMED",
          expected_current_sha256: TARGET_SHA256,
          nonce_sha256: nonceSha256,
          outcome: "COMMITTED",
          previous_release_sha256: TARGET_SHA256,
          receipt_sha256: CURRENT_LIFECYCLE_RECEIPT_SHA256,
          release_sha256: PREVIOUS_SHA256,
        } satisfies ProfileReleaseTransitionOutcome);
      }
      throw new Error(`unexpected request: ${path}`);
    });

    render(
      <ProfileReleaseConsole
        fetchImpl={fetchImpl as typeof fetch}
        release={mutation(PREVIOUS_SHA256, "APPROVED_INACTIVE")}
        role="activator"
      />,
    );
    expect(
      await screen.findByText("APPROVED_INACTIVE · 독립 승인됨, 아직 비활성"),
    ).toBeTruthy();
    fireEvent.change(screen.getByLabelText("기존 세션 reference"), {
      target: { value: oldSessionRef },
    });
    fireEvent.click(screen.getByRole("button", { name: "기존 세션 pin 확인" }));
    await screen.findByText(oldPin.pin_sha256);
    fireEvent.change(screen.getByLabelText("신규 세션 reference"), {
      target: { value: newSessionRef },
    });
    fireEvent.click(screen.getByRole("button", { name: "신규 세션 pin 확인" }));
    await screen.findByText(newPin.pin_sha256);
    fireEvent.change(screen.getByLabelText("전환할 full release SHA-256"), {
      target: { value: PREVIOUS_SHA256 },
    });
    fireEvent.change(screen.getByLabelText("Rollback 사유 (trimmed 1..300자)"), {
      target: { value: "  합성 호환 release 복구  " },
    });
    fireEvent.click(
      screen.getByLabelText("새 세션에만 적용되는 pointer 전환임을 확인했습니다"),
    );
    fireEvent.click(screen.getByRole("button", { name: "이전 active release로 되돌리기" }));
    fireEvent.click(
      screen.getByRole("button", { name: "호환 release로 rollback하기" }),
    );

    expect(await screen.findByText("ACTIVE · 현재 active release")).toBeTruthy();
    expect(screen.getByText(/ROLLBACK receipt, active pointer/)).toBeTruthy();
    expect(pinReads.get(oldSessionRef)).toBe(2);
    expect(pinReads.get(newSessionRef)).toBe(2);
    expect(rawNonce).toMatch(/^[0-9a-f]{64}$/);
    expect(document.documentElement.outerHTML).not.toContain(rawNonce);
    expect(requests.filter((path) => path.includes(rawNonce))).toEqual([]);
  });

  it("requires confirmation and preserves old and new session pins", async () => {
    const oldSessionRef = "synthetic-session-before-activation";
    const newSessionRef = "synthetic-session-after-activation";
    const pinnedAt = "2026-08-06T07:00:00Z";
    const oldPin = {
      pin_sha256: "1".repeat(64),
      pinned_at: pinnedAt,
      release_sha256: PREVIOUS_SHA256,
      session_ref: oldSessionRef,
    } satisfies ProfileReleasePinProjection;
    const newPin = {
      pin_sha256: "2".repeat(64),
      pinned_at: pinnedAt,
      release_sha256: TARGET_SHA256,
      session_ref: newSessionRef,
    } satisfies ProfileReleasePinProjection;
    let pointerReads = 0;
    let rollbackRequests = 0;
    let rawRollbackNonce = "";
    let rejectRollback: (response: Response) => void = () => {
      throw new Error("rollback rejection resolver was not initialized");
    };
    let resolveRollback: (response: Response) => void = () => {
      throw new Error("rollback success resolver was not initialized");
    };
    const rejectedRollbackResponse = new Promise<Response>((resolve) => {
      rejectRollback = resolve;
    });
    const successfulRollbackResponse = new Promise<Response>((resolve) => {
      resolveRollback = resolve;
    });
    const pinReads = new Map<string, number>();
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith("active-pointer")) {
        pointerReads += 1;
        return json(pointer(pointerReads === 1 ? TARGET_SHA256 : PREVIOUS_SHA256));
      }
      if (path.endsWith(`/${PREVIOUS_SHA256}/state`)) {
        return json(
          state(
            PREVIOUS_SHA256,
            pointerReads === 1 ? "APPROVED_INACTIVE" : "ACTIVE",
          ),
        );
      }
      if (path.endsWith(`/sessions/${oldSessionRef}/pin`)) {
        pinReads.set(oldSessionRef, (pinReads.get(oldSessionRef) ?? 0) + 1);
        return json(oldPin);
      }
      if (path.endsWith(`/sessions/${newSessionRef}/pin`)) {
        pinReads.set(newSessionRef, (pinReads.get(newSessionRef) ?? 0) + 1);
        return json(newPin);
      }
      if (path.endsWith("/rollback")) {
        rollbackRequests += 1;
        expect(init?.method).toBe("POST");
        rawRollbackNonce = (JSON.parse(String(init?.body)) as { nonce: string }).nonce;
        return await (rollbackRequests === 1
          ? rejectedRollbackResponse
          : successfulRollbackResponse);
      }
      if (path.includes("transition-receipts")) {
        const nonceSha256 = await sha256Ascii(rawRollbackNonce);
        expect(path).toContain(nonceSha256);
        return json({
          action: "ROLLBACK",
          binding_sha256: BINDING_SHA256,
          completion: "MUTATION_COMMITTED",
          expected_current_sha256: TARGET_SHA256,
          nonce_sha256: nonceSha256,
          outcome: "COMMITTED",
          previous_release_sha256: TARGET_SHA256,
          receipt_sha256: CURRENT_LIFECYCLE_RECEIPT_SHA256,
          release_sha256: PREVIOUS_SHA256,
        } satisfies ProfileReleaseTransitionOutcome);
      }
      throw new Error(`unexpected request: ${path}`);
    });

    render(
      <ProfileReleaseConsole
        fetchImpl={fetchImpl as typeof fetch}
        release={mutation(PREVIOUS_SHA256, "APPROVED_INACTIVE")}
        role="activator"
      />,
    );
    await screen.findByText("APPROVED_INACTIVE · 독립 승인됨, 아직 비활성");

    fireEvent.change(screen.getByLabelText("기존 세션 reference"), {
      target: { value: oldSessionRef },
    });
    fireEvent.click(screen.getByRole("button", { name: "기존 세션 pin 확인" }));
    await screen.findByText(oldPin.pin_sha256);
    fireEvent.change(screen.getByLabelText("신규 세션 reference"), {
      target: { value: newSessionRef },
    });
    fireEvent.click(screen.getByRole("button", { name: "신규 세션 pin 확인" }));
    await screen.findByText(newPin.pin_sha256);

    fireEvent.change(screen.getByLabelText("전환할 full release SHA-256"), {
      target: { value: PREVIOUS_SHA256 },
    });
    fireEvent.change(screen.getByLabelText("Rollback 사유 (trimmed 1..300자)"), {
      target: { value: "합성 호환 release 복구" },
    });
    fireEvent.click(
      screen.getByLabelText("새 세션에만 적용되는 pointer 전환임을 확인했습니다"),
    );
    const trigger = screen.getByRole("button", {
      name: "이전 active release로 되돌리기",
    });
    fireEvent.click(trigger);
    expect(rollbackRequests).toBe(0);
    const dialog = screen.getByRole("dialog", {
      name: "이 release로 rollback할까요?",
    });
    const safe = screen.getByRole("button", { name: "현재 release 유지하기" });
    expect(document.activeElement).toBe(safe);
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(trigger);

    fireEvent.click(trigger);
    fireEvent.click(
      screen.getByRole("button", { name: "호환 release로 rollback하기" }),
    );
    await waitFor(() => expect(rollbackRequests).toBe(1));
    const busyDialog = screen.getByRole("dialog", {
      name: "이 release로 rollback할까요?",
    });
    fireEvent.keyDown(busyDialog, { key: "Escape" });
    expect(screen.getByRole("dialog")).toBeTruthy();
    expect(
      screen.getByRole("button", { name: "현재 release 유지하기" }).hasAttribute("disabled"),
    ).toBe(true);

    rejectRollback(retryableAbort("ROLLBACK"));
    const rollbackError = await screen.findByRole("alert");
    expect(document.activeElement).toBe(rollbackError);
    fireEvent.keyDown(rollbackError, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(screen.queryByRole("alert")).toBeNull();
    expect(document.activeElement).toBe(trigger);

    fireEvent.click(trigger);
    fireEvent.click(
      screen.getByRole("button", { name: "호환 release로 rollback하기" }),
    );
    await waitFor(() => expect(rollbackRequests).toBe(2));
    resolveRollback(json(mutation(PREVIOUS_SHA256, "ACTIVE")));
    expect(await screen.findByText(/old\/new session pin을 모두 확인했습니다/)).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(pinReads.get(oldSessionRef)).toBe(2);
    expect(pinReads.get(newSessionRef)).toBe(2);
    expect(screen.getAllByText(oldPin.release_sha256).length).toBeGreaterThan(0);
    expect(screen.getAllByText(newPin.release_sha256).length).toBeGreaterThan(0);
    expect(document.activeElement).toBe(
      screen.getByRole("heading", { name: "서버가 생성한 release receipt" }),
    );
  });

  it("leaves a transition UNKNOWN when the same release was reactivated under another receipt", async () => {
    let pointerReads = 0;
    let stateReads = 0;
    const replacementReceipt = REPLACEMENT_TRANSITION_RECEIPT_SHA256;
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith("active-pointer")) {
        pointerReads += 1;
        return pointerReads === 1
          ? json(pointer(PREVIOUS_SHA256))
          : json({
              active_release_sha256: TARGET_SHA256,
              receipt_sha256: replacementReceipt,
              state: "ACTIVE",
            } satisfies ProfileReleaseActivePointerProjection);
      }
      if (path.endsWith(`/${TARGET_SHA256}/state`)) {
        stateReads += 1;
        return stateReads === 1
          ? json(state(TARGET_SHA256, "APPROVED_INACTIVE"))
          : json({
              ...state(TARGET_SHA256, "ACTIVE"),
              lifecycle_head_receipt_sha256: replacementReceipt,
              provenance_receipt_sha256: replacementReceipt,
            });
      }
      if (path.endsWith("/activate")) {
        return json(mutation(TARGET_SHA256, "ACTIVE"));
      }
      if (path.includes("transition-receipts")) {
        return json({
          action: "ACTIVATE",
          binding_sha256: BINDING_SHA256,
          completion: "MUTATION_COMMITTED",
          expected_current_sha256: PREVIOUS_SHA256,
          nonce_sha256: "5".repeat(64),
          outcome: "COMMITTED",
          previous_release_sha256: PREVIOUS_SHA256,
          receipt_sha256: CURRENT_LIFECYCLE_RECEIPT_SHA256,
          release_sha256: TARGET_SHA256,
        } satisfies ProfileReleaseTransitionOutcome);
      }
      throw new Error(`unexpected request: ${path}`);
    });

    render(
      <ProfileReleaseConsole
        fetchImpl={fetchImpl as typeof fetch}
        release={mutation(TARGET_SHA256, "APPROVED_INACTIVE")}
        role="activator"
      />,
    );
    await screen.findByText("APPROVED_INACTIVE · 독립 승인됨, 아직 비활성");
    fireEvent.change(screen.getByLabelText("전환할 full release SHA-256"), {
      target: { value: TARGET_SHA256 },
    });
    fireEvent.click(
      screen.getByLabelText("새 세션에만 적용되는 pointer 전환임을 확인했습니다"),
    );
    fireEvent.click(screen.getByRole("button", { name: "승인된 release 활성화하기" }));

    expect(await screen.findByText(/활성화 결과는 UNKNOWN/)).toBeTruthy();
    expect(screen.queryByText("ACTIVE · 현재 active release")).toBeNull();
    expect(
      screen.getByText("APPROVED_INACTIVE · 독립 승인됨, 아직 비활성"),
    ).toBeTruthy();
  });

  it("keeps builder, approver, and activator routes separate", async () => {
    const { appRoutes, sanitizeBuildDraft } = await import("../../app/routes");
    const paths = appRoutes.map((route) => route.path);
    expect(paths).toEqual(
      expect.arrayContaining([
        "/internal/profile-releases/builder",
        "/internal/profile-releases/approver",
        "/internal/profile-releases/activator",
      ]),
    );
    let protectedPostBody = "";
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith("/build-drafts")) {
        protectedPostBody = String(init?.body);
        const request = JSON.parse(protectedPostBody) as {
          draft_ref: string;
          reconciliation_nonce: string;
        };
        return json({
          ...buildDraft(),
          draft_ref: request.draft_ref,
          nonce_sha256: await sha256Ascii(request.reconciliation_nonce),
        });
      }
      if (path.endsWith("active-pointer")) return json(pointer(null));
      throw new Error(`unexpected request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchImpl);
    const router = createMemoryRouter(appRoutes, {
      initialEntries: ["/internal/profile-releases/builder"],
    });
    render(<RouterProvider router={router} />);
    expect(await screen.findByText("DEV profile release 후보 준비")).toBeTruthy();
    const candidateFile = new File(
      [JSON.stringify(buildInput())],
      "reviewed-release-candidate.json",
      { type: "application/json" },
    );
    fireEvent.change(screen.getByLabelText("검토된 release 후보 JSON"), {
      target: { files: [candidateFile] },
    });
    fireEvent.click(screen.getByRole("button", { name: "보호 draft 준비하기" }));
    expect(
      await screen.findByRole("button", { name: "불변 release 후보 만들기" }),
    ).toBeTruthy();
    expect(router.state.location.pathname).toBe("/internal/profile-releases/builder");
    expect(Object.keys(router.state.location.state as object)).toEqual(["buildDraft"]);
    expect(JSON.stringify(router.state.location.state)).not.toMatch(
      /cohort|place_ref|profile_sha256/,
    );
    expect(document.documentElement.outerHTML).not.toContain("synthetic-place-0");
    expect(protectedPostBody).toContain("synthetic-place-0");
    expect(JSON.parse(protectedPostBody)).toMatchObject({
      draft_ref: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
    });
    const expectedDraft = buildDraft();
    expect(
      sanitizeBuildDraft({
        ...expectedDraft,
        cohort: buildInput().cohort,
        capability: "must-not-survive",
      }),
    ).toEqual(expectedDraft);
    vi.unstubAllGlobals();
  });

  it("does not let a delayed non-abortable request from the previous role repopulate state", async () => {
    let resolveOldPointer: ((response: Response) => void) | undefined;
    const oldPointer = new Promise<Response>((resolve) => {
      resolveOldPointer = resolve;
    });
    let pointerCalls = 0;
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith("active-pointer")) {
        pointerCalls += 1;
        return pointerCalls === 1 ? oldPointer : json(pointer(null));
      }
      return json(state(TARGET_SHA256, "ACTIVE"));
    });
    const view = render(
      <ProfileReleaseConsole fetchImpl={fetchImpl as typeof fetch} role="builder" />,
    );
    await waitFor(() => expect(pointerCalls).toBe(1));
    view.rerender(
      <ProfileReleaseConsole fetchImpl={fetchImpl as typeof fetch} role="approver" />,
    );
    await waitFor(() => expect(pointerCalls).toBe(2));
    resolveOldPointer?.(json(pointer(TARGET_SHA256)));
    await waitFor(() =>
      expect(
        screen.getByText("서버 active pointer와 exact release 상태를 확인했습니다."),
      ).toBeTruthy(),
    );
    expect(screen.queryByText("ACTIVE · 현재 active release")).toBeNull();
    expect(screen.getByRole("button", { name: "정확한 release 승인하기" })).toBeTruthy();
  });

  it("keeps public journey storage while removing only internal evaluator keys", async () => {
    localStorage.setItem("itda.quiz.draft", "public-journey");
    localStorage.setItem("another-app", "unrelated");
    localStorage.setItem("profile-release-sensitive", "internal");
    sessionStorage.setItem("evaluation-route", "internal");
    const fetchImpl = vi.fn(async () => json(pointer(null)));
    render(<ProfileReleaseConsole fetchImpl={fetchImpl as typeof fetch} role="builder" />);
    await waitFor(() => expect(fetchImpl).toHaveBeenCalled());
    expect(localStorage.getItem("itda.quiz.draft")).toBe("public-journey");
    expect(localStorage.getItem("another-app")).toBe("unrelated");
    expect(localStorage.getItem("profile-release-sensitive")).toBeNull();
    expect(sessionStorage.getItem("evaluation-route")).toBeNull();
  });

  it("gives each rendered hash copy control a category-specific accessible name", async () => {
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) =>
      String(input).endsWith("active-pointer")
        ? json(pointer(TARGET_SHA256))
        : json(state(TARGET_SHA256, "ACTIVE")),
    );
    render(<ProfileReleaseConsole fetchImpl={fetchImpl as typeof fetch} role="activator" />);
    expect(
      await screen.findByRole("button", { name: "Exact release SHA-256 전체 hash 복사" }),
    ).toBeTruthy();
    expect(
      screen.getByRole("button", {
        name: "Current lifecycle receipt SHA-256 전체 hash 복사",
      }),
    ).toBeTruthy();
    expect(
      screen.getByRole("button", { name: "Expected current SHA-256 전체 hash 복사" }),
    ).toBeTruthy();
  });
});
