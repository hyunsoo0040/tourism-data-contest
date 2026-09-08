import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ComponentType, ReactNode } from "react";
import {
  createMemoryRouter,
  MemoryRouter,
  RouterProvider,
} from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

import {
  EvaluatorPrincipalChangedError,
  createEvidenceReviewClient,
  createEvaluatorClient,
  type EvidenceCandidate,
  type EvidenceReviewQueue,
  type EvaluatorSubmission,
  type ReviewedEvidenceManifest,
  type StoredLabelRevision,
} from "./api";
import {
  EvidenceReview,
  LaneReviewCard,
  ReviewedEvidencePreview,
} from "./EvidenceReview";
import {
  ConfirmationDialog,
  GateChecklist,
  SubmissionStatusList,
} from "./OperatorAdjudication";

type Fixture = {
  rubric: {
    ordered_attribute_ids: string[];
    subattributes: Array<{
      attribute_id: string;
      axis: string;
      label_ko: string;
      examples_ko: string[];
      counterexamples_ko: string[];
    }>;
  };
  evidence_items: Array<{
    evidence_id: string;
    source_id: string;
    lane: string;
    dedup_cluster_id: string;
    direct: boolean;
    concordance_key: string;
  }>;
  forbidden_canaries: string[];
};

type EvaluationModule = {
  EvaluatorWorkspace: ComponentType;
  InternalRoleShell: ComponentType<{
    actorLabel: string;
    accessState: "AUTHORIZED" | "FORBIDDEN";
    clearRoleState: () => void;
    children: ReactNode;
  }>;
  AttributeScoreField: ComponentType<{
    spec: Fixture["rubric"]["subattributes"][number];
    score: number | null;
    unknownSelected: boolean;
    onScoreChange: (value: number | null) => void;
    onUnknownChange: (selected: boolean) => void;
  }>;
  UnknownReasonFields: ComponentType<{
    reason: string | null;
    note: string;
    showErrors: boolean;
    onReasonChange: (value: string) => void;
    onNoteChange: (value: string) => void;
  }>;
  EvidencePicker: ComponentType<{
    items: Array<
      Fixture["evidence_items"][number] & {
        sentence_text_ko?: string;
      }
    >;
    selectedEvidenceIds: string[];
    requiredMode: "ZERO" | "SCORE_3" | "SCORE_4";
    onChange: (value: string[]) => void;
  }>;
  ImmutableRevisionBanner: ComponentType<{
    status: "DRAFT" | "SUBMITTED" | "CORRECTED";
    revisionRef: string;
    parentRef: string | null;
    submittedAt: string | null;
  }>;
};

type RoleApiModule = {
  createOperatorClient: (options?: {
    fetchImpl?: typeof fetch;
    onSecurityBoundary?: (reason: string) => void;
  }) => {
    getStatus: () => Promise<unknown>;
  };
  createAdjudicatorClient: (options?: {
    fetchImpl?: typeof fetch;
    onSecurityBoundary?: (reason: string) => void;
  }) => {
    getProjection: (assignmentId: string) => Promise<unknown>;
    selectAcceptedHead: (
      revisionSha256: string,
      input: { reason: string; expected_chain_sha256: string },
    ) => Promise<unknown>;
  };
};

const fixture = JSON.parse(
  readFileSync(resolve(process.cwd(), "../fixtures/synthetic/phase3/labeling.json"), "utf8"),
) as Fixture;
const phaseUiStyles = readFileSync(resolve(process.cwd(), "src/app/styles/internal.css"), "utf8");

async function loadEvaluationModule(): Promise<EvaluationModule> {
  try {
    const modulePath = "./EvaluatorWorkspace";
    return (await import(/* @vite-ignore */ modulePath)) as EvaluationModule;
  } catch {
    throw new Error("Expected the isolated Phase 3 evaluator components to be implemented");
  }
}

async function loadRoleApiModule(): Promise<RoleApiModule> {
  return (await import("./api")) as unknown as RoleApiModule;
}

const attributeIds = ["H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "R1", "R2", "R3", "R4"] as const;

function submission(submittedAt = "2026-08-04T00:00:00Z"): EvaluatorSubmission {
  return {
    assignment_id: "synthetic-runtime-assignment-alpha",
    judgments: attributeIds.map((attribute_id) => ({
      attribute_id,
      evidence: [],
      score: 2,
      unknown_note: null,
      unknown_reason: null,
    })) as unknown as EvaluatorSubmission["judgments"],
    primary_axis: null,
    rubric_version: "synthetic-rubric-v1",
    source_snapshot_version: "synthetic-runtime-source-v1",
    submitted_at: submittedAt,
  };
}

function storedReceipt(
  principal: string,
  digestCharacter: string,
  input = submission(),
): StoredLabelRevision {
  return {
    created_at: "2026-08-04T00:00:01Z",
    evaluator_principal: principal,
    receipt_sha256: digestCharacter.repeat(64),
    revision: {
      ...input,
      correction_reason: null,
      evaluator_pseudonym: principal,
      parent_revision_sha256: null,
    },
    revision_sha256: digestCharacter.repeat(64),
  };
}

const hash = (character: string) => character.repeat(64);

function evidenceCandidate(lane: "DESCRIPTION" | "ODII" = "DESCRIPTION"): EvidenceCandidate {
  return {
    attribute_scores: [],
    candidate_id: hash("1"),
    candidate_sha256: hash("2"),
    dedup_cluster_id: "synthetic-cluster-a",
    dedup_edges: [],
    end_byte: 42,
    end_char: 20,
    lane,
    original_order: 0,
    score: 0.75,
    slice_sha256: hash("3"),
    source_id: "synthetic-official-description",
    source_sha256: hash("4"),
    span_id: "synthetic-span-a",
    start_byte: 0,
    start_char: 0,
    text: "신라 시대의 석조 유산을 가까이에서 살펴볼 수 있습니다.",
  };
}

function evidenceQueue(): EvidenceReviewQueue {
  return {
    candidate_manifest_sha256: hash("5"),
    lanes: [
      { candidates: [evidenceCandidate()], lane: "DESCRIPTION", status: "AVAILABLE" },
      { candidates: [], lane: "ODII", status: "MISSING" },
    ],
    provenance: {
      accepted_revision_set_sha256: hash("6"),
      candidate_output_sha256: hash("7"),
      code_git_sha: "synthetic-git-sha",
      completed_at: "2026-08-04T00:01:00Z",
      config_sha256: hash("8"),
      data_lineage_sha256: hash("9"),
      data_version: "synthetic-data-v1",
      freeze_receipt_sha256: hash("a"),
      model_config_sha256: hash("b"),
      model_id: "synthetic-local-encoder",
      model_revision: "synthetic-revision",
      preprocessing_version: "synthetic-preprocess-v1",
      prompt_anchor_version: "synthetic-anchor-v1",
      scoring_version: "synthetic-score-v1",
      source_manifest_sha256: hash("c"),
      started_at: "2026-08-04T00:00:00Z",
      tokenizer_sha256: hash("d"),
      weight_sha256: hash("e"),
    },
  };
}

function reviewedEvidenceManifest(): ReviewedEvidenceManifest {
  const queue = evidenceQueue();
  return {
    accepted_review_set_sha256: hash("f"),
    candidate_manifest_sha256: queue.candidate_manifest_sha256,
    finalized_at: "2026-08-04T01:00:00Z",
    finalized_by: "synthetic-reviewer",
    lanes: [
      {
        evidence: [
          {
            accepted_head_sha256: hash("0"),
            accepted_review_sha256: hash("1"),
            candidate: evidenceCandidate(),
          },
        ],
        lane: "DESCRIPTION",
        missing_reason: null,
        status: "AVAILABLE",
      },
      {
        evidence: [],
        lane: "ODII",
        missing_reason: "UPSTREAM_CANDIDATE_LANE_MISSING",
        status: "MISSING",
      },
    ],
    manifest_sha256: hash("2"),
    provenance: queue.provenance,
    schema_version: "phase3-reviewed-evidence-manifest-v1",
  };
}

describe("evidence review capability and UI contracts", () => {
  it("mounts EvidenceReview only at the builder route", async () => {
    const queue = evidenceQueue();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (String(input).endsWith("/evidence-review/candidates")) {
          return new Response(JSON.stringify(queue), {
            headers: { "Content-Type": "application/json" },
          });
        }
        return new Response(null, { status: 404 });
      }),
    );
    const { appRoutes } = await import("../../app/routes");
    const builderRoute = appRoutes.find(
      (route) => route.path === "/internal/profile-releases/builder/evidence-review",
    );
    expect(builderRoute?.element).toBeDefined();
    if (builderRoute?.element === undefined) return;

    render(
      <MemoryRouter
        initialEntries={["/internal/profile-releases/builder/evidence-review"]}
      >
        {builderRoute.element}
      </MemoryRouter>,
    );

    const heading = await screen.findByRole("heading", {
      level: 1,
      name: "Description/Odii 근거 검수",
    });
    await waitFor(() => expect(document.activeElement).toBe(heading));
    expect(document.querySelector("[data-evaluation-role='evaluator']")).toBeNull();
    expect(document.querySelector("[data-evaluation-role='adjudicator']")).toBeNull();
    expect(document.querySelector("[data-traveler-shell]")).toBeNull();
    expect(window.localStorage.length + window.sessionStorage.length).toBe(0);
    vi.unstubAllGlobals();
  });

  it("evidence review uses a separate no-store adapter and rejects client authority fields", async () => {
    const requests: Array<[string, RequestInit | undefined]> = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      requests.push([String(input), init]);
      return new Response(JSON.stringify(evidenceQueue()), {
        headers: { "Content-Type": "application/json" },
      });
    });
    const client = createEvidenceReviewClient({ fetchImpl: fetchImpl as typeof fetch });

    expect(createEvaluatorClient()).not.toHaveProperty("getQueue");
    await client.getQueue();

    expect(requests[0]?.[0]).toBe("/internal/evaluation/evidence-review/candidates");
    expect(requests[0]?.[1]?.cache).toBe("no-store");
    expect(requests[0]?.[1]?.credentials).toBe("same-origin");
    expect(JSON.stringify(requests[0]?.[1] ?? {})).not.toMatch(
      /actor_id|role|evaluator|expert|blind|token/i,
    );
  });

  it("evidence review clears queue, DOM, and browser storage when capability is lost", async () => {
    const queue = evidenceQueue();
    let requestCount = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        requestCount += 1;
        if (requestCount === 1) {
          return new Response(JSON.stringify(queue), {
            headers: { "Content-Type": "application/json" },
          });
        }
        if (requestCount === 2) return new Response(null, { status: 404 });
        return new Response(null, { status: 403 });
      }),
    );
    window.localStorage.setItem("review-cache", "candidate-canary");
    window.sessionStorage.setItem("review-route", "candidate-canary");
    render(<EvidenceReview />);

    expect(await screen.findByText(queue.lanes[0].candidates[0]!.text)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "관련 근거로 승인" }));

    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "이 역할은 이 자료를 볼 수 없습니다." })).toBeTruthy(),
    );
    expect(screen.queryByText(queue.lanes[0].candidates[0]!.text)).toBeNull();
    expect(window.localStorage.length + window.sessionStorage.length).toBe(0);
    vi.unstubAllGlobals();
  });

  it("replaces protected history with the internal access entry when capability is lost", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(null, { status: 403 })),
    );
    const { appRoutes } = await import("../../app/routes");
    const router = createMemoryRouter(appRoutes, {
      initialEntries: ["/internal/profile-releases/builder/evidence-review"],
    });

    render(<RouterProvider router={router} />);

    expect(
      await screen.findByRole("heading", { name: "내부 작업 접근 확인" }),
    ).toBeTruthy();
    expect(router.state.location.pathname).toBe("/internal/access");
    expect(router.state.historyAction).toBe("REPLACE");
    vi.unstubAllGlobals();
  });

  it("focuses a load error summary so keyboard users hear the recovery copy", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(null, { status: 500 })),
    );

    render(<EvidenceReview />);

    const alert = await screen.findByRole("alert");
    await waitFor(() => expect(document.activeElement).toBe(alert));
    expect(alert.getAttribute("tabindex")).toBe("-1");
    vi.unstubAllGlobals();
  });

  it("evidence review renders source before relevance-only controls and keeps provenance immutable", () => {
    const candidate = evidenceCandidate();
    const { container } = render(
      <LaneReviewCard
        busy={false}
        candidate={candidate}
        draft={{
          correctionReason: "",
          decision: "ACCEPT",
          note: "",
          reasonCode: "DIRECT_CURRENT_SITE_EVIDENCE",
        }}
        onDraftChange={vi.fn()}
        onReview={vi.fn()}
        onSelectHead={vi.fn()}
      />,
    );

    const source = screen.getByRole("region", { name: "변경할 수 없는 후보 원문" });
    const controls = screen.getByRole("group", { name: "근거 관련성 판단" });
    expect(source.compareDocumentPosition(controls) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(within(controls).getAllByRole("radio")).toHaveLength(3);
    expect(screen.getByRole("button", { name: "관련 근거로 승인" })).toBeTruthy();
    expect(screen.getByText(candidate.candidate_sha256)).toBeTruthy();
    expect(container.querySelector(`input[value="${candidate.candidate_sha256}"]`)).toBeNull();
    expect(container.querySelector("input[name='actor_id'], input[name='role']")).toBeNull();
    expect(screen.getByText("Description")).toBeTruthy();
  });

  it("evidence review manifest preview exposes separate lane counts, MISSING, and full hashes only", () => {
    const manifest = reviewedEvidenceManifest();
    const { container } = render(<ReviewedEvidencePreview manifest={manifest} />);

    expect(
      screen.getByText((_, element) =>
        Boolean(element?.tagName === "LI" && element.textContent?.includes("승인 근거 1개")),
      ),
    ).toBeTruthy();
    expect(
      screen.getByText((_, element) =>
        Boolean(element?.tagName === "LI" && element.textContent?.includes("자료 없음 (MISSING)")),
      ),
    ).toBeTruthy();
    expect(screen.getByText(manifest.manifest_sha256!)).toBeTruthy();
    const rendered = container.textContent?.toLowerCase() ?? "";
    expect(rendered).not.toContain("attribute_scores");
    expect(rendered).not.toContain("expert");
    expect(rendered).not.toContain("blind");
    expect(rendered).not.toContain("token");
  });
});

describe("isolated evaluator API contracts", () => {
  it("uses only canonical evaluator paths and omits client actor or role authority", async () => {
    const input = submission();
    const fetchImpl = vi.fn(async () =>
      new Response(JSON.stringify(storedReceipt("synthetic-evaluator-a", "a", input)), {
        headers: { "Content-Type": "application/json" },
        status: 201,
      }),
    );
    const client = createEvaluatorClient({ fetchImpl: fetchImpl as typeof fetch });

    await client.submit(input);

    expect(fetchImpl).toHaveBeenCalledOnce();
    const [path, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(path).toBe("/internal/evaluation/revisions");
    expect(init.cache).toBe("no-store");
    expect(init.credentials).toBe("same-origin");
    const body = JSON.parse(String(init.body)) as Record<string, unknown>;
    expect(body).not.toHaveProperty("actor_id");
    expect(body).not.toHaveProperty("role");
    expect(body).not.toHaveProperty("evaluator_pseudonym");
    expect(body).not.toHaveProperty("parent_revision_sha256");
  });

  it.each([401, 403])(
    "cancels in-flight work and clears all browser state after %s",
    async (status) => {
      window.localStorage.setItem("evaluation-draft", "sensitive");
      window.sessionStorage.setItem("evaluation-route", "sensitive");
      const onSecurityBoundary = vi.fn();
      let requestCount = 0;
      const fetchImpl = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
        requestCount += 1;
        if (requestCount === 1) {
          return new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
          });
        }
        return Promise.resolve(new Response(null, { status }));
      });
      const client = createEvaluatorClient({
        fetchImpl: fetchImpl as typeof fetch,
        onSecurityBoundary,
      });
      const pending = client.getOwnChain();

      await expect(client.submit(submission())).rejects.toMatchObject({ status });
      await expect(pending).rejects.toMatchObject({ status: null });
      expect(onSecurityBoundary).toHaveBeenCalledWith("AUTHORIZATION_LOST");
      expect(window.localStorage.length + window.sessionStorage.length).toBe(0);
    },
  );

  it("rejects a changed principal only after clearing request, cache, and browser state", async () => {
    window.localStorage.setItem("evaluation-draft", "sensitive");
    const onSecurityBoundary = vi.fn();
    const responses = [
      storedReceipt("synthetic-evaluator-a", "a"),
      storedReceipt("synthetic-evaluator-b", "b", submission("2026-08-04T00:01:00Z")),
    ];
    const fetchImpl = vi.fn(async () =>
      new Response(JSON.stringify(responses.shift()), {
        headers: { "Content-Type": "application/json" },
        status: 200,
      }),
    );
    const client = createEvaluatorClient({
      fetchImpl: fetchImpl as typeof fetch,
      onSecurityBoundary,
    });

    await client.submit(submission());
    await expect(client.getReceipt("b".repeat(64))).rejects.toBeInstanceOf(
      EvaluatorPrincipalChangedError,
    );
    expect(onSecurityBoundary).toHaveBeenCalledWith("PRINCIPAL_CHANGED");
    expect(window.localStorage.length + window.sessionStorage.length).toBe(0);
  });
});

describe("operator and adjudicator role isolation", () => {
  it("generates closed status-only and model-free adjudicator schemas", () => {
    const openapi = JSON.parse(
      readFileSync(resolve(process.cwd(), "../contracts/openapi.json"), "utf8"),
    ) as {
      components: { schemas: Record<string, { properties?: Record<string, unknown> }> };
      paths: Record<string, unknown>;
    };
    const statusKeys = Object.keys(
      openapi.components.schemas.LabelSubmissionStatus?.properties ?? {},
    ).sort();
    expect(statusKeys).toEqual([
      "all_required_submissions_exist",
      "evaluator_pseudonym",
      "latest_server_event_at",
      "submission_status",
    ]);
    const forbiddenStatusFields = [
      "score",
      "evidence",
      "unknown_reason",
      "unknown_note",
      "model",
      "member",
    ];
    const statusContract = JSON.stringify(
      openapi.components.schemas.LabelSubmissionStatus,
    ).toLowerCase();
    for (const field of forbiddenStatusFields) {
      expect(statusContract).not.toContain(field);
    }

    expect(openapi.paths).toHaveProperty("/internal/evaluation/status");
    expect(openapi.paths).toHaveProperty(
      "/internal/evaluation/assignments/{assignment_id}/adjudication-projection",
    );
    expect(openapi.components.schemas.AdjudicationProjection).toBeTruthy();
    const projectionContract = JSON.stringify(
      openapi.components.schemas.AdjudicationProjection,
    ).toLowerCase();
    for (const canary of ["model_output", "traveler", "blind", "dsn", "source_path"]) {
      expect(projectionContract).not.toContain(canary);
    }
  });

  it("keeps operator status and adjudicator digest-bound mutation on separate adapters", async () => {
    const requests: Array<[string, RequestInit | undefined]> = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      requests.push([String(input), init]);
      if (String(input).endsWith("/status")) {
        return new Response(
          JSON.stringify([
            {
              all_required_submissions_exist: false,
              evaluator_pseudonym: "평가자 A",
              latest_server_event_at: "2026-08-04T00:00:00Z",
              submission_status: "SUBMITTED",
            },
          ]),
          { headers: { "Content-Type": "application/json" } },
        );
      }
      return new Response(
        JSON.stringify({ event_sha256: "e".repeat(64), revision_sha256: "b".repeat(64) }),
        { headers: { "Content-Type": "application/json" } },
      );
    });
    const { createAdjudicatorClient, createOperatorClient } = await loadRoleApiModule();
    const operator = createOperatorClient({ fetchImpl: fetchImpl as typeof fetch });
    const adjudicator = createAdjudicatorClient({ fetchImpl: fetchImpl as typeof fetch });

    expect(operator).not.toHaveProperty("getProjection");
    expect(operator).not.toHaveProperty("selectAcceptedHead");
    expect(adjudicator).not.toHaveProperty("getStatus");
    expect(adjudicator).not.toHaveProperty("freeze");
    expect(createEvaluatorClient()).not.toHaveProperty("selectAcceptedHead");

    await operator.getStatus();
    await adjudicator.selectAcceptedHead("b".repeat(64), {
      expected_chain_sha256: "c".repeat(64),
      reason: "현재 correction chain tip 선택",
    });

    expect(requests[0]?.[0]).toBe("/internal/evaluation/status");
    expect(requests[1]?.[0]).toBe(
      `/internal/evaluation/revisions/${"b".repeat(64)}/accepted-head`,
    );
    const body = JSON.parse(String(requests[1]?.[1]?.body)) as Record<string, unknown>;
    expect(body).toEqual({
      expected_chain_sha256: "c".repeat(64),
      reason: "현재 correction chain tip 선택",
    });
    expect(body).not.toHaveProperty("actor_id");
    expect(body).not.toHaveProperty("role");
  });

  it("clears storage and reports the role boundary before another role can render", async () => {
    window.localStorage.setItem("operator-cache", "status-canary");
    window.sessionStorage.setItem("adjudicator-route", "projection-canary");
    const onSecurityBoundary = vi.fn();
    const fetchImpl = vi.fn(async () => new Response(null, { status: 403 }));
    const { createOperatorClient } = await loadRoleApiModule();
    const operator = createOperatorClient({
      fetchImpl: fetchImpl as typeof fetch,
      onSecurityBoundary,
    });

    await expect(operator.getStatus()).rejects.toMatchObject({ status: 403 });
    expect(onSecurityBoundary).toHaveBeenCalledWith("AUTHORIZATION_LOST");
    expect(window.localStorage.length + window.sessionStorage.length).toBe(0);
    expect(document.body.textContent).not.toContain("projection-canary");
  });

  it("keeps evaluator, operator, and adjudicator SPA routes disjoint", async () => {
    const { appRoutes } = await import("../../app/routes");
    const paths = appRoutes.map((route) => route.path).filter(Boolean);
    expect(paths).toContain("/internal/evaluator/assignments/:assignmentId");
    expect(paths).toContain("/internal/operator/assignments/:assignmentId");
    expect(paths).toContain("/internal/adjudicator/assignments/:assignmentId");
    expect(new Set(paths).size).toBe(paths.length);
  });

  it("renders the closed server status and submission readiness as separate facts", () => {
    render(
      <SubmissionStatusList
        statuses={[
          {
            all_required_submissions_exist: true,
            evaluator_pseudonym: "synthetic-evaluator-a",
            latest_server_event_at: "2026-08-06T00:00:00Z",
            submission_status: "SUBMITTED",
          },
        ]}
      />,
    );

    expect(screen.getByText(/제출됨 \(SUBMITTED\)/)).toBeTruthy();
    expect(screen.getByText(/필수 제출 충족/)).toBeTruthy();
  });

  it("distinguishes passed, blocked, and external-evidence gate states", () => {
    const ContractGateChecklist = GateChecklist as ComponentType<{
      gates: Array<{
        label: string;
        state: "PASSED" | "BLOCKED" | "EXTERNAL_PENDING";
        reason: string;
        nextActor: string;
      }>;
    }>;
    render(
      <ContractGateChecklist
        gates={[
          {
            label: "권리 증거",
            nextActor: "권리 검수자",
            reason: "외부 증빙 도착 전 게시 불가",
            state: "EXTERNAL_PENDING",
          },
        ]}
      />,
    );

    expect(screen.getByText(/외부 증거 대기/)).toBeTruthy();
    expect(screen.getByText(/다음 담당: 권리 검수자/)).toBeTruthy();
  });

  it("contains focus while busy and focuses an in-dialog async error", () => {
    const view = render(
      <ConfirmationDialog
        busy={false}
        confirmLabel="정확한 상태 게시"
        error={null}
        onCancel={vi.fn()}
        onConfirm={vi.fn()}
        safeLabel="계속 확인"
        title="불변 상태를 게시할까요?"
      >
        <p>현재 원본은 그대로 보존되고 새 불변 상태만 추가됩니다.</p>
      </ConfirmationDialog>,
    );

    const dialog = screen.getByRole("dialog", { name: "불변 상태를 게시할까요?" });
    const descriptionId = dialog.getAttribute("aria-describedby");
    expect(descriptionId).not.toBeNull();
    expect(document.getElementById(descriptionId!)?.textContent).toContain(
      "현재 원본은 그대로 보존",
    );

    const confirm = screen.getByRole("button", { name: "정확한 상태 게시" });
    confirm.focus();
    view.rerender(
      <ConfirmationDialog
        busy
        confirmLabel="정확한 상태 게시"
        error={null}
        onCancel={vi.fn()}
        onConfirm={vi.fn()}
        safeLabel="계속 확인"
        title="불변 상태를 게시할까요?"
      >
        <p>현재 원본은 그대로 보존되고 새 불변 상태만 추가됩니다.</p>
      </ConfirmationDialog>,
    );
    expect(document.activeElement).toBe(dialog);
    fireEvent.keyDown(dialog, { key: "Tab" });
    expect(document.activeElement).toBe(dialog);
    fireEvent.keyDown(dialog, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(dialog);

    view.rerender(
      <ConfirmationDialog
        busy={false}
        confirmLabel="정확한 상태 게시"
        error="합성 비동기 오류"
        onCancel={vi.fn()}
        onConfirm={vi.fn()}
        safeLabel="계속 확인"
        title="불변 상태를 게시할까요?"
      >
        <p>현재 원본은 그대로 보존되고 새 불변 상태만 추가됩니다.</p>
      </ConfirmationDialog>,
    );
    const error = screen.getByRole("alert");
    expect(dialog.contains(error)).toBe(true);
    expect(document.activeElement).toBe(error);
    fireEvent.keyDown(error, { key: "Tab" });
    expect(document.activeElement).toBe(
      screen.getByRole("button", { name: "계속 확인" }),
    );
    error.focus();
    fireEvent.keyDown(error, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(confirm);
  });
});

describe("Phase 3 synthetic rubric fixture", () => {
  it("locks the exact twelve-item order with visible Korean examples and counterexamples", () => {
    expect(fixture.rubric.ordered_attribute_ids).toEqual([
      "H1",
      "H2",
      "H3",
      "H4",
      "I1",
      "I2",
      "I3",
      "I4",
      "R1",
      "R2",
      "R3",
      "R4",
    ]);
    expect(fixture.rubric.subattributes.map((item) => item.attribute_id)).toEqual(
      fixture.rubric.ordered_attribute_ids,
    );
    for (const item of fixture.rubric.subattributes) {
      expect(item.examples_ko.every((value) => value.trim().length > 0)).toBe(true);
      expect(item.counterexamples_ko.every((value) => value.trim().length > 0)).toBe(true);
    }
  });
});

describe("isolated evaluator component contracts", () => {
  it("clears role state and removes evaluator content on a forbidden transition", async () => {
    const { InternalRoleShell } = await loadEvaluationModule();
    const clearRoleState = vi.fn();
    const { rerender } = render(
      <InternalRoleShell
        actorLabel="합성 평가자 가"
        accessState="AUTHORIZED"
        clearRoleState={clearRoleState}
      >
        <p>합성 전용 평가 초안</p>
      </InternalRoleShell>,
    );
    expect(screen.getByText("합성 전용 평가 초안")).toBeTruthy();

    rerender(
      <InternalRoleShell
        actorLabel="합성 평가자 가"
        accessState="FORBIDDEN"
        clearRoleState={clearRoleState}
      >
        <p>합성 전용 평가 초안</p>
      </InternalRoleShell>,
    );
    expect(clearRoleState).toHaveBeenCalledOnce();
    expect(screen.queryByText("합성 전용 평가 초안")).toBeNull();
    expect(screen.getByText("이 역할은 이 자료를 볼 수 없습니다.")).toBeTruthy();
  });

  it("renders ordered fieldset semantics with no default score and visible anchors", async () => {
    const { AttributeScoreField } = await loadEvaluationModule();
    const spec = fixture.rubric.subattributes[0];
    render(
      <AttributeScoreField
        spec={spec}
        score={null}
        unknownSelected={false}
        onScoreChange={vi.fn()}
        onUnknownChange={vi.fn()}
      />,
    );

    const group = screen.getByRole("group", { name: spec.label_ko });
    expect(within(group).getAllByRole("radio")).toHaveLength(6);
    expect(within(group).getByText(spec.examples_ko[0])).toBeTruthy();
    expect(within(group).getByText(spec.counterexamples_ko[0])).toBeTruthy();
    expect(within(group).getAllByRole("radio").every((radio) => !radio.hasAttribute("checked"))).toBe(
      true,
    );
  });

  it("preserves an unknown reason and note until a numeric-score deletion is confirmed", async () => {
    const { EvaluatorWorkspace } = await loadEvaluationModule();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            synthetic_only: true,
            assignment: {
              assignment_id: "synthetic-runtime-assignment-alpha",
              rubric_version: "synthetic-rubric-v1",
              source_snapshot_version: "synthetic-source-v1",
            },
            sources: [
              {
                lane: "DESCRIPTION",
                source_id: "synthetic-description",
                text_ko: "신라 시대의 석조 유산을 천천히 살펴볼 수 있습니다.",
              },
              {
                lane: "ODII",
                source_id: "synthetic-odii",
                text_ko: "해설은 보존된 석조 유산의 역사적 맥락을 설명합니다.",
              },
            ],
          }),
          { headers: { "Content-Type": "application/json" } },
        ),
      ),
    );

    render(
      <MemoryRouter>
        <EvaluatorWorkspace />
      </MemoryRouter>,
    );
    const field = await screen.findByRole("group", { name: "역사 서사 밀도" });
    fireEvent.click(within(field).getByRole("radio", { name: "판단 불가" }));
    fireEvent.change(within(field).getByLabelText("판단 불가 사유"), {
      target: { value: "NO_EVIDENCE" },
    });
    fireEvent.change(within(field).getByLabelText("판단 불가 설명"), {
      target: { value: "공식 원문만으로 현재 경험을 단정하기 어렵습니다." },
    });

    const numericTrigger = within(field).getByRole("radio", { name: /^2,/ });
    numericTrigger.focus();
    fireEvent.click(numericTrigger);
    const dialog = screen.getByRole("alertdialog", {
      name: "판단 불가 내용을 지울까요?",
    });
    const safeAction = within(dialog).getByRole("button", {
      name: "판단 불가 유지하기",
    });
    const destructiveAction = within(dialog).getByRole("button", {
      name: "내용 지우고 2점 선택하기",
    });
    expect(document.activeElement).toBe(safeAction);
    fireEvent.keyDown(safeAction, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(destructiveAction);
    fireEvent.keyDown(destructiveAction, { key: "Tab" });
    expect(document.activeElement).toBe(safeAction);
    expect(
      (within(field).getByLabelText("판단 불가 설명") as HTMLTextAreaElement).value,
    ).toBe("공식 원문만으로 현재 경험을 단정하기 어렵습니다.");
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(document.activeElement).toBe(numericTrigger);
    expect(
      (within(field).getByRole("radio", { name: "판단 불가" }) as HTMLInputElement)
        .checked,
    ).toBe(true);

    numericTrigger.focus();
    fireEvent.click(numericTrigger);
    fireEvent.click(screen.getByRole("button", { name: "판단 불가 유지하기" }));
    expect(document.activeElement).toBe(numericTrigger);

    numericTrigger.focus();
    fireEvent.click(numericTrigger);
    fireEvent.click(
      screen.getByRole("button", { name: "내용 지우고 2점 선택하기" }),
    );
    expect(document.activeElement).toBe(numericTrigger);
    expect(
      (within(field).getByRole("radio", { name: /^2,/ }) as HTMLInputElement).checked,
    ).toBe(true);
    expect(within(field).queryByLabelText("판단 불가 설명")).toBeNull();
    vi.unstubAllGlobals();
  });

  it("labels evaluator evidence with its lane, source sentence, and audit id", async () => {
    const { EvidencePicker } = await loadEvaluationModule();
    const item = {
      ...fixture.evidence_items[0]!,
      sentence_text_ko: "신라 시대의 석조 유산을 가까이에서 살펴볼 수 있습니다.",
    };
    render(
      <EvidencePicker
        items={[item]}
        onChange={vi.fn()}
        requiredMode="SCORE_3"
        selectedEvidenceIds={[]}
      />,
    );

    expect(
      screen.getByRole("checkbox", {
        name: /공식 설명.*신라 시대의 석조 유산.*synthetic-desc-direct-a/,
      }),
    ).toBeTruthy();
  });

  it.each([
    ["가", false],
    ["가".repeat(300), false],
    ["", true],
    ["   ", true],
    ["가".repeat(301), true],
  ])("enforces trimmed unknown-note boundaries", async (note, shouldError) => {
    const { UnknownReasonFields } = await loadEvaluationModule();
    render(
      <UnknownReasonFields
        reason="NO_EVIDENCE"
        note={note}
        showErrors
        onReasonChange={vi.fn()}
        onNoteChange={vi.fn()}
      />,
    );
    expect(Boolean(screen.queryByRole("alert"))).toBe(shouldError);
  });

  it("rejects duplicate-cluster inflation while accepting both score-four support branches", async () => {
    const { EvidencePicker } = await loadEvaluationModule();
    const onChange = vi.fn();
    const { rerender } = render(
      <EvidencePicker
        items={fixture.evidence_items}
        selectedEvidenceIds={["synthetic-desc-direct-a", "synthetic-desc-direct-a-copy"]}
        requiredMode="SCORE_4"
        onChange={onChange}
      />,
    );
    expect(screen.getByRole("alert").textContent).toContain("서로 다른 직접 근거");

    rerender(
      <EvidencePicker
        items={fixture.evidence_items}
        selectedEvidenceIds={["synthetic-desc-direct-a", "synthetic-desc-direct-b"]}
        requiredMode="SCORE_4"
        onChange={onChange}
      />,
    );
    expect(screen.queryByRole("alert")).toBeNull();

    rerender(
      <EvidencePicker
        items={fixture.evidence_items}
        selectedEvidenceIds={["synthetic-desc-direct-a", "synthetic-odii-direct-a"]}
        requiredMode="SCORE_4"
        onChange={onChange}
      />,
    );
    expect(screen.queryByRole("alert")).toBeNull();

    rerender(
      <EvidencePicker
        items={fixture.evidence_items}
        selectedEvidenceIds={["synthetic-desc-direct-a", "synthetic-odii-discordant"]}
        requiredMode="SCORE_4"
        onChange={onChange}
      />,
    );
    expect(screen.getByRole("alert").textContent).toContain("일치 근거");
    fireEvent.click(screen.getAllByRole("checkbox")[0]);
    expect(onChange).toHaveBeenCalled();
  });

  it("shows immutable receipt identity only after submitted server state", async () => {
    const { ImmutableRevisionBanner } = await loadEvaluationModule();
    render(
      <ImmutableRevisionBanner
        status="SUBMITTED"
        revisionRef="synthetic-revision-receipt-alpha"
        parentRef={null}
        submittedAt="2026-08-03T00:00:00Z"
      />,
    );
    expect(screen.getByText("제출 완료")).toBeTruthy();
    expect(screen.getByText("synthetic-revision-receipt-alpha")).toBeTruthy();
    expect(screen.getByText(/수정하거나 삭제할 수 없습니다/)).toBeTruthy();
  });
});

describe("Phase 3 quiet-ledger CSS contract", () => {
  it("uses the exact type scale, mobile gutter, radii, and visible overflow proof", () => {
    const internalCss = phaseUiStyles.slice(phaseUiStyles.indexOf(".evaluator-shell"));
    expect(internalCss).not.toMatch(/font-size:\s*(?:18|24)px|font-size:\s*clamp\(/);
    expect(internalCss).not.toMatch(/border-radius:\s*(?:10|16)px/);
    expect(phaseUiStyles).not.toMatch(/overflow-x:\s*clip/);
    expect(internalCss).toMatch(
      /\.evaluator-shell\s*\{[^}]*100%\s*-\s*\(2\s*\*\s*var\(--space-md\)\)/s,
    );
  });

  it("switches evaluator source and controls to the required 7/5 desktop composition", () => {
    expect(phaseUiStyles).toMatch(
      /@media\s*\(min-width:\s*1024px\)[\s\S]*?\.evaluation-workspace\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*7fr\)\s*minmax\(0,\s*5fr\)/,
    );
  });
});
