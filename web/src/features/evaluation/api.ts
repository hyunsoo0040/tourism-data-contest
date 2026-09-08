import type { components, paths } from "../../contracts/generated/api";

type RawLabelRevision = components["schemas"]["RawLabelRevision"];

export type StoredLabelRevision = components["schemas"]["StoredLabelRevision"];
export type EvaluatorJudgment = components["schemas"]["RevisionJudgment"];
export type EvaluatorEvidence = components["schemas"]["EvidenceReference"];
export type EvaluatorPrimaryAxis = components["schemas"]["PrimaryAxis"];
export type EvaluatorUnknownReason = components["schemas"]["UnknownReason"];
export type OperatorStatus = components["schemas"]["LabelSubmissionStatus"];
export type AdjudicationProjection = components["schemas"]["AdjudicationProjection"];
export type AcceptedHeadInput = components["schemas"]["AcceptedHeadRequest"];
export type AcceptedHeadReceipt = components["schemas"]["AcceptedHeadReceipt"];
export type ReviewTrigger = components["schemas"]["ReviewTrigger"];
export type ReviewResolutionInput = components["schemas"]["ReviewResolutionRequest"];
export type ReviewTriggerResolution = components["schemas"]["ReviewTriggerResolution"];
export type AggregateInput = components["schemas"]["AggregateRequest"];
export type AdjudicatedLabelExport = components["schemas"]["AdjudicatedLabelExport"];
export type LabelFreezeInput = components["schemas"]["LabelFreezeRequest"];
export type LabelFreezeReceipt = components["schemas"]["LabelFreezeReceipt"];
export type EvidenceReviewQueue = components["schemas"]["EvidenceReviewQueue"];
export type EvidenceCandidate = components["schemas"]["EvidenceCandidate"];
export type EvidenceReviewInput = components["schemas"]["EvidenceReviewRequest"];
export type EvidenceReviewCorrectionInput =
  components["schemas"]["EvidenceReviewCorrectionRequest"];
export type EvidenceReviewRevision = components["schemas"]["EvidenceReviewRevision"];
export type EvidenceReviewReceipt = components["schemas"]["EvidenceReviewReceipt"];
export type EvidenceReviewChain = components["schemas"]["EvidenceReviewChain"];
export type EvidenceReviewHeadInput = components["schemas"]["EvidenceReviewHeadRequest"];
export type AcceptedEvidenceReviewHead =
  components["schemas"]["AcceptedEvidenceReviewHead"];
export type ReviewedEvidenceFinalizeInput =
  components["schemas"]["ReviewedEvidenceFinalizeRequest"];
export type ReviewedEvidenceManifest = components["schemas"]["ReviewedEvidenceManifest"];
export type EvidenceLane = components["schemas"]["EvidenceLane-Input"];
export type EvidenceDecision = components["schemas"]["EvidenceRelevanceDecision"];
export type ProfileReleaseBuildInput = Omit<
  components["schemas"]["ProfileReleaseBuildRequest"],
  "reconciliation_nonce"
>;
export type ProfileReleaseBuildRequest = components["schemas"]["ProfileReleaseBuildRequest"];
export type ProfileReleaseBuildDraftCreateRequest =
  components["schemas"]["ProfileReleaseBuildDraftCreateRequest"];
export type ProfileReleaseBuildDraftReference =
  components["schemas"]["ProfileReleaseBuildDraftReference"];
export type ProfileReleaseBuildDraftRequest =
  components["schemas"]["ProfileReleaseBuildDraftRequest"];
export type ProfileReleaseBuildOutcome = components["schemas"]["ProfileReleaseBuildOutcome"];
export type ProfileReleaseActivePointerProjection =
  components["schemas"]["ProfileReleaseActivePointerProjection"];
export type ProfileReleaseStateProjection =
  components["schemas"]["ProfileReleaseStateProjection"];
export type ProfileReleasePinProjection =
  components["schemas"]["ProfileReleaseSessionPinProjection"];
export type ProfileReleaseTransitionOutcome =
  components["schemas"]["ProfileReleaseTransitionOutcome"];
export type ProfileReleaseMutationResponse =
  components["schemas"]["ProfileReleaseMutationResponse"];
export type ProfileReleaseUnknownOutcomeResponse =
  components["schemas"]["ProfileReleaseUnknownOutcomeResponse"];
export type ProfileReleaseActivateInput =
  components["schemas"]["ProfileReleaseActivateRequest"];
export type ProfileReleaseRollbackInput =
  components["schemas"]["ProfileReleaseRollbackRequest"];

type ProfileReleaseBuildOutcomeOperation = NonNullable<
  paths["/internal/evaluation/profile-releases/build-receipts/by-nonce/{nonce_sha256}"]["get"]
>;
type ProfileReleaseActivePointerOperation = NonNullable<
  paths["/internal/evaluation/profile-releases/active-pointer"]["get"]
>;
type ProfileReleaseStateOperation = NonNullable<
  paths["/internal/evaluation/profile-releases/{release_sha256}/state"]["get"]
>;
type ProfileReleaseTransitionOutcomeOperation = NonNullable<
  paths["/internal/evaluation/profile-releases/transition-receipts/by-nonce/{nonce_sha256}"]["get"]
>;
type ProfileReleaseSessionPinOperation = NonNullable<
  paths["/internal/evaluation/profile-releases/sessions/{session_ref}/pin"]["get"]
>;

export type ProfileReleaseReadContractOperations = {
  buildOutcomeByNonce: ProfileReleaseBuildOutcomeOperation;
  activePointer: ProfileReleaseActivePointerOperation;
  state: ProfileReleaseStateOperation;
  transitionOutcomeByNonce: ProfileReleaseTransitionOutcomeOperation;
  sessionPin: ProfileReleaseSessionPinOperation;
};

export type EvaluatorSubmission = Omit<
  RawLabelRevision,
  "correction_reason" | "evaluator_pseudonym" | "parent_revision_sha256"
>;

export type EvaluatorCorrection = EvaluatorSubmission & {
  correction_reason: string;
};

type EvaluatorCreateOperation = NonNullable<
  paths["/internal/evaluation/revisions"]["post"]
>;
type EvaluatorCorrectionOperation = NonNullable<
  paths["/internal/evaluation/revisions/{parent_revision_sha256}/corrections"]["post"]
>;
type EvaluatorReceiptOperation = NonNullable<
  paths["/internal/evaluation/revisions/{revision_sha256}/receipt"]["get"]
>;

export type EvaluatorContractOperations = {
  create: EvaluatorCreateOperation;
  correct: EvaluatorCorrectionOperation;
  receipt: EvaluatorReceiptOperation;
};

type FetchLike = typeof fetch;
export type BoundaryReason = "AUTHORIZATION_LOST" | "PRINCIPAL_CHANGED" | "ROLE_CHANGED";

type EvaluatorClientOptions = {
  fetchImpl?: FetchLike;
  onSecurityBoundary?: (reason: BoundaryReason) => void;
};

type ProfileReleaseUnknownPolicy =
  | { operation: "DIRECT_BUILD"; action: "BUILD"; lookupPath: string }
  | { operation: "DRAFT_BUILD"; action: "BUILD"; lookupPath: string }
  | { operation: "APPROVE"; action: "APPROVE"; lookupPath: string }
  | { operation: "ACTIVATE"; action: "ACTIVATE"; lookupPath: string }
  | { operation: "ROLLBACK"; action: "ROLLBACK"; lookupPath: string };

export class EvaluatorApiError extends Error {
  constructor(
    message: string,
    readonly status: number | null,
  ) {
    super(message);
    this.name = "EvaluatorApiError";
  }
}

export class ProfileReleaseUnknownOutcomeError extends EvaluatorApiError {
  constructor(
    readonly action: "BUILD" | "APPROVE" | "ACTIVATE" | "ROLLBACK",
    readonly lookupPath: string,
  ) {
    super("서버 mutation 결과가 확정되지 않았습니다.", 503);
    this.name = "ProfileReleaseUnknownOutcomeError";
  }
}

export class ProfileReleaseRetryableAbortError extends EvaluatorApiError {
  constructor(readonly action: ProfileReleaseUnknownOutcomeError["action"]) {
    super("서버 mutation이 안전하게 중단되었습니다. 동일 입력으로 다시 시도할 수 있습니다.", 503);
    this.name = "ProfileReleaseRetryableAbortError";
  }
}

export class ProfileReleaseBuildUnavailableError extends EvaluatorApiError {
  constructor(
    readonly retryPath:
      | "/internal/evaluation/profile-releases/build"
      | "/internal/evaluation/profile-releases/build-drafts/build",
  ) {
    super("BUILD 시작 전 서버 상태를 읽지 못했습니다. 동일 입력으로 다시 시도할 수 있습니다.", 503);
    this.name = "ProfileReleaseBuildUnavailableError";
  }
}

export class ProfileReleaseDraftCleanupUnknownError extends EvaluatorApiError {
  readonly outcome = "DRAFT_CLEANUP_UNKNOWN" as const;

  constructor(
    readonly lookupPath: string,
    readonly retryPath: string,
    readonly provenBuild: ProfileReleaseBuildOutcome | null = null,
    readonly lookupCause: unknown = null,
  ) {
    super("BUILD는 확인되었지만 보호 draft 정리 결과를 확정하지 못했습니다.", 503);
    this.name = "ProfileReleaseDraftCleanupUnknownError";
  }
}

export class EvaluatorPrincipalChangedError extends EvaluatorApiError {
  constructor() {
    super("평가자 권한이 변경되어 이전 평가 내용을 모두 지웠어요.", 403);
    this.name = "EvaluatorPrincipalChangedError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return (
    actual.length === sortedExpected.length &&
    actual.every((key, index) => key === sortedExpected[index])
  );
}

function isSha256(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

export async function sha256Ascii(value: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

function isProfileReleaseUnknownOutcomeResponse(
  value: unknown,
): value is ProfileReleaseUnknownOutcomeResponse {
  if (!isRecord(value) || !hasExactKeys(value, ["detail"]) || !isRecord(value.detail)) {
    return false;
  }
  const detail = value.detail;
  return (
    hasExactKeys(detail, ["action", "lookup_path", "outcome"]) &&
    detail.outcome === "UNKNOWN" &&
    (detail.action === "BUILD" ||
      detail.action === "APPROVE" ||
      detail.action === "ACTIVATE" ||
      detail.action === "ROLLBACK") &&
    typeof detail.lookup_path === "string"
  );
}

function profileRelease503Detail(value: unknown): Record<string, unknown> | null {
  return isRecord(value) && hasExactKeys(value, ["detail"]) && isRecord(value.detail)
    ? value.detail
    : null;
}

function isStoredLabelRevision(value: unknown): value is StoredLabelRevision {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "created_at",
      "evaluator_principal",
      "receipt_sha256",
      "revision",
      "revision_sha256",
    ]) ||
    !isSha256(value.receipt_sha256) ||
    !isSha256(value.revision_sha256) ||
    typeof value.evaluator_principal !== "string" ||
    value.evaluator_principal.length === 0 ||
    typeof value.created_at !== "string" ||
    !isRecord(value.revision)
  ) {
    return false;
  }
  return hasExactKeys(value.revision, [
    "assignment_id",
    "correction_reason",
    "evaluator_pseudonym",
    "judgments",
    "parent_revision_sha256",
    "primary_axis",
    "rubric_version",
    "source_snapshot_version",
    "submitted_at",
  ]);
}

const INTERNAL_STORAGE_PREFIXES = [
  "adjudicator-",
  "evaluation-",
  "itda.internal.",
  "operator-",
  "profile-release-",
  "review-",
] as const;

function clearInternalStorage(storage: Storage): void {
  const keys = Array.from({ length: storage.length }, (_, index) => storage.key(index)).filter(
    (key): key is string => key !== null,
  );
  for (const key of keys) {
    if (INTERNAL_STORAGE_PREFIXES.some((prefix) => key.startsWith(prefix))) {
      storage.removeItem(key);
    }
  }
}

export function clearBrowserState(): void {
  if (typeof window === "undefined") return;
  clearInternalStorage(window.localStorage);
  clearInternalStorage(window.sessionStorage);
}

function sameInstant(left: string, right: string): boolean {
  const leftTime = Date.parse(left);
  const rightTime = Date.parse(right);
  return Number.isFinite(leftTime) && Number.isFinite(rightTime) && leftTime === rightTime;
}

function sameRevisionInput(
  stored: StoredLabelRevision,
  input: EvaluatorSubmission | EvaluatorCorrection,
  parentRevisionSha256: string | null,
): boolean {
  const revision = stored.revision;
  return (
    revision.assignment_id === input.assignment_id &&
    revision.rubric_version === input.rubric_version &&
    revision.source_snapshot_version === input.source_snapshot_version &&
    sameInstant(revision.submitted_at, input.submitted_at) &&
    revision.parent_revision_sha256 === parentRevisionSha256 &&
    revision.correction_reason === ("correction_reason" in input ? input.correction_reason : null)
  );
}

export class EvaluatorClient {
  private readonly fetchImpl: FetchLike;
  private readonly onSecurityBoundary?: (reason: BoundaryReason) => void;
  private readonly activeRequests = new Set<AbortController>();
  private readonly receiptMemory = new Map<string, StoredLabelRevision>();
  private principal: string | null = null;

  constructor(options: EvaluatorClientOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.onSecurityBoundary = options.onSecurityBoundary;
  }

  clear(reason?: BoundaryReason): void {
    for (const controller of this.activeRequests) controller.abort();
    this.activeRequests.clear();
    this.receiptMemory.clear();
    this.principal = null;
    clearBrowserState();
    if (reason) this.onSecurityBoundary?.(reason);
  }

  private adoptPrincipal(receipt: StoredLabelRevision): void {
    if (this.principal !== null && this.principal !== receipt.evaluator_principal) {
      this.clear("PRINCIPAL_CHANGED");
      throw new EvaluatorPrincipalChangedError();
    }
    this.principal = receipt.evaluator_principal;
  }

  private async request(path: string, init: RequestInit = {}): Promise<Response> {
    const controller = new AbortController();
    this.activeRequests.add(controller);
    try {
      const response = await this.fetchImpl(path, {
        ...init,
        cache: "no-store",
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          ...(init.body === undefined ? {} : { "Content-Type": "application/json" }),
          ...init.headers,
        },
        signal: controller.signal,
      });
      if (response.status === 401 || response.status === 403) {
        this.clear("AUTHORIZATION_LOST");
        throw new EvaluatorApiError(
          "평가자 권한을 확인할 수 없어 이전 평가 내용을 모두 지웠어요.",
          response.status,
        );
      }
      if (!response.ok) {
        throw new EvaluatorApiError("평가 요청을 완료하지 못했어요.", response.status);
      }
      return response;
    } catch (error) {
      if (error instanceof EvaluatorApiError) throw error;
      throw new EvaluatorApiError("평가 서버의 응답을 확인하지 못했어요.", null);
    } finally {
      this.activeRequests.delete(controller);
    }
  }

  private async readReceipt(response: Response): Promise<StoredLabelRevision> {
    let value: unknown;
    try {
      value = (await response.json()) as unknown;
    } catch {
      throw new EvaluatorApiError("평가 영수증 형식을 확인하지 못했어요.", response.status);
    }
    if (!isStoredLabelRevision(value)) {
      throw new EvaluatorApiError("평가 영수증 계약이 일치하지 않아요.", response.status);
    }
    this.adoptPrincipal(value);
    this.receiptMemory.set(value.revision_sha256, value);
    return value;
  }

  async submit(input: EvaluatorSubmission): Promise<StoredLabelRevision> {
    const response = await this.request("/internal/evaluation/revisions", {
      method: "POST",
      body: JSON.stringify(input),
    });
    return this.readReceipt(response);
  }

  async correct(
    parentRevisionSha256: string,
    input: EvaluatorCorrection,
  ): Promise<StoredLabelRevision> {
    const response = await this.request(
      `/internal/evaluation/revisions/${encodeURIComponent(parentRevisionSha256)}/corrections`,
      { method: "POST", body: JSON.stringify(input) },
    );
    return this.readReceipt(response);
  }

  async getReceipt(revisionSha256: string): Promise<StoredLabelRevision> {
    const cached = this.receiptMemory.get(revisionSha256);
    if (cached) return cached;
    const response = await this.request(
      `/internal/evaluation/revisions/${encodeURIComponent(revisionSha256)}/receipt`,
    );
    return this.readReceipt(response);
  }

  async getOwnChain(): Promise<StoredLabelRevision[]> {
    const response = await this.request("/internal/evaluation/revisions/own-chain");
    let value: unknown;
    try {
      value = (await response.json()) as unknown;
    } catch {
      throw new EvaluatorApiError("평가 이력 형식을 확인하지 못했어요.", response.status);
    }
    if (!Array.isArray(value) || !value.every(isStoredLabelRevision)) {
      throw new EvaluatorApiError("평가 이력 계약이 일치하지 않아요.", response.status);
    }
    for (const receipt of value) {
      this.adoptPrincipal(receipt);
    }
    return value;
  }

  async submitWithRecovery(input: EvaluatorSubmission): Promise<StoredLabelRevision> {
    try {
      return await this.submit(input);
    } catch (error) {
      if (!(error instanceof EvaluatorApiError) || error.status !== null) throw error;
      return this.recover(input, null, error);
    }
  }

  async correctWithRecovery(
    parentRevisionSha256: string,
    input: EvaluatorCorrection,
  ): Promise<StoredLabelRevision> {
    try {
      return await this.correct(parentRevisionSha256, input);
    } catch (error) {
      if (!(error instanceof EvaluatorApiError) || error.status !== null) throw error;
      return this.recover(input, parentRevisionSha256, error);
    }
  }

  private async recover(
    input: EvaluatorSubmission | EvaluatorCorrection,
    parentRevisionSha256: string | null,
    originalError: EvaluatorApiError,
  ): Promise<StoredLabelRevision> {
    try {
      const chain = await this.getOwnChain();
      const recovered = [...chain]
        .reverse()
        .find((receipt) => sameRevisionInput(receipt, input, parentRevisionSha256));
      if (!recovered) throw originalError;
      return this.getReceipt(recovered.revision_sha256);
    } catch (recoveryError) {
      if (recoveryError instanceof EvaluatorApiError && recoveryError.status !== null) {
        throw recoveryError;
      }
      throw originalError;
    }
  }
}

export function createEvaluatorClient(options: EvaluatorClientOptions = {}): EvaluatorClient {
  return new EvaluatorClient(options);
}

type RoleClientOptions = {
  fetchImpl?: FetchLike;
  onSecurityBoundary?: (reason: BoundaryReason) => void;
};

const STATUS_KEYS = [
  "all_required_submissions_exist",
  "evaluator_pseudonym",
  "latest_server_event_at",
  "submission_status",
] as const;

const PROJECTION_KEYS = [
  "accepted_revision_set_sha256",
  "assignment_id",
  "chains",
  "official_source_sha256",
  "official_sources",
  "projection_sha256",
  "release_blocked",
  "review_triggers",
  "rubric_version",
  "schema_version",
  "source_snapshot_version",
] as const;

const FORBIDDEN_PROJECTION_KEY_PARTS = [
  "capability",
  "dsn",
  "member",
  "model",
  "password",
  "principal",
  "source_path",
  "token",
  "traveler",
  "blind",
] as const;

function hasForbiddenProjectionKey(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(hasForbiddenProjectionKey);
  if (!isRecord(value)) return false;
  return Object.entries(value).some(
    ([key, child]) =>
      FORBIDDEN_PROJECTION_KEY_PARTS.some((part) => key.toLowerCase().includes(part)) ||
      hasForbiddenProjectionKey(child),
  );
}

function isOperatorStatus(value: unknown): value is OperatorStatus {
  return (
    isRecord(value) &&
    hasExactKeys(value, STATUS_KEYS) &&
    typeof value.evaluator_pseudonym === "string" &&
    value.evaluator_pseudonym.length > 0 &&
    value.submission_status === "SUBMITTED" &&
    typeof value.latest_server_event_at === "string" &&
    Number.isFinite(Date.parse(value.latest_server_event_at)) &&
    typeof value.all_required_submissions_exist === "boolean"
  );
}

function isAdjudicationProjection(value: unknown): value is AdjudicationProjection {
  return (
    isRecord(value) &&
    hasExactKeys(value, PROJECTION_KEYS) &&
    value.schema_version === "itda.phase3-adjudication-projection.v1" &&
    typeof value.assignment_id === "string" &&
    typeof value.rubric_version === "string" &&
    typeof value.source_snapshot_version === "string" &&
    isSha256(value.official_source_sha256) &&
    (value.accepted_revision_set_sha256 === null ||
      isSha256(value.accepted_revision_set_sha256)) &&
    isSha256(value.projection_sha256) &&
    typeof value.release_blocked === "boolean" &&
    Array.isArray(value.official_sources) &&
    value.official_sources.length > 0 &&
    Array.isArray(value.chains) &&
    value.chains.length > 0 &&
    Array.isArray(value.review_triggers) &&
    !hasForbiddenProjectionKey(value)
  );
}

function isAcceptedHeadReceipt(value: unknown): value is AcceptedHeadReceipt {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["event_sha256", "revision_sha256"]) &&
    isSha256(value.event_sha256) &&
    isSha256(value.revision_sha256)
  );
}

function isReviewTrigger(value: unknown): value is ReviewTrigger {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      "attribute_id",
      "kind",
      "observed_numeric_values",
      "review_trigger_sha256",
    ]) &&
    typeof value.kind === "string" &&
    Array.isArray(value.observed_numeric_values) &&
    isSha256(value.review_trigger_sha256)
  );
}

function isReviewTriggerResolution(value: unknown): value is ReviewTriggerResolution {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      "adjudicator_pseudonym",
      "reason",
      "resolution_sha256",
      "resolved_at",
      "review_trigger_sha256",
    ]) &&
    isSha256(value.review_trigger_sha256) &&
    isSha256(value.resolution_sha256)
  );
}

function isAdjudicatedLabelExport(value: unknown): value is AdjudicatedLabelExport {
  return (
    isRecord(value) &&
    value.schema_version === "itda.phase3-adjudicated-label-export.v1" &&
    isSha256(value.accepted_revision_set_sha256) &&
    isSha256(value.export_sha256) &&
    Array.isArray(value.aggregates) &&
    value.aggregates.length === 12
  );
}

function isLabelFreezeReceipt(value: unknown): value is LabelFreezeReceipt {
  return (
    isRecord(value) &&
    value.schema_version === "phase3-label-freeze-receipt-v1" &&
    value.status === "APPROVED_FROZEN" &&
    isSha256(value.receipt_sha256) &&
    Array.isArray(value.authority_grants) &&
    value.authority_grants.length === 0
  );
}

class RoleScopedClient {
  private readonly fetchImpl: FetchLike;
  private readonly onSecurityBoundary?: (reason: BoundaryReason) => void;
  private readonly activeRequests = new Set<AbortController>();
  private readonly responseMemory = new Map<string, unknown>();
  private epoch = 0;

  constructor(options: RoleClientOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.onSecurityBoundary = options.onSecurityBoundary;
  }

  clear(reason?: BoundaryReason): void {
    this.epoch += 1;
    for (const controller of this.activeRequests) controller.abort();
    this.activeRequests.clear();
    this.responseMemory.clear();
    clearBrowserState();
    if (reason) this.onSecurityBoundary?.(reason);
  }

  async request<T>(
    path: string,
    init: RequestInit,
    validator: (value: unknown) => value is T,
    conflictMessage = "현재 revision chain이 변경되었습니다. 최신 projection을 다시 확인하세요.",
    unknownPolicy?: ProfileReleaseUnknownPolicy,
  ): Promise<T> {
    const requestEpoch = this.epoch;
    const controller = new AbortController();
    this.activeRequests.add(controller);
    try {
      const response = await this.fetchImpl(path, {
        ...init,
        cache: "no-store",
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          ...(init.body === undefined ? {} : { "Content-Type": "application/json" }),
          ...init.headers,
        },
        signal: controller.signal,
      });
      if (requestEpoch !== this.epoch) {
        throw new EvaluatorApiError("역할이 바뀌어 이전 요청을 폐기했습니다.", null);
      }
      if (response.status === 401 || response.status === 403) {
        this.clear("AUTHORIZATION_LOST");
        throw new EvaluatorApiError("이 역할은 이 자료를 볼 수 없습니다.", response.status);
      }
      if (response.status === 409) {
        this.responseMemory.clear();
        throw new EvaluatorApiError(conflictMessage, 409);
      }
      if (response.status === 503 && unknownPolicy !== undefined) {
        let value: unknown;
        try {
          value = (await response.json()) as unknown;
        } catch {
          throw new EvaluatorApiError("서버 응답 계약을 확인하지 못했습니다.", 503);
        }
        const detail = profileRelease503Detail(value);
        if (
          detail !== null &&
          hasExactKeys(detail, ["action", "outcome"]) &&
          detail.outcome === "RETRYABLE_ABORT" &&
          detail.action === unknownPolicy.action
        ) {
          throw new ProfileReleaseRetryableAbortError(unknownPolicy.action);
        }
        const buildUnavailableRetryPath =
          unknownPolicy.operation === "DIRECT_BUILD"
            ? "/internal/evaluation/profile-releases/build"
            : unknownPolicy.operation === "DRAFT_BUILD"
              ? "/internal/evaluation/profile-releases/build-drafts/build"
              : null;
        if (
          detail !== null &&
          hasExactKeys(detail, ["action", "outcome", "retry_path"]) &&
          detail.action === "BUILD" &&
          detail.outcome === "BUILD_UNAVAILABLE" &&
          buildUnavailableRetryPath !== null &&
          typeof detail.retry_path === "string" &&
          detail.retry_path === buildUnavailableRetryPath
        ) {
          throw new ProfileReleaseBuildUnavailableError(detail.retry_path);
        }
        if (
          detail !== null &&
          hasExactKeys(detail, ["action", "lookup_path", "outcome", "retry_path"]) &&
          detail.action === "BUILD" &&
          detail.outcome === "DRAFT_CLEANUP_UNKNOWN" &&
          unknownPolicy.operation === "DRAFT_BUILD" &&
          detail.lookup_path === unknownPolicy.lookupPath &&
          detail.retry_path ===
            "/internal/evaluation/profile-releases/build-drafts/build"
        ) {
          throw new ProfileReleaseDraftCleanupUnknownError(
            detail.lookup_path,
            detail.retry_path,
          );
        }
        if (!isProfileReleaseUnknownOutcomeResponse(value)) {
          throw new EvaluatorApiError("서버 응답 계약이 일치하지 않습니다.", 503);
        }
        if (
          value.detail.action !== unknownPolicy.action ||
          value.detail.lookup_path !== unknownPolicy.lookupPath
        ) {
          throw new EvaluatorApiError("서버 조정 경로가 요청과 일치하지 않습니다.", 503);
        }
        this.responseMemory.clear();
        throw new ProfileReleaseUnknownOutcomeError(
          value.detail.action,
          value.detail.lookup_path,
        );
      }
      if (!response.ok) {
        throw new EvaluatorApiError(
          "현재 상태를 확인하지 못했습니다. 입력은 변경되지 않았습니다.",
          response.status,
        );
      }
      let value: unknown;
      try {
        value = (await response.json()) as unknown;
      } catch {
        throw new EvaluatorApiError("서버 응답 계약을 확인하지 못했습니다.", response.status);
      }
      if (!validator(value)) {
        throw new EvaluatorApiError("서버 응답 계약이 일치하지 않습니다.", response.status);
      }
      this.responseMemory.set(path, value);
      return value;
    } catch (error) {
      if (
        error instanceof EvaluatorApiError &&
        (error.status === 401 || error.status === 403)
      ) {
        throw error;
      }
      if (requestEpoch !== this.epoch) {
        throw new EvaluatorApiError("역할이 바뀌어 이전 요청을 폐기했습니다.", null);
      }
      if (error instanceof EvaluatorApiError) throw error;
      throw new EvaluatorApiError("서버 응답을 확인하지 못했습니다.", null);
    } finally {
      this.activeRequests.delete(controller);
    }
  }
}

export class OperatorClient {
  private readonly scoped: RoleScopedClient;

  constructor(options: RoleClientOptions = {}) {
    this.scoped = new RoleScopedClient(options);
  }

  clear(reason?: BoundaryReason): void {
    this.scoped.clear(reason);
  }

  getStatus(): Promise<OperatorStatus[]> {
    return this.scoped.request(
      "/internal/evaluation/status",
      {},
      (value): value is OperatorStatus[] => Array.isArray(value) && value.every(isOperatorStatus),
    );
  }

  freeze(input: LabelFreezeInput): Promise<LabelFreezeReceipt> {
    return this.scoped.request(
      "/internal/evaluation/freeze",
      { method: "POST", body: JSON.stringify(input) },
      isLabelFreezeReceipt,
      "라벨 동결 gate가 완전하지 않거나 입력 hash가 최신 상태와 일치하지 않습니다.",
    );
  }
}

export class AdjudicatorClient {
  private readonly scoped: RoleScopedClient;

  constructor(options: RoleClientOptions = {}) {
    this.scoped = new RoleScopedClient(options);
  }

  clear(reason?: BoundaryReason): void {
    this.scoped.clear(reason);
  }

  getProjection(assignmentId: string): Promise<AdjudicationProjection> {
    return this.scoped.request(
      `/internal/evaluation/assignments/${encodeURIComponent(assignmentId)}/adjudication-projection`,
      {},
      isAdjudicationProjection,
    );
  }

  selectAcceptedHead(
    revisionSha256: string,
    input: AcceptedHeadInput,
  ): Promise<AcceptedHeadReceipt> {
    return this.scoped.request(
      `/internal/evaluation/revisions/${encodeURIComponent(revisionSha256)}/accepted-head`,
      { method: "POST", body: JSON.stringify(input) },
      isAcceptedHeadReceipt,
    );
  }

  deriveReviewTriggers(assignmentId: string): Promise<ReviewTrigger[]> {
    return this.scoped.request(
      `/internal/evaluation/assignments/${encodeURIComponent(assignmentId)}/review-triggers`,
      { method: "POST" },
      (value): value is ReviewTrigger[] => Array.isArray(value) && value.every(isReviewTrigger),
    );
  }

  resolveReviewTrigger(
    assignmentId: string,
    input: ReviewResolutionInput,
  ): Promise<ReviewTriggerResolution> {
    return this.scoped.request(
      `/internal/evaluation/assignments/${encodeURIComponent(assignmentId)}/review-trigger-resolution`,
      { method: "POST", body: JSON.stringify(input) },
      isReviewTriggerResolution,
    );
  }

  aggregate(
    assignmentId: string,
    input: AggregateInput,
  ): Promise<AdjudicatedLabelExport> {
    return this.scoped.request(
      `/internal/evaluation/assignments/${encodeURIComponent(assignmentId)}/aggregate`,
      { method: "POST", body: JSON.stringify(input) },
      isAdjudicatedLabelExport,
      "모든 재검토 사유와 반 단계 median 조정을 해결한 뒤 다시 게시하세요.",
    );
  }
}

export function createOperatorClient(options: RoleClientOptions = {}): OperatorClient {
  return new OperatorClient(options);
}

export function createAdjudicatorClient(options: RoleClientOptions = {}): AdjudicatorClient {
  return new AdjudicatorClient(options);
}

const PROVENANCE_KEYS = [
  "accepted_revision_set_sha256",
  "candidate_output_sha256",
  "code_git_sha",
  "completed_at",
  "config_sha256",
  "data_lineage_sha256",
  "data_version",
  "freeze_receipt_sha256",
  "model_config_sha256",
  "model_id",
  "model_revision",
  "preprocessing_version",
  "prompt_anchor_version",
  "scoring_version",
  "source_manifest_sha256",
  "started_at",
  "tokenizer_sha256",
  "weight_sha256",
] as const;

const CANDIDATE_KEYS = [
  "attribute_scores",
  "candidate_id",
  "candidate_sha256",
  "dedup_cluster_id",
  "dedup_edges",
  "end_byte",
  "end_char",
  "lane",
  "original_order",
  "score",
  "slice_sha256",
  "source_id",
  "source_sha256",
  "span_id",
  "start_byte",
  "start_char",
  "text",
] as const;

const REVIEW_REVISION_KEYS = [
  "candidate_id",
  "candidate_manifest_sha256",
  "candidate_sha256",
  "correction_reason",
  "decision",
  "lane",
  "parent_review_sha256",
  "provenance",
  "reason",
  "review_sha256",
  "reviewed_at",
  "reviewer_pseudonym",
  "schema_version",
] as const;

const EVIDENCE_FORBIDDEN_KEY_PARTS = [
  "adjudicat",
  "blind",
  "capability",
  "dsn",
  "evaluator",
  "expert",
  "member",
  "password",
  "peer",
  "traveler",
] as const;

const EVIDENCE_FORBIDDEN_EXACT_KEYS = new Set([
  "access_token",
  "authority_token",
  "refresh_token",
  "token",
]);

function hasForbiddenEvidenceKey(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(hasForbiddenEvidenceKey);
  if (!isRecord(value)) return false;
  return Object.entries(value).some(
    ([key, child]) =>
      EVIDENCE_FORBIDDEN_EXACT_KEYS.has(key.toLowerCase()) ||
      EVIDENCE_FORBIDDEN_KEY_PARTS.some((part) => key.toLowerCase().includes(part)) ||
      hasForbiddenEvidenceKey(child),
  );
}

function isEvidenceLane(value: unknown): value is EvidenceLane {
  return value === "DESCRIPTION" || value === "ODII";
}

function isEvidenceDecision(value: unknown): value is EvidenceDecision {
  return value === "ACCEPT" || value === "REJECT" || value === "NOT_CURRENT_SITE";
}

function isEvidenceProvenance(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, PROVENANCE_KEYS) &&
    isSha256(value.accepted_revision_set_sha256) &&
    isSha256(value.candidate_output_sha256) &&
    isSha256(value.config_sha256) &&
    isSha256(value.data_lineage_sha256) &&
    isSha256(value.freeze_receipt_sha256) &&
    isSha256(value.model_config_sha256) &&
    isSha256(value.source_manifest_sha256) &&
    isSha256(value.tokenizer_sha256) &&
    isSha256(value.weight_sha256) &&
    typeof value.code_git_sha === "string" &&
    typeof value.data_version === "string" &&
    typeof value.model_id === "string" &&
    typeof value.model_revision === "string" &&
    typeof value.preprocessing_version === "string" &&
    typeof value.prompt_anchor_version === "string" &&
    typeof value.scoring_version === "string" &&
    typeof value.started_at === "string" &&
    typeof value.completed_at === "string"
  );
}

function isEvidenceCandidate(value: unknown): value is EvidenceCandidate {
  return (
    isRecord(value) &&
    hasExactKeys(value, CANDIDATE_KEYS) &&
    isSha256(value.candidate_id) &&
    isSha256(value.candidate_sha256) &&
    isSha256(value.slice_sha256) &&
    isSha256(value.source_sha256) &&
    isEvidenceLane(value.lane) &&
    typeof value.text === "string" &&
    typeof value.source_id === "string" &&
    typeof value.span_id === "string" &&
    typeof value.dedup_cluster_id === "string" &&
    Array.isArray(value.dedup_edges) &&
    value.dedup_edges.every((edge) => typeof edge === "string") &&
    Array.isArray(value.attribute_scores) &&
    Number.isFinite(value.score) &&
    Number.isInteger(value.original_order) &&
    Number.isInteger(value.start_byte) &&
    Number.isInteger(value.end_byte) &&
    Number.isInteger(value.start_char) &&
    Number.isInteger(value.end_char)
  );
}

function isEvidenceReviewRevision(value: unknown): value is EvidenceReviewRevision {
  return (
    isRecord(value) &&
    hasExactKeys(value, REVIEW_REVISION_KEYS) &&
    value.schema_version === "phase3-evidence-review-v1" &&
    isSha256(value.candidate_id) &&
    isSha256(value.candidate_manifest_sha256) &&
    isSha256(value.candidate_sha256) &&
    isSha256(value.review_sha256) &&
    (value.parent_review_sha256 === null || isSha256(value.parent_review_sha256)) &&
    isEvidenceLane(value.lane) &&
    isEvidenceDecision(value.decision) &&
    typeof value.reason === "string" &&
    typeof value.reviewer_pseudonym === "string" &&
    typeof value.reviewed_at === "string" &&
    isEvidenceProvenance(value.provenance)
  );
}

function isEvidenceReviewReceipt(value: unknown): value is EvidenceReviewReceipt {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["created_at", "receipt_sha256", "revision"]) &&
    typeof value.created_at === "string" &&
    isSha256(value.receipt_sha256) &&
    isEvidenceReviewRevision(value.revision) &&
    !hasForbiddenEvidenceKey(value)
  );
}

function isAcceptedEvidenceReviewHead(value: unknown): value is AcceptedEvidenceReviewHead {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      "accepted_review_sha256",
      "candidate_id",
      "candidate_manifest_sha256",
      "candidate_sha256",
      "event_sha256",
      "expected_chain_sha256",
      "lane",
      "provenance",
      "schema_version",
      "selected_at",
      "selected_by",
      "selection_reason",
    ]) &&
    value.schema_version === "phase3-evidence-review-head-v1" &&
    isSha256(value.accepted_review_sha256) &&
    isSha256(value.candidate_id) &&
    isSha256(value.candidate_manifest_sha256) &&
    isSha256(value.candidate_sha256) &&
    isSha256(value.event_sha256) &&
    isSha256(value.expected_chain_sha256) &&
    isEvidenceLane(value.lane) &&
    isEvidenceProvenance(value.provenance) &&
    typeof value.selected_at === "string" &&
    typeof value.selected_by === "string" &&
    typeof value.selection_reason === "string"
  );
}

function isEvidenceReviewChain(value: unknown): value is EvidenceReviewChain {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      "accepted_head",
      "candidate_id",
      "candidate_manifest_sha256",
      "candidate_sha256",
      "chain_sha256",
      "lane",
      "revisions",
      "tip_review_sha256",
    ]) &&
    isSha256(value.candidate_id) &&
    isSha256(value.candidate_manifest_sha256) &&
    isSha256(value.candidate_sha256) &&
    isSha256(value.chain_sha256) &&
    isSha256(value.tip_review_sha256) &&
    isEvidenceLane(value.lane) &&
    Array.isArray(value.revisions) &&
    value.revisions.length > 0 &&
    value.revisions.every(isEvidenceReviewRevision) &&
    (value.accepted_head === null || isAcceptedEvidenceReviewHead(value.accepted_head)) &&
    !hasForbiddenEvidenceKey(value)
  );
}

function isEvidenceReviewQueue(value: unknown): value is EvidenceReviewQueue {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["candidate_manifest_sha256", "lanes", "provenance"]) ||
    !isSha256(value.candidate_manifest_sha256) ||
    !isEvidenceProvenance(value.provenance) ||
    !Array.isArray(value.lanes) ||
    value.lanes.length !== 2 ||
    hasForbiddenEvidenceKey(value)
  ) {
    return false;
  }
  const lanes = value.lanes;
  return (
    lanes.map((lane) => (isRecord(lane) ? lane.lane : null)).join(",") ===
      "DESCRIPTION,ODII" &&
    lanes.every(
      (lane) =>
        isRecord(lane) &&
        hasExactKeys(lane, ["candidates", "lane", "status"]) &&
        isEvidenceLane(lane.lane) &&
        (lane.status === "AVAILABLE" || lane.status === "MISSING") &&
        Array.isArray(lane.candidates) &&
        lane.candidates.every(
          (candidate) => isEvidenceCandidate(candidate) && candidate.lane === lane.lane,
        ) &&
        (lane.status === "AVAILABLE" || lane.candidates.length === 0),
    )
  );
}

function isReviewedEvidenceManifest(value: unknown): value is ReviewedEvidenceManifest {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      "accepted_review_set_sha256",
      "candidate_manifest_sha256",
      "finalized_at",
      "finalized_by",
      "lanes",
      "manifest_sha256",
      "provenance",
      "schema_version",
    ]) &&
    value.schema_version === "phase3-reviewed-evidence-manifest-v1" &&
    isSha256(value.accepted_review_set_sha256) &&
    isSha256(value.candidate_manifest_sha256) &&
    isSha256(value.manifest_sha256) &&
    typeof value.finalized_at === "string" &&
    typeof value.finalized_by === "string" &&
    isEvidenceProvenance(value.provenance) &&
    Array.isArray(value.lanes) &&
    value.lanes.length === 2 &&
    value.lanes.every(
      (lane) =>
        isRecord(lane) &&
        hasExactKeys(lane, ["evidence", "lane", "missing_reason", "status"]) &&
        isEvidenceLane(lane.lane) &&
        (lane.status === "AVAILABLE" || lane.status === "MISSING") &&
        Array.isArray(lane.evidence) &&
        lane.evidence.length <= 3 &&
        (lane.status === "AVAILABLE"
          ? lane.evidence.every(
              (item) =>
                isRecord(item) &&
                hasExactKeys(item, [
                  "accepted_head_sha256",
                  "accepted_review_sha256",
                  "candidate",
                ]) &&
                isSha256(item.accepted_head_sha256) &&
                isSha256(item.accepted_review_sha256) &&
                isEvidenceCandidate(item.candidate) &&
                item.candidate.lane === lane.lane,
            )
          : lane.evidence.length === 0 &&
            lane.missing_reason === "UPSTREAM_CANDIDATE_LANE_MISSING"),
    ) &&
    !hasForbiddenEvidenceKey(value)
  );
}

function matchesReviewInput(
  revision: EvidenceReviewRevision,
  input: EvidenceReviewInput | EvidenceReviewCorrectionInput,
  parentReviewSha256: string | null,
): boolean {
  return (
    revision.candidate_manifest_sha256 === input.candidate_manifest_sha256 &&
    revision.candidate_sha256 === input.candidate_sha256 &&
    revision.lane === input.lane &&
    revision.decision === input.decision &&
    revision.reason === input.reason &&
    revision.parent_review_sha256 === parentReviewSha256 &&
    revision.correction_reason ===
      ("correction_reason" in input ? input.correction_reason : null)
  );
}

export class EvidenceReviewClient {
  private readonly scoped: RoleScopedClient;

  constructor(options: RoleClientOptions = {}) {
    this.scoped = new RoleScopedClient(options);
  }

  clear(reason?: BoundaryReason): void {
    this.scoped.clear(reason);
  }

  getQueue(): Promise<EvidenceReviewQueue> {
    return this.scoped.request(
      "/internal/evaluation/evidence-review/candidates",
      {},
      isEvidenceReviewQueue,
    );
  }

  getChain(candidateManifestSha256: string, candidateId: string): Promise<EvidenceReviewChain> {
    return this.scoped.request(
      `/internal/evaluation/evidence-review/manifests/${encodeURIComponent(candidateManifestSha256)}/candidates/${encodeURIComponent(candidateId)}/chain`,
      {},
      isEvidenceReviewChain,
    );
  }

  private async appendWithRecovery(
    candidateId: string,
    path: string,
    input: EvidenceReviewInput | EvidenceReviewCorrectionInput,
    parentReviewSha256: string | null,
  ): Promise<EvidenceReviewRevision> {
    try {
      const receipt = await this.scoped.request(
        path,
        { method: "POST", body: JSON.stringify(input) },
        isEvidenceReviewReceipt,
      );
      return receipt.revision;
    } catch (error) {
      if (!(error instanceof EvaluatorApiError) || error.status !== null) throw error;
      try {
        const chain = await this.getChain(input.candidate_manifest_sha256, candidateId);
        const recovered = [...chain.revisions]
          .reverse()
          .find((revision) => matchesReviewInput(revision, input, parentReviewSha256));
        if (recovered) return recovered;
      } catch (recoveryError) {
        if (recoveryError instanceof EvaluatorApiError && recoveryError.status !== null) {
          throw recoveryError;
        }
      }
      throw error;
    }
  }

  review(candidateId: string, input: EvidenceReviewInput): Promise<EvidenceReviewRevision> {
    return this.appendWithRecovery(
      candidateId,
      `/internal/evaluation/evidence-review/candidates/${encodeURIComponent(candidateId)}/reviews`,
      input,
      null,
    );
  }

  correct(
    candidateId: string,
    parentReviewSha256: string,
    input: EvidenceReviewCorrectionInput,
  ): Promise<EvidenceReviewRevision> {
    return this.appendWithRecovery(
      candidateId,
      `/internal/evaluation/evidence-review/candidates/${encodeURIComponent(candidateId)}/reviews/${encodeURIComponent(parentReviewSha256)}/corrections`,
      input,
      parentReviewSha256,
    );
  }

  selectAcceptedHead(
    reviewSha256: string,
    input: EvidenceReviewHeadInput,
  ): Promise<AcceptedEvidenceReviewHead> {
    return this.scoped.request(
      `/internal/evaluation/evidence-review/reviews/${encodeURIComponent(reviewSha256)}/accepted-head`,
      { method: "POST", body: JSON.stringify(input) },
      isAcceptedEvidenceReviewHead,
      "현재 review chain이 변경되었습니다. 최신 chain을 다시 확인하세요.",
    );
  }

  finalize(input: ReviewedEvidenceFinalizeInput): Promise<ReviewedEvidenceManifest> {
    return this.scoped.request(
      "/internal/evaluation/evidence-review/finalize",
      { method: "POST", body: JSON.stringify(input) },
      isReviewedEvidenceManifest,
      "accepted review head가 최신이 아니거나 lane 검수가 완전하지 않습니다.",
    );
  }

  getReviewedManifest(manifestSha256: string): Promise<ReviewedEvidenceManifest> {
    return this.scoped.request(
      `/internal/evaluation/evidence-review/reviewed-manifests/${encodeURIComponent(manifestSha256)}`,
      {},
      isReviewedEvidenceManifest,
    );
  }
}

export function createEvidenceReviewClient(
  options: RoleClientOptions = {},
): EvidenceReviewClient {
  return new EvidenceReviewClient(options);
}

function isProfileReleaseState(value: unknown): boolean {
  return value === "BUILT_UNAPPROVED" || value === "APPROVED_INACTIVE" || value === "ACTIVE";
}

function isProfileReleaseCompletion(value: unknown): boolean {
  return value === "MUTATION_COMMITTED" || value === "RELOOKUP_CONFIRMED";
}

function isProfileReleaseBuildDraftReference(
  value: unknown,
): value is ProfileReleaseBuildDraftReference {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["draft_ref", "expires_at", "nonce_sha256"]) &&
    typeof value.draft_ref === "string" &&
    /^[A-Za-z0-9_-]{43}$/.test(value.draft_ref) &&
    typeof value.expires_at === "string" &&
    Number.isFinite(Date.parse(value.expires_at)) &&
    isSha256(value.nonce_sha256)
  );
}

function isProfileReleaseBuildOutcome(value: unknown): value is ProfileReleaseBuildOutcome {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      "binding_sha256",
      "completion",
      "nonce_sha256",
      "outcome",
      "receipt_sha256",
      "release_sha256",
      "state",
    ]) &&
    value.outcome === "COMMITTED" &&
    value.state === "BUILT_UNAPPROVED" &&
    isProfileReleaseCompletion(value.completion) &&
    isSha256(value.binding_sha256) &&
    isSha256(value.nonce_sha256) &&
    isSha256(value.receipt_sha256) &&
    isSha256(value.release_sha256)
  );
}

function isProfileReleaseActivePointer(
  value: unknown,
): value is ProfileReleaseActivePointerProjection {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["active_release_sha256", "receipt_sha256", "state"])
  ) {
    return false;
  }
  const allNull =
    value.active_release_sha256 === null && value.receipt_sha256 === null && value.state === null;
  const allActive =
    isSha256(value.active_release_sha256) &&
    isSha256(value.receipt_sha256) &&
    value.state === "ACTIVE";
  return allNull || allActive;
}

function isProfileReleaseStateProjection(
  value: unknown,
): value is ProfileReleaseStateProjection {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "lifecycle_head_receipt_sha256",
      "provenance_kind",
      "provenance_receipt_sha256",
      "release_sha256",
      "state",
    ]) ||
    !isSha256(value.release_sha256) ||
    !isProfileReleaseState(value.state) ||
    !isSha256(value.provenance_receipt_sha256)
  ) {
    return false;
  }
  if (value.state === "BUILT_UNAPPROVED") {
    return value.provenance_kind === "BUILD" && value.lifecycle_head_receipt_sha256 === null;
  }
  if (
    !isSha256(value.lifecycle_head_receipt_sha256) ||
    value.lifecycle_head_receipt_sha256 !== value.provenance_receipt_sha256
  ) {
    return false;
  }
  if (value.state === "ACTIVE") return value.provenance_kind === "TRANSITION";
  return value.provenance_kind === "APPROVAL" || value.provenance_kind === "TRANSITION";
}

const PROFILE_RELEASE_SESSION_REF_PATTERN = /^[A-Za-z0-9_-]{1,100}$/;

function isProfileReleasePinProjection(
  value: unknown,
): value is ProfileReleasePinProjection {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["pin_sha256", "pinned_at", "release_sha256", "session_ref"]) &&
    PROFILE_RELEASE_SESSION_REF_PATTERN.test(String(value.session_ref)) &&
    isSha256(value.release_sha256) &&
    isSha256(value.pin_sha256) &&
    typeof value.pinned_at === "string" &&
    value.pinned_at.endsWith("Z") &&
    Number.isFinite(Date.parse(value.pinned_at))
  );
}

function isProfileReleaseTransitionOutcome(
  value: unknown,
): value is ProfileReleaseTransitionOutcome {
  if (
    !(
    isRecord(value) &&
    hasExactKeys(value, [
      "action",
      "binding_sha256",
      "completion",
      "expected_current_sha256",
      "nonce_sha256",
      "outcome",
      "previous_release_sha256",
      "receipt_sha256",
      "release_sha256",
    ]) &&
    value.outcome === "COMMITTED" &&
    (value.action === "ACTIVATE" || value.action === "ROLLBACK") &&
    isProfileReleaseCompletion(value.completion) &&
    isSha256(value.binding_sha256) &&
    isSha256(value.nonce_sha256) &&
    isSha256(value.receipt_sha256) &&
    isSha256(value.release_sha256) &&
    (value.previous_release_sha256 === null || isSha256(value.previous_release_sha256)) &&
    (value.expected_current_sha256 === null || isSha256(value.expected_current_sha256))
    )
  ) {
    return false;
  }
  if (value.previous_release_sha256 !== value.expected_current_sha256) return false;
  return value.action !== "ROLLBACK" || value.previous_release_sha256 !== null;
}

function isProfileReleaseMutationResponse(
  value: unknown,
): value is ProfileReleaseMutationResponse {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["completion", "receipt_sha256", "release_sha256", "state"]) &&
    isSha256(value.release_sha256) &&
    isProfileReleaseState(value.state) &&
    (value.receipt_sha256 === null || isSha256(value.receipt_sha256)) &&
    (value.completion === null || isProfileReleaseCompletion(value.completion))
  );
}

export class ProfileReleaseClient {
  private readonly scoped: RoleScopedClient;

  constructor(options: RoleClientOptions = {}) {
    this.scoped = new RoleScopedClient(options);
  }

  clear(reason?: BoundaryReason): void {
    this.scoped.clear(reason);
  }

  async build(input: ProfileReleaseBuildRequest): Promise<ProfileReleaseBuildOutcome> {
    const nonceSha256 = await sha256Ascii(input.reconciliation_nonce);
    return this.scoped.request(
      "/internal/evaluation/profile-releases/build",
      { method: "POST", body: JSON.stringify(input) },
      isProfileReleaseBuildOutcome,
      "Release build binding 또는 reconciliation nonce가 충돌했습니다.",
      {
        operation: "DIRECT_BUILD",
        action: "BUILD",
        lookupPath:
          `/internal/evaluation/profile-releases/build-receipts/by-nonce/${nonceSha256}`,
      },
    );
  }

  async createBuildDraft(
    input: ProfileReleaseBuildDraftCreateRequest,
  ): Promise<ProfileReleaseBuildDraftReference> {
    const request = () => this.scoped.request(
        "/internal/evaluation/profile-releases/build-drafts",
        { method: "POST", body: JSON.stringify(input) },
        isProfileReleaseBuildDraftReference,
        "Release build draft를 만들 수 없습니다.",
      );
    try {
      return await request();
    } catch (error) {
      if (!(error instanceof EvaluatorApiError) || (error.status !== null && error.status !== 503)) {
        throw error;
      }
      return request();
    }
  }

  async buildDraft(
    input: ProfileReleaseBuildDraftRequest,
    nonceSha256: string,
  ): Promise<ProfileReleaseBuildOutcome> {
    const lookupPath =
      `/internal/evaluation/profile-releases/build-receipts/by-nonce/${nonceSha256}`;
    const request = () => this.scoped.request(
        "/internal/evaluation/profile-releases/build-drafts/build",
        { method: "POST", body: JSON.stringify(input) },
        isProfileReleaseBuildOutcome,
        "Release build draft가 만료되었거나 binding이 충돌했습니다.",
        { operation: "DRAFT_BUILD", action: "BUILD", lookupPath },
      );
    try {
      return await request();
    } catch (error) {
      if (!(error instanceof ProfileReleaseDraftCleanupUnknownError)) throw error;
      try {
        const provenBuild = await this.getProfileReleaseBuildOutcomeByNonce(nonceSha256);
        throw new ProfileReleaseDraftCleanupUnknownError(
          error.lookupPath,
          error.retryPath,
          provenBuild,
        );
      } catch (lookupError) {
        if (
          lookupError instanceof ProfileReleaseDraftCleanupUnknownError &&
          lookupError.provenBuild !== null
        ) {
          throw lookupError;
        }
        throw new ProfileReleaseDraftCleanupUnknownError(
          error.lookupPath,
          error.retryPath,
          null,
          lookupError,
        );
      }
    }
  }

  approve(releaseSha256: string): Promise<ProfileReleaseMutationResponse> {
    return this.scoped.request(
      `/internal/evaluation/profile-releases/${encodeURIComponent(releaseSha256)}/approve`,
      { method: "POST" },
      isProfileReleaseMutationResponse,
      "Exact BUILT_UNAPPROVED release를 독립 승인할 수 없습니다.",
      {
        operation: "APPROVE",
        action: "APPROVE",
        lookupPath: `/internal/evaluation/profile-releases/${encodeURIComponent(releaseSha256)}/state`,
      },
    );
  }

  async activate(
    releaseSha256: string,
    input: ProfileReleaseActivateInput,
  ): Promise<ProfileReleaseMutationResponse> {
    const nonceSha256 = await sha256Ascii(input.nonce);
    return this.scoped.request(
      `/internal/evaluation/profile-releases/${encodeURIComponent(releaseSha256)}/activate`,
      { method: "POST", body: JSON.stringify(input) },
      isProfileReleaseMutationResponse,
      "활성 pointer가 변경되었거나 transition nonce가 충돌했습니다.",
      {
        operation: "ACTIVATE",
        action: "ACTIVATE",
        lookupPath:
          `/internal/evaluation/profile-releases/transition-receipts/by-nonce/${nonceSha256}`,
      },
    );
  }

  async rollback(
    releaseSha256: string,
    input: ProfileReleaseRollbackInput,
  ): Promise<ProfileReleaseMutationResponse> {
    const nonceSha256 = await sha256Ascii(input.nonce);
    return this.scoped.request(
      `/internal/evaluation/profile-releases/${encodeURIComponent(releaseSha256)}/rollback`,
      { method: "POST", body: JSON.stringify(input) },
      isProfileReleaseMutationResponse,
      "Rollback 대상, 사유, pointer 또는 transition nonce가 유효하지 않습니다.",
      {
        operation: "ROLLBACK",
        action: "ROLLBACK",
        lookupPath:
          `/internal/evaluation/profile-releases/transition-receipts/by-nonce/${nonceSha256}`,
      },
    );
  }

  getProfileReleaseBuildOutcomeByNonce(
    nonceSha256: string,
  ): Promise<ProfileReleaseBuildOutcome> {
    return this.scoped.request(
      `/internal/evaluation/profile-releases/build-receipts/by-nonce/${encodeURIComponent(nonceSha256)}`,
      {},
      isProfileReleaseBuildOutcome,
      "Build receipt binding이 저장된 결과와 일치하지 않습니다.",
    );
  }

  getProfileReleaseActivePointer(): Promise<ProfileReleaseActivePointerProjection> {
    return this.scoped.request(
      "/internal/evaluation/profile-releases/active-pointer",
      {},
      isProfileReleaseActivePointer,
      "Active pointer provenance가 일치하지 않습니다.",
    );
  }

  getProfileReleaseState(releaseSha256: string): Promise<ProfileReleaseStateProjection> {
    return this.scoped.request(
      `/internal/evaluation/profile-releases/${encodeURIComponent(releaseSha256)}/state`,
      {},
      isProfileReleaseStateProjection,
      "Release lifecycle provenance가 일치하지 않습니다.",
    );
  }

  getProfileReleaseTransitionOutcomeByNonce(
    nonceSha256: string,
  ): Promise<ProfileReleaseTransitionOutcome> {
    return this.scoped.request(
      `/internal/evaluation/profile-releases/transition-receipts/by-nonce/${encodeURIComponent(nonceSha256)}`,
      {},
      isProfileReleaseTransitionOutcome,
      "Transition receipt binding이 저장된 결과와 일치하지 않습니다.",
    );
  }

  getSessionPin(sessionRef: string): Promise<ProfileReleasePinProjection> {
    if (!PROFILE_RELEASE_SESSION_REF_PATTERN.test(sessionRef)) {
      throw new EvaluatorApiError("세션 reference 형식이 올바르지 않습니다.", null);
    }
    return this.scoped.request(
      `/internal/evaluation/profile-releases/sessions/${encodeURIComponent(sessionRef)}/pin`,
      { method: "GET" },
      isProfileReleasePinProjection,
      "세션 pin provenance가 일치하지 않습니다.",
    );
  }
}

export function createProfileReleaseClient(
  options: RoleClientOptions = {},
): ProfileReleaseClient {
  return new ProfileReleaseClient(options);
}
