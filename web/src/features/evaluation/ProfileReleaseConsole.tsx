import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type FormEvent,
} from "react";

import {
  EvaluatorApiError,
  ProfileReleaseBuildUnavailableError,
  ProfileReleaseDraftCleanupUnknownError,
  ProfileReleaseRetryableAbortError,
  ProfileReleaseUnknownOutcomeError,
  clearBrowserState,
  createProfileReleaseClient,
  sha256Ascii,
  type ProfileReleaseActivePointerProjection,
  type ProfileReleaseBuildDraftReference,
  type ProfileReleaseBuildInput,
  type ProfileReleaseBuildOutcome,
  type ProfileReleaseMutationResponse,
  type ProfileReleasePinProjection,
  type ProfileReleaseStateProjection,
  type ProfileReleaseTransitionOutcome,
} from "./api";
import { ConfirmationDialog } from "./OperatorAdjudication";
import { InternalRoleHeader } from "./EvaluatorWorkspace";

export type ProfileReleaseMutation = ProfileReleaseMutationResponse;
export type { ProfileReleaseBuildInput } from "./api";
export type ProfileReleaseState = ProfileReleaseStateProjection["state"];

export type ProfileReleaseConsoleProps = {
  role: "builder" | "approver" | "activator";
  release?: ProfileReleaseMutation | null;
  expectedCurrentSha256?: string | null;
  buildDraft?: ProfileReleaseBuildDraftReference;
  fetchImpl?: typeof fetch;
  onAuthorizationLost?: () => void;
};

type MutationKind = "BUILD" | "APPROVE" | "ACTIVATE" | "ROLLBACK";

const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const SESSION_REF_PATTERN = /^[A-Za-z0-9_-]{1,100}$/;
const STATE_COPY: Record<ProfileReleaseState, string> = {
  ACTIVE: "ACTIVE · 현재 active release",
  APPROVED_INACTIVE: "APPROVED_INACTIVE · 독립 승인됨, 아직 비활성",
  BUILT_UNAPPROVED: "BUILT_UNAPPROVED · 후보 생성됨, 독립 승인 전",
};

const ROLE_ACTIONS = {
  activator: ["승인된 release 활성화하기", "이전 active release로 되돌리기"],
  approver: ["정확한 release 승인하기"],
  builder: ["불변 release 후보 만들기"],
} as const;

export function profileReleaseSurfaceContract(
  role: ProfileReleaseConsoleProps["role"],
  release: ProfileReleaseMutation,
) {
  return {
    actions: ROLE_ACTIONS[role],
    release_sha256: release.release_sha256,
    state: release.state,
    state_copy: STATE_COPY[release.state],
  };
}

function isSha256(value: unknown): value is string {
  return typeof value === "string" && SHA256_PATTERN.test(value);
}

function sameSessionPin(
  left: ProfileReleasePinProjection,
  right: ProfileReleasePinProjection,
): boolean {
  return (
    left.session_ref === right.session_ref &&
    left.release_sha256 === right.release_sha256 &&
    left.pin_sha256 === right.pin_sha256 &&
    left.pinned_at === right.pinned_at
  );
}

export function newNonce(): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

export { sha256Ascii } from "./api";

export function normalizeRollbackReason(value: string): string | null {
  const normalized = value.trim();
  return normalized.length >= 1 && normalized.length <= 300 ? normalized : null;
}

function HashBlock({ label, value }: { label: string; value: string }) {
  const [copyStatus, setCopyStatus] = useState("");
  return (
    <div className="hash-block">
      <strong>{label}</strong>
      <p className="hash-value" style={{ overflowWrap: "anywhere" }}>
        {value}
      </p>
      <button
        aria-label={`${label} 전체 hash 복사`}
        className="button button--secondary"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(value);
            setCopyStatus(`${label} 복사 완료`);
          } catch {
            setCopyStatus(`${label} 복사 실패`);
          }
        }}
        type="button"
      >
        {label} 전체 hash 복사
      </button>
      <span aria-live="polite">{copyStatus}</span>
    </div>
  );
}

export function ProfileReleaseConsole({
  role,
  release: initialRelease = null,
  expectedCurrentSha256 = null,
  buildDraft,
  fetchImpl,
  onAuthorizationLost,
}: ProfileReleaseConsoleProps) {
  const exactHashId = useId();
  const reasonId = useId();
  const oldSessionRefId = useId();
  const newSessionRefId = useId();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const errorRef = useRef<HTMLParagraphElement>(null);
  const resultRef = useRef<HTMLHeadingElement>(null);
  const rollbackTriggerRef = useRef<HTMLButtonElement>(null);
  const activationNonceRef = useRef<string | null>(null);
  const rollbackNonceRef = useRef<string | null>(null);
  const mountedRef = useRef(true);
  const roleEpochRef = useRef(0);
  const [release, setRelease] = useState<ProfileReleaseStateProjection | null>(null);
  const [activePointer, setActivePointer] =
    useState<ProfileReleaseActivePointerProjection>({
      active_release_sha256: expectedCurrentSha256,
      receipt_sha256: null,
      state: expectedCurrentSha256 === null ? null : "ACTIVE",
    });
  const [lastOutcome, setLastOutcome] = useState<
    ProfileReleaseBuildOutcome | ProfileReleaseTransitionOutcome | null
  >(null);
  const [provenBuildWithoutLifecycle, setProvenBuildWithoutLifecycle] = useState<{
    outcome: ProfileReleaseBuildOutcome;
    cleanupUnknown: boolean;
  } | null>(null);
  const [exactHash, setExactHash] = useState("");
  const [rollbackReason, setRollbackReason] = useState("");
  const [newSessionConfirmed, setNewSessionConfirmed] = useState(false);
  const [oldSessionRef, setOldSessionRef] = useState("");
  const [newSessionRef, setNewSessionRef] = useState("");
  const [oldSessionPin, setOldSessionPin] =
    useState<ProfileReleasePinProjection | null>(null);
  const [newSessionPin, setNewSessionPin] =
    useState<ProfileReleasePinProjection | null>(null);
  const [pinBusy, setPinBusy] = useState<"OLD" | "NEW" | null>(null);
  const [rollbackDialogOpen, setRollbackDialogOpen] = useState(false);
  const [busy, setBusy] = useState<MutationKind | null>(null);
  const [message, setMessage] = useState("서버가 증명한 release 상태를 확인하세요.");
  const [error, setError] = useState<string | null>(null);
  const client = useMemo(
    () => createProfileReleaseClient({ fetchImpl, onSecurityBoundary: onAuthorizationLost }),
    [fetchImpl, onAuthorizationLost],
  );

  const clearSensitiveState = useCallback(() => {
    activationNonceRef.current = null;
    rollbackNonceRef.current = null;
    client.clear();
    setRelease(null);
    setLastOutcome(null);
    setProvenBuildWithoutLifecycle(null);
    setExactHash("");
    setRollbackReason("");
    setNewSessionConfirmed(false);
    setOldSessionRef("");
    setNewSessionRef("");
    setOldSessionPin(null);
    setNewSessionPin(null);
    setPinBusy(null);
    setRollbackDialogOpen(false);
    clearBrowserState();
  }, [client]);

  const isCurrentEpoch = useCallback(
    (epoch: number) => mountedRef.current && roleEpochRef.current === epoch,
    [],
  );

  const isReconcilableMutationError = useCallback(
    (
      requestError: unknown,
      action: ProfileReleaseUnknownOutcomeError["action"],
      lookupPath: string,
    ) =>
      (requestError instanceof EvaluatorApiError && requestError.status === null) ||
      (requestError instanceof ProfileReleaseUnknownOutcomeError &&
        requestError.action === action &&
        requestError.lookupPath === lookupPath),
    [],
  );

  const reportApiError = useCallback(
    (requestError: unknown, uncertainCopy: string, epoch: number) => {
      if (!isCurrentEpoch(epoch)) return;
      if (requestError instanceof EvaluatorApiError) {
        if (requestError instanceof ProfileReleaseRetryableAbortError) {
          setError(
            `${requestError.action} mutation은 커밋 전에 안전하게 중단되었습니다. 동일 입력으로 다시 시도하세요.`,
          );
          return;
        }
        if (requestError instanceof ProfileReleaseBuildUnavailableError) {
          setError("BUILD 시작 전 서버가 일시적으로 unavailable입니다. 동일 입력으로 다시 시도하세요.");
          return;
        }
        if (requestError.status === 401 || requestError.status === 403) {
          clearSensitiveState();
          setError(
            "이 역할은 이 자료를 볼 수 없습니다. 이전 payload와 브라우저 상태를 모두 지웠습니다.",
          );
          return;
        }
        if (requestError.status === 404) {
          setError(`${uncertainCopy} 서버 조회 결과는 UNKNOWN입니다.`);
          return;
        }
        if (requestError.status === 409) {
          setError(
            "서버 provenance 또는 nonce binding이 충돌했습니다. 성공으로 표시하지 않았습니다.",
          );
          return;
        }
      }
      setError(`${uncertainCopy} 성공으로 표시하지 않았습니다.`);
    },
    [clearSensitiveState, isCurrentEpoch],
  );

  const readState = useCallback(
    async (
      releaseSha256: string,
      epoch = roleEpochRef.current,
      commitProjection = true,
    ) => {
      const projection = await client.getProfileReleaseState(releaseSha256);
      if (commitProjection && isCurrentEpoch(epoch)) setRelease(projection);
      return projection;
    },
    [client, isCurrentEpoch],
  );

  const refreshPointer = useCallback(async (
    epoch = roleEpochRef.current,
    commitProjection = true,
  ) => {
    const pointer = await client.getProfileReleaseActivePointer();
    if (commitProjection && isCurrentEpoch(epoch)) setActivePointer(pointer);
    return pointer;
  }, [client, isCurrentEpoch]);

  useEffect(() => {
    const epoch = roleEpochRef.current + 1;
    roleEpochRef.current = epoch;
    mountedRef.current = true;
    activationNonceRef.current = null;
    rollbackNonceRef.current = null;
    setRelease(null);
    setLastOutcome(null);
    setProvenBuildWithoutLifecycle(null);
    setExactHash("");
    setRollbackReason("");
    setNewSessionConfirmed(false);
    setOldSessionRef("");
    setNewSessionRef("");
    setOldSessionPin(null);
    setNewSessionPin(null);
    setPinBusy(null);
    setRollbackDialogOpen(false);
    setError(null);
    setMessage("역할이 바뀌어 이전 payload와 입력을 모두 지웠습니다. 서버 상태를 다시 확인하세요.");
    clearBrowserState();
    const load = async () => {
      try {
        const pointer = await refreshPointer(epoch);
        const selectedSha256 = initialRelease?.release_sha256 ?? pointer.active_release_sha256;
        if (selectedSha256 !== null) await readState(selectedSha256, epoch);
        if (isCurrentEpoch(epoch)) {
          setMessage("서버 active pointer와 exact release 상태를 확인했습니다.");
        }
      } catch (loadError) {
        reportApiError(loadError, "초기 release 상태를 확인할 수 없습니다.", epoch);
      }
    };
    void load();
    const frame = requestAnimationFrame(() => headingRef.current?.focus());
    return () => {
      if (roleEpochRef.current === epoch) mountedRef.current = false;
      cancelAnimationFrame(frame);
      activationNonceRef.current = null;
      rollbackNonceRef.current = null;
      client.clear();
    };
  }, [client, initialRelease?.release_sha256, isCurrentEpoch, readState, refreshPointer, reportApiError, role]);

  useEffect(() => {
    if ((release === null && provenBuildWithoutLifecycle === null) || lastOutcome === null) return;
    resultRef.current?.focus();
  }, [lastOutcome, provenBuildWithoutLifecycle, release]);

  useEffect(() => {
    if (error === null || rollbackDialogOpen) return;
    const frame = requestAnimationFrame(() => errorRef.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [error, rollbackDialogOpen]);

  const targetMatches = release !== null && exactHash === release.release_sha256;
  const normalizedReason = useMemo(
    () => normalizeRollbackReason(rollbackReason),
    [rollbackReason],
  );
  const build = async (event: FormEvent) => {
    event.preventDefault();
    const epoch = roleEpochRef.current;
    if (buildDraft === undefined || Date.parse(buildDraft.expires_at) <= Date.now()) {
      if (isCurrentEpoch(epoch)) {
        setError("Release를 만들 수 없습니다. 서버 build draft가 없거나 만료되었습니다.");
      }
      return;
    }
    setBusy("BUILD");
    setError(null);
    setLastOutcome(null);
    setProvenBuildWithoutLifecycle(null);
    try {
      let outcome: ProfileReleaseBuildOutcome;
      let cleanupUnknown = false;
      try {
        outcome = await client.buildDraft(
          {
            draft_ref: buildDraft.draft_ref,
            nonce_sha256: buildDraft.nonce_sha256,
          },
          buildDraft.nonce_sha256,
        );
      } catch (buildError) {
        if (
          buildError instanceof ProfileReleaseDraftCleanupUnknownError &&
          buildError.provenBuild !== null
        ) {
          outcome = buildError.provenBuild;
          cleanupUnknown = true;
        } else {
        const lookupPath =
          `/internal/evaluation/profile-releases/build-receipts/by-nonce/${buildDraft.nonce_sha256}`;
        if (!isReconcilableMutationError(buildError, "BUILD", lookupPath)) {
          throw buildError;
        }
        outcome = await client.getProfileReleaseBuildOutcomeByNonce(
          buildDraft.nonce_sha256,
        );
        }
      }
      if (outcome.nonce_sha256 !== buildDraft.nonce_sha256) {
        throw new Error("build receipt nonce was not confirmed");
      }
      let projection: ProfileReleaseStateProjection;
      try {
        projection = await readState(outcome.release_sha256, epoch, false);
      } catch (lifecycleError) {
        const lifecycleUnavailable =
          lifecycleError instanceof EvaluatorApiError &&
          (lifecycleError.status === null ||
            lifecycleError.status === 404 ||
            lifecycleError.status === 503);
        if (!lifecycleUnavailable) throw lifecycleError;
        if (isCurrentEpoch(epoch)) {
          setRelease(null);
          setProvenBuildWithoutLifecycle({ outcome, cleanupUnknown });
          setLastOutcome(outcome);
          setExactHash(outcome.release_sha256);
          setError("현재 lifecycle projection을 서버에서 조회할 수 없습니다.");
          setMessage(
            cleanupUnknown
              ? "불변 BUILD receipt는 확인했습니다. 보호 draft 정리는 아직 확인되지 않았고 현재 lifecycle 조회는 unavailable입니다."
              : "불변 BUILD receipt는 확인했습니다. 현재 lifecycle 조회만 unavailable입니다.",
          );
        }
        return;
      }
      if (projection.release_sha256 !== outcome.release_sha256) {
        throw new Error("build receipt release was not confirmed");
      }
      if (isCurrentEpoch(epoch)) {
        setProvenBuildWithoutLifecycle(null);
        setRelease(projection);
        setLastOutcome(outcome);
        setExactHash(outcome.release_sha256);
        setMessage(
          cleanupUnknown
            ? `불변 BUILD receipt는 확인했습니다. 현재 lifecycle 상태는 ${projection.state}이며 보호 draft 정리는 아직 확인되지 않았습니다.`
            : `불변 BUILD receipt를 확인했습니다. 현재 lifecycle 상태는 ${projection.state}입니다.`,
        );
      }
    } catch (buildError) {
      const cleanupProofUnavailable =
        buildError instanceof ProfileReleaseDraftCleanupUnknownError &&
        buildError.provenBuild === null;
      reportApiError(
        buildError,
        cleanupProofUnavailable
          ? "보호 draft 정리 불확실성은 유지되지만 BUILD receipt 조회도 완료하지 못했습니다."
          : "Build 응답을 nonce digest receipt로 조정하지 못했습니다.",
        epoch,
      );
      if (isCurrentEpoch(epoch)) {
        setMessage(
          cleanupProofUnavailable
            ? "보호 draft 정리 결과는 여전히 불확실하며 BUILD receipt는 아직 확인되지 않았습니다. cleanup 재시도 전에 receipt 조회를 다시 수행하세요."
            : buildError instanceof ProfileReleaseRetryableAbortError
            ? "BUILD는 커밋 전에 안전하게 중단되었습니다. 동일 입력으로 다시 시도할 수 있습니다."
            : buildError instanceof ProfileReleaseBuildUnavailableError
              ? "BUILD 시작 전 서버가 일시적으로 unavailable입니다. 동일 입력으로 다시 시도할 수 있습니다."
              : "Build 결과는 UNKNOWN이며 release hash를 추측하지 않습니다.",
        );
      }
    } finally {
      if (isCurrentEpoch(epoch)) {
        setBusy(null);
      }
    }
  };

  const approve = async (event: FormEvent) => {
    event.preventDefault();
    const epoch = roleEpochRef.current;
    if (!isSha256(exactHash)) {
      setError("BUILT_UNAPPROVED 상태의 exact full release hash를 입력하세요.");
      return;
    }
    setBusy("APPROVE");
    setError(null);
    setLastOutcome(null);
    try {
      const before = await readState(exactHash, epoch);
      if (before.state !== "BUILT_UNAPPROVED") {
        throw new Error("approval target state mismatch");
      }
      let outcome: ProfileReleaseMutationResponse | null = null;
      try {
        outcome = await client.approve(exactHash);
      } catch (approvalError) {
        const lookupPath =
          `/internal/evaluation/profile-releases/${encodeURIComponent(exactHash)}/state`;
        if (!isReconcilableMutationError(approvalError, "APPROVE", lookupPath)) {
          throw approvalError;
        }
      }
      const confirmed = await readState(exactHash, epoch, false);
      if (
        confirmed.state !== "APPROVED_INACTIVE" ||
        confirmed.provenance_kind !== "APPROVAL" ||
        confirmed.lifecycle_head_receipt_sha256 !== confirmed.provenance_receipt_sha256 ||
        (outcome !== null &&
          (outcome.release_sha256 !== exactHash ||
            outcome.state !== "APPROVED_INACTIVE" ||
            outcome.receipt_sha256 === null ||
            confirmed.provenance_receipt_sha256 !== outcome.receipt_sha256))
      ) {
        throw new Error("approval receipt was not confirmed");
      }
      if (isCurrentEpoch(epoch)) {
        setRelease(confirmed);
        setMessage("서버 exact state에서 APPROVED_INACTIVE와 approver receipt를 확인했습니다.");
        setExactHash("");
      }
    } catch (approvalError) {
      reportApiError(
        approvalError,
        "독립 승인 결과를 exact receipt로 확인하지 못했습니다.",
        epoch,
      );
    } finally {
      if (isCurrentEpoch(epoch)) setBusy(null);
    }
  };

  const reconcileTransition = async (
    rawNonce: string,
    expectedAction: "ACTIVATE" | "ROLLBACK",
    epoch: number,
    commitSuccess = true,
  ) => {
    const nonceSha256 = await sha256Ascii(rawNonce);
    const outcome = await client.getProfileReleaseTransitionOutcomeByNonce(nonceSha256);
    if (outcome.action !== expectedAction || outcome.nonce_sha256 !== nonceSha256) {
      throw new Error("transition action mismatch");
    }
    const pointer = await refreshPointer(epoch, commitSuccess);
    const projection = await readState(outcome.release_sha256, epoch, false);
    if (
      pointer.active_release_sha256 !== outcome.release_sha256 ||
      pointer.receipt_sha256 !== outcome.receipt_sha256 ||
      projection.state !== "ACTIVE" ||
      projection.provenance_kind !== "TRANSITION" ||
      projection.lifecycle_head_receipt_sha256 !== outcome.receipt_sha256 ||
      projection.provenance_receipt_sha256 !== outcome.receipt_sha256
    ) {
      throw new Error("transition receipt was not confirmed");
    }
    if (commitSuccess && isCurrentEpoch(epoch)) {
      setRelease(projection);
      setLastOutcome(outcome);
      setMessage(
        `${expectedAction} receipt, active pointer, exact ACTIVE state를 모두 확인했습니다.`,
      );
      setExactHash("");
      setRollbackReason("");
      setNewSessionConfirmed(false);
    }
    return { outcome, pointer, projection };
  };

  const activate = async () => {
    const epoch = roleEpochRef.current;
    if (!targetMatches || release?.state !== "APPROVED_INACTIVE" || !newSessionConfirmed) {
      setError("APPROVED_INACTIVE exact hash와 새 세션 전환 확인을 모두 완료하세요.");
      return;
    }
    setBusy("ACTIVATE");
    setError(null);
    setLastOutcome(null);
    const rawNonce = newNonce();
    activationNonceRef.current = rawNonce;
    try {
      try {
        await client.activate(exactHash, {
          expected_current_sha256: activePointer.active_release_sha256,
          nonce: rawNonce,
        });
      } catch (activationError) {
        const nonceSha256 = await sha256Ascii(rawNonce);
        const lookupPath =
          `/internal/evaluation/profile-releases/transition-receipts/by-nonce/${nonceSha256}`;
        if (!isReconcilableMutationError(activationError, "ACTIVATE", lookupPath)) {
          throw activationError;
        }
      }
      await reconcileTransition(rawNonce, "ACTIVATE", epoch);
    } catch (activationError) {
      reportApiError(
        activationError,
        "활성화 결과를 transition nonce digest와 pointer로 확인할 수 없습니다.",
        epoch,
      );
      if (isCurrentEpoch(epoch)) {
        setMessage(
          activationError instanceof ProfileReleaseRetryableAbortError
            ? "ACTIVATE는 커밋 전에 안전하게 중단되었습니다. 동일 입력으로 다시 시도할 수 있습니다."
            : "활성화 결과는 UNKNOWN이며 mutation을 자동 재시도하지 않습니다.",
        );
      }
    } finally {
      if (isCurrentEpoch(epoch)) {
        activationNonceRef.current = null;
        setBusy(null);
      }
    }
  };

  const inspectSessionPin = async (kind: "OLD" | "NEW") => {
    const epoch = roleEpochRef.current;
    const sessionRef = kind === "OLD" ? oldSessionRef : newSessionRef;
    if (!SESSION_REF_PATTERN.test(sessionRef)) {
      setError("세션 reference는 영문, 숫자, _, - 조합 1..100자로 입력하세요.");
      return;
    }
    setPinBusy(kind);
    setError(null);
    try {
      const pin = await client.getSessionPin(sessionRef);
      if (!isCurrentEpoch(epoch)) return;
      if (kind === "OLD") setOldSessionPin(pin);
      else setNewSessionPin(pin);
      setMessage(`${kind === "OLD" ? "기존" : "신규"} 세션의 불변 pin을 확인했습니다.`);
    } catch (pinError) {
      reportApiError(pinError, "세션 pin을 확인하지 못했습니다.", epoch);
    } finally {
      if (isCurrentEpoch(epoch)) setPinBusy(null);
    }
  };

  const closeRollbackDialog = () => {
    if (busy === "ROLLBACK") return;
    setError(null);
    setRollbackDialogOpen(false);
    rollbackTriggerRef.current?.focus();
  };

  const openRollbackDialog = () => {
    const pinsAreCurrent =
      oldSessionPin?.session_ref === oldSessionRef &&
      newSessionPin?.session_ref === newSessionRef;
    if (
      !isSha256(exactHash) ||
      activePointer.active_release_sha256 === null ||
      normalizedReason === null ||
      !newSessionConfirmed ||
      !pinsAreCurrent ||
      oldSessionRef === newSessionRef ||
      oldSessionPin.release_sha256 !== exactHash ||
      newSessionPin.release_sha256 !== activePointer.active_release_sha256
    ) {
      setError(
        "이전 release와 현재 active release에 연결된 서로 다른 기존/신규 세션 pin, rollback 사유, 새 세션 전환 확인이 모두 필요합니다.",
      );
      return;
    }
    setError(null);
    setRollbackDialogOpen(true);
  };

  const rollback = async () => {
    const epoch = roleEpochRef.current;
    const oldPinBefore = oldSessionPin;
    const newPinBefore = newSessionPin;
    const currentReleaseBefore = activePointer.active_release_sha256;
    if (
      !isSha256(exactHash) ||
      currentReleaseBefore === null ||
      normalizedReason === null ||
      !newSessionConfirmed ||
      oldPinBefore === null ||
      newPinBefore === null ||
      oldPinBefore.session_ref !== oldSessionRef ||
      newPinBefore.session_ref !== newSessionRef ||
      oldSessionRef === newSessionRef ||
      oldPinBefore.release_sha256 !== exactHash ||
      newPinBefore.release_sha256 !== currentReleaseBefore
    ) {
      setError("Rollback 입력 또는 기존/신규 세션 pin 증명이 현재 서버 상태와 일치하지 않습니다.");
      return;
    }
    setBusy("ROLLBACK");
    setError(null);
    setLastOutcome(null);
    const rawNonce = newNonce();
    rollbackNonceRef.current = rawNonce;
    try {
      try {
        await client.rollback(exactHash, {
          expected_current_sha256: currentReleaseBefore,
          nonce: rawNonce,
          reason: normalizedReason,
        });
      } catch (rollbackError) {
        const nonceSha256 = await sha256Ascii(rawNonce);
        const lookupPath =
          `/internal/evaluation/profile-releases/transition-receipts/by-nonce/${nonceSha256}`;
        if (!isReconcilableMutationError(rollbackError, "ROLLBACK", lookupPath)) {
          throw rollbackError;
        }
      }
      const reconciled = await reconcileTransition(rawNonce, "ROLLBACK", epoch, false);
      const [oldPinAfter, newPinAfter] = await Promise.all([
        client.getSessionPin(oldSessionRef),
        client.getSessionPin(newSessionRef),
      ]);
      if (
        !sameSessionPin(oldPinBefore, oldPinAfter) ||
        !sameSessionPin(newPinBefore, newPinAfter) ||
        reconciled.outcome.previous_release_sha256 !== currentReleaseBefore ||
        reconciled.outcome.release_sha256 !== oldPinBefore.release_sha256 ||
        reconciled.pointer.active_release_sha256 !== oldPinBefore.release_sha256 ||
        oldPinAfter.release_sha256 === newPinAfter.release_sha256
      ) {
        throw new Error("rollback session pins were not preserved");
      }
      if (isCurrentEpoch(epoch)) {
        setActivePointer(reconciled.pointer);
        setRelease(reconciled.projection);
        setLastOutcome(reconciled.outcome);
        setOldSessionPin(oldPinAfter);
        setNewSessionPin(newPinAfter);
        setRollbackDialogOpen(false);
        setMessage(
          "ROLLBACK receipt, active pointer, exact ACTIVE state, old/new session pin을 모두 확인했습니다.",
        );
        setExactHash("");
        setRollbackReason("");
        setNewSessionConfirmed(false);
      }
    } catch (rollbackError) {
      reportApiError(
        rollbackError,
        "Rollback 결과를 transition nonce digest와 pointer로 확인할 수 없습니다.",
        epoch,
      );
      if (isCurrentEpoch(epoch)) {
        setMessage(
          rollbackError instanceof ProfileReleaseRetryableAbortError
            ? "ROLLBACK은 커밋 전에 안전하게 중단되었습니다. 동일 입력으로 다시 시도할 수 있습니다."
            : "Rollback 결과는 UNKNOWN이며 mutation을 자동 재시도하지 않습니다.",
        );
      }
    } finally {
      if (isCurrentEpoch(epoch)) {
        rollbackNonceRef.current = null;
        setBusy(null);
      }
    }
  };

  const inspectExactState = async () => {
    const epoch = roleEpochRef.current;
    if (!isSha256(exactHash)) {
      setError("확인할 exact full release SHA-256을 입력하세요.");
      return;
    }
    setError(null);
    try {
      await readState(exactHash, epoch);
      await refreshPointer(epoch);
      if (isCurrentEpoch(epoch)) {
        setMessage("서버 exact state와 active pointer를 다시 확인했습니다.");
      }
    } catch (stateError) {
      reportApiError(stateError, "Exact release 상태를 확인하지 못했습니다.", epoch);
    }
  };

  return (
    <main className="evaluator-shell" data-profile-release-role={role}>
      <InternalRoleHeader
        onExit={
          onAuthorizationLost === undefined
            ? undefined
            : () => {
                clearSensitiveState();
                onAuthorizationLost();
              }
        }
        roleLabel={`Profile release ${role}`}
      />
      <header className="evaluator-intro">
        <p className="eyebrow">Phase 3 · DEV profile release 원장</p>
        <h1 ref={headingRef} tabIndex={-1}>DEV profile release 후보</h1>
        <p>Builder, independent approver, activator 작업은 서로 다른 서버 권한으로 수행됩니다.</p>
      </header>
      <p aria-live="polite" className="async-status" role="status">
        {message}
      </p>
      {error && !rollbackDialogOpen ? (
        <p
          className="async-status async-status--error"
          ref={errorRef}
          role="alert"
          tabIndex={-1}
        >
          {error}
        </p>
      ) : null}

      <section aria-labelledby="release-state-heading" className="source-material">
        <h2 id="release-state-heading">서버 release 상태</h2>
        {release === null && provenBuildWithoutLifecycle === null ? (
          <p>아직 서버 receipt로 확인된 release가 없습니다.</p>
        ) : release === null && provenBuildWithoutLifecycle !== null ? (
          <>
            <p>
              <strong>현재 lifecycle 조회 불가</strong>
            </p>
            <HashBlock
              label="Exact release SHA-256"
              value={provenBuildWithoutLifecycle.outcome.release_sha256}
            />
            <section>
              <h3 ref={resultRef} tabIndex={-1}>
                서버가 생성한 release receipt
              </h3>
              <HashBlock
                label="Immutable BUILD receipt SHA-256"
                value={provenBuildWithoutLifecycle.outcome.receipt_sha256}
              />
              <p>Provenance kind: BUILD</p>
              <p>완료 증명: {provenBuildWithoutLifecycle.outcome.completion}</p>
              <p>현재 lifecycle projection은 unavailable이며 BUILD proof와 구분됩니다.</p>
              {provenBuildWithoutLifecycle.cleanupUnknown ? (
                <p>보호 draft 정리는 아직 확인되지 않았습니다.</p>
              ) : null}
            </section>
          </>
        ) : (
          <>
            <p>
              <strong>{STATE_COPY[release!.state]}</strong>
            </p>
            <HashBlock label="Exact release SHA-256" value={release!.release_sha256} />
            <section>
              <h3 ref={resultRef} tabIndex={-1}>
                서버가 생성한 release receipt
              </h3>
              <HashBlock
                label={
                  release!.state === "BUILT_UNAPPROVED"
                    ? "Immutable BUILD receipt SHA-256"
                    : "Current lifecycle receipt SHA-256"
                }
                value={release!.provenance_receipt_sha256}
              />
              <p>Provenance kind: {release!.provenance_kind}</p>
              {lastOutcome ? <p>완료 증명: {lastOutcome.completion}</p> : null}
            </section>
          </>
        )}
        {activePointer.active_release_sha256 ? (
          <HashBlock
            label="Expected current SHA-256"
            value={activePointer.active_release_sha256}
          />
        ) : (
          <p>현재 active pointer: 없음</p>
        )}
      </section>

      {role === "builder" ? (
        <form aria-busy={busy === "BUILD"} onSubmit={build}>
          <h2>Builder · 후보 빌드</h2>
          <p>현재 검증된 전체 DEV profile set을 하나의 불변 후보로 게시합니다.</p>
          {buildDraft ? (
            <p>보호된 DEV cohort는 서버 draft에만 있으며 {buildDraft.expires_at}에 만료됩니다.</p>
          ) : (
            <p>Builder 권한으로 생성한 만료형 server draft reference가 필요합니다.</p>
          )}
          <button className="button button--primary" disabled={busy !== null} type="submit">
            {ROLE_ACTIONS.builder[0]}
          </button>
        </form>
      ) : null}

      {role === "approver" ? (
        <form aria-busy={busy === "APPROVE"} onSubmit={approve}>
          <h2>Independent approver · exact-hash 승인</h2>
          <p>승인은 APPROVED_INACTIVE만 만들며 active pointer를 바꾸지 않습니다.</p>
          <label htmlFor={exactHashId}>승인할 full release SHA-256</label>
          <input
            autoComplete="off"
            id={exactHashId}
            inputMode="text"
            onChange={(event) => setExactHash(event.target.value)}
            spellCheck={false}
            value={exactHash}
          />
          <button
            className="button button--secondary"
            disabled={busy !== null}
            onClick={() => void inspectExactState()}
            type="button"
          >
            Exact release 상태 확인
          </button>
          <button className="button button--primary" disabled={busy !== null} type="submit">
            {ROLE_ACTIONS.approver[0]}
          </button>
        </form>
      ) : null}

      {role === "activator" ? (
        <>
        <section aria-busy={busy === "ACTIVATE" || busy === "ROLLBACK"}>
          <h2>Activator · 활성화와 호환 rollback</h2>
          <p>새 세션부터 선택한 release를 사용하며 기존 세션과 결과의 pin은 유지됩니다.</p>
          <div className="source-material">
            <h3>전환 전후 세션 pin 증명</h3>
            <label htmlFor={oldSessionRefId}>기존 세션 reference</label>
            <input
              autoComplete="off"
              id={oldSessionRefId}
              onChange={(event) => {
                setOldSessionRef(event.target.value);
                setOldSessionPin(null);
              }}
              spellCheck={false}
              value={oldSessionRef}
            />
            <button
              className="button button--secondary"
              disabled={busy !== null || pinBusy !== null}
              onClick={() => void inspectSessionPin("OLD")}
              type="button"
            >
              기존 세션 pin 확인
            </button>
            {oldSessionPin ? (
              <section aria-label="기존 세션 pin 결과">
                <HashBlock label="기존 세션 release SHA-256" value={oldSessionPin.release_sha256} />
                <HashBlock label="기존 세션 pin SHA-256" value={oldSessionPin.pin_sha256} />
                <p>서버 pinned_at (UTC): {oldSessionPin.pinned_at}</p>
              </section>
            ) : null}

            <label htmlFor={newSessionRefId}>신규 세션 reference</label>
            <input
              autoComplete="off"
              id={newSessionRefId}
              onChange={(event) => {
                setNewSessionRef(event.target.value);
                setNewSessionPin(null);
              }}
              spellCheck={false}
              value={newSessionRef}
            />
            <button
              className="button button--secondary"
              disabled={busy !== null || pinBusy !== null}
              onClick={() => void inspectSessionPin("NEW")}
              type="button"
            >
              신규 세션 pin 확인
            </button>
            {newSessionPin ? (
              <section aria-label="신규 세션 pin 결과">
                <HashBlock label="신규 세션 release SHA-256" value={newSessionPin.release_sha256} />
                <HashBlock label="신규 세션 pin SHA-256" value={newSessionPin.pin_sha256} />
                <p>서버 pinned_at (UTC): {newSessionPin.pinned_at}</p>
              </section>
            ) : null}
          </div>
          <label htmlFor={exactHashId}>전환할 full release SHA-256</label>
          <input
            autoComplete="off"
            id={exactHashId}
            inputMode="text"
            onChange={(event) => setExactHash(event.target.value)}
            spellCheck={false}
            value={exactHash}
          />
          <button
            className="button button--secondary"
            disabled={busy !== null}
            onClick={() => void inspectExactState()}
            type="button"
          >
            Exact release 상태 확인
          </button>
          <label>
            <input
              checked={newSessionConfirmed}
              onChange={(event) => setNewSessionConfirmed(event.target.checked)}
              type="checkbox"
            />
            새 세션에만 적용되는 pointer 전환임을 확인했습니다
          </label>
          <button
            className="button button--primary"
            disabled={busy !== null}
            onClick={() => void activate()}
            type="button"
          >
            {ROLE_ACTIONS.activator[0]}
          </button>
          <label htmlFor={reasonId}>Rollback 사유 (trimmed 1..300자)</label>
          <textarea
            id={reasonId}
            maxLength={300}
            onChange={(event) => setRollbackReason(event.target.value)}
            value={rollbackReason}
          />
          <p>{rollbackReason.trim().length}/300</p>
          <button
            className="button button--secondary"
            disabled={busy !== null}
            onClick={openRollbackDialog}
            ref={rollbackTriggerRef}
            type="button"
          >
            {ROLE_ACTIONS.activator[1]}
          </button>
        </section>
        {rollbackDialogOpen ? (
          <div
            className="confirmation-backdrop"
            onMouseDown={(event) => {
              if (event.target === event.currentTarget) closeRollbackDialog();
            }}
          >
            <ConfirmationDialog
              busy={busy === "ROLLBACK"}
              confirmLabel="호환 release로 rollback하기"
              error={error}
              onCancel={closeRollbackDialog}
              onConfirm={() => void rollback()}
              returnFocusRef={rollbackTriggerRef}
              safeLabel="현재 release 유지하기"
              title="이 release로 rollback할까요?"
            >
              <p>
                현재 release는 삭제되지 않습니다. active pointer만 이전에 활성화된 호환
                release로 전환되고 불변 receipt가 남습니다.
              </p>
            </ConfirmationDialog>
          </div>
        ) : null}
        </>
      ) : null}
    </main>
  );
}
