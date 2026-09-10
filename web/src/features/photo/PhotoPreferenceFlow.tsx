import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";

import { useJourneyAnnouncements } from "../../app/AppShell";
import {
  clearPhotoDraft,
  readPhotoDraft,
  writePhotoDraft,
} from "../../app/storage";

import {
  PHOTO_CONSENT_COPY,
  PhotoConsentPanel,
} from "./PhotoConsentPanel";
import {
  PhotoJobStatus,
  PHOTO_FALLBACK_COPY,
  PHOTO_STATUS_COPY,
} from "./PhotoJobStatus";
import {
  PhotoPreflightPicker,
  PREFLIGHT_COPY,
  PICKER_COPY,
  validateIngestion,
  type PreflightProblem,
  type SelectedPhoto,
} from "./PhotoPreflightPicker";
import {
  isValidCandidatePayload,
  PhotoTraitReview,
  type ConfirmedTrait,
} from "./PhotoTraitReview";
import {
  usePhotoJobPolling,
  type PhotoJobSnapshotLike,
} from "./usePhotoJobPolling";
import type { PhotoTraitCandidatePayload } from "./PhotoTraitReview";
import { DELETE_COPY, PhotoDeleteDialog } from "./PhotoDeleteDialog";
import { PhotoStorageNotice } from "./PhotoStorageNotice";
import { PhotoMoodConfirmation, type MoodConfirmationInput } from "./PhotoMoodConfirmation";
import { moodReviewSchema, confirmedMoodSchema, validateMoodReview, validateMoodConfirmation,
  type MoodReview, type ConfirmedMood } from "../../api/visual-mood";

/**
 * Traveler entry, consent, local preflight, and bounded upload start.
 *
 * Closed UI state machine: entry|consent_unchecked|consent_ready|
 * preflight_empty|preflight_partial|preflight_ready|uploading|polling|
 * review|fallback. No file control exists before consent; no durable job
 * exists before every local row validates AND the explicit start action
 * fires. sessionStorage holds only the bounded ≤2KB opaque reference under
 * itda.phase6.photo-draft.v1 (schema_version/job_id/profile_id/
 * notice_version/created_at) — never bytes, preview URLs, filenames,
 * candidates, confirmed values, provider output, or deletion evidence.
 * localStorage is never used by this feature.
 */

export const PHOTO_FLOW_NOTICE_VERSION_DEFAULT = "photo-consent-2026-08-v1";

type FlowState =
  | "entry"
  | "consent_unchecked"
  | "consent_ready"
  | "preflight_empty"
  | "preflight_partial"
  | "preflight_ready"
  | "uploading"
  | "polling"
  | "review"
  | "mood_review"
  | "fallback";

type FallbackKind =
  | "unknown"
  | "expired"
  | "deletePending"
  | "deletedVerified"
  | "providerUnavailable"
  | "analysisFailed"
  | "uploadUncertainty"
  | "pollError"
  | "timeout"
  | "directEntry";

/** Strict snapshot validator: unknown/malformed payloads collapse to fallback. */
function parseSnapshot(value: unknown): PhotoJobSnapshotLike | null {
  if (typeof value !== "object" || value === null) return null;
  const row = value as Record<string, unknown>;
  if (typeof row.job_id !== "string" || typeof row.state !== "string") return null;
  if (row.analysis_family !== undefined && row.analysis_family !== "photo-mood-v1") return null;
  if (
    !["queued", "running", "succeeded", "failed", "expired", "deleted"].includes(row.state)
  ) {
    return null;
  }
  return value as PhotoJobSnapshotLike;
}

export function PhotoPreferenceFlow({
  profileId,
  noticeVersion = PHOTO_FLOW_NOTICE_VERSION_DEFAULT,
  startAtConsent = false,
  consentHeadingLevel = 1,
  client,
  onNoPhoto,
  onJobCreated,
  onConfirmed,
  onMoodConfirmed,
}: {
  profileId: string;
  noticeVersion?: string;
  startAtConsent?: boolean;
  consentHeadingLevel?: 1 | 2;
  client: {
    createPhotoJob: (input: {
      consent_accepted: boolean;
      consent_version: string;
    }) => Promise<{ job_id: string; state: string; analysis_family?: "photo-mood-v1" }>;
    getPhotoJob: (jobId: string) => Promise<unknown>;
    getPhotoJobTraits?: (jobId: string) => Promise<unknown>;
    getPhotoJobMoods?: (jobId: string) => Promise<unknown>;
    confirmPhotoJobMoods?: (jobId: string, input: MoodConfirmationInput) => Promise<unknown>;
    requestPhotoDeletion?: (jobId: string) => Promise<{
      state: string;
      residue_verified?: boolean;
      ledger_recorded?: boolean;
    }>;
    putPhotoJobImage?: (input: {
      jobId: string;
      imageIndex: number;
      file: File;
    }) => Promise<unknown>;
    submitPhotoJob?: (jobId: string) => Promise<unknown>;
    confirmPhotoJobTraits?: (
      jobId: string,
      input: {
        confirmations: Array<{
          trait_id: string;
          text_ko: string;
          source_candidate_id: string | null;
          included: boolean;
        }>;
      },
    ) => Promise<unknown>;
  };
  onNoPhoto: () => void;
  onJobCreated?: (jobId: string) => void;
  onConfirmed?: (confirmed: ConfirmedTrait[], jobId: string) => void;
  onMoodConfirmed?: (confirmed: ConfirmedMood, jobId: string) => void;
}) {
  const [state, setState] = useState<FlowState>("entry");
  const [consentChecked, setConsentChecked] = useState(false);
  const [consentError, setConsentError] = useState(false);
  const [rows, setRows] = useState<SelectedPhoto[]>([]);
  const [problem, setProblem] = useState<PreflightProblem | null>(null);
  const [emptyError, setEmptyError] = useState(false);
  const [uploadOrdinal, setUploadOrdinal] = useState(0);
  const [uploadTotal, setUploadTotal] = useState(0);
  const [jobId, setJobId] = useState<string | null>(null);
  const [snapshot, setSnapshot] = useState<PhotoJobSnapshotLike | null>(null);
  const [fallback, setFallback] = useState<FallbackKind | null>(null);
  const [candidates, setCandidates] = useState<PhotoTraitCandidatePayload | null>(null);
  const [analysisFamily, setAnalysisFamily] = useState<"photo-mood-v1" | null>(null);
  const [moodReview, setMoodReview] = useState<MoodReview | null>(null);
  const moodLoadRef = useRef<string | null>(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const deleteTriggerRef = useRef<HTMLButtonElement | null>(null);
  const [storageNotice, setStorageNotice] = useState(false);
  const [announce, setAnnounce] = useState("");
  const [confirmAnnounced, setConfirmAnnounced] = useState(false);
  const [confirmError, setConfirmError] = useState(false);
  const [pollGate, setPollGate] = useState(false);
  const journeyAnnouncements = useJourneyAnnouncements();

  const summaryRef = useRef<HTMLDivElement | null>(null);
  const pickerHeadingRef = useRef<HTMLHeadingElement>(null);
  const pollingFocusRef = useRef<HTMLSpanElement>(null);
  const fallbackHeadingRef = useRef<HTMLHeadingElement>(null);
  const submitGenerationRef = useRef(0);
  const durableJobIdRef = useRef<string | null>(null);
  const objectUrlRef = useRef<Set<string>>(new Set());
  const uploadingRef = useRef(false);

  const revokeAll = useCallback(() => {
    for (const url of objectUrlRef.current) URL.revokeObjectURL(url);
    objectUrlRef.current = new Set();
  }, []);

  useEffect(() => revokeAll, [revokeAll]);
  useEffect(() => () => { submitGenerationRef.current += 1; }, []);

  useLayoutEffect(() => {
    if (problem !== null || emptyError) summaryRef.current?.focus();
  }, [problem, emptyError]);

  useLayoutEffect(() => {
    if (state === "polling") pollingFocusRef.current?.focus();
  }, [state]);

  const trackRow = useCallback((row: SelectedPhoto) => {
    if (row.previewUrl !== "") objectUrlRef.current.add(row.previewUrl);
  }, []);

  const handleIngest = (files: File[]) => {
    const result = validateIngestion(rows, files);
    for (const row of result.rows) trackRow(row);
    setRows(result.rows);
    // Row-level rejections surface the replace action in the summary; the
    // validation detail stays on the affected row (ordinal-only copy).
    setProblem(
      result.problem ??
        (result.rows.some((row) => row.error !== null)
          ? { kind: "row", message: PICKER_COPY.emptyBody }
          : null),
    );
    setEmptyError(false);
  };

  const handleRemove = (rowId: string) => {
    const target = rows.find((row) => row.rowId === rowId);
    if (target !== undefined && target.previewUrl !== "") {
      URL.revokeObjectURL(target.previewUrl);
      objectUrlRef.current.delete(target.previewUrl);
    }
    const remaining = rows
      .filter((row) => row.rowId !== rowId)
      .map((row, index) => ({ ...row, ordinal: index + 1 }));
    setRows(remaining);
    if (problem?.kind === "aggregate" && remaining.length > 0) {
      const total = remaining
        .filter((row) => row.error === null)
        .reduce((sum, row) => sum + row.bytes, 0);
      const over =
        remaining.some((row) => row.error !== null) || total > 20 * 1024 * 1024;
      setProblem(over ? problem : null);
    } else {
      setProblem(null);
    }
    setEmptyError(false);
  };

  const allValid =
    problem === null &&
    rows.length >= 1 &&
    rows.length <= 3 &&
    rows.every((row) => row.error === null);

  const enterConsent = () => {
    setState("consent_unchecked");
    setConsentChecked(false);
    setConsentError(false);
  };

  const toggleConsent = (checked: boolean) => {
    setConsentChecked(checked);
    if (checked) setConsentError(false);
    setState(checked ? "consent_ready" : "consent_unchecked");
  };

  const continueConsent = () => {
    if (!consentChecked) {
      setConsentError(true);
      return;
    }
    setConsentError(false);
    setRows([]);
    setProblem(null);
    setEmptyError(false);
    setState("preflight_empty");
    window.setTimeout(() => pickerHeadingRef.current?.focus(), 0);
  };

  const restart = () => {
    revokeAll();
    setRows([]);
    setProblem(null);
    setEmptyError(false);
    setSnapshot(null);
    setCandidates(null);
    setMoodReview(null);
    setAnalysisFamily(null);
    moodLoadRef.current = null;
    setFallback(null);
    setJobId(null);
    durableJobIdRef.current = null;
    setUploadOrdinal(0);
    setUploadTotal(0);
    setState("consent_unchecked");
    setConsentChecked(false);
    setConsentError(false);
  };

  const goNoPhoto = () => {
    submitGenerationRef.current += 1;
    revokeAll();
    const durableJobId = durableJobIdRef.current ?? jobId;
    if (durableJobId !== null) {
      clearPhotoDraft();
      void client.requestPhotoDeletion?.(durableJobId).catch(() => undefined);
    }
    onNoPhoto();
  };

  const startUpload = async () => {
    if (!allValid || uploadingRef.current) return;
    uploadingRef.current = true;
    const generation = submitGenerationRef.current;
    setState("uploading");
    setUploadTotal(rows.length);
    let createdJobId: string | null = null;
    let analysisRequested = false;
    try {
      const created = await client.createPhotoJob({
        consent_accepted: true,
        consent_version: noticeVersion,
      });
      createdJobId = created.job_id;
      durableJobIdRef.current = created.job_id;
      if (generation !== submitGenerationRef.current) {
        void client.requestPhotoDeletion?.(created.job_id).catch(() => undefined);
        return;
      }
      setJobId(created.job_id);
      if (created.analysis_family !== undefined && created.analysis_family !== "photo-mood-v1") throw new Error("unsupported photo family");
      setAnalysisFamily(created.analysis_family ?? null);
      const stored = writePhotoDraft({
        jobId: created.job_id,
        profileId,
        noticeVersion,
      });
      setStorageNotice(stored.state === "memory-fallback");
      const files = rows.map((row) => row.file);
      for (let index = 0; index < files.length; index += 1) {
        if (generation !== submitGenerationRef.current) return;
        setUploadOrdinal(index + 1);
        await client.putPhotoJobImage?.({
          jobId: created.job_id,
          imageIndex: index + 1,
          file: files[index]!,
        });
      }
      if (generation !== submitGenerationRef.current) return;
      revokeAll();
      analysisRequested = true;
      await client.submitPhotoJob?.(created.job_id);
      if (generation !== submitGenerationRef.current) return;
      setUploadOrdinal(0);
      setState("polling");
      onJobCreated?.(created.job_id);
    } catch {
      if (generation !== submitGenerationRef.current) return;
      setUploadOrdinal(0);
      setFallback(createdJobId === null ? "providerUnavailable" : analysisRequested ? "analysisFailed" : "uploadUncertainty");
      setState("fallback");
    } finally {
      uploadingRef.current = false;
    }
  };

  const fetchJobState = useCallback(
    async (signal: AbortSignal): Promise<PhotoJobSnapshotLike> => {
      const raw = await client.getPhotoJob(jobId ?? "");
      if (signal.aborted) throw new DOMException("aborted", "AbortError");
      const parsed = parseSnapshot(raw);
      if (parsed === null) {
        const malformed = new Error("malformed") as Error & { malformed?: boolean };
        malformed.malformed = true;
        throw malformed;
      }
      return parsed;
    },
    [client, jobId],
  );

  const onTimeout = useCallback(() => {
    setFallback("timeout");
    setState("fallback");
  }, []);

  const onMalformed = useCallback(() => {
    setFallback("unknown");
    setState("fallback");
  }, []);

  const onPollError = useCallback(() => {
    setFallback("pollError");
    setState("fallback");
  }, []);

  const polledSnapshot = usePhotoJobPolling({
    jobId: jobId ?? "",
    fetchJobState,
    onAnnounce: (message) => setAnnounce(message),
    onTimeout,
    onMalformed,
    onError: onPollError,
    enabled: jobId !== null && state === "polling" && pollGate,
  });

  // Adopt polled snapshots into flow state for rendering and transitions.
  useEffect(() => {
    if (polledSnapshot === null || polledSnapshot === snapshot) return;
    setSnapshot(polledSnapshot);
  }, [polledSnapshot, snapshot]);

  // Polling starts one deferral after the polling screen mounts, so the
  // queued status is visible before the first status request.
  useEffect(() => {
    if (state !== "polling") {
      if (pollGate) setPollGate(false);
      return;
    }
    const timer = window.setTimeout(() => setPollGate(true), 0);
    return () => window.clearTimeout(timer);
  }, [state, pollGate]);

  // Reload recovery: adopt the bounded opaque session reference only when a
  // real session record names this profile and is fresh. An unavailable
  // browser never blocks entry — the flow shows the nonblocking notice and
  // this instance continues from React state alone. Corrupt/expired/
  // mismatched records clear only the feature key and stay at the original
  // no-photo-first entry without probing other jobs or claiming cleanup.
  const resumeAdoptedRef = useRef(false);
  useEffect(() => {
    if (resumeAdoptedRef.current || state !== "entry") return;
    resumeAdoptedRef.current = true;
    const read = readPhotoDraft(profileId);
    if (read.state === "valid") {
      durableJobIdRef.current = read.record.job_id;
      setJobId(read.record.job_id);
      setState("polling");
      return;
    }
    if (read.state === "unavailable") {
      setStorageNotice(true);
      if (read.record !== null) {
        durableJobIdRef.current = read.record.job_id;
        setJobId(read.record.job_id);
        setState("polling");
        return;
      }
      if (startAtConsent) setState("consent_unchecked");
      return;
    }
    if (read.state === "empty") {
      if (startAtConsent) setState("consent_unchecked");
      return;
    }
    // corrupt | expired | profile_mismatch: the storage layer already cleared
    // the feature key; embedded entry returns to consent without probing jobs.
    clearPhotoDraft();
    setState(startAtConsent ? "consent_unchecked" : "entry");
  }, [profileId, startAtConsent, state]);

  // Focus the fallback heading once per fallback entry (failed/unknown);
  // polling itself never steals focus.
  const focusFallback =
    fallback === "providerUnavailable" || fallback === "analysisFailed" || fallback === "unknown";
  useEffect(() => {
    if (!focusFallback || state !== "fallback") return;
    fallbackHeadingRef.current?.focus();
  }, [focusFallback, state, fallback]);

  // React to snapshot transitions. The snapshot is retained so a terminal
  // transition stays rendered inside its fallback shell.
  useEffect(() => {
    if (snapshot === null) return;
    if (state !== "polling" && state !== "fallback") return;
    if (snapshot.state === "succeeded") {
      if (snapshot.analysis_family === "photo-mood-v1" || analysisFamily === "photo-mood-v1") {
        if (state !== "polling" || moodLoadRef.current === snapshot.job_id) return;
        moodLoadRef.current = snapshot.job_id;
        const generation = submitGenerationRef.current;
        if (!client.getPhotoJobMoods) {
          setFallback("unknown"); setState("fallback"); return;
        }
        void client.getPhotoJobMoods(snapshot.job_id).then(async (raw) => {
          const parsed = moodReviewSchema.safeParse(raw);
          if (!parsed.success || parsed.data.job_id !== snapshot.job_id || parsed.data.preference_profile_id !== profileId ||
            !await validateMoodReview(parsed.data)) throw new Error("invalid mood review");
          if (generation !== submitGenerationRef.current) return;
          setMoodReview(parsed.data); setAnalysisFamily("photo-mood-v1"); setState("mood_review");
        }).catch(() => {
          if (generation !== submitGenerationRef.current) return;
          setFallback("unknown"); setState("fallback");
        });
        return;
      }
      if (isValidCandidatePayload(snapshot.trait_candidates)) {
        setCandidates(snapshot.trait_candidates);
        setState("review");
        return;
      }
      if (state === "polling" && client.getPhotoJobTraits !== undefined) {
        void client.getPhotoJobTraits(snapshot.job_id).then((raw) => {
          const payload = raw as { candidates?: Array<Record<string, unknown>> };
          const traits = payload.candidates?.map((row) => ({
            candidate_id: String(row.candidate_id ?? ""),
            trait_id: String(row.trait_id ?? ""),
            text_ko: String(row.text_ko ?? ""),
            origin: "MODEL_SUGGESTION",
          }));
          const adapted = {
            schema_version: "photo-trait-candidates-v1",
            authority_scope: "CANDIDATE_EVIDENCE_ONLY",
            traits: traits ?? [],
          };
          if (isValidCandidatePayload(adapted)) {
            setCandidates(adapted);
            setState("review");
          } else {
            setFallback("unknown");
            setState("fallback");
          }
        }).catch(() => {
          setFallback("unknown");
          setState("fallback");
        });
      } else if (state === "polling") {
        setFallback("unknown");
        setState("fallback");
      }
      return;
    }
    if (state !== "polling") return;
    if (snapshot.state === "failed") {
      setFallback("analysisFailed");
      setState("fallback");
      return;
    }
    if (snapshot.state === "expired") {
      setFallback("expired");
      setState("fallback");
      return;
    }
    if (snapshot.state === "deleted") {
      const verified =
        snapshot.deletion?.residue_verified === true &&
        snapshot.deletion?.ledger_recorded === true;
      setFallback(verified ? "deletedVerified" : "deletePending");
      setState("fallback");
    }
  }, [client, snapshot, state, analysisFamily, profileId]);

  const confirmMoods = async (input: MoodConfirmationInput) => {
    if (!client.confirmPhotoJobMoods || !jobId || !moodReview) throw new Error("mood confirmation unavailable");
    const generation = submitGenerationRef.current;
    const stored = moodReview.confirmation;
    const selected = input.choices.filter((row) => row.included).map((row) => row.candidate_id).sort();
    if (stored && JSON.stringify(selected) !== JSON.stringify(stored.choices.filter((row) => row.included).map((row) => row.candidate_id).sort())) {
      throw new Error("stored mood selection cannot change");
    }
    const parsed = confirmedMoodSchema.safeParse(stored ?? await client.confirmPhotoJobMoods(jobId, input));
    if (!parsed.success || !await validateMoodConfirmation(parsed.data, moodReview) ||
      parsed.data.job_id !== jobId || parsed.data.preference_profile_id !== profileId) throw new Error("invalid mood confirmation");
    if (!stored && JSON.stringify(parsed.data.choices) !== JSON.stringify([...input.choices].sort((a, b) => a.candidate_id.localeCompare(b.candidate_id)))) throw new Error("mood confirmation differs from the chosen draft");
    if (generation !== submitGenerationRef.current) return;
    setMoodReview((previous) => previous ? { ...previous, confirmation: parsed.data } : previous);
    onMoodConfirmed?.(parsed.data, jobId);
    const count = parsed.data.moods.filter((row) => row.value !== null).length;
    setAnnounce(count ? `사진 분위기 ${count}개를 직접 확정했어요.` : "사진 분위기 없이 설문 기준으로 계속해요.");
    setConfirmAnnounced(true);
  };

  // The batch CTA is the single caller of the explicit confirm POST; edits,
  // blurs, Enter, and navigation never reach this path. Only included,
  // nonempty explicitly confirmed values are sent.
  const confirmTraits = async (confirmed: ConfirmedTrait[]) => {
    setConfirmError(false);
    if (client.confirmPhotoJobTraits === undefined) {
      setConfirmError(true);
      return;
    }
    try {
      await client.confirmPhotoJobTraits(jobId ?? "", {
        confirmations: confirmed.map((trait) => ({
          trait_id: trait.trait_id,
          text_ko: trait.text_ko,
          source_candidate_id: trait.source_candidate_id,
          included: trait.included,
        })),
      });
    } catch {
      setConfirmError(true);
      return;
    }
    onConfirmed?.(confirmed, jobId ?? "");
    setAnnounce(`사진 취향 ${confirmed.length}개를 직접 확정했어요.`);
    setConfirmAnnounced(true);
  };

  const requestDeletion = async (): Promise<boolean> => {
    try {
      const result =
        fallback === "deletePending"
          ? await client.getPhotoJob(jobId ?? "")
          : await client.requestPhotoDeletion?.(jobId ?? "");
      const parsed = typeof result === "object" && result !== null ? result as Record<string, unknown> : null;
      const deletion = parsed?.deletion;
      const verified =
        (parsed?.residue_verified === true && parsed?.ledger_recorded === true) ||
        (typeof deletion === "object" &&
          deletion !== null &&
          (deletion as Record<string, unknown>).residue_verified === true &&
          (deletion as Record<string, unknown>).ledger_recorded === true);
      setFallback(verified ? "deletedVerified" : "deletePending");
      setState("fallback");
      return true;
    } catch {
      // The deletion request itself is uncertain: keep the dialog open with
      // the bounded failure copy; the no-photo journey stays available.
      setAnnounce(DELETE_COPY.failure);
      return false;
    }
  };

  if (state === "entry") {
    return (
      <article className="profile-state" style={{ padding: "var(--space-lg)" }}>
        <p className="eyebrow">선택 사진 취향</p>
        <h1 tabIndex={-1}>사진으로 이번 여행 취향을 더할까요?</h1>
        <p>
          선택 사항이에요. 사진 없이도 지금 만든 기대 프로필로 추천 5곳을 바로 볼 수 있어요.
        </p>
        <div style={{ display: "grid", gap: "var(--space-sm)", marginTop: "var(--space-md)" }}>
          <button type="button" className="button button--primary" onClick={goNoPhoto}>
            사진 없이 추천 5곳 보기
          </button>
          <button type="button" className="button button--secondary" onClick={enterConsent}>
            사진으로 취향 더하기
          </button>
        </div>
      </article>
    );
  }

  if (state === "consent_unchecked" || state === "consent_ready") {
    return (
      <PhotoConsentPanel
        checked={consentChecked}
        error={consentError}
        headingLevel={consentHeadingLevel}
        onToggle={toggleConsent}
        onContinue={continueConsent}
      >
        <button
          type="button"
          className="button button--secondary"
          style={{ width: "100%", marginTop: "var(--space-sm)" }}
          onClick={goNoPhoto}
        >
          사진 없이 추천 5곳 보기
        </button>
      </PhotoConsentPanel>
    );
  }

  if (state === "preflight_empty" || state === "preflight_partial" || state === "preflight_ready") {
    const submitDisabled = !allValid;
    return (
      <>
        <PhotoPreflightPicker
          rows={rows}
          problem={problem}
          emptyError={emptyError}
          summaryRef={summaryRef}
          headingRef={pickerHeadingRef}
          onIngest={handleIngest}
          onRemove={handleRemove}
          onReplace={() => {
            revokeAll();
            setRows([]);
            setProblem(null);
            setEmptyError(false);
          }}
        >
          {rows.length === 0 && emptyError !== true ? null : null}
        </PhotoPreflightPicker>
        <div className="start-action-bar" style={{ position: "static", padding: 0, border: 0, background: "transparent" }}>
          <button type="button" className="button button--secondary" onClick={goNoPhoto}>
            사진 없이 추천 5곳 보기
          </button>
          <button
            type="button"
            className="button button--primary"
            disabled={submitDisabled}
            aria-label={`사진 ${rows.length}장 분석 시작하기`}
            onClick={() => void startUpload()}
          >
            {/* Ordinal lives in its own span so no single text node carries
                "사진 N" — substring text queries must stay unique per row. */}
            <span>사진</span>
            <span> {rows.length}장 분석 시작하기</span>
          </button>
        </div>
      </>
    );
  }

  if (state === "uploading") {
    return (
      <article className="profile-state" aria-busy="true" style={{ padding: "var(--space-lg)" }}>
        <h1 tabIndex={-1}>사진 분석을 준비하고 있어요.</h1>
        <p role="status" aria-live="polite" aria-atomic="true">
          {uploadOrdinal > 0 ? `사진 ${uploadOrdinal} / ${uploadTotal}장 보내는 중` : "사진을 준비하고 있어요."}
        </p>
        <div className="profile-loading" aria-hidden="true">
          <span />
          <span />
          <span />
        </div>
        <button type="button" className="button button--secondary" onClick={goNoPhoto}>
          사진 없이 추천 5곳 보기
        </button>
      </article>
    );
  }

  if (state === "polling") {
    return (
      <>
        <span ref={pollingFocusRef} tabIndex={-1} className="visually-hidden" />
        {snapshot !== null ? (
          <PhotoJobStatus state={snapshot.state} />
        ) : (
          <PhotoJobStatus state="queued" />
        )}
        {storageNotice ? <PhotoStorageNotice /> : null}
        {journeyAnnouncements !== null ? (
          <p className="visually-hidden" role="status" aria-live="polite" aria-atomic="true">
            {announce}
          </p>
        ) : null}
        <div className="start-action-bar" style={{ position: "static", padding: 0, border: 0, background: "transparent" }}>
          <button type="button" className="button button--secondary" onClick={goNoPhoto}>
            사진 없이 추천 5곳 보기
          </button>
          <button
            ref={deleteTriggerRef}
            type="button"
            className="button button--text-destructive"
            onClick={() => setDeleteDialogOpen(true)}
          >
            {DELETE_COPY.trigger}
          </button>
        </div>
        <PhotoDeleteDialog
          open={deleteDialogOpen}
          onClose={() => setDeleteDialogOpen(false)}
          onConfirm={() => requestDeletion()}
          triggerRef={deleteTriggerRef}
        />
      </>
    );
  }

  if (state === "mood_review" && moodReview !== null) {
    return <>
      <PhotoMoodConfirmation review={moodReview} onConfirm={confirmMoods} onSkip={goNoPhoto} />
      {confirmAnnounced && <p role="status" className="privacy-note">{announce}</p>}
      <button ref={deleteTriggerRef} type="button" className="button button--text-destructive" onClick={() => setDeleteDialogOpen(true)}>{DELETE_COPY.trigger}</button>
      <PhotoDeleteDialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)} onConfirm={() => requestDeletion()} triggerRef={deleteTriggerRef} />
    </>;
  }

  if (state === "review" && candidates !== null) {
    return (
      <>
        <span ref={pollingFocusRef} tabIndex={-1} className="visually-hidden" />
        <PhotoTraitReview
          candidates={candidates}
          onConfirm={confirmTraits}
          onNoPhoto={goNoPhoto}
        />
        {confirmError ? (
          <p role="alert" className="privacy-note">
            확정한 사진 취향을 저장하지 못했어요. 다시 시도해 주세요.
          </p>
        ) : null}
        {journeyAnnouncements !== null ? (
          <p className="visually-hidden" role="status" aria-live="polite" aria-atomic="true">
            {announce}
          </p>
        ) : null}
        {confirmAnnounced ? (
          <p role="status" aria-live="polite" aria-atomic="true" className="privacy-note">
            {announce}
          </p>
        ) : null}
        <div className="start-action-bar" style={{ position: "static", padding: 0, border: 0, background: "transparent" }}>
          <button
            ref={deleteTriggerRef}
            type="button"
            className="button button--text-destructive"
            onClick={() => setDeleteDialogOpen(true)}
          >
            {DELETE_COPY.trigger}
          </button>
        </div>
        <PhotoDeleteDialog
          open={deleteDialogOpen}
          onClose={() => setDeleteDialogOpen(false)}
          onConfirm={() => requestDeletion()}
          triggerRef={deleteTriggerRef}
        />
      </>
    );
  }

  // Fallbacks: every path keeps the full-size no-photo continuation available
  // and never awaits cleanup. Terminal server states render the closed public
  // heading with the bounded recovery copy; transport-level fallbacks render
  // their own heading. `failed` is the single alert role and focuses its
  // heading exactly once.
  const isFailed = fallback === "providerUnavailable" || fallback === "analysisFailed";
  const isUnknown = fallback === "unknown";
  const fallbackCopy = ((): { text: string; restart?: boolean; refresh?: boolean } => {
    switch (fallback) {
      case "expired":
        return { text: PHOTO_FALLBACK_COPY.expired, restart: true };
      case "deletePending":
        return { text: PHOTO_FALLBACK_COPY.deletePending, refresh: true };
      case "deletedVerified":
        return { text: PHOTO_FALLBACK_COPY.deletedVerified };
      case "uploadUncertainty":
        return { text: PHOTO_FALLBACK_COPY.uploadUncertainty };
      case "pollError":
        return { text: PHOTO_FALLBACK_COPY.pollError };
      case "timeout":
        return { text: PHOTO_FALLBACK_COPY.timeout };
      case "unknown":
        return { text: PHOTO_FALLBACK_COPY.unknown };
      case "analysisFailed":
        return { text: PHOTO_STATUS_COPY.failed.body };
      case "providerUnavailable":
      default:
        return { text: PHOTO_FALLBACK_COPY.storageProviderUnavailable };
    }
  })();

  const headingText =
    fallback === "deletePending" || fallback === "deletedVerified"
      ? PHOTO_STATUS_COPY.deleted.heading
      : isFailed
        ? PHOTO_STATUS_COPY.failed.heading
        : fallbackCopy.text;

  return (
    <article
      className="profile-state"
      data-photo-status={fallback ?? undefined}
      role={isFailed || isUnknown ? "alert" : "status"}
      aria-live="polite"
      aria-atomic="true"
      style={{ padding: "var(--space-lg)" }}
    >
      <h1 ref={focusFallback ? fallbackHeadingRef : undefined} tabIndex={-1}>
        {headingText}
      </h1>
      {headingText !== fallbackCopy.text ? <p>{fallbackCopy.text}</p> : null}
      {fallbackCopy.restart ? (
        <button
          type="button"
          className="button button--secondary"
          style={{ width: "100%" }}
          onClick={restart}
        >
          {PHOTO_FALLBACK_COPY.restart}
        </button>
      ) : null}
      {fallbackCopy.refresh ? (
        <button
          type="button"
          className="button button--secondary"
          style={{ width: "100%" }}
          onClick={() => void requestDeletion()}
        >
          {PHOTO_FALLBACK_COPY.refreshDeletion}
        </button>
      ) : null}
      {storageNotice ? <PhotoStorageNotice /> : null}
      {announce !== "" && journeyAnnouncements !== null ? (
        <p className="visually-hidden" role="status" aria-live="polite" aria-atomic="true">
          {announce}
        </p>
      ) : null}
      <button
        type="button"
        className="button button--primary"
        style={{ width: "100%", marginTop: "var(--space-md)" }}
        onClick={goNoPhoto}
      >
        사진 없이 추천 5곳 보기
      </button>
    </article>
  );
}
