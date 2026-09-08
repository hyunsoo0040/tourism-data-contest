import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import type { ComponentType } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * Controlled-RED Phase 6 browser contract (Wave 0).
 *
 * This file freezes the optional-photo preference and privacy lifecycle BEFORE
 * any production component exists. Every test resolves its Phase 6 owner
 * through a runtime dynamic import, so:
 *   - vitest discovers, transforms, and collects this file successfully, and
 *   - execution fails ONLY because the planned production owners are absent
 *     (each failure names the absent owner module).
 *
 * Synthetic adapters only: no provider clients, no credentials, no restricted
 * files, no network. The photo-job client is always injected by the test.
 */

type PhotoJobPublicState =
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "expired"
  | "deleted";

type PhotoJobSnapshot = {
  job_id: string;
  state: PhotoJobPublicState | string;
  uploaded_count?: number;
  selected_count?: number;
  trait_candidates?: unknown;
  deletion?: { residue_verified: boolean; ledger_recorded: boolean } | null;
};

type SyntheticPhotoClient = {
  createPhotoJob: ReturnType<typeof vi.fn>;
  getPhotoJob: ReturnType<typeof vi.fn>;
  requestPhotoDeletion: ReturnType<typeof vi.fn>;
  confirmPhotoJobTraits: ReturnType<typeof vi.fn>;
};

type PhotoOwners = {
  PhotoPreferenceChoice: ComponentType<Record<string, unknown>>;
  PhotoPreferenceFlow: ComponentType<Record<string, unknown>>;
  PhotoJobStatus: ComponentType<Record<string, unknown>>;
  PhotoRecommendationProvenance: ComponentType<Record<string, unknown>>;
  usePhotoJobPolling: (options: Record<string, unknown>) => unknown;
};

/**
 * Planned Phase 6 owner modules. The runtime-computed specifier plus
 * `@vite-ignore` keeps Vite from statically resolving them at transform time,
 * so collection succeeds while the owners are absent; the module runner then
 * resolves each one at test runtime, and a missing owner fails the individual
 * test (naming the owner) instead of blocking collection. Anchoring against
 * `import.meta.url` keeps resolution correct once the owners are implemented.
 */
const OWNER_SPECS = {
  flow: "PhotoPreferenceFlow",
  choice: "PhotoPreferenceChoice",
  status: "PhotoJobStatus",
  provenance: "PhotoRecommendationProvenance",
  polling: "usePhotoJobPolling",
} as const;

async function importOwner(basename: string): Promise<Record<string, unknown>> {
  // String concat (not `new URL(template)`) avoids Vite rewriting asset-style
  // URL templates; the runner then resolves the owner at test runtime.
  const specifier = import.meta.url.replace(/[^/]*$/, basename);
  return (await import(/* @vite-ignore */ specifier)) as Record<string, unknown>;
}

let ownersCache: PhotoOwners | null = null;

async function importPhotoOwners(): Promise<PhotoOwners> {
  if (ownersCache === null) {
    const [flow, choice, status, provenance, polling] = await Promise.all([
      importOwner(OWNER_SPECS.flow),
      importOwner(OWNER_SPECS.choice),
      importOwner(OWNER_SPECS.status),
      importOwner(OWNER_SPECS.provenance),
      importOwner(OWNER_SPECS.polling),
    ]);
    ownersCache = {
      PhotoPreferenceFlow: flow.PhotoPreferenceFlow as ComponentType<Record<string, unknown>>,
      PhotoPreferenceChoice: choice.PhotoPreferenceChoice as ComponentType<Record<string, unknown>>,
      PhotoJobStatus: status.PhotoJobStatus as ComponentType<Record<string, unknown>>,
      PhotoRecommendationProvenance: provenance.PhotoRecommendationProvenance as ComponentType<
        Record<string, unknown>
      >,
      usePhotoJobPolling: polling.usePhotoJobPolling as PhotoOwners["usePhotoJobPolling"],
    };
  }
  return ownersCache;
}

const NOTICE_VERSION = "photo-consent-notice-v1";

const ENTRY_COPY = {
  eyebrow: "선택 사진 취향",
  heading: "사진으로 이번 여행 취향을 더할까요?",
  body: "선택 사항이에요. 사진 없이도 지금 만든 기대 프로필로 추천 5곳을 바로 볼 수 있어요.",
  noPhoto: "사진 없이 추천 5곳 보기",
  photoPath: "사진으로 취향 더하기",
} as const;

const CONSENT_COPY = {
  heading: "사진 사용 내용을 먼저 확인해 주세요",
  facts: [
    "선택한 사진은 이번 여행에서 선호하는 분위기와 경험 후보를 찾는 데만 사용해요.",
    "지원 형식과 크기, 실제 이미지 여부를 확인한 뒤 새 파일명과 안전한 형식으로 다시 만들어요. 원본 파일명과 위치 정보 같은 EXIF 메타데이터는 분석에 사용하지 않아요.",
    "사진 분석 기능이 별도로 승인되어 켜진 경우, 정제된 사진이 승인된 외부 분석 제공자에게 전송될 수 있어요. 공개 취향 기준과 필요한 최소 작업 식별자만 함께 보내며, 여행 답변·내부 점수·비공개 경로는 보내지 않아요.",
    "원본은 검증과 분석에 필요한 동안만 격리해 두고, 성공·거부·오류·시간 초과·삭제 요청으로 처리가 끝나면 즉시 삭제 절차를 시작해요. 원본 잔존이 0인지 확인되고 삭제 기록이 남은 뒤에만 삭제 완료로 표시해요.",
  ],
  factLabels: ["목적", "처리 범위", "외부 전송 가능성", "최소 보유와 삭제 시점"],
  checkbox: "위 내용을 읽었고, 이 사진들을 이번 여행 취향 분석에 사용하는 데 동의해요.",
  cta: "동의하고 사진 고르기",
  error: "사진 사용 내용을 확인하고 동의해 주세요. 동의하지 않아도 사진 없이 추천을 볼 수 있어요.",
  midJourneyStop:
    "분석 중에도 “사진 사용 중단하고 삭제하기”를 선택할 수 있고, 사진 없이 추천은 기다리지 않고 계속할 수 있어요.",
} as const;

const PICKER_COPY = {
  heading: "분석할 사진을 골라 주세요",
  emptyBody:
    "JPEG, PNG, WEBP 사진을 1–3장 골라 주세요. 각 10MB 이하, 전체 20MB 이하, 해상도 4천만 픽셀 이하만 확인해요.",
  trigger: "사진 고르기",
} as const;

const STATUS_COPY = {
  queued: {
    heading: "사진 분석을 준비하고 있어요.",
    body: "사진을 안전하게 확인했고 분석 순서를 기다리고 있어요. 사진 없이 추천은 언제든 바로 볼 수 있어요.",
    role: "status",
  },
  running: {
    heading: "사진에서 여행 취향 후보를 찾고 있어요.",
    body: "완료 비율을 추측해 표시하지 않아요. 분석이 끝나면 직접 확인할 제안을 보여드릴게요.",
    role: "status",
  },
  succeeded: {
    heading: "원본 사진 삭제를 확인하고 있어요.",
    body: "추천은 사진 없이 바로 계속할 수 있어요. 삭제 확인이 끝나기 전에는 원본이 삭제됐다고 표시하지 않아요.",
    role: "status",
  },
  failed: {
    heading: "사진 분석을 마치지 못했어요.",
    body: "사진 없이 추천을 바로 계속할 수 있어요.",
    role: "alert",
  },
  expired: {
    heading: "사진 작업 시간이 지나 분석을 이어갈 수 없어요.",
    body: "",
    role: "alert",
  },
  deleted: {
    heading: "삭제를 요청했어요.",
    body: "원본 사진이 남지 않았는지 계속 확인하고 있어요.",
    role: "status",
  },
} as const;

const FALLBACK_COPY = {
  uploadUncertainty: "사진을 보내지 못했어요. 다시 시도하거나 사진 없이 추천을 계속해 주세요.",
  storageProviderUnavailable:
    "사진 분석을 지금 사용할 수 없어요. 사진은 외부 분석으로 전송되지 않았어요.",
  timeout:
    "기다리는 시간이 길어 사진 분석을 중단했어요. 사진 없이 추천을 바로 계속할 수 있어요.",
  expired: "사진 작업 시간이 지나 분석을 이어갈 수 없어요.",
  restart: "새 사진으로 다시 시작하기",
  deletedVerified: "원본 사진과 이 작업의 분석 제안을 삭제했어요.",
  deletePending: "삭제를 요청했어요. 원본 사진이 남지 않았는지 계속 확인하고 있어요.",
  refreshDeletion: "삭제 상태 다시 확인",
  pollError: "사진 진행 상태를 확인하지 못했어요. 연결을 확인하거나 사진 없이 추천을 계속해 주세요.",
  unknown:
    "사진 작업 상태를 확인하지 못했어요. 분석 결과를 사용하지 않고 사진 없이 계속해 주세요.",
  directEntry: "이 사진 작업을 다시 확인할 수 없어요. 사진 없이 추천을 계속해 주세요.",
  storageUnavailable:
    "이 브라우저에 사진 진행 상태를 저장하지 못했어요. 이 탭에서는 계속할 수 있지만, 화면을 닫으면 다시 이어서 확인하지 못할 수 있어요. 사진 파일은 브라우저 저장소에 보관하지 않아요.",
} as const;

const REVIEW_COPY = {
  eyebrow: "사진 분석 제안",
  heading: "추천에 반영할 취향을 확인해 주세요",
  body: "아래 내용은 사진 분석이 제안한 후보예요. 수정하거나 빼고, 남긴 내용만 직접 확정해 주세요.",
  suggestedBadge: "분석 제안",
  editedBadge: "내가 수정함",
  confirmedBadge: "확정한 취향",
  excludedBadge: "추천에 반영하지 않음",
  confirmCta: "확정한 취향으로 추천 5곳 보기",
  zeroTagHeading: "반영할 사진 취향을 남기지 않았어요.",
  zeroTagBody:
    "사진 분석 제안을 사용하지 않고, 원래 기대 프로필로 추천을 계속할 수 있어요.",
} as const;

const DELETE_COPY = {
  trigger: "사진 사용 중단하고 삭제하기",
  heading: "사진 사용을 중단할까요?",
  description:
    "선택한 사진과 이 작업의 분석 제안을 삭제하도록 요청하고, 사진 없이 추천을 계속할 수 있어요. 삭제 확인이 끝나면 완료 상태를 알려드릴게요.",
  safe: "계속 사진 사용하기",
  destructive: "사진 삭제 요청하기",
  busy: "삭제 요청 중…",
  failure:
    "삭제 요청을 확인하지 못했어요. 사진 없이 추천은 계속할 수 있고, 서버의 만료·정리 절차는 별도로 진행돼요.",
} as const;

const PROVENANCE_COPY = {
  photo: "직접 확인한 사진 취향을 기대 프로필에 반영해 고른 경주 여행지예요.",
  noPhoto: "사진 없이 만든 기대 프로필로 고른 경주 여행지예요.",
} as const;

const TRAIT_TEXTS = {
  first: "조용한 사찰과 숲길 중심으로 둘러보고 싶어요",
  second: "사진 찍기 좋은 야경 명소도 포함됐으면 해요",
  third: "걷기 편한 코스 위주로 묶어 주세요",
} as const;

const TRAIT_EDIT = "바다 보이는 카페와 야경 산책을 추가해 주세요";
const CONFIRM_ERROR = "확정한 사진 취향을 저장하지 못했어요. 다시 시도해 주세요.";

const SYNTHETIC_CANDIDATES = {
  schema_version: "photo-trait-candidates-v1",
  authority_scope: "CANDIDATE_EVIDENCE_ONLY",
  traits: [
    { trait_id: "candidate-1", text_ko: TRAIT_TEXTS.first, origin: "MODEL_SUGGESTION" },
    { trait_id: "candidate-2", text_ko: TRAIT_TEXTS.second, origin: "MODEL_SUGGESTION" },
    { trait_id: "candidate-3", text_ko: TRAIT_TEXTS.third, origin: "MODEL_SUGGESTION" },
  ],
} as const;

function syntheticClient(): SyntheticPhotoClient {
  return {
    createPhotoJob: vi.fn(async () => ({ job_id: "synthetic-job-1", state: "queued" })),
    getPhotoJob: vi.fn(async () => ({ job_id: "synthetic-job-1", state: "queued" })),
    requestPhotoDeletion: vi.fn(async () => ({
      state: "deleted",
      residue_verified: true,
      ledger_recorded: true,
    })),
    confirmPhotoJobTraits: vi.fn(async () => ({
      confirmed: [],
      included_count: 0,
      job_id: "synthetic-job-1",
      preference_profile_id: "profile-photo-flow",
      state: "succeeded",
    })),
  };
}

function photoFile(
  ordinal: number,
  overrides: { type?: string; bytes?: number; name?: string } = {},
): File {
  const bytes = overrides.bytes ?? 1024;
  return new File([new Uint8Array(bytes)], overrides.name ?? `original-photo-${ordinal}.png`, {
    type: overrides.type ?? "image/png",
  });
}

function setInputFiles(input: HTMLInputElement, files: File[]) {
  Object.defineProperty(input, "files", { value: files, configurable: true });
  fireEvent.change(input);
}

function fileInput(): HTMLInputElement {
  const input = document.querySelector<HTMLInputElement>('input[type="file"]');
  expect(input).toBeTruthy();
  return input as HTMLInputElement;
}

async function renderPhotoFlow(client: SyntheticPhotoClient) {
  const owners = await importPhotoOwners();
  const Flow = owners.PhotoPreferenceFlow;
  const onNoPhoto = vi.fn();
  const onConfirmed = vi.fn();
  const view = render(
    <Flow
      profileId="profile-photo-flow"
      noticeVersion={NOTICE_VERSION}
      client={client}
      onNoPhoto={onNoPhoto}
      onConfirmed={onConfirmed}
    />,
  );
  return { view, onNoPhoto, onConfirmed, client };
}

/**
 * Drain the async upload chain inside act. The submit path is a multi-hop
 * microtask chain (create → storage write → per-image PUT → submit → polling
 * state); without this pump its state updates land in the gap between
 * fireEvent's act scope and the test's next act, producing React
 * "not wrapped in act" warnings. A fixed pump count bounds the drain
 * deterministically — the chain contains no timers, only microtasks.
 */
async function flushUploadChain() {
  await act(async () => {
    for (let drain = 0; drain < 50; drain += 1) {
      await Promise.resolve();
    }
  });
}

async function startConsentAndPickFiles(client: SyntheticPhotoClient, fileCount: number) {
  fireEvent.click(screen.getByRole("button", { name: ENTRY_COPY.photoPath }));
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(screen.getByRole("button", { name: CONSENT_COPY.cta }));
  setInputFiles(
    fileInput(),
    Array.from({ length: fileCount }, (_, index) => photoFile(index + 1)),
  );
  fireEvent.click(screen.getByRole("button", { name: `사진 ${fileCount}장 분석 시작하기` }));
  await flushUploadChain();
}

async function walkToReview(client: SyntheticPhotoClient) {
  vi.useFakeTimers();
  const harness = await renderPhotoFlow(client);

  await startConsentAndPickFiles(client, 2);
  await act(async () => {});

  for (
    let guard = 0;
    guard < 40 &&
    screen.queryByRole("heading", { name: REVIEW_COPY.heading }) === null;
    guard += 1
  ) {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_500);
    });
  }

  expect(screen.getByRole("heading", { name: REVIEW_COPY.heading })).toBeTruthy();
  return harness;
}

/** Polls a succeeded snapshot to its terminal review-or-fallback landing. */
async function walkToActiveJobForReview(client: SyntheticPhotoClient) {
  vi.useFakeTimers();
  const harness = await renderPhotoFlow(client);

  await startConsentAndPickFiles(client, 2);
  await act(async () => {});

  for (
    let guard = 0;
    guard < 40 &&
    screen.queryByRole("heading", { name: REVIEW_COPY.heading }) === null &&
    screen.queryByText(FALLBACK_COPY.unknown, { exact: false }) === null;
    guard += 1
  ) {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_500);
    });
  }
  return harness;
}

function setHidden(hidden: boolean) {
  Object.defineProperty(document, "visibilityState", {
    configurable: true,
    get: () => (hidden ? "hidden" : "visible"),
  });
  document.dispatchEvent(new Event("visibilitychange"));
}

afterEach(async () => {
  // Visibility restoration and any async continuation it triggers must run
  // inside act so mounted polling hooks never update state outside act.
  await act(async () => {
    setHidden(false);
  });
  vi.useRealTimers();
  vi.restoreAllMocks();
  const storage = await import("../../app/storage");
  storage.clearPhotoDraft();
  window.sessionStorage.clear();
  window.localStorage.clear();
});

describe("optional photo entry", () => {
  it("keeps the no-photo journey first-class with exact entry copy and DOM order", async () => {
    const { PhotoPreferenceChoice } = await importPhotoOwners();
    const onNoPhoto = vi.fn();
    const onPhotoPath = vi.fn();
    const { container } = render(
      <PhotoPreferenceChoice onNoPhoto={onNoPhoto} onPhotoPath={onPhotoPath} />,
    );

    expect(screen.getByText(ENTRY_COPY.eyebrow, { exact: false })).toBeTruthy();
    expect(screen.getByRole("heading", { name: ENTRY_COPY.heading, level: 1 })).toBeTruthy();
    expect(screen.getByText(ENTRY_COPY.body, { exact: false })).toBeTruthy();

    const noPhoto = screen.getByRole("button", { name: ENTRY_COPY.noPhoto });
    const photoPath = screen.getByRole("button", { name: ENTRY_COPY.photoPath });
    expect(
      noPhoto.compareDocumentPosition(photoPath) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();

    fireEvent.click(noPhoto);
    expect(onNoPhoto).toHaveBeenCalledOnce();
    fireEvent.click(photoPath);
    expect(onPhotoPath).toHaveBeenCalledOnce();
    expect(onNoPhoto).toHaveBeenCalledTimes(1);

    // Entry never mounts a file control and never writes storage.
    expect(container.querySelectorAll('input[type="file"]')).toHaveLength(0);
    expect(window.sessionStorage.length).toBe(0);
  });
});

describe("consent precedes every file control", () => {
  it("shows four visible privacy facts and an unchecked checkbox before any picker exists", async () => {
    const client = syntheticClient();
    await renderPhotoFlow(client);

    fireEvent.click(screen.getByRole("button", { name: ENTRY_COPY.photoPath }));

    expect(screen.getByRole("heading", { name: CONSENT_COPY.heading, level: 1 })).toBeTruthy();
    for (const fact of CONSENT_COPY.facts) {
      expect(screen.getByText(fact, { exact: false })).toBeTruthy();
    }
    for (const label of CONSENT_COPY.factLabels) {
      expect(screen.getByText(label, { exact: false })).toBeTruthy();
    }
    expect(screen.getByText(CONSENT_COPY.midJourneyStop, { exact: false })).toBeTruthy();

    const checkbox = screen.getByRole("checkbox");
    expect((checkbox as HTMLInputElement).checked).toBe(false);

    // No file control is mounted and no job exists before consent.
    expect(document.querySelectorAll('input[type="file"]')).toHaveLength(0);
    expect(client.createPhotoJob).not.toHaveBeenCalled();
    expect(client.getPhotoJob).not.toHaveBeenCalled();
  });

  it("blocks the consent CTA without checking and starts nothing from the checkbox alone", async () => {
    const client = syntheticClient();
    await renderPhotoFlow(client);

    fireEvent.click(screen.getByRole("button", { name: ENTRY_COPY.photoPath }));

    fireEvent.click(screen.getByRole("button", { name: CONSENT_COPY.cta }));
    expect(screen.getByText(CONSENT_COPY.error, { exact: false })).toBeTruthy();
    expect(document.querySelectorAll('input[type="file"]')).toHaveLength(0);
    expect(client.createPhotoJob).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("checkbox"));
    expect((screen.getByRole("checkbox") as HTMLInputElement).checked).toBe(true);
    expect(document.querySelectorAll('input[type="file"]')).toHaveLength(0);
    expect(client.createPhotoJob).not.toHaveBeenCalled();
    expect(client.getPhotoJob).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: CONSENT_COPY.cta }));
    expect(screen.getByText(CONSENT_COPY.error, { exact: false })).toBeTruthy();
  });

  it("binds the consent facts to the checkbox for assistive tech with a single h1", async () => {
    await renderPhotoFlow(syntheticClient());

    fireEvent.click(screen.getByRole("button", { name: ENTRY_COPY.photoPath }));

    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);

    const checkbox = screen.getByRole("checkbox");
    const describedBy = checkbox.getAttribute("aria-describedby");
    expect(describedBy).toBeTruthy();
    const description = (describedBy ?? "")
      .split(/\s+/)
      .map((id) => document.getElementById(id)?.textContent ?? "")
      .join(" ");
    for (const fact of CONSENT_COPY.facts) {
      expect(description).toContain(fact);
    }
  });
});

describe("preflight accepts exactly one to three validated photos", () => {
  async function openPicker() {
    const client = syntheticClient();
    const { view } = await renderPhotoFlow(client);
    fireEvent.click(screen.getByRole("button", { name: ENTRY_COPY.photoPath }));
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: CONSENT_COPY.cta }));
    expect(screen.getByRole("heading", { name: PICKER_COPY.heading, level: 1 })).toBeTruthy();
    expect(screen.getByText(PICKER_COPY.emptyBody, { exact: false })).toBeTruthy();
    return { client, container: view.container };
  }

  it("shows the empty picker copy and creates no job without files", async () => {
    const { client } = await openPicker();

    expect(screen.getByRole("button", { name: PICKER_COPY.trigger })).toBeTruthy();
    expect(screen.getByRole("button", { name: ENTRY_COPY.noPhoto })).toBeTruthy();
    expect(client.createPhotoJob).not.toHaveBeenCalled();
  });

  it("rejects a fourth file while keeping the first three choices", async () => {
    await openPicker();

    setInputFiles(fileInput(), [
      photoFile(1),
      photoFile(2),
      photoFile(3),
      photoFile(4),
    ]);

    expect(screen.getByText("사진은 한 번에 최대 3장까지 고를 수 있어요.", { exact: false })).toBeTruthy();
    for (const ordinal of [1, 2, 3]) {
      expect(screen.getByText(`사진 ${ordinal}`, { exact: false })).toBeTruthy();
    }
    expect(screen.queryByText("사진 4", { exact: false })).toBeNull();
    expect(screen.getByRole("button", { name: "사진 3장 분석 시작하기" })).toBeTruthy();
  });

  it("marks unsupported types and oversize files by ordinal without ever showing filenames", async () => {
    const { container } = await openPicker();

    setInputFiles(fileInput(), [
      photoFile(1, { bytes: 11 * 1024 * 1024 }),
      photoFile(2, { type: "image/gif" }),
    ]);

    expect(screen.getByText("사진 1은 10MB보다 커요.", { exact: false })).toBeTruthy();
    expect(screen.getByText("사진 2은 JPEG, PNG, WEBP 형식이 아니에요.", { exact: false })).toBeTruthy();
    expect(screen.getByText("다른 사진 고르기", { exact: false })).toBeTruthy();
    expect(document.body.textContent).not.toContain("original-photo-1");
    expect(document.body.textContent).not.toContain("original-photo-2");

    const rows = within(container).getAllByRole("listitem");
    expect(rows.length).toBeGreaterThanOrEqual(2);
    expect(rows.some((row) => row.getAttribute("aria-invalid") === "true")).toBe(true);
  });

  it("disables submission for mixed validity and creates no durable job", async () => {
    const { client } = await openPicker();

    setInputFiles(fileInput(), [photoFile(1), photoFile(2, { type: "image/heic" })]);

    expect(screen.getByText("사진 2은 JPEG, PNG, WEBP 형식이 아니에요.", { exact: false })).toBeTruthy();
    const submit = screen.queryByRole("button", { name: "사진 2장 분석 시작하기" });
    expect(submit === null || (submit as HTMLButtonElement).disabled).toBe(true);
    expect(client.createPhotoJob).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: ENTRY_COPY.noPhoto })).toBeTruthy();
  });

  it("keeps the aggregate size bounded at 20MB with recovery actions and no job", async () => {
    const { client } = await openPicker();

    setInputFiles(fileInput(), [
      photoFile(1, { bytes: 8 * 1024 * 1024 }),
      photoFile(2, { bytes: 8 * 1024 * 1024 }),
      photoFile(3, { bytes: 8 * 1024 * 1024 }),
    ]);

    expect(
      screen.getByText(
        "선택한 사진 전체가 20MB보다 커요. 사진을 선택에서 빼거나 더 작은 사진을 골라 주세요.",
        { exact: false },
      ),
    ).toBeTruthy();
    expect(screen.getByRole("button", { name: ENTRY_COPY.noPhoto })).toBeTruthy();
    expect(screen.getAllByRole("button", { name: /선택에서 빼기/ }).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("다른 사진 고르기", { exact: false })).toBeTruthy();
    const submit = screen.getByRole("button", { name: "사진 3장 분석 시작하기" });
    expect((submit as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(submit);
    expect(client.createPhotoJob).not.toHaveBeenCalled();
  });
});

describe("the six public states are the only server truth", () => {
  it.each([
    ["queued", STATUS_COPY.queued],
    ["running", STATUS_COPY.running],
    ["succeeded", STATUS_COPY.succeeded],
    ["failed", STATUS_COPY.failed],
    ["expired", STATUS_COPY.expired],
    ["deleted", STATUS_COPY.deleted],
  ] as const)("renders the exact closed copy for the %s public state", async (state, copy) => {
    const { PhotoJobStatus } = await importPhotoOwners();
    render(<PhotoJobStatus state={state} />);

    expect(screen.getByRole("heading", { name: copy.heading })).toBeTruthy();
    if (copy.body !== "") {
      expect(screen.getByText(copy.body, { exact: false })).toBeTruthy();
    }
    expect(screen.getByRole(copy.role)).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/\d+\s*%/);
  });

  it("shows verified deletion copy only after residue and ledger evidence", async () => {
    const { PhotoJobStatus } = await importPhotoOwners();

    const { unmount } = render(
      <PhotoJobStatus
        state="deleted"
        deletion={{ residue_verified: true, ledger_recorded: true }}
      />,
    );
    expect(screen.getByText(FALLBACK_COPY.deletedVerified, { exact: false })).toBeTruthy();
    unmount();

    render(<PhotoJobStatus state="deleted" deletion={null} />);
    expect(screen.queryByText(FALLBACK_COPY.deletedVerified)).toBeNull();
    expect(screen.getByText(FALLBACK_COPY.deletePending, { exact: false })).toBeTruthy();
  });

  it("renders UI-derived states with closed copy, never fabricated percentages", async () => {
    const { PhotoJobStatus } = await importPhotoOwners();

    const derived: Array<{
      state: string;
      heading: string;
      role: "status" | "alert";
      body?: string;
    }> = [
      {
        state: "uploading",
        heading: STATUS_COPY.queued.heading,
        role: "status",
        body: "사진 1 / 2장 보내는 중",
      },
      { state: "timeout", heading: FALLBACK_COPY.timeout, role: "status" },
      { state: "cleanup_pending", heading: STATUS_COPY.deleted.heading, role: "status" },
      { state: "poll_error", heading: FALLBACK_COPY.pollError, role: "alert" },
      { state: "unknown", heading: FALLBACK_COPY.unknown, role: "alert" },
    ];
    for (const item of derived) {
      const { unmount } = render(
        <PhotoJobStatus state={item.state} fallbackBody={item.body} />,
      );
      expect(
        screen.getByRole("heading", { name: item.heading }),
        `heading for ${item.state}`,
      ).toBeTruthy();
      expect(
        screen.getByRole(item.role),
        `role for ${item.state}`,
      ).toBeTruthy();
      if (item.body !== undefined) {
        expect(screen.getByText(item.body, { exact: false })).toBeTruthy();
      }
      expect(document.body.textContent).not.toMatch(/\d+\s*%/);
      unmount();
    }
  });

  it("falls back to unknown for malformed states without rendering partial candidates", async () => {
    vi.useFakeTimers();
    const client = syntheticClient();
    client.getPhotoJob.mockResolvedValue({
      job_id: "synthetic-job-1",
      state: "QUANTUM_ENRICHED",
    });
    const { onNoPhoto } = await renderPhotoFlow(client);

    await startConsentAndPickFiles(client, 2);
    await act(async () => {});
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_500);
    });

    expect(screen.getByText(FALLBACK_COPY.unknown, { exact: false })).toBeTruthy();
    expect(screen.queryByText(TRAIT_TEXTS.first)).toBeNull();
    expect(screen.queryByText(TRAIT_TEXTS.second)).toBeNull();
    expect(screen.getByRole("button", { name: ENTRY_COPY.noPhoto })).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: ENTRY_COPY.noPhoto }));
    expect(onNoPhoto).toHaveBeenCalledOnce();
  });
});

it("UI-BS-04 polling lifecycle is bounded and deduplicated", async () => {
  const { usePhotoJobPolling } = await importPhotoOwners();
  vi.useFakeTimers();

  function mountPollingHarness(options: {
    fetchJobState: (signal: AbortSignal) => Promise<PhotoJobSnapshot>;
    onTimeout: () => void;
    onAnnounce?: (message: string) => void;
    onMalformed?: () => void;
  }) {
    function Harness() {
      const snapshot = usePhotoJobPolling({
        jobId: "synthetic-job-1",
        fetchJobState: options.fetchJobState,
        onAnnounce: options.onAnnounce ?? vi.fn(),
        onTimeout: options.onTimeout,
        onMalformed: options.onMalformed,
      }) as PhotoJobSnapshot | null;
      return (
        <p role="status" aria-live="polite" aria-atomic="true">
          {snapshot?.state ?? "idle"}
        </p>
      );
    }
    return render(<Harness />);
  }

  // Phase 1 — cadence: an immediate first check, ten checks 1.5s apart, then 3s.
  const cadenceFetch = vi.fn(async () => ({ job_id: "synthetic-job-1", state: "queued" }));
  const cadence = mountPollingHarness({ fetchJobState: cadenceFetch, onTimeout: vi.fn() });
  await act(async () => {});
  expect(cadenceFetch).toHaveBeenCalledTimes(1);
  for (let tick = 2; tick <= 10; tick += 1) {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_500);
    });
    expect(cadenceFetch).toHaveBeenCalledTimes(tick);
  }
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1_500);
  });
  expect(cadenceFetch).toHaveBeenCalledTimes(10);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1_500);
  });
  expect(cadenceFetch).toHaveBeenCalledTimes(11);
  cadence.unmount();

  // Phase 2 — one request maximum: no overlap while a request is in flight.
  let releaseInFlight: () => void = () => undefined;
  const inFlightGate = new Promise<void>((resolve) => {
    releaseInFlight = resolve;
  });
  const slowFetch = vi.fn(
    () =>
      inFlightGate.then(() => ({ job_id: "synthetic-job-1", state: "queued" }) as PhotoJobSnapshot),
  );
  const inFlight = mountPollingHarness({ fetchJobState: slowFetch, onTimeout: vi.fn() });
  await act(async () => {});
  expect(slowFetch).toHaveBeenCalledTimes(1);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(10_000);
  });
  expect(slowFetch).toHaveBeenCalledTimes(1);
  await act(async () => {
    releaseInFlight();
    await inFlightGate;
  });
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1_500);
  });
  expect(slowFetch).toHaveBeenCalledTimes(2);
  inFlight.unmount();

  // Phase 3 — hidden pages pause polling; visibility resumes with an immediate check.
  const visibilityFetch = vi.fn(async () => ({ job_id: "synthetic-job-1", state: "queued" }));
  const paused = mountPollingHarness({ fetchJobState: visibilityFetch, onTimeout: vi.fn() });
  await act(async () => {});
  expect(visibilityFetch).toHaveBeenCalledTimes(1);
  setHidden(true);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(30_000);
  });
  expect(visibilityFetch).toHaveBeenCalledTimes(1);
  setHidden(false);
  await act(async () => {});
  expect(visibilityFetch).toHaveBeenCalledTimes(2);
  paused.unmount();

  // Phase 4 — unmount aborts the in-flight request and stops the cadence.
  const abortSignals: AbortSignal[] = [];
  let releaseAbortable: () => void = () => undefined;
  const abortGate = new Promise<void>((resolve) => {
    releaseAbortable = resolve;
  });
  const abortableFetch = vi.fn((signal: AbortSignal) => {
    abortSignals.push(signal);
    return abortGate.then(
      () => ({ job_id: "synthetic-job-1", state: "queued" }) as PhotoJobSnapshot,
    );
  });
  const abortable = mountPollingHarness({ fetchJobState: abortableFetch, onTimeout: vi.fn() });
  await act(async () => {});
  abortable.unmount();
  await act(async () => {
    releaseAbortable();
    await abortGate;
  });
  expect(abortSignals).toHaveLength(1);
  expect(abortSignals[0]?.aborted).toBe(true);
  const callsAtUnmount = abortableFetch.mock.calls.length;
  await act(async () => {
    await vi.advanceTimersByTimeAsync(30_000);
  });
  expect(abortableFetch).toHaveBeenCalledTimes(callsAtUnmount);

  // Phase 5 — the 60s deadline trips exactly once and stops all further requests.
  const deadlineFetch = vi.fn(async () => ({ job_id: "synthetic-job-1", state: "queued" }));
  const onTimeout = vi.fn();
  mountPollingHarness({ fetchJobState: deadlineFetch, onTimeout });
  await act(async () => {});
  await act(async () => {
    await vi.advanceTimersByTimeAsync(59_500);
  });
  expect(onTimeout).not.toHaveBeenCalled();
  await act(async () => {
    await vi.advanceTimersByTimeAsync(500);
  });
  expect(onTimeout).toHaveBeenCalledTimes(1);
  const callsAtDeadline = deadlineFetch.mock.calls.length;
  await act(async () => {
    await vi.advanceTimersByTimeAsync(10_000);
  });
  expect(deadlineFetch).toHaveBeenCalledTimes(callsAtDeadline);

  // Phase 6 — meaningful transitions announce exactly once, never once per poll.
  const announcements: string[] = [];
  const scripted: PhotoJobSnapshot[] = [
    { job_id: "synthetic-job-1", state: "queued" },
    { job_id: "synthetic-job-1", state: "running" },
  ];
  const transitionFetch = vi.fn(async () =>
    scripted.shift() ?? { job_id: "synthetic-job-1", state: "running" },
  );
  mountPollingHarness({
    fetchJobState: transitionFetch,
    onTimeout: vi.fn(),
    onAnnounce: (message) => announcements.push(message),
  });
  await act(async () => {});
  expect(announcements.filter((message) => message.includes("분석 순서"))).toHaveLength(1);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1_500);
  });
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1_500);
  });
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1_500);
  });
  expect(announcements.filter((message) => message.includes("취향 후보"))).toHaveLength(1);

  // Phase 7 — ownership mismatch: a snapshot naming a different job aborts
  // polling permanently and reports the mismatch exactly once.
  const mismatchFetch = vi.fn(async () =>
    ({ job_id: "synthetic-job-OTHER", state: "queued" }) as PhotoJobSnapshot,
  );
  const onMalformed = vi.fn();
  const mismatchHarness = mountPollingHarness({
    fetchJobState: mismatchFetch,
    onTimeout: vi.fn(),
    onMalformed,
  });
  await act(async () => {});
  expect(onMalformed).toHaveBeenCalledTimes(1);
  const mismatchCalls = mismatchFetch.mock.calls.length;
  await act(async () => {
    await vi.advanceTimersByTimeAsync(10_000);
  });
  expect(mismatchFetch).toHaveBeenCalledTimes(mismatchCalls);
  mismatchHarness.unmount();
});

describe("the optional-photo journey stays synthetic and recoverable", () => {
  it("walks consent, preflight, and polling to trait review with a synthetic client", async () => {
    const client = syntheticClient();
    client.getPhotoJob
      .mockResolvedValueOnce({ job_id: "synthetic-job-1", state: "queued" })
      .mockResolvedValueOnce({ job_id: "synthetic-job-1", state: "running" })
      .mockResolvedValue({
        job_id: "synthetic-job-1",
        state: "succeeded",
        uploaded_count: 2,
        selected_count: 2,
        trait_candidates: SYNTHETIC_CANDIDATES,
      });

    vi.useFakeTimers();
    const { view } = await renderPhotoFlow(client);

    // No-photo authority exists at entry, before any consent interaction.
    expect(screen.getByRole("button", { name: ENTRY_COPY.noPhoto })).toBeTruthy();

    await startConsentAndPickFiles(client, 2);
    await act(async () => {});
    expect(client.createPhotoJob).toHaveBeenCalledTimes(1);

    // Bounded storage reference is written once a durable job exists.
    const photoKeys = Object.keys(window.sessionStorage).filter((key) => key.startsWith("itda."));
    expect(photoKeys).toHaveLength(1);
    const raw = window.sessionStorage.getItem(photoKeys[0]!) ?? "";
    expect(raw.length).toBeLessThanOrEqual(2048);
    const record = JSON.parse(raw) as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      expect(["schema_version", "job_id", "profile_id", "notice_version", "created_at"]).toContain(
        key,
      );
    }
    expect(raw).not.toContain("original-photo");
    expect(raw).not.toContain(TRAIT_TEXTS.first);
    expect(Object.keys(window.localStorage).filter((key) => key.includes("photo"))).toHaveLength(0);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_500);
    });
    expect(screen.getByRole("heading", { name: STATUS_COPY.queued.heading })).toBeTruthy();
    expect(screen.getByRole("status")).toBeTruthy();
    expect(view.container.getAttribute("aria-busy")).toBeNull();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_500);
    });
    expect(screen.getByRole("heading", { name: STATUS_COPY.running.heading })).toBeTruthy();

    for (
      let guard = 0;
      guard < 40 &&
      screen.queryByRole("heading", { name: REVIEW_COPY.heading }) === null;
      guard += 1
    ) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1_500);
      });
    }

    expect(screen.getByText(REVIEW_COPY.eyebrow, { exact: false })).toBeTruthy();
    expect(screen.getByText(REVIEW_COPY.body, { exact: false })).toBeTruthy();
    // Scoped to the semantic review list: the section eyebrow ("사진 분석
    // 제안") legitimately contains the badge substring, so the exact count
    // of three badges is asserted inside the list container only.
    expect(
      within(screen.getByRole("list", { name: "사진 취향 제안 목록" })).getAllByText(
        REVIEW_COPY.suggestedBadge,
        { exact: false },
      ),
    ).toHaveLength(3);
    // Cleanup truth never claims completion before evidence.
    expect(screen.queryByText(FALLBACK_COPY.deletedVerified)).toBeNull();
  });

  it("uses neutral failed copy and starts cleanup without blocking no-photo", async () => {
    vi.useFakeTimers();
    const client = syntheticClient();
    client.getPhotoJob.mockResolvedValue({ job_id: "synthetic-job-1", state: "failed" });
    client.requestPhotoDeletion.mockReturnValue(new Promise(() => undefined));
    const { onNoPhoto } = await renderPhotoFlow(client);

    await startConsentAndPickFiles(client, 2);
    await act(async () => {});
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_500);
    });

    expect(screen.getByRole("heading", { name: STATUS_COPY.failed.heading })).toBeTruthy();
    expect(screen.getByText(STATUS_COPY.failed.body, { exact: false })).toBeTruthy();
    expect(screen.queryByText(FALLBACK_COPY.storageProviderUnavailable, { exact: false })).toBeNull();
    const noPhoto = screen.getByRole("button", { name: ENTRY_COPY.noPhoto });

    fireEvent.click(noPhoto);
    expect(client.requestPhotoDeletion).toHaveBeenCalledWith("synthetic-job-1");
    expect(onNoPhoto).toHaveBeenCalledOnce();
    expect(window.sessionStorage.getItem("itda.phase6.photo-draft.v1")).toBeNull();
  });

  it("treats expiry with bounded copy and a fresh restart action", async () => {
    vi.useFakeTimers();
    const client = syntheticClient();
    client.getPhotoJob.mockResolvedValue({ job_id: "synthetic-job-1", state: "expired" });
    const { onNoPhoto } = await renderPhotoFlow(client);

    await startConsentAndPickFiles(client, 2);
    await act(async () => {});
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_500);
    });

    expect(screen.getByText(FALLBACK_COPY.expired, { exact: false })).toBeTruthy();
    expect(screen.getByRole("button", { name: FALLBACK_COPY.restart })).toBeTruthy();
    const noPhoto = screen.getByRole("button", { name: ENTRY_COPY.noPhoto });
    expect(noPhoto).toBeTruthy();
    fireEvent.click(noPhoto);
    expect(onNoPhoto).toHaveBeenCalledOnce();
  });

  it("returns to an unchecked consent for each new job after restart", async () => {
    vi.useFakeTimers();
    const client = syntheticClient();
    client.getPhotoJob.mockResolvedValue({ job_id: "synthetic-job-1", state: "expired" });
    await renderPhotoFlow(client);

    await startConsentAndPickFiles(client, 1);
    await act(async () => {});
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_500);
    });
    expect(screen.getByText(FALLBACK_COPY.expired, { exact: false })).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: FALLBACK_COPY.restart }));
    expect(screen.getByRole("heading", { name: CONSENT_COPY.heading, level: 1 })).toBeTruthy();
    expect((screen.getByRole("checkbox") as HTMLInputElement).checked).toBe(false);
    expect(document.querySelectorAll('input[type="file"]')).toHaveLength(0);
    expect(client.createPhotoJob).toHaveBeenCalledTimes(1);
  });

  it("derives cleanup_pending until residue and ledger evidence arrive", async () => {
    vi.useFakeTimers();
    const client = syntheticClient();
    client.getPhotoJob.mockResolvedValue({
      job_id: "synthetic-job-1",
      state: "deleted",
      deletion: null,
    });
    await renderPhotoFlow(client);

    await startConsentAndPickFiles(client, 2);
    await act(async () => {});
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_500);
    });

    expect(screen.getByText(FALLBACK_COPY.deletePending, { exact: false })).toBeTruthy();
    expect(screen.queryByText(FALLBACK_COPY.deletedVerified)).toBeNull();
    expect(screen.getByRole("button", { name: FALLBACK_COPY.refreshDeletion })).toBeTruthy();
    expect(screen.getByRole("button", { name: ENTRY_COPY.noPhoto })).toBeTruthy();
  });

  it("requires explicit batch confirmation and keeps provenance distinct in review", async () => {
    const client = syntheticClient();
    client.getPhotoJob
      .mockResolvedValueOnce({ job_id: "synthetic-job-1", state: "queued" })
      .mockResolvedValueOnce({ job_id: "synthetic-job-1", state: "running" })
      .mockResolvedValue({
        job_id: "synthetic-job-1",
        state: "succeeded",
        trait_candidates: SYNTHETIC_CANDIDATES,
      });
    const { onConfirmed } = await walkToReview(client);

    // Scoped to the semantic review list: the section eyebrow ("사진 분석
    // 제안") legitimately contains the badge substring, so the exact count
    // of three badges is asserted inside the list container only.
    expect(
      within(screen.getByRole("list", { name: "사진 취향 제안 목록" })).getAllByText(
        REVIEW_COPY.suggestedBadge,
        { exact: false },
      ),
    ).toHaveLength(3);

    // Editing marks provenance but never confirms.
    const firstInput = screen.getByLabelText(TRAIT_TEXTS.first) as HTMLInputElement;
    expect(firstInput.getAttribute("maxlength")).toBe("24");
    fireEvent.change(firstInput, { target: { value: TRAIT_EDIT } });
    fireEvent.blur(firstInput);
    expect(screen.getAllByText(REVIEW_COPY.editedBadge, { exact: false }).length).toBe(1);
    expect(onConfirmed).not.toHaveBeenCalled();
    fireEvent.keyDown(firstInput, { key: "Enter" });
    expect(onConfirmed).not.toHaveBeenCalled();

    // Exclusion is visible and reversible.
    fireEvent.click(
      screen.getByRole("button", { name: `${TRAIT_TEXTS.second} 제안 빼기` }),
    );
    expect(screen.getAllByText(REVIEW_COPY.excludedBadge, { exact: false }).length).toBe(1);
    fireEvent.click(
      screen.getByRole("button", { name: `${TRAIT_TEXTS.second} 제안 다시 포함하기` }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: `${TRAIT_TEXTS.second} 제안 빼기` }),
    );

    // Only the batch CTA confirms included non-empty values.
    fireEvent.click(screen.getByRole("button", { name: REVIEW_COPY.confirmCta }));
    await act(async () => {});
    expect(onConfirmed).toHaveBeenCalledOnce();
    const confirmed = onConfirmed.mock.calls[0]?.[0] as Array<{ text_ko: string }>;
    expect(confirmed.map((trait) => trait.text_ko)).toEqual([TRAIT_EDIT, TRAIT_TEXTS.third]);
    expect(screen.getByText("사진 취향 2개를 직접 확정했어요.", { exact: false })).toBeTruthy();
  });

  it("keeps edits in review until a confirmation retry succeeds", async () => {
    const client = syntheticClient();
    client.getPhotoJob.mockResolvedValue({
      job_id: "synthetic-job-1",
      state: "succeeded",
      trait_candidates: SYNTHETIC_CANDIDATES,
    });
    client.confirmPhotoJobTraits
      .mockRejectedValueOnce(new Error("synthetic confirmation outage"))
      .mockResolvedValueOnce({ state: "succeeded" });
    const { onConfirmed } = await walkToReview(client);

    const firstInput = screen.getByLabelText(TRAIT_TEXTS.first) as HTMLInputElement;
    fireEvent.change(firstInput, { target: { value: TRAIT_EDIT } });
    fireEvent.click(
      screen.getByRole("button", { name: `${TRAIT_TEXTS.second} 제안 빼기` }),
    );

    fireEvent.click(screen.getByRole("button", { name: REVIEW_COPY.confirmCta }));
    await act(async () => {});

    expect(client.confirmPhotoJobTraits).toHaveBeenCalledTimes(1);
    expect(onConfirmed).not.toHaveBeenCalled();
    expect(screen.getByRole("heading", { name: REVIEW_COPY.heading })).toBeTruthy();
    expect(screen.getByLabelText(TRAIT_EDIT)).toBeTruthy();
    expect(screen.getByText(REVIEW_COPY.excludedBadge, { exact: false })).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toContain(CONFIRM_ERROR);

    fireEvent.click(screen.getByRole("button", { name: REVIEW_COPY.confirmCta }));
    await act(async () => {});

    expect(client.confirmPhotoJobTraits).toHaveBeenCalledTimes(2);
    expect(onConfirmed).toHaveBeenCalledOnce();
    const confirmed = onConfirmed.mock.calls[0]?.[0] as Array<{ text_ko: string }>;
    expect(confirmed.map((trait) => trait.text_ko)).toEqual([TRAIT_EDIT, TRAIT_TEXTS.third]);
    expect(screen.queryByText(CONFIRM_ERROR)).toBeNull();
  });

  it("falls back to the zero-tag state when no confirmed trait remains", async () => {
    const client = syntheticClient();
    client.getPhotoJob
      .mockResolvedValueOnce({ job_id: "synthetic-job-1", state: "queued" })
      .mockResolvedValueOnce({ job_id: "synthetic-job-1", state: "running" })
      .mockResolvedValue({
        job_id: "synthetic-job-1",
        state: "succeeded",
        trait_candidates: SYNTHETIC_CANDIDATES,
      });
    const { onNoPhoto } = await walkToReview(client);

    for (const trait of [TRAIT_TEXTS.first, TRAIT_TEXTS.second, TRAIT_TEXTS.third]) {
      fireEvent.click(screen.getByRole("button", { name: `${trait} 제안 빼기` }));
    }

    expect(screen.getByRole("heading", { name: REVIEW_COPY.zeroTagHeading })).toBeTruthy();
    expect(screen.getByText(REVIEW_COPY.zeroTagBody, { exact: false })).toBeTruthy();
    const noPhoto = screen.getByRole("button", { name: ENTRY_COPY.noPhoto });
    expect(noPhoto).toBeTruthy();
    expect(screen.queryByRole("button", { name: REVIEW_COPY.confirmCta })).toBeNull();

    fireEvent.click(noPhoto);
    expect(onNoPhoto).toHaveBeenCalledOnce();
  });

  it("UI-BS-05 component basis: reload re-renders full provenance and confirm POSTs only included nonempty values", async () => {
    const client = syntheticClient();
    client.getPhotoJob
      .mockResolvedValueOnce({ job_id: "synthetic-job-1", state: "queued" })
      .mockResolvedValueOnce({ job_id: "synthetic-job-1", state: "running" })
      .mockResolvedValue({
        job_id: "synthetic-job-1",
        state: "succeeded",
        trait_candidates: SYNTHETIC_CANDIDATES,
      });
    const { onConfirmed } = await walkToReview(client);

    // Edit row 1 (24-char boundary), exclude row 2, leave row 3 suggested.
    const firstInput = screen.getByLabelText(TRAIT_TEXTS.first) as HTMLInputElement;
    fireEvent.change(firstInput, { target: { value: TRAIT_EDIT } });
    fireEvent.click(
      screen.getByRole("button", { name: `${TRAIT_TEXTS.second} 제안 빼기` }),
    );
    expect(screen.getAllByText(REVIEW_COPY.editedBadge, { exact: false }).length).toBe(1);
    expect(screen.getAllByText(REVIEW_COPY.excludedBadge, { exact: false }).length).toBe(1);
    expect(
      within(screen.getByRole("list", { name: "사진 취향 제안 목록" })).getAllByText(
        REVIEW_COPY.suggestedBadge,
        { exact: false },
      ),
    ).toHaveLength(1);

    // Simulate a reload: render a fresh flow instance with the same
    // candidate payload — provenance resets to model state, candidate text
    // stays immutable, and no stale edit/exclusion leaks across mounts.
    cleanup();
    window.sessionStorage.clear();
    const rerendered = await walkToReview(client);
    void rerendered;
    expect(
      within(screen.getByRole("list", { name: "사진 취향 제안 목록" })).getAllByText(
        REVIEW_COPY.suggestedBadge,
        { exact: false },
      ),
    ).toHaveLength(3);
    expect(screen.queryByText(REVIEW_COPY.editedBadge)).toBeNull();
    expect(screen.queryByText(REVIEW_COPY.excludedBadge)).toBeNull();

    // Excluding everything then restoring keeps confirm payload bounded.
    fireEvent.click(
      screen.getByRole("button", { name: `${TRAIT_TEXTS.first} 제안 빼기` }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: `${TRAIT_TEXTS.first} 제안 다시 포함하기` }),
    );

    // Only the batch CTA triggers the confirm client call with included,
    // nonempty values matching the generated PhotoConfirmedTraitView shape.
    // After reload all three rows are included again (exclude of second was
    // reset with the mount), so the payload carries all three candidate texts.
    fireEvent.click(screen.getByRole("button", { name: REVIEW_COPY.confirmCta }));
    await act(async () => {});
    expect(rerendered.onConfirmed).toHaveBeenCalledOnce();
    expect(client.confirmPhotoJobTraits).toHaveBeenCalledOnce();
    const confirmCall = client.confirmPhotoJobTraits.mock.calls[0] as [
      string,
      { confirmations: Array<{ text_ko: string; included: boolean }> },
    ];
    expect(confirmCall[1].confirmations.map((row) => row.text_ko)).toEqual([
      TRAIT_TEXTS.first,
      TRAIT_TEXTS.second,
      TRAIT_TEXTS.third,
    ]);
    for (const row of confirmCall[1].confirmations) {
      expect(row.included).toBe(true);
      expect(row.text_ko.trim()).not.toBe("");
    }
  });

  it("renders six traits with accessible ordinals and one-trait review keeps confirm semantics", async () => {
    const sixCandidates = {
      schema_version: "photo-trait-candidates-v1",
      authority_scope: "CANDIDATE_EVIDENCE_ONLY",
      traits: [
        "조용한 사찰과 숲길 중심으로 둘러보고 싶어요",
        "사진 찍기 좋은 야경 명소도 포함됐으면 해요",
        "걷기 편한 코스 위주로 묶어 주세요",
        "바다가 보이는 카페에서 쉬어가고 싶어요",
        "사진 찍기 좋은 골목과 벽화를 함께 봤으면 해요",
        "야경이 아름다운 전망대를 마지막으로 둘러보고 싶어요",
      ].map((text, index) => ({
        trait_id: `candidate-${index + 1}`,
        text_ko: text,
        origin: "MODEL_SUGGESTION",
      })),
    };
    const client = syntheticClient();
    client.getPhotoJob
      .mockResolvedValueOnce({ job_id: "synthetic-job-1", state: "queued" })
      .mockResolvedValueOnce({ job_id: "synthetic-job-1", state: "running" })
      .mockResolvedValue({
        job_id: "synthetic-job-1",
        state: "succeeded",
        trait_candidates: sixCandidates,
      });
    await walkToReview(client);

    const list = screen.getByRole("list", { name: "사진 취향 제안 목록" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(6);
    expect(
      within(list).getAllByText(REVIEW_COPY.suggestedBadge, { exact: false }),
    ).toHaveLength(6);

    // One-trait payload still shows the review heading and batch CTA.
    cleanup();
    const oneCandidate = {
      schema_version: "photo-trait-candidates-v1",
      authority_scope: "CANDIDATE_EVIDENCE_ONLY",
      traits: [
        { trait_id: "candidate-1", text_ko: TRAIT_TEXTS.first, origin: "MODEL_SUGGESTION" },
      ],
    };
    const oneClient = syntheticClient();
    oneClient.getPhotoJob.mockResolvedValue({
      job_id: "synthetic-job-1",
      state: "succeeded",
      trait_candidates: oneCandidate,
    });
    const oneOwners = await importPhotoOwners();
    const oneOnNoPhoto = vi.fn();
    const oneOnConfirmed = vi.fn();
    const Flow = oneOwners.PhotoPreferenceFlow;
    // Seed the bounded session draft so resume adopts the job, then advance
    // through polling to the one-row review.
    window.sessionStorage.setItem(
      "itda.phase6.photo-draft.v1",
      JSON.stringify({
        schema_version: "itda.phase6.photo-draft.v1",
        job_id: "synthetic-job-1",
        profile_id: "profile-photo-flow",
        notice_version: NOTICE_VERSION,
        created_at: new Date().toISOString(),
      }),
    );
    vi.useFakeTimers();
    render(
      <Flow
        profileId="profile-photo-flow"
        noticeVersion={NOTICE_VERSION}
        client={oneClient as unknown as SyntheticPhotoClient}
        onNoPhoto={oneOnNoPhoto}
        onConfirmed={oneOnConfirmed}
      />,
    );
    for (
      let guard = 0;
      guard < 40 &&
      screen.queryByRole("heading", { name: REVIEW_COPY.heading }) === null;
      guard += 1
    ) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1_500);
      });
    }
    expect(screen.getByRole("heading", { name: REVIEW_COPY.heading })).toBeTruthy();
    const oneList = screen.getByRole("list", { name: "사진 취향 제안 목록" });
    expect(within(oneList).getAllByRole("listitem")).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: REVIEW_COPY.confirmCta }));
    await act(async () => {});
    expect(oneOnConfirmed).toHaveBeenCalledOnce();
    const confirmed = oneOnConfirmed.mock.calls[0]?.[0] as Array<{ text_ko: string }>;
    expect(confirmed.map((trait) => trait.text_ko)).toEqual([TRAIT_TEXTS.first]);
  });

  it("malformed candidate payloads render no partial traits and keep no-photo", async () => {
    const client = syntheticClient();
    client.getPhotoJob
      .mockResolvedValueOnce({ job_id: "synthetic-job-1", state: "queued" })
      .mockResolvedValueOnce({ job_id: "synthetic-job-1", state: "running" })
      .mockResolvedValue({
        job_id: "synthetic-job-1",
        state: "succeeded",
        trait_candidates: {
          schema_version: "photo-trait-candidates-v1",
          authority_scope: "CANDIDATE_EVIDENCE_ONLY",
          traits: [
            { trait_id: "candidate-1", text_ko: TRAIT_TEXTS.first },
            { trait_id: "", text_ko: TRAIT_TEXTS.second, origin: "MODEL_SUGGESTION" },
          ],
        },
      });
    const { onNoPhoto } = await walkToActiveJobForReview(client);

    // Whole-payload validation fails: the unknown fallback renders, zero
    // candidate text appears, and no-photo remains available.
    expect(screen.getByText(FALLBACK_COPY.unknown, { exact: false })).toBeTruthy();
    expect(screen.queryByText(TRAIT_TEXTS.first)).toBeNull();
    expect(screen.queryByText(TRAIT_TEXTS.second)).toBeNull();
    expect(screen.queryByRole("list", { name: "사진 취향 제안 목록" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: ENTRY_COPY.noPhoto }));
    expect(onNoPhoto).toHaveBeenCalledOnce();
  });
});

describe("deletion requests never block the no-photo journey", () => {
  async function walkToActiveJob(client: SyntheticPhotoClient) {
    vi.useFakeTimers();
    const harness = await renderPhotoFlow(client);
    await startConsentAndPickFiles(client, 2);
    await act(async () => {});
    return harness;
  }

  it("opens a safe-first dialog and reports verified deletion only after evidence", async () => {
    const { client } = await walkToActiveJob(syntheticClient());

    fireEvent.click(screen.getByRole("button", { name: DELETE_COPY.trigger }));
    const dialog = screen.getByRole("dialog", { name: DELETE_COPY.heading });
    expect(within(dialog).getByText(DELETE_COPY.description, { exact: false })).toBeTruthy();
    expect(document.activeElement).toBe(
      within(dialog).getByRole("button", { name: DELETE_COPY.safe }),
    );
    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement).toBe(
      within(dialog).getByRole("button", { name: DELETE_COPY.destructive }),
    );

    fireEvent.click(within(dialog).getByRole("button", { name: DELETE_COPY.destructive }));
    expect(within(dialog).getByText(DELETE_COPY.busy, { exact: false })).toBeTruthy();
    await act(async () => {});
    expect(client.requestPhotoDeletion).toHaveBeenCalledOnce();
    expect(screen.getByText(FALLBACK_COPY.deletedVerified, { exact: false })).toBeTruthy();
  });

  it("reports uncertain deletion as pending and never claims completion", async () => {
    const client = syntheticClient();
    client.requestPhotoDeletion.mockResolvedValue({
      state: "deleted",
      residue_verified: false,
      ledger_recorded: false,
    });
    await walkToActiveJob(client);

    fireEvent.click(screen.getByRole("button", { name: DELETE_COPY.trigger }));
    fireEvent.click(
      within(screen.getByRole("dialog", { name: DELETE_COPY.heading })).getByRole("button", {
        name: DELETE_COPY.destructive,
      }),
    );
    await act(async () => {});
    expect(client.requestPhotoDeletion).toHaveBeenCalledOnce();
    expect(screen.getByText(FALLBACK_COPY.deletePending, { exact: false })).toBeTruthy();
    expect(screen.queryByText(FALLBACK_COPY.deletedVerified)).toBeNull();
    expect(screen.getByRole("button", { name: ENTRY_COPY.noPhoto })).toBeTruthy();
  });

  it("reports a failed deletion request without blocking no-photo", async () => {
    const client = syntheticClient();
    client.requestPhotoDeletion.mockRejectedValue(new Error("synthetic deletion outage"));
    const { onNoPhoto } = await walkToActiveJob(client);

    fireEvent.click(screen.getByRole("button", { name: DELETE_COPY.trigger }));
    fireEvent.click(
      within(screen.getByRole("dialog", { name: DELETE_COPY.heading })).getByRole("button", {
        name: DELETE_COPY.destructive,
      }),
    );
    await act(async () => {});
    expect(screen.getByText(DELETE_COPY.failure, { exact: false })).toBeTruthy();

    const noPhoto = screen.getByRole("button", { name: ENTRY_COPY.noPhoto });
    expect(noPhoto).toBeTruthy();
    fireEvent.click(noPhoto);
    expect(onNoPhoto).toHaveBeenCalledOnce();
  });

  it("keeps the delete trigger reachable in review after upload begins", async () => {
    const client = syntheticClient();
    client.getPhotoJob
      .mockResolvedValueOnce({ job_id: "synthetic-job-1", state: "queued" })
      .mockResolvedValueOnce({ job_id: "synthetic-job-1", state: "running" })
      .mockResolvedValue({
        job_id: "synthetic-job-1",
        state: "succeeded",
        trait_candidates: SYNTHETIC_CANDIDATES,
      });
    await walkToReview(client);

    const trigger = screen.getByRole("button", { name: DELETE_COPY.trigger });
    expect(trigger).toBeTruthy();

    fireEvent.click(trigger);
    const dialog = screen.getByRole("dialog", { name: DELETE_COPY.heading });
    expect(within(dialog).getByRole("button", { name: DELETE_COPY.safe })).toBeTruthy();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });
});

describe("browser storage stays bounded and private", () => {
  it("shows the exact storage notice and keeps the journey available when storage fails", async () => {
    const descriptor = Object.getOwnPropertyDescriptor(window, "sessionStorage");
    Object.defineProperty(window, "sessionStorage", {
      configurable: true,
      get() {
        throw new DOMException("blocked", "SecurityError");
      },
    });

    try {
      vi.useFakeTimers();
      const client = syntheticClient();
      await renderPhotoFlow(client);

      await startConsentAndPickFiles(client, 2);
      await act(async () => {});

      expect(screen.getByText(FALLBACK_COPY.storageUnavailable, { exact: false })).toBeTruthy();
      expect(client.createPhotoJob).toHaveBeenCalledTimes(1);
      expect(screen.getByRole("button", { name: ENTRY_COPY.noPhoto })).toBeTruthy();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1_500);
      });
      expect(screen.getByRole("heading", { name: STATUS_COPY.queued.heading })).toBeTruthy();
      expect(screen.getByText(FALLBACK_COPY.storageUnavailable, { exact: false })).toBeTruthy();
    } finally {
      if (descriptor) {
        Object.defineProperty(window, "sessionStorage", descriptor);
      }
    }
  });
});

describe("confirmed photo recommendation reference", () => {
  it("stores only an exact profile-bound opaque job and recovers it after reload", async () => {
    const storagePath = "./photoProjection";
    const storage = await import(/* @vite-ignore */ storagePath);
    const profileId = "profile:current-photo";
    const jobId = "a".repeat(64);

    expect(storage.writeConfirmedPhotoReference(profileId, jobId)).toBe(true);
    expect(storage.readConfirmedPhotoReference(profileId)).toBe(jobId);
    expect(storage.readConfirmedPhotoReference("profile:foreign")).toBeNull();
    expect(JSON.parse(window.sessionStorage.getItem(
      storage.CONFIRMED_PHOTO_REFERENCE_STORAGE_KEY,
    ) ?? "null")).toEqual({
      schema_version: "itda.phase6.confirmed-photo-reference.v1",
      preference_profile_id: profileId,
      photo_job_id: jobId,
    });

    storage.clearConfirmedPhotoReference(profileId);
    expect(storage.readConfirmedPhotoReference(profileId)).toBeNull();
  });

  it("rejects malformed references and removes corrupt session data", async () => {
    const storagePath = "./photoProjection";
    const storage = await import(/* @vite-ignore */ storagePath);
    window.sessionStorage.setItem(
      storage.CONFIRMED_PHOTO_REFERENCE_STORAGE_KEY,
      JSON.stringify({
        schema_version: "itda.phase6.confirmed-photo-reference.v1",
        preference_profile_id: "profile:current-photo",
        photo_job_id: "not-a-job-id",
        traits: ["must-not-persist"],
      }),
    );

    expect(storage.readConfirmedPhotoReference("profile:current-photo")).toBeNull();
    expect(window.sessionStorage.getItem(
      storage.CONFIRMED_PHOTO_REFERENCE_STORAGE_KEY,
    )).toBeNull();
    expect(storage.writeConfirmedPhotoReference("profile:current-photo", "b".repeat(63))).toBe(false);
    expect(storage.writeConfirmedPhotoReference("profile:current-photo", "B".repeat(64))).toBe(false);

    window.sessionStorage.setItem(
      storage.CONFIRMED_PHOTO_REFERENCE_STORAGE_KEY,
      "x".repeat(513),
    );
    expect(storage.readConfirmedPhotoReference("profile:current-photo")).toBeNull();
    expect(window.sessionStorage.getItem(
      storage.CONFIRMED_PHOTO_REFERENCE_STORAGE_KEY,
    )).toBeNull();
  });

  it("uses the bounded memory fallback when session storage is blocked", async () => {
    const storagePath = "./photoProjection";
    const storage = await import(/* @vite-ignore */ storagePath);
    const descriptor = Object.getOwnPropertyDescriptor(window, "sessionStorage");
    const profileId = "profile:memory-photo";
    const jobId = "e".repeat(64);
    Object.defineProperty(window, "sessionStorage", {
      configurable: true,
      get() {
        throw new DOMException("blocked", "SecurityError");
      },
    });

    try {
      expect(storage.writeConfirmedPhotoReference(profileId, jobId)).toBe(true);
      expect(storage.readConfirmedPhotoReference(profileId)).toBe(jobId);
      expect(storage.readConfirmedPhotoReference("profile:foreign")).toBeNull();
      storage.clearConfirmedPhotoReference(profileId);
      expect(storage.readConfirmedPhotoReference(profileId)).toBeNull();
    } finally {
      if (descriptor) Object.defineProperty(window, "sessionStorage", descriptor);
    }
  });
});

describe("recommendation provenance stays static and confirmed-only", () => {
  it("shows only the confirmed-photo or no-photo provenance sentence", async () => {
    const { PhotoRecommendationProvenance } = await importPhotoOwners();

    const first = render(<PhotoRecommendationProvenance provenance="CONFIRMED_PHOTO" />);
    expect(screen.getByText(PROVENANCE_COPY.photo, { exact: false })).toBeTruthy();
    expect(first.container.textContent).not.toContain("provider");
    expect(first.container.textContent).not.toContain("GLM");
    first.unmount();

    render(<PhotoRecommendationProvenance provenance="NO_PHOTO" />);
    expect(screen.getByText(PROVENANCE_COPY.noPhoto, { exact: false })).toBeTruthy();
  });
});

describe("accessibility and reduced motion", () => {
  it("keeps one polite status during polling, one alert on terminal failure, and focus-once semantics", async () => {
    vi.useFakeTimers();
    const client = syntheticClient();
    client.getPhotoJob
      .mockResolvedValueOnce({ job_id: "synthetic-job-1", state: "queued" })
      .mockResolvedValue({ job_id: "synthetic-job-1", state: "failed" });
    await renderPhotoFlow(client);

    await startConsentAndPickFiles(client, 2);
    await act(async () => {});
    const focusBeforePolling = document.activeElement;

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_500);
    });
    const status = screen.getAllByRole("status");
    expect(status.length).toBeGreaterThanOrEqual(1);
    for (const region of status) {
      expect(region.getAttribute("aria-live")).toBe("polite");
      expect(region.getAttribute("aria-atomic")).toBe("true");
    }
    expect(document.activeElement).toBe(focusBeforePolling);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_500);
    });
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    expect(document.activeElement).toBe(
      screen.getByRole("heading", { name: STATUS_COPY.failed.heading }),
    );
    expect(screen.getByRole("button", { name: ENTRY_COPY.noPhoto })).toBeTruthy();
  });

  it("reports progress without fabricated percentages or motion-only elements", async () => {
    vi.useFakeTimers();
    const client = syntheticClient();
    client.getPhotoJob.mockResolvedValue({ job_id: "synthetic-job-1", state: "running" });
    const { view } = await renderPhotoFlow(client);

    await startConsentAndPickFiles(client, 2);
    await act(async () => {});
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_500);
    });

    expect(view.container.textContent).not.toMatch(/\d+\s*%/);
    expect(screen.getByText(STATUS_COPY.running.heading, { exact: false })).toBeTruthy();
    expect(screen.getByRole("status")).toBeTruthy();
  });
});

describe("optional routes keep Profile current with a four-step stepper", () => {
  it("keeps the JourneyStepper at four steps on photo routes with Profile current", async () => {
    const { JourneyStepper } = await import("../../components/JourneyStepper");
    for (const pathname of ["/photo", "/photo/jobs/synthetic-job-1", "/photo/jobs/synthetic-job-1/review"]) {
      const { unmount } = render(<JourneyStepper pathname={pathname} />);
      const steps = screen.getAllByRole("listitem");
      expect(steps, pathname).toHaveLength(4);
      const current = steps.filter((step) => step.getAttribute("aria-current") === "step");
      expect(current, pathname).toHaveLength(1);
      expect(current[0]?.textContent).toContain("기대 프로필");
      unmount();
    }
  });
});
