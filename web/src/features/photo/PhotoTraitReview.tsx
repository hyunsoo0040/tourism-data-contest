import { useState } from "react";

import { REVIEW_HEADING_COPY } from "./review-copy";

/**
 * All-or-nothing candidate review: render only when the whole strict
 * candidate list validates. Editing/excluding never confirms; the batch CTA
 * is the single confirmation event and carries only included, non-empty
 * values. Zero included values makes no-photo primary again. Enter and blur
 * never confirm.
 */

export type PhotoTraitCandidate = {
  candidate_id?: string;
  trait_id: string;
  text_ko: string;
  origin: string;
};

export type PhotoTraitCandidatePayload = {
  schema_version: string;
  authority_scope: string;
  traits: PhotoTraitCandidate[];
};

export type ConfirmedTrait = {
  trait_id: string;
  text_ko: string;
  source_candidate_id: string | null;
  included: boolean;
};

/**
 * Strict whole-payload validation. The candidates value must be the complete
 * closed schema object; partial or malformed shapes render nothing.
 */
export function isValidCandidatePayload(
  value: unknown,
): value is PhotoTraitCandidatePayload {
  if (typeof value !== "object" || value === null) return false;
  const payload = value as Record<string, unknown>;
  if (typeof payload.schema_version !== "string" || payload.schema_version.length === 0) {
    return false;
  }
  if (payload.authority_scope !== "CANDIDATE_EVIDENCE_ONLY") return false;
  const traits = payload.traits;
  if (!Array.isArray(traits) || traits.length === 0 || traits.length > 6) return false;
  return traits.every(
    (row) =>
      typeof row === "object" &&
      row !== null &&
      typeof (row as Record<string, unknown>).trait_id === "string" &&
      (row as Record<string, unknown>).trait_id !== "" &&
      typeof (row as Record<string, unknown>).text_ko === "string" &&
      ((row as Record<string, unknown>).text_ko as string).length > 0 &&
      typeof (row as Record<string, unknown>).origin === "string",
  );
}

const BADGE_COPY = {
  suggested: "분석 제안",
  edited: "내가 수정함",
  excluded: "추천에 반영하지 않음",
} as const;

function excludeLabel(text: string) {
  return `${text} 제안 빼기`;
}
function restoreLabel(text: string) {
  return `${text} 제안 다시 포함하기`;
}

/**
 * One review row: visible model/edited/excluded provenance, a bounded 16px
 * labelled input capped at 24 Korean characters, and a reversible exclude/
 * restore action. Editing never confirms.
 */
export function PhotoTraitEditorRow({
  candidate,
  value,
  isEdited,
  isExcluded,
  onEdit,
  onToggleExcluded,
}: {
  candidate: PhotoTraitCandidate;
  value: string;
  isEdited: boolean;
  isExcluded: boolean;
  onEdit: (value: string) => void;
  onToggleExcluded: () => void;
}) {
  return (
    <li className="photo-review__row">
      {isExcluded ? (
        <span className="photo-trait-badge">{BADGE_COPY.excluded}</span>
      ) : isEdited ? (
        <span className="photo-trait-badge">{BADGE_COPY.edited}</span>
      ) : (
        <span className="photo-trait-badge photo-trait-badge--suggested">
          {BADGE_COPY.suggested}
        </span>
      )}
      <label style={{ display: "grid", gap: "var(--space-xs)", fontWeight: 600 }}>
        {isEdited ? value : candidate.text_ko}
        <input
          type="text"
          className="photo-trait-input"
          value={value}
          maxLength={24}
          disabled={isExcluded}
          onChange={(event) => onEdit(event.target.value)}
          onKeyDown={(event) => {
            // Enter never batch-confirms.
            if (event.key === "Enter") event.preventDefault();
          }}
        />
      </label>
      {isExcluded ? (
        <button type="button" className="button button--secondary" onClick={onToggleExcluded}>
          {restoreLabel(candidate.text_ko)}
        </button>
      ) : (
        <button
          type="button"
          className="button button--text-destructive"
          onClick={onToggleExcluded}
        >
          {excludeLabel(candidate.text_ko)}
        </button>
      )}
    </li>
  );
}

export function PhotoTraitReview({
  candidates,
  onConfirm,
  onNoPhoto,
}: {
  candidates: {
    schema_version: string;
    authority_scope: string;
    traits: PhotoTraitCandidate[];
  };
  onConfirm: (confirmed: ConfirmedTrait[]) => void;
  onNoPhoto: () => void;
}) {
  const [edits, setEdits] = useState<Record<string, string>>({});
  const [excluded, setExcluded] = useState<Record<string, boolean>>({});

  const rows = candidates.traits.map((candidate) => {
    const editedValue = edits[candidate.trait_id];
    const text = editedValue !== undefined && editedValue !== "" ? editedValue : candidate.text_ko;
    const isEdited =
      editedValue !== undefined && editedValue !== "" && editedValue !== candidate.text_ko;
    const isExcluded = excluded[candidate.trait_id] ?? false;
    return { candidate, text, isEdited, isExcluded };
  });

  const includedRows = rows.filter((row) => !row.isExcluded && row.text.trim() !== "");

  if (includedRows.length === 0) {
    return (
      <section className="profile-state" style={{ padding: "var(--space-lg)" }}>
        <h2 tabIndex={-1}>반영할 사진 취향을 남기지 않았어요.</h2>
        <p>사진 분석 제안을 사용하지 않고, 원래 기대 프로필로 추천을 계속할 수 있어요.</p>
        <button
          type="button"
          className="button button--primary"
          style={{ width: "100%" }}
          onClick={onNoPhoto}
        >
          사진 없이 추천 5곳 보기
        </button>
      </section>
    );
  }

  return (
    <section
      aria-labelledby="photo-review-heading"
      className="photo-review"
    >
      <div className="profile-state">
        <p className="eyebrow">사진 분석 제안</p>
        <h1 id="photo-review-heading" tabIndex={-1}>
          {REVIEW_HEADING_COPY}
        </h1>
        <p>
          아래 내용은 사진 분석이 제안한 후보예요. 수정하거나 빼고, 남긴 내용만 직접 확정해
          주세요.
        </p>
      </div>
      <ul className="photo-review__list" aria-label="사진 취향 제안 목록">
        {rows.map(({ candidate, text, isEdited, isExcluded }) => (
          <PhotoTraitEditorRow
            key={candidate.trait_id}
            candidate={candidate}
            value={edits[candidate.trait_id] ?? ""}
            isEdited={isEdited}
            isExcluded={isExcluded}
            onEdit={(next) =>
              setEdits((current) => ({ ...current, [candidate.trait_id]: next }))
            }
            onToggleExcluded={() =>
              setExcluded((current) => ({ ...current, [candidate.trait_id]: !isExcluded }))
            }
          />
        ))}
      </ul>
      <div className="start-action-bar" style={{ position: "static", padding: 0, border: 0, background: "transparent" }}>
        <button type="button" className="button button--secondary" onClick={onNoPhoto}>
          사진 없이 추천 5곳 보기
        </button>
        <button
          type="button"
          className="button button--primary"
          onClick={() =>
            onConfirm(
              includedRows.map((row) => ({
                trait_id: row.candidate.trait_id,
                text_ko: row.text,
                source_candidate_id: row.candidate.candidate_id ?? row.candidate.trait_id,
                included: true,
              })),
            )
          }
        >
          확정한 취향으로 추천 5곳 보기
        </button>
      </div>
    </section>
  );
}
