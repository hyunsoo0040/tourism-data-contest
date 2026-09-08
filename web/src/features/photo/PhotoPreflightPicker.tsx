import { useEffect, useId, useRef, useState } from "react";

/**
 * Local 1–3 photo preflight.
 *
 * Native multiple input with a JPEG/PNG/WEBP allowlist. Selected files are
 * checked entirely client-side: count 1–3, 10 MiB per file, 20 MiB aggregate.
 * Rows are identified only by generated ordinals (사진 N); original filenames
 * are never rendered, stored, logged, or transmitted. Local object-URL
 * previews are revoked on removal, replacement, submit, and unmount. Nothing
 * here creates a job — submission is an explicit parent action.
 */

export const PICKER_COPY = {
  heading: "분석할 사진을 골라 주세요",
  emptyBody:
    "JPEG, PNG, WEBP 사진을 1–3장 골라 주세요. 각 10MB 이하, 전체 20MB 이하, 해상도 4천만 픽셀 이하만 확인해요.",
  trigger: "사진 고르기",
} as const;

export const PREFLIGHT_COPY = {
  zeroFiles: "사진을 1장 이상 골라 주세요.",
  fourthFile: "사진은 한 번에 최대 3장까지 고를 수 있어요.",
  unsupportedType: (ordinal: number) => `사진 ${ordinal}은 JPEG, PNG, WEBP 형식이 아니에요.`,
  tooLarge: (ordinal: number) => `사진 ${ordinal}은 10MB보다 커요.`,
  aggregateTooLarge:
    "선택한 사진 전체가 20MB보다 커요. 사진을 선택에서 빼거나 더 작은 사진을 골라 주세요.",
  decodeRejected: (ordinal: number) =>
    `사진 ${ordinal}을 안전하게 확인하지 못했어요. 다른 사진으로 바꾸거나 사진 없이 계속해 주세요.`,
  chooseOther: "다른 사진 고르기",
  removeFromSelection: (ordinal: number) => `사진 ${ordinal} 선택에서 빼기`,
} as const;

const ALLOWED_TYPES: ReadonlySet<string> = new Set(["image/jpeg", "image/png", "image/webp"]);
const MAX_FILES = 3;
const MAX_FILE_BYTES = 10 * 1024 * 1024;
const MAX_TOTAL_BYTES = 20 * 1024 * 1024;

const FORMAT_LABELS: Record<string, string> = {
  "image/jpeg": "JPEG",
  "image/png": "PNG",
  "image/webp": "WEBP",
};

/**
 * Remove-control label. The ordinal and the action text live in separate
 * text nodes so the accessible name stays "사진 N 선택에서 빼기" while no
 * single text node duplicates the row's "사진 N" label (substring queries
 * must stay unique per ordinal).
 */
function RemoveLabel({ ordinal }: { ordinal: number }) {
  return (
    <>
      <span>사진</span> <span>{ordinal}</span>
      <span> 선택에서 빼기</span>
    </>
  );
}

function sizeLabel(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${Math.round((bytes / (1024 * 1024)) * 10) / 10}MB`;
  return `${Math.max(1, Math.round(bytes / 1024))}KB`;
}

export type SelectedPhoto = {
  /** Generated identity; never derived from the file name. */
  rowId: string;
  ordinal: number;
  file: File;
  previewUrl: string;
  bytes: number;
  formatLabel: string;
  error: string | null;
};

export type PreflightProblem =
  | { kind: "count"; message: string }
  | { kind: "aggregate"; message: string }
  | { kind: "row"; message: string };

export type IngestResult = {
  rows: SelectedPhoto[];
  problem: PreflightProblem | null;
};

const ROW_ERROR_COPY: Record<string, (ordinal: number) => string> = {
  tooLarge: PREFLIGHT_COPY.tooLarge,
  unsupportedType: PREFLIGHT_COPY.unsupportedType,
  decodeRejected: PREFLIGHT_COPY.decodeRejected,
};

/** Validate one ingestion batch against the local bounds; no side effects. */
export function validateIngestion(
  existing: SelectedPhoto[],
  incoming: File[],
): IngestResult {
  if (incoming.length === 0) return { rows: existing, problem: null };

  const rejectedRows: SelectedPhoto[] = [];
  let aggregateProblem: PreflightProblem | null = null;
  let aggregateBytes = existing.reduce((total, row) => {
    if (row.error !== null) return total;
    return total + row.bytes;
  }, 0);

  const nextOrdinal = (): number => existing.length + rejectedRows.length + 1;
  for (const file of incoming) {
    if (existing.length + rejectedRows.length >= MAX_FILES) {
      // Keep the first valid choices; the overflow file is dropped locally.
      return { rows: rejectedRows, problem: { kind: "count", message: PREFLIGHT_COPY.fourthFile } };
    }
    const ordinal = nextOrdinal();
    const rowId = `row-${ordinal}-${existing.length + rejectedRows.length}`;
    if (!ALLOWED_TYPES.has(file.type)) {
      rejectedRows.push({
        rowId,
        ordinal,
        file,
        previewUrl: "",
        bytes: file.size,
        formatLabel: file.type === "" ? "알 수 없는 형식" : file.type,
        error: ROW_ERROR_COPY.unsupportedType(ordinal),
      });
      continue;
    }
    if (file.size > MAX_FILE_BYTES) {
      rejectedRows.push({
        rowId,
        ordinal,
        file,
        previewUrl: "",
        bytes: file.size,
        formatLabel: FORMAT_LABELS[file.type] ?? file.type,
        error: ROW_ERROR_COPY.tooLarge(ordinal),
      });
      continue;
    }
    if (aggregateBytes + file.size > MAX_TOTAL_BYTES) {
      aggregateProblem = { kind: "aggregate", message: PREFLIGHT_COPY.aggregateTooLarge };
    }
    const row: SelectedPhoto = {
      rowId,
      ordinal,
      file,
      previewUrl: URL.createObjectURL(file),
      bytes: file.size,
      formatLabel: FORMAT_LABELS[file.type] ?? file.type,
      error: null,
    };
    if (aggregateProblem === null) aggregateBytes += file.size;
    rejectedRows.push(row);
  }

  return { rows: rejectedRows, problem: aggregateProblem };
}

export function PhotoPreflightPicker({
  rows,
  problem,
  emptyError,
  summaryRef,
  headingRef,
  onIngest,
  onRemove,
  onReplace,
  children,
}: {
  rows: SelectedPhoto[];
  problem: PreflightProblem | null;
  emptyError?: boolean;
  summaryRef?: React.RefObject<HTMLDivElement | null>;
  headingRef?: React.RefObject<HTMLHeadingElement | null>;
  onIngest: (files: File[]) => void;
  onRemove: (rowId: string) => void;
  onReplace: () => void;
  children?: React.ReactNode;
}) {
  const inputId = useId();
  const inputRef = useRef<HTMLInputElement>(null);
  const createdUrlsRef = useRef<Set<string>>(new Set());
  const [previewTick, setPreviewTick] = useState(0);

  // Own every preview URL this component created; revoke on replacement and
  // unmount. Parent revocation (remove/submit) flows through onRemove/onReplace.
  useEffect(() => {
    const created = createdUrlsRef.current;
    const current = new Set(rows.map((row) => row.previewUrl).filter((url) => url !== ""));
    for (const url of created) {
      if (!current.has(url)) URL.revokeObjectURL(url);
    }
    for (const url of current) created.add(url);
  });

  useEffect(
    () => () => {
      for (const url of createdUrlsRef.current) URL.revokeObjectURL(url);
      createdUrlsRef.current = new Set();
    },
    [],
  );

  const ingest = () => {
    const files = Array.from(inputRef.current?.files ?? []);
    if (inputRef.current !== null) inputRef.current.value = "";
    setPreviewTick((tick) => tick + 1);
    onIngest(files);
  };

  const summaryVisible = problem !== null || emptyError === true;
  void summaryVisible;
  void previewTick;

  return (
    <section
      className="profile-state"
      aria-labelledby="photo-preflight-heading"
      style={{ padding: "var(--space-lg)" }}
    >
      <h1 ref={headingRef} id="photo-preflight-heading" tabIndex={-1}>
        {PICKER_COPY.heading}
      </h1>
      <p>{PICKER_COPY.emptyBody}</p>
      {problem !== null ? (
        <div
          ref={summaryRef}
          tabIndex={-1}
          className="error-summary"
          role="alert"
          style={{ marginTop: "var(--space-md)" }}
        >
          <p style={{ margin: 0 }}>{problem.message}</p>
          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: "var(--space-sm)",
              marginTop: "var(--space-sm)",
            }}
          >
            {problem.kind === "aggregate"
              ? rows
                  .filter((row) => row.error === null)
                  .map((row) => (
                    <button
                      key={row.rowId}
                      type="button"
                      className="button button--secondary"
                      onClick={() => onRemove(row.rowId)}
                    >
                      <RemoveLabel ordinal={row.ordinal} />
                    </button>
                  ))
              : null}
            {problem.kind === "aggregate" ||
            problem.kind === "count" ||
            rows.some((row) => row.error !== null) ? (
              <button type="button" className="button button--secondary" onClick={onReplace}>
                <span>{PREFLIGHT_COPY.chooseOther}</span>
              </button>
            ) : null}
          </div>
        </div>
      ) : null}
      {emptyError === true ? (
        <div
          ref={summaryRef}
          tabIndex={-1}
          className="error-summary"
          role="alert"
          style={{ marginTop: "var(--space-md)" }}
        >
          <p style={{ margin: 0 }}>{PREFLIGHT_COPY.zeroFiles}</p>
        </div>
      ) : null}
      {rows.length > 0 ? (
        <ul style={{ display: "grid", gap: "var(--space-sm)", listStyle: "none", padding: 0 }}>
          {rows.map((row) => (
            <li
              key={row.rowId}
              aria-invalid={row.error !== null || undefined}
              style={{
                display: "grid",
                gridTemplateColumns: "72px minmax(0, 1fr) auto",
                gap: "var(--space-sm)",
                alignItems: "center",
                paddingBlock: "var(--space-sm)",
                borderTop: "1px solid var(--line)",
              }}
            >
              {row.previewUrl === "" ? (
                <span
                  aria-hidden="true"
                  style={{
                    width: "72px",
                    height: "72px",
                    borderRadius: "12px",
                    background: "var(--surface-muted)",
                  }}
                />
              ) : (
                <img
                  src={row.previewUrl}
                  alt=""
                  width={72}
                  height={72}
                  style={{
                    width: "72px",
                    height: "72px",
                    objectFit: "cover",
                    borderRadius: "12px",
                  }}
                />
              )}
              <div style={{ minWidth: 0 }}>
                <p style={{ margin: 0, fontWeight: 600 }}>
                  <span>사진 {row.ordinal}</span>
                </p>
                <p style={{ margin: 0, color: "var(--ink-muted)", fontSize: "14px" }}>
                  {row.formatLabel} · {sizeLabel(row.bytes)}
                </p>
                {row.error !== null ? (
                  <p className="field-error" role="alert" style={{ marginTop: "var(--space-xs)" }}>
                    {row.error}
                  </p>
                ) : null}
              </div>
              <button
                type="button"
                className="button button--text-destructive"
                style={{ minWidth: "44px" }}
                onClick={() => onRemove(row.rowId)}
              >
                <RemoveLabel ordinal={row.ordinal} />
              </button>

            </li>
          ))}
        </ul>
      ) : null}
      <input
        id={inputId}
        ref={inputRef}
        type="file"
        accept="image/jpeg,image/png,image/webp"
        multiple
        onChange={ingest}
        style={{
          display: "block",
          marginTop: "var(--space-md)",
          minWidth: 0,
          width: "100%",
        }}
      />
      <button
        type="button"
        className="button button--secondary"
        style={{ marginTop: "var(--space-sm)" }}
        onClick={() => inputRef.current?.click()}
      >
        {PICKER_COPY.trigger}
      </button>
      {children}
    </section>
  );
}
