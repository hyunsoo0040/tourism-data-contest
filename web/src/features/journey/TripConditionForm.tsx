import { useMemo, useRef, useState } from "react";
import {
  useForm,
  type FieldErrors,
  type Path,
  type Resolver,
  type SubmitHandler,
} from "react-hook-form";

import {
  tripConditionFormSchema,
  type TripConditionFormValues,
  type TripConditions,
} from "../../app/schemas";
import { STORAGE_MESSAGES } from "../../app/storage";
import { ResetDraftDialog } from "../profile/ResetDraftDialog";

type Choice = { value: string; label: string };

const FIELD_LABELS: Record<Exclude<keyof TripConditionFormValues, "visit_date">, string> = {
  visit_time: "방문 시간",
  companion: "동행",
  transport: "이동수단",
  walking_tolerance: "도보 허용",
  indoor_outdoor_preference: "실내외 선호",
  crowd_avoidance: "혼잡 회피",
};

const CHOICES: Record<Exclude<keyof TripConditionFormValues, "visit_date">, Choice[]> = {
  visit_time: [
    { value: "MORNING", label: "오전" },
    { value: "DAYTIME", label: "낮" },
    { value: "SUNSET", label: "해질녘" },
    { value: "EVENING", label: "저녁" },
    { value: "UNDECIDED", label: "아직 미정" },
  ],
  companion: [
    { value: "SOLO", label: "혼자" },
    { value: "FRIEND_OR_PARTNER", label: "친구·연인" },
    { value: "FAMILY_WITH_CHILDREN", label: "가족·아이" },
    { value: "WITH_SENIORS", label: "어르신 동반" },
    { value: "GROUP", label: "여럿이" },
  ],
  transport: [
    { value: "WALK_OR_TRANSIT", label: "도보·대중교통" },
    { value: "CAR_OR_TAXI", label: "자가용·택시" },
    { value: "MIXED", label: "둘 다" },
  ],
  walking_tolerance: [
    { value: "WITHIN_30_MINUTES", label: "30분 이내로 가볍게" },
    { value: "ABOUT_1_HOUR", label: "1시간 안팎" },
    { value: "EXTENDED_WALKING_OK", label: "충분히 걸어도 괜찮아요" },
  ],
  indoor_outdoor_preference: [
    { value: "INDOOR", label: "실내 위주" },
    { value: "NO_PREFERENCE", label: "상관없어요" },
    { value: "OUTDOOR", label: "야외 위주" },
  ],
  crowd_avoidance: [
    { value: "LOW", label: "괜찮아요" },
    { value: "MEDIUM", label: "조금 피하고 싶어요" },
    { value: "HIGH", label: "많이 피하고 싶어요" },
  ],
};

const REQUIRED_FIELD_ORDER = Object.keys(FIELD_LABELS) as Array<keyof typeof FIELD_LABELS>;

const resolver: Resolver<TripConditionFormValues> = async (values) => {
  const result = tripConditionFormSchema.safeParse(values);
  if (result.success) return { values, errors: {} };

  const errors: FieldErrors<TripConditionFormValues> = {};
  for (const issue of result.error.issues) {
    const name = issue.path[0] as keyof TripConditionFormValues | undefined;
    if (name === undefined || name === "visit_date" || errors[name] !== undefined) continue;
    errors[name] = {
      type: "required",
      message: `${FIELD_LABELS[name]}을 선택해 주세요.`,
    };
  }
  return { values: {}, errors };
};

function ChoiceGroup({
  name,
  register,
  error,
}: {
  name: keyof typeof FIELD_LABELS;
  register: ReturnType<typeof useForm<TripConditionFormValues>>["register"];
  error?: string;
}) {
  const errorId = `${name}-error`;
  return (
    <fieldset className="choice-group" id={`${name}-field`} aria-describedby={error ? errorId : undefined}>
      <legend>{FIELD_LABELS[name]}</legend>
      <div className="choice-grid">
        {CHOICES[name].map((choice) => (
          <label className="choice-card" key={choice.value}>
            <input type="radio" value={choice.value} {...register(name)} />
            <span>{choice.label}</span>
          </label>
        ))}
      </div>
      {error ? (
        <p className="field-error" id={errorId}>
          {error}
        </p>
      ) : null}
    </fieldset>
  );
}

export function TripConditionForm({
  defaultValues,
  recovered,
  onDismissRecovery,
  onReset,
  onSubmit,
  primaryLabel = "취향 테스트 시작하기",
  secondaryLabel,
  onSecondary,
  busy = false,
  requestError,
}: {
  defaultValues: TripConditionFormValues;
  recovered: boolean;
  onDismissRecovery: () => void;
  onReset: () => boolean;
  onSubmit: (conditions: TripConditions) => void;
  primaryLabel?: string;
  secondaryLabel?: string;
  onSecondary?: () => void;
  busy?: boolean;
  requestError?: string | null;
}) {
  const [dialogOpen, setDialogOpen] = useState(false);
  const recoveryResetRef = useRef<HTMLButtonElement>(null);
  const errorSummaryRef = useRef<HTMLDivElement>(null);
  const {
    register,
    handleSubmit,
    setFocus,
    reset,
    formState: { errors },
  } = useForm<TripConditionFormValues>({ defaultValues, resolver, shouldFocusError: false });

  const errorNames = useMemo(
    () => REQUIRED_FIELD_ORDER.filter((name) => errors[name] !== undefined),
    [errors],
  );

  const submitValid: SubmitHandler<TripConditionFormValues> = (values) => {
    const parsed = tripConditionFormSchema.parse(values);
    onSubmit(parsed);
  };

  const submitInvalid = (invalidErrors: FieldErrors<TripConditionFormValues>) => {
    const first = REQUIRED_FIELD_ORDER.find((name) => invalidErrors[name] !== undefined);
    window.setTimeout(() => {
      errorSummaryRef.current?.focus();
      if (first) window.setTimeout(() => setFocus(first as Path<TripConditionFormValues>), 50);
    }, 0);
  };

  const focusFirstIncomplete = () => {
    const values = document.querySelector<HTMLFormElement>("#trip-condition-form");
    const firstIncomplete = REQUIRED_FIELD_ORDER.find(
      (name) => values?.querySelector<HTMLInputElement>(`input[name="${name}"]:checked`) === null,
    );
    onDismissRecovery();
    if (firstIncomplete) setFocus(firstIncomplete);
    else document.querySelector<HTMLElement>("#start-heading")?.focus();
  };

  return (
    <>
      {recovered ? (
        <section className="recovery-notice" role="status" aria-live="polite">
          <p>{STORAGE_MESSAGES.recovered}</p>
          <div className="inline-actions">
            <button type="button" className="button button--secondary" onClick={focusFirstIncomplete}>
              계속 작성하기
            </button>
            <button
              ref={recoveryResetRef}
              type="button"
              className="button button--text-destructive"
              onClick={() => setDialogOpen(true)}
            >
              처음부터 시작하기
            </button>
          </div>
        </section>
      ) : null}

      <form
        id="trip-condition-form"
        className="trip-form"
        aria-labelledby="start-heading"
        noValidate
        aria-busy={busy || undefined}
        onSubmit={handleSubmit(submitValid, submitInvalid)}
      >
        {requestError ? <p className="error-summary" role="alert">{requestError}</p> : null}
        {errorNames.length > 0 ? (
          <div className="error-summary" role="alert" tabIndex={-1} ref={errorSummaryRef}>
            <h2>확인할 여행 조건이 있어요.</h2>
            <ul>
              {errorNames.map((name) => (
                <li key={name}>
                  <a
                    href={`#${name}-field`}
                    onClick={(event) => {
                      event.preventDefault();
                      setFocus(name);
                    }}
                  >
                    {errors[name]?.message}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        <fieldset className="visit-fieldset">
          <legend>방문 시점</legend>
          <label className="date-field">
            <span>방문 날짜 (선택)</span>
            <input type="date" {...register("visit_date")} />
          </label>
          <ChoiceGroup
            name="visit_time"
            register={register}
            error={errors.visit_time?.message}
          />
        </fieldset>

        <ChoiceGroup name="companion" register={register} error={errors.companion?.message} />
        <ChoiceGroup name="transport" register={register} error={errors.transport?.message} />
        <ChoiceGroup
          name="walking_tolerance"
          register={register}
          error={errors.walking_tolerance?.message}
        />
        <ChoiceGroup
          name="indoor_outdoor_preference"
          register={register}
          error={errors.indoor_outdoor_preference?.message}
        />
        <ChoiceGroup
          name="crowd_avoidance"
          register={register}
          error={errors.crowd_avoidance?.message}
        />

        <div className="start-action-bar">
          {secondaryLabel && onSecondary ? (
            <button type="button" className="button button--secondary" onClick={onSecondary} disabled={busy}>
              {secondaryLabel}
            </button>
          ) : null}
          <button type="submit" className="button button--primary" disabled={busy} aria-busy={busy || undefined}>
            {busy ? "프로필 만드는 중…" : primaryLabel}
          </button>
        </div>
      </form>

      <ResetDraftDialog
        open={dialogOpen}
        triggerRef={recoveryResetRef}
        onClose={() => setDialogOpen(false)}
        onConfirm={() => {
          const succeeded = onReset();
          if (succeeded) {
            reset({
              visit_date: "",
              visit_time: "",
              companion: "",
              transport: "",
              walking_tolerance: "",
              indoor_outdoor_preference: "",
              crowd_avoidance: "",
            });
          }
          return succeeded;
        }}
      />
    </>
  );
}
