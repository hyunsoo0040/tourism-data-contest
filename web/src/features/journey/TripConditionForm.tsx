import { JOURNEY_COPY, TRIP_CHOICES, TRIP_FIELD_LABELS, tripChoiceLabel } from "../../content/journey.ko";
import { useEffect, useMemo, useRef, useState } from "react";
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
import { localDate } from "./tripDate";
import {
  FACILITY_CHOICES,
  readGroundedTripInput,
  resetGroundedTripInput,
  writeGroundedTripInput,
  type RequiredFacility,
} from "./groundedTrip";
import { useTravelRegions } from "../../api/recommendation-regions";

const REQUIRED_FIELD_ORDER = Object.keys(TRIP_FIELD_LABELS) as Array<keyof typeof TRIP_FIELD_LABELS>;

const ERROR_FIELD_ORDER: Array<keyof TripConditionFormValues> = ["visit_date", ...REQUIRED_FIELD_ORDER];

const resolver: Resolver<TripConditionFormValues, unknown, TripConditions> = async (values) => {
  const result = tripConditionFormSchema.safeParse(values);
  const errors: FieldErrors<TripConditionFormValues> = {};
  if (!result.success) {
    for (const issue of result.error.issues) {
      const name = issue.path[0] as keyof TripConditionFormValues | undefined;
      if (name === undefined || errors[name] !== undefined) continue;
      errors[name] = name === "visit_date"
        ? { type: "validate", message: "올바른 방문 날짜를 입력해 주세요." }
        : { type: "required", message: `${TRIP_FIELD_LABELS[name]}을 선택해 주세요.` };
    }
  }
  if (values.visit_date && !errors.visit_date && values.visit_date < localDate()) {
    errors.visit_date = { type: "min", message: "오늘 또는 이후 날짜를 선택해 주세요." };
  }
  if (result.success && Object.keys(errors).length === 0) {
    return { values: result.data, errors: {} };
  }
  return { values: {}, errors };
};

function ChoiceGroup({
  name,
  register,
  error,
  retainedGroup = false,
}: {
  name: keyof typeof TRIP_FIELD_LABELS;
  register: ReturnType<typeof useForm<TripConditionFormValues>>["register"];
  error?: string;
  retainedGroup?: boolean;
}) {
  const errorId = `${name}-error`;
  return (
    <fieldset className="choice-group" id={`${name}-field`} aria-describedby={error ? errorId : undefined}>
      <legend>{TRIP_FIELD_LABELS[name]}</legend>
      <div className="choice-grid">
        {name === "companion" && retainedGroup ? (
          <label className="choice-card">
            <input type="radio" value="GROUP" {...register(name)} />
            <span>{tripChoiceLabel("companion", "GROUP")}</span>
          </label>
        ) : null}
        {TRIP_CHOICES[name].map((choice) => (
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
  primaryLabel = JOURNEY_COPY.start.primaryLabel,
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
  const [today, setToday] = useState(() => localDate());
  const [groundedDraft] = useState(readGroundedTripInput);
  const travelRegions = useTravelRegions();
  const [regionCode, setRegionCode] = useState(groundedDraft.region_code ?? "");
  const [requiredFacilities, setRequiredFacilities] = useState<RequiredFacility[]>(groundedDraft.required_facilities);
  const [exactVisitTime, setExactVisitTime] = useState(groundedDraft.visit_time ?? "");
  const [groundedError, setGroundedError] = useState<string | null>(null);
  const recoveryResetRef = useRef<HTMLButtonElement>(null);
  const errorSummaryRef = useRef<HTMLDivElement>(null);
  const {
    register,
    handleSubmit,
    setFocus,
    reset,
    watch,
    formState: { errors },
  } = useForm<TripConditionFormValues, unknown, TripConditions>({
    defaultValues: {
      ...defaultValues,
      visit_date: !defaultValues.visit_date || defaultValues.visit_date < today ? today : defaultValues.visit_date,
    },
    resolver,
    shouldFocusError: false,
  });
  // Only restored selections expose the retired option; new trips use the design's four choices.
  const retainedGroup = defaultValues.companion === "GROUP" && watch("companion") === "GROUP";

  useEffect(() => {
    let timer: number;
    const refreshToday = () => {
      window.clearTimeout(timer);
      const now = new Date();
      setToday(localDate(now));
      const midnight = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
      timer = window.setTimeout(refreshToday, midnight.getTime() - now.getTime());
    };
    const onVisible = () => {
      if (document.visibilityState === "visible") refreshToday();
    };
    refreshToday();
    window.addEventListener("focus", refreshToday);
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.clearTimeout(timer);
      window.removeEventListener("focus", refreshToday);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, []);

  const errorNames = useMemo(
    () => ERROR_FIELD_ORDER.filter((name) => errors[name] !== undefined),
    [errors],
  );

  const submitValid: SubmitHandler<TripConditions> = (values) => {
    if (!writeGroundedTripInput({
      region_code: regionCode || null,
      visit_date: values.visit_date ?? null,
      visit_time: exactVisitTime || null,
      required_facilities: requiredFacilities,
    })) {
      setGroundedError("선택한 추가 여행 조건을 저장하지 못했어요. 방문 시간과 브라우저 저장 설정을 확인해 주세요.");
      return;
    }
    setGroundedError(null);
    onSubmit(values);
  };

  const submitInvalid = (invalidErrors: FieldErrors<TripConditionFormValues>) => {
    const first = ERROR_FIELD_ORDER.find((name) => invalidErrors[name] !== undefined);
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
        onSubmit={(event) => {
          setToday(localDate());
          void handleSubmit(submitValid, submitInvalid)(event);
        }}
      >
        {requestError ? <p className="error-summary" role="alert">{requestError}</p> : null}
        {groundedError ? <p className="error-summary" role="alert">{groundedError}</p> : null}
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

        <fieldset className="visit-fieldset travel-region-fieldset">
          <legend>{JOURNEY_COPY.region.legend}</legend>
          <label className="date-field">
            <span>{JOURNEY_COPY.region.label}</span>
            <select value={regionCode} onChange={(event) => setRegionCode(event.target.value)} aria-describedby="travel-region-help">
              <option value="">{JOURNEY_COPY.region.all}</option>
              {regionCode && !travelRegions.regions.some((region) => region.region_code === regionCode) &&
                <option value={regionCode}>{JOURNEY_COPY.region.previous}</option>}
              {travelRegions.regions.map((region) => <option key={region.region_code} value={region.region_code}>{region.region_name} · {region.place_count}곳</option>)}
            </select>
          </label>
          <p id="travel-region-help">{JOURNEY_COPY.region.help}</p>
          {travelRegions.kind === "loading" && <p role="status">추천할 수 있는 지역을 확인하고 있어요.</p>}
          {travelRegions.kind === "unavailable" && <p>지역 목록을 확인하지 못했어요.{" "}
            <button type="button" className="button button--secondary" onClick={travelRegions.refresh}>지역 목록 다시 확인</button></p>}
        </fieldset>

        <fieldset className="visit-fieldset">
          <legend>{JOURNEY_COPY.visit.legend}</legend>
          <label className="date-field">
            <span>{JOURNEY_COPY.visit.dateLabel}</span>
            <input
              id="visit_date-field"
              type="date"
              min={today}
              aria-invalid={errors.visit_date ? true : undefined}
              aria-describedby={errors.visit_date ? "visit_date-error" : undefined}
              {...register("visit_date")}
            />
          </label>
          {errors.visit_date ? <p className="field-error" id="visit_date-error">{errors.visit_date.message}</p> : null}
          <ChoiceGroup
            name="visit_time"
            register={register}
            error={errors.visit_time?.message}
          />
          <label className="date-field">
            <span>{JOURNEY_COPY.visit.timeLabel}</span>
            <input type="time" value={exactVisitTime} onChange={(event) => setExactVisitTime(event.target.value)} />
          </label>
        </fieldset>

        <ChoiceGroup name="companion" register={register} error={errors.companion?.message} retainedGroup={retainedGroup} />
        <fieldset className="choice-group" aria-describedby="facility-preferences-help">
          <legend>{JOURNEY_COPY.facilities.legend}</legend>
          <p id="facility-preferences-help">{JOURNEY_COPY.facilities.help}</p>
          <div className="choice-grid">
            {FACILITY_CHOICES.map((choice) => (
              <label className="choice-card" key={choice.id}>
                <input
                  type="checkbox"
                  checked={requiredFacilities.includes(choice.id)}
                  onChange={(event) => setRequiredFacilities((current) => event.target.checked
                    ? [...current, choice.id]
                    : current.filter((id) => id !== choice.id))}
                />
                <span>{choice.label}</span>
              </label>
            ))}
          </div>
        </fieldset>
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
            if (!resetGroundedTripInput()) {
              setGroundedError("추가 여행 조건을 지우지 못했어요. 브라우저 저장 설정을 확인해 주세요.");
              return false;
            }
            setRequiredFacilities([]);
            setRegionCode("");
            setExactVisitTime("");
            setGroundedError(null);
            const resetDate = localDate();
            setToday(resetDate);
            reset({
              visit_date: resetDate,
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
