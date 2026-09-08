import { useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import {
  ApiRequestError,
  type QuestionnaireDefinition,
} from "../api/api";
import { useJourneyDraft } from "../app/AppShell";
import { tripConditionsSchema, type QuestionnaireAnswers } from "../app/schemas";
import { QuestionCard, QuestionnaireBoundary } from "../features/journey/QuestionCard";
import { QuizProgress } from "../features/journey/QuizProgress";
import { createAndStorePreferenceProfile } from "../features/profile/profileSubmission";

function requestedOrdinal(search: string): number | null {
  const raw = new URLSearchParams(search).get("q");
  if (raw === null || !/^\d+$/.test(raw)) return null;
  const value = Number(raw);
  return Number.isInteger(value) && value >= 1 && value <= 12 ? value : null;
}

function validationQuestionOrdinal(body: unknown): number | null {
  if (typeof body !== "object" || body === null || !("detail" in body)) return null;
  const detail = (body as { detail?: unknown }).detail;
  if (!Array.isArray(detail)) return null;
  for (const item of detail) {
    if (typeof item !== "object" || item === null || !("loc" in item)) continue;
    const location = (item as { loc?: unknown }).loc;
    if (!Array.isArray(location)) continue;
    const questionId = location.find(
      (part): part is string => typeof part === "string" && /^q(?:[1-9]|1[0-2])$/.test(part),
    );
    if (questionId !== undefined) return Number(questionId.slice(1));
  }
  return null;
}

function QuizContent({ questionnaire }: { questionnaire: QuestionnaireDefinition }) {
  const location = useLocation();
  const navigate = useNavigate();
  const { draft, updateDraft, reportStorageUnavailable } = useJourneyDraft();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const submittingRef = useRef(false);
  const submissionGenerationRef = useRef(0);
  const activeSubmissionRef = useRef<{
    controller: AbortController;
    generation: number;
    originOrdinal: number;
  } | null>(null);
  const currentOrdinalRef = useRef<number | null>(null);
  const previousOrdinalRef = useRef<number | null>(null);
  const [invalid, setInvalid] = useState(false);
  const [busy, setBusy] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [validationOrdinal, setValidationOrdinal] = useState<number | null>(null);
  const requested = requestedOrdinal(location.search);
  const editingProfile =
    (location.state as { editingProfile?: boolean } | null)?.editingProfile === true;
  const editNavigationState = useMemo(
    () => (editingProfile ? { editingProfile: true } : undefined),
    [editingProfile],
  );
  const ordinal = requested ?? 1;
  currentOrdinalRef.current = ordinal;
  const firstIncomplete = questionnaire.question_order.find((candidate) => {
    const item = questionnaire.questions.find(({ ordinal: value }) => value === candidate);
    return item ? draft?.answers[item.question_id as keyof QuestionnaireAnswers] === undefined : true;
  });
  const availableOrdinal =
    firstIncomplete !== undefined && ordinal > firstIncomplete ? firstIncomplete : ordinal;
  const redirecting = requested === null || availableOrdinal !== ordinal;
  const question = questionnaire.questions.find(({ ordinal: value }) => value === availableOrdinal);

  useEffect(() => {
    if (redirecting) {
      void navigate(`/quiz?q=${availableOrdinal}`, { replace: true, state: editNavigationState });
      return;
    }
    const focusTimer = window.setTimeout(() => headingRef.current?.focus({ preventScroll: true }), 0);
    return () => window.clearTimeout(focusTimer);
  }, [availableOrdinal, editNavigationState, navigate, ordinal, redirecting]);

  useEffect(() => {
    if (previousOrdinalRef.current !== null && previousOrdinalRef.current !== ordinal) {
      const activeSubmission = activeSubmissionRef.current;
      if (activeSubmission !== null && activeSubmission.originOrdinal !== ordinal) {
        activeSubmission.controller.abort();
        activeSubmissionRef.current = null;
        submittingRef.current = false;
        setBusy(false);
      }
      setInvalid(false);
      setSubmitError(null);
      setValidationOrdinal(null);
    }
    previousOrdinalRef.current = ordinal;
  }, [ordinal]);

  useEffect(
    () => () => {
      activeSubmissionRef.current?.controller.abort();
      activeSubmissionRef.current = null;
      submittingRef.current = false;
    },
    [],
  );

  if (!question || redirecting) {
    return (
      <p className="inline-notice" role="status" aria-live="polite">
        이어서 답할 질문으로 이동했어요.
      </p>
    );
  }

  const answerKey = question.question_id as keyof QuestionnaireAnswers;
  const selected = draft?.answers[answerKey];
  const currentIndex = questionnaire.question_order.indexOf(ordinal);
  const previousOrdinal = questionnaire.question_order[currentIndex - 1];
  const nextOrdinal = questionnaire.question_order[currentIndex + 1];
  const answered = questionnaire.question_order.filter((candidate) => {
    const item = questionnaire.questions.find(({ ordinal: value }) => value === candidate);
    return item ? draft?.answers[item.question_id as keyof QuestionnaireAnswers] !== undefined : false;
  });

  const selectAnswer = (value: number) => {
    if (busy) return;
    setInvalid(false);
    setSubmitError(null);
    setValidationOrdinal(null);
    const answers = { ...draft?.answers, [answerKey]: value };
    updateDraft({
      current_route: "/quiz",
      current_question: nextOrdinal ?? ordinal,
      answers,
    });
    if (nextOrdinal !== undefined) {
      void navigate(`/quiz?q=${nextOrdinal}`, { state: editNavigationState });
      return;
    }
    window.setTimeout(() => void submitProfileWithAnswers(answers), 0);
  };

  const submitProfileWithAnswers = async (selectedAnswers?: Partial<QuestionnaireAnswers>) => {
    if (submittingRef.current) return;
    const answersSource = selectedAnswers ?? draft?.answers;
    const answerEntries = questionnaire.question_order.map((candidate) => {
      const item = questionnaire.questions.find(({ ordinal: value }) => value === candidate);
      return item ? [item.question_id, answersSource?.[item.question_id as keyof QuestionnaireAnswers]] : null;
    });
    if (answerEntries.some((entry) => entry === null || entry[1] === undefined)) {
      setInvalid(true);
      return;
    }
    const answers = Object.fromEntries(answerEntries as [string, number][]) as QuestionnaireAnswers;
    const tripConditions = tripConditionsSchema.parse(draft?.trip_conditions);
    submittingRef.current = true;
    const originOrdinal = ordinal;
    const generation = submissionGenerationRef.current + 1;
    submissionGenerationRef.current = generation;
    const controller = new AbortController();
    activeSubmissionRef.current = { controller, generation, originOrdinal };
    const isCurrentSubmission = () =>
      activeSubmissionRef.current?.generation === generation &&
      currentOrdinalRef.current === originOrdinal &&
      !controller.signal.aborted;
    setBusy(true);
    setSubmitError(null);
    setValidationOrdinal(null);
    try {
      const result = await createAndStorePreferenceProfile(
        tripConditions,
        answers,
        controller.signal,
        isCurrentSubmission,
      );
      if (!isCurrentSubmission()) return;
      updateDraft({ current_route: "/profile", current_question: ordinal, answers });
      if (result.reference?.state === "memory-fallback") reportStorageUnavailable();
      void navigate(
        "/profile",
        editingProfile
          ? {
              state: {
                announcement: "수정한 답변으로 기대 프로필을 다시 만들었어요.",
                focusProfile: true,
              },
            }
          : undefined,
      );
    } catch (error) {
      if (!isCurrentSubmission()) return;
      if (error instanceof ApiRequestError && error.status === 422) {
        setValidationOrdinal(validationQuestionOrdinal(error.body));
        setSubmitError("확인할 답변이 있어요.");
      } else if (
        error instanceof ApiRequestError &&
        error.message === "프로필 형식을 확인하지 못했어요."
      ) {
        setSubmitError("프로필 형식을 확인하지 못했어요. 잠시 후 다시 시도해 주세요.");
      } else {
        setSubmitError("프로필을 만들지 못했어요. 입력한 답변은 이 브라우저에 보관되어 있어요.");
      }
    } finally {
      if (activeSubmissionRef.current?.generation === generation) {
        activeSubmissionRef.current = null;
        submittingRef.current = false;
        setBusy(false);
      }
    }
  };

  const submitProfile = () => submitProfileWithAnswers();

  const goBack = () => {
    setInvalid(false);
    setSubmitError(null);
    setValidationOrdinal(null);
    if (previousOrdinal === undefined) {
      updateDraft({ current_route: "/start", current_question: 1 });
      void navigate("/start");
      return;
    }
    updateDraft({ current_route: "/quiz", current_question: previousOrdinal });
    void navigate(`/quiz?q=${previousOrdinal}`, { state: editNavigationState });
  };

  const reviewAnswers = () => {
    setSubmitError(null);
    const targetOrdinal = validationOrdinal;
    setValidationOrdinal(null);
    if (targetOrdinal !== null) {
      updateDraft({ current_route: "/quiz", current_question: targetOrdinal });
      void navigate(`/quiz?q=${targetOrdinal}`, { state: editNavigationState });
      return;
    }
    headingRef.current?.focus();
  };

  return (
    <section className="test-shell">
      <QuizProgress total={questionnaire.question_order.length} answered={answered} />
      <p className="visually-hidden" role="status" aria-live="polite">
        질문 {ordinal}, {questionnaire.question_order.length}개 중 {ordinal}번째
      </p>
      <QuestionCard
        question={question}
        answerOptions={question.options}
        value={selected}
        onChange={selectAnswer}
        invalid={invalid}
        disabled={busy}
        headingRef={headingRef}
        countLabel={`${ordinal} / ${questionnaire.question_order.length}`}
        onBack={goBack}
        onRestart={() => {
          updateDraft({ current_route: "/quiz", current_question: 1, answers: {} });
          void navigate("/quiz?q=1", { state: editNavigationState });
        }}
      />
      {submitError ? (
        <div className="panel error-summary" role="alert">
          <p>{submitError}</p>
          <div className="controls">
            <button className="control primary" onClick={() => void submitProfile()} type="button">
              다시 시도하기
            </button>
            <button className="control" onClick={reviewAnswers} type="button">
              답변 확인하기
            </button>
          </div>
        </div>
      ) : null}
    </section>
  );
}

export function QuizPage() {
  const navigate = useNavigate();
  const { draft } = useJourneyDraft();
  const hasTripConditions = tripConditionsSchema.safeParse(draft?.trip_conditions).success;

  useEffect(() => {
    if (!hasTripConditions) void navigate("/start", { replace: true });
  }, [hasTripConditions, navigate]);

  if (!hasTripConditions) {
    return (
      <p className="inline-notice" role="status" aria-live="polite">
        먼저 이번 여행 조건을 알려 주세요.
      </p>
    );
  }

  return <QuestionnaireBoundary>{(questionnaire) => <QuizContent questionnaire={questionnaire} />}</QuestionnaireBoundary>;
}
