import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import questionnaireArtifact from "../../../../contracts/questionnaire-v2.json";
import { QuestionnaireContractError, fetchCurrentQuestionnaire } from "../../api/api";
import { QuestionCard, QuestionnaireBoundary } from "./QuestionCard";
import { QuizProgress } from "./QuizProgress";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("canonical questionnaire consumer", () => {
  it("fetches the served contract and renders its first question, five labels, and progress", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify(questionnaireArtifact), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    const questionnaire = await fetchCurrentQuestionnaire();
    expect(questionnaire).toEqual(questionnaireArtifact);
    const firstOrdinal = questionnaire.question_order[0];
    const firstQuestion = questionnaire.questions.find(
      ({ ordinal }) => ordinal === firstOrdinal,
    );
    expect(firstQuestion).toBeDefined();

    const onChange = vi.fn();
    render(
      <>
        <QuizProgress total={questionnaire.question_order.length} answered={[]} />
        <QuestionCard
          question={firstQuestion!}
          answerOptions={firstQuestion!.options}
          value={undefined}
          onChange={onChange}
          countLabel="1 / 12"
          onBack={vi.fn()}
          onRestart={vi.fn()}
        />
      </>,
    );

    expect(
      screen.getByRole("radiogroup", {
        name: "기차에서 내렸는데 예상보다 30분 일찍 도착했다.",
      }),
    ).toBeTruthy();
    expect(screen.getAllByRole("radio")).toHaveLength(3);
    expect(screen.getByRole("radio", { name: "근처 벤치에 앉아 여행이 시작된 기분을 느껴본다." })).toBeTruthy();
    expect(screen.getByRole("radio", { name: "역 주변을 천천히 걸으며 동네 모습을 살펴본다." })).toBeTruthy();
    expect(screen.getByText("1 / 12")).toBeTruthy();
    expect(screen.getByText("0 / 12 응답 완료")).toBeTruthy();
    expect(screen.queryByText("HISTORY_TRADITION")).toBeNull();

    fireEvent.click(screen.getByRole("radio", { name: "역 주변을 천천히 걸으며 동네 모습을 살펴본다." }));
    expect(onChange).toHaveBeenCalledWith(3);
  });

  it("shows loading and a recoverable Korean error without substituting local questions", async () => {
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new TypeError("offline"))
      .mockResolvedValueOnce(
        new Response(JSON.stringify(questionnaireArtifact), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);

    render(
      <QuestionnaireBoundary>
        {(questionnaire) => <p>{questionnaire.questions[0]?.title_ko}</p>}
      </QuestionnaireBoundary>,
    );

    expect(screen.getByText("질문을 불러오는 중이에요.")).toBeTruthy();
    expect(await screen.findByRole("alert")).toHaveProperty(
      "textContent",
      "질문을 불러오지 못했어요. 잠시 후 다시 시도해 주세요.",
    );
    expect(screen.queryByText(questionnaireArtifact.questions[0]!.title_ko)).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "다시 시도하기" }));

    expect(await screen.findByText(questionnaireArtifact.questions[0]!.title_ko)).toBeTruthy();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("fails closed when a served version, hash, or canonical field is changed", async () => {
    const tampered = structuredClone(questionnaireArtifact);
    tampered.config_hash = "tampered-config-hash";
    tampered.questions[2]!.title_ko = "변경되어서는 안 되는 질문";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify(tampered), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    await expect(fetchCurrentQuestionnaire()).rejects.toBeInstanceOf(
      QuestionnaireContractError,
    );
  });
});
