import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import scoringSnapshot from "../../../../contracts/questionnaire-v2.json";
import { QuestionnaireContractError, fetchCurrentQuestionnaire } from "../../api/api";
import { FRONTEND_QUESTIONNAIRE } from "../../content/questionnaire";
import { QuestionCard } from "./QuestionCard";
import { QuizProgress } from "./QuizProgress";

afterEach(() => vi.unstubAllGlobals());

function serve(payload: unknown) {
  const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(payload), {
    status: 200, headers: { "Content-Type": "application/json" },
  }));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("frontend questionnaire and backend scoring boundary", () => {
  it("renders local copy and submits the stable option value without fetching questions", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const firstQuestion = FRONTEND_QUESTIONNAIRE.questions[0]!;
    const onChange = vi.fn();
    render(<>
      <QuizProgress total={FRONTEND_QUESTIONNAIRE.question_order.length} answered={[]} />
      <QuestionCard question={firstQuestion} answerOptions={firstQuestion.options}
        value={undefined} onChange={onChange} countLabel="1 / 12"
        onBack={vi.fn()} onRestart={vi.fn()} />
    </>);
    expect(screen.getByRole("radiogroup", { name: firstQuestion.title_ko })).toBeTruthy();
    expect(screen.getAllByRole("radio")).toHaveLength(3);
    fireEvent.click(screen.getByRole("radio", { name: firstQuestion.options[2]!.text_ko }));
    expect(onChange).toHaveBeenCalledWith(3);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("ignores backend presentation changes and returns the frontend copy after checking scoring", async () => {
    const remote = structuredClone(scoringSnapshot);
    remote.questions[0]!.title_ko = "서버에 남아 있는 이전 제목";
    remote.questions[0]!.description_ko = "서버에 남아 있는 이전 설명";
    remote.questions[0]!.options[0]!.text_ko = "서버에 남아 있는 이전 선택지";
    remote.questions[0]!.options[0]!.keywords_ko = ["이전", "표현"];
    serve(remote);
    expect(await fetchCurrentQuestionnaire()).toBe(FRONTEND_QUESTIONNAIRE);
    expect(FRONTEND_QUESTIONNAIRE.questions[0]!.title_ko).not.toBe(remote.questions[0]!.title_ko);
  });

  it.each([
    ["version", (remote: typeof scoringSnapshot) => { remote.questionnaire_version = "unknown"; }],
    ["hash", (remote: typeof scoringSnapshot) => { remote.config_hash = "wrong"; }],
    ["scoring version", (remote: typeof scoringSnapshot) => { remote.scoring_version = "unknown"; }],
    ["order", (remote: typeof scoringSnapshot) => { remote.question_order.reverse(); }],
    ["question ID", (remote: typeof scoringSnapshot) => { remote.questions[0]!.question_id = "q2"; }],
    ["choice ID", (remote: typeof scoringSnapshot) => { remote.questions[0]!.options[0]!.choice_id = "q1o2"; }],
    ["choice value", (remote: typeof scoringSnapshot) => { remote.questions[0]!.options[0]!.value = 2; }],
    ["choice axis", (remote: typeof scoringSnapshot) => { remote.questions[0]!.options[0]!.axis = "WRONG"; }],
    ["weights", (remote: typeof scoringSnapshot) => { remote.scoring_matrix.q5o2.HISTORY_TRADITION = 10; }],
    ["missing question", (remote: typeof scoringSnapshot) => { remote.questions.pop(); }],
  ])("rejects incompatible %s even when the backend reports the expected config hash", async (_name, mutate) => {
    const remote = structuredClone(scoringSnapshot);
    mutate(remote);
    serve(remote);
    await expect(fetchCurrentQuestionnaire()).rejects.toBeInstanceOf(QuestionnaireContractError);
  });

  it("does not treat an unreachable backend as a verified scoring contract", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("offline")));
    await expect(fetchCurrentQuestionnaire()).rejects.toThrow("질문을 불러오지 못했어요.");
  });
});
