import { useEffect, useMemo, useState } from "react";

import type { PreferenceProfile, QuestionnaireDefinition } from "../../api/api";
import { downloadProfileStory, profileStoryData, renderProfileStory } from "./profileStory";

export function ProfileStoryButton({ profile, questionnaire }: {
  profile: PreferenceProfile;
  questionnaire: QuestionnaireDefinition;
}) {
  const data = useMemo(() => profileStoryData(profile, questionnaire), [profile, questionnaire]);
  const [prepared, setPrepared] = useState<{ data: typeof data; file: File } | null>(null);
  const [failed, setFailed] = useState(false);
  const [sharing, setSharing] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [message, setMessage] = useState("");
  const file = prepared?.data === data ? prepared.file : null;

  useEffect(() => {
    let active = true;
    setFailed(false);
    setMessage("");
    setPrepared(null);
    if (data === null) return;
    void renderProfileStory(data).then((file) => {
      if (active) setPrepared({ data, file });
    }).catch(() => {
      if (active) {
        setFailed(true);
        setMessage("이미지를 준비하지 못했어요. 버튼을 눌러 다시 시도해 주세요.");
      }
    });
    return () => { active = false; };
  }, [data, attempt]);

  const share = async () => {
    if (failed) { setAttempt((value) => value + 1); return; }
    if (!file || sharing) return;
    setSharing(true);
    setMessage("");
    try {
      // The file is prepared before the tap: native sharing retains user activation on iOS.
      if (navigator.canShare?.({ files: [file] }) && navigator.share) {
        await navigator.share({ files: [file] });
      } else {
        downloadProfileStory(file);
        setMessage("PNG 다운로드를 시작했어요. 인스타그램 스토리에서 저장한 이미지를 선택해 주세요.");
      }
    } catch (error) {
      const cancelled = typeof error === "object" && error !== null && "name" in error && error.name === "AbortError";
      if (!cancelled) {
        downloadProfileStory(file);
        setMessage("공유창을 열지 못해 PNG 다운로드를 시작했어요.");
      }
    } finally {
      setSharing(false);
    }
  };

  if (data === null) return null;

  return (
    <>
      <button
        type="button"
        className="control"
        disabled={sharing || (!file && !failed)}
        aria-busy={sharing || (!file && !failed)}
        title={message || "1080 × 1920 PNG · 공유창에서 이미지 저장 또는 공유 대상을 선택해 주세요"}
        onClick={() => void share()}
      >
        {sharing ? "공유창 여는 중…" : failed ? "스토리 이미지 다시 준비" : !file ? "스토리 이미지 준비 중…" : "스토리 이미지 공유·저장"}
      </button>
      <span className="visually-hidden" role="status" aria-live="polite">{message}</span>
    </>
  );
}
