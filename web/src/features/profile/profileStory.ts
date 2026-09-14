import type { PreferenceProfile, QuestionnaireDefinition } from "../../api/api";
import { pickResultForProfile } from "../../app/upstream/resultProjection";
import { PROFILE_AXIS_ORDER, projectDisplayScores } from "./displayScores";

export const STORY_WIDTH = 1080;
export const STORY_HEIGHT = 1920;

const AXIS_LABELS = ["대상•원형형", "의미•이미지형", "자기•몰입형"] as const;
const THEMES = {
  history: { paper: "#FBF2E5", ink: "#48291D", accent: "#A64B2A", wash: "#E8D5BB" },
  image: { paper: "#F6EDF7", ink: "#492C52", accent: "#85508D", wash: "#DFCEE4" },
  rest: { paper: "#EFF2E7", ink: "#253F34", accent: "#426C53", wash: "#CBD8C4" },
} as const;

export function profileStoryData(profile: PreferenceProfile, questionnaire: QuestionnaireDefinition) {
  const display = projectDisplayScores(profile.scores, questionnaire.axis_tie_break);
  if (display === null) return null;
  const result = pickResultForProfile(questionnaire, profile);
  return {
    character: result.character,
    type: result.name,
    role: result.role.split("|").pop()!.trim(),
    lens: result.lens,
    image: result.image,
    theme: result.badgeClass as keyof typeof THEMES,
    scores: PROFILE_AXIS_ORDER.map((axis, i) => ({ label: AXIS_LABELS[i]!, value: display[axis] })),
    // No answers, trip details, profile identifiers, or uploaded photos enter the image.
    isMock: profile.description_ko.includes("UI 목업"),
  };
}

export type ProfileStoryData = NonNullable<ReturnType<typeof profileStoryData>>;

function loadImage(src: string): Promise<HTMLImageElement> {
  const image = new Image();
  image.src = src;
  return image.decode().then(() => image);
}

function fitText(ctx: CanvasRenderingContext2D, text: string, size: number, weight: number, width: number) {
  ctx.font = `${weight} ${size}px "Noto Sans KR"`;
  while (ctx.measureText(text).width > width && size > 28) {
    size -= 1;
    ctx.font = `${weight} ${size}px "Noto Sans KR"`;
  }
}

function wrapText(ctx: CanvasRenderingContext2D, text: string, width: number): string[] {
  const lines: string[] = [];
  let line = "";
  for (const word of text.split(/\s+/)) {
    if (line && ctx.measureText(`${line} ${word}`).width > width) {
      lines.push(line);
      line = word;
    } else line = line ? `${line} ${word}` : word;
  }
  if (line) lines.push(line);
  return lines;
}

/** A separate print composition. Never captures or restyles the visible page. */
export async function renderProfileStory(data: ProfileStoryData): Promise<File> {
  // A font/image failure is retryable; never export a half-loaded or fallback-font poster.
  const assets = Promise.all([
    loadImage(data.image),
    loadImage("/itda-logo-icon.png"),
    document.fonts.load('800 112px "Noto Sans KR"', data.character),
    document.fonts.load('500 36px "Noto Sans KR"', data.lens),
    document.fonts.load('700 64px "Inter"', "IT-DA 0123456789"),
  ]);
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const [character, logo] = await Promise.race([
    assets,
    new Promise<never>((_, reject) => { timeout = setTimeout(() => reject(new Error("Story assets timed out")), 15_000); }),
  ]).finally(() => clearTimeout(timeout));

  const canvas = document.createElement("canvas");
  canvas.width = STORY_WIDTH;
  canvas.height = STORY_HEIGHT;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("Canvas unavailable");
  const contentLeft = 108;
  const contentWidth = STORY_WIDTH - contentLeft * 2;
  const contentRight = contentLeft + contentWidth;
  const theme = THEMES[data.theme];
  ctx.fillStyle = theme.paper;
  ctx.fillRect(0, 0, STORY_WIDTH, STORY_HEIGHT);
  ctx.imageSmoothingQuality = "high";

  // Keep all essential text inside y=210…1660, clear of story app controls.
  ctx.drawImage(logo, contentLeft, 206, 64, 64);
  ctx.font = '800 43px "Inter"';
  ctx.fillStyle = "#FC651A";
  ctx.fillText("IT-DA", contentLeft + 76, 255);
  ctx.fillStyle = theme.ink;

  fitText(ctx, data.character, 112, 800, contentWidth);
  ctx.fillText(data.character, contentLeft, 402);
  fitText(ctx, `${data.role}  /  ${data.type}`, 35, 500, contentWidth);
  ctx.fillStyle = theme.accent;
  ctx.fillText(`${data.role}  /  ${data.type}`, contentLeft, 463);

  // Art-directed portrait crop: retain the existing character's face and body.
  const photo = { x: contentLeft, y: 566, width: contentWidth, height: 722 };
  const sourceHeight = character.naturalWidth * photo.height / photo.width;
  const sourceY = (character.naturalHeight - sourceHeight) * 0.67;
  ctx.save();
  ctx.beginPath();
  ctx.roundRect(photo.x, photo.y, photo.width, photo.height, 16);
  ctx.clip();
  ctx.drawImage(character, 0, sourceY, character.naturalWidth, sourceHeight, photo.x, photo.y, photo.width, photo.height);
  ctx.restore();

  // A short caption belongs to the photograph, not another UI card.
  ctx.fillStyle = theme.ink;
  ctx.font = '500 35px "Noto Sans KR"';
  const lines = wrapText(ctx, data.lens, contentWidth);
  lines.forEach((line, i) => ctx.fillText(line, contentLeft, 1400 + i * 51));

  const columnGap = 32;
  const columnWidth = (contentWidth - columnGap * 2) / 3;
  data.scores.forEach((score, i) => {
    const x = contentLeft + i * (columnWidth + columnGap);
    ctx.font = '500 30px "Noto Sans KR"';
    ctx.fillStyle = theme.ink;
    ctx.fillText(score.label, x, 1541);
    ctx.font = '700 65px "Inter"';
    ctx.fillText(String(score.value), x, 1619);
    const numberWidth = ctx.measureText(String(score.value)).width;
    ctx.font = '500 27px "Noto Sans KR"';
    ctx.fillText("점", x + numberWidth + 8, 1617);
    ctx.fillStyle = theme.wash;
    ctx.fillRect(x, 1644, columnWidth, 8);
    ctx.fillStyle = theme.accent;
    ctx.fillRect(x, 1644, columnWidth * score.value / 100, 8);
  });

  ctx.font = '500 25px "Noto Sans KR"';
  ctx.fillStyle = theme.accent;
  ctx.fillText(data.isMock ? "UI 목업 · 예시 결과" : "이번 여행의 기대 비중 · 합계 100점", contentLeft, 1722);
  ctx.textAlign = "right";
  ctx.font = '600 29px "Inter"';
  ctx.fillText("it-da.app", contentRight, 1722);

  const blob = await new Promise<Blob>((resolve, reject) => canvas.toBlob(
    (value) => value ? resolve(value) : reject(new Error("PNG export failed")), "image/png",
  ));
  // Release the drawing buffer. Only the resulting PNG remains for this mounted result.
  canvas.width = 0;
  canvas.height = 0;
  return new File([blob], `IT-DA-${data.character.replace(/\s+/g, "-")}-story.png`, { type: "image/png" });
}

export function downloadProfileStory(file: File): void {
  const url = URL.createObjectURL(file);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = file.name;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  // Safari needs the URL to survive the click while its download process reads it.
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}
