import type { RecommendationResultsResponse } from "../../api/api";

type ItemImageState = RecommendationResultsResponse["run"]["items"][number]["image_state"];

export type TextFirstMediaStateName =
  | "DISPLAY_ASSET_AVAILABLE"
  | "IMAGE_MISSING"
  | "IMAGE_RIGHTS_RESTRICTED"
  | "IMAGE_ANALYSIS_FAILED";

export type AuthorizedDisplayAsset = {
  src: string;
  alt: string;
  attribution: string;
};

const MEDIA_COPY = {
  IMAGE_MISSING: {
    label: "대표 이미지 없음",
    body: "확인된 대표 이미지가 없어 설명과 근거를 중심으로 안내해요.",
  },
  IMAGE_RIGHTS_RESTRICTED: {
    label: "이미지 표시 제한",
    body: "표시 권한을 확인할 수 없어 대표 이미지를 보여드리지 않아요.",
  },
  IMAGE_ANALYSIS_FAILED: {
    label: "이미지 분석 미완료",
    body: "이미지 분석을 완료하지 못해 확인된 텍스트 근거로 안내해요.",
  },
} as const;

export function mediaStateFromImageState(state: ItemImageState): TextFirstMediaStateName {
  if (state === "ABSENT") return "IMAGE_MISSING";
  if (state === "RIGHTS_RESTRICTED") return "IMAGE_RIGHTS_RESTRICTED";
  return "DISPLAY_ASSET_AVAILABLE";
}

function isAuthorizedAsset(asset: AuthorizedDisplayAsset | undefined): asset is AuthorizedDisplayAsset {
  if (asset === undefined) return false;
  const safeSource = asset.src.startsWith("/") || asset.src.startsWith("https://");
  return safeSource && asset.alt.trim().length > 0 && asset.attribution.trim().length > 0;
}

export function TextFirstMediaState({
  state,
  asset,
}: {
  state: TextFirstMediaStateName;
  asset?: AuthorizedDisplayAsset;
}) {
  if (state === "DISPLAY_ASSET_AVAILABLE" && isAuthorizedAsset(asset)) {
    return (
      <figure className="recommendation-media recommendation-media--asset" data-media-state={state}>
        <img alt={asset.alt} loading="lazy" src={asset.src} />
        <figcaption>
          <strong>검증된 대표 이미지</strong>
          <span>{asset.attribution}</span>
        </figcaption>
      </figure>
    );
  }

  if (state === "DISPLAY_ASSET_AVAILABLE") {
    return (
      <section className="recommendation-media" data-media-state={state}>
        <p className="recommendation-media__label">검증된 대표 이미지</p>
        <p>표시 자산 정보가 없어 이미지를 요청하지 않고 텍스트 근거로 안내해요.</p>
      </section>
    );
  }

  const copy = MEDIA_COPY[state];
  return (
    <section className="recommendation-media" data-media-state={state}>
      <p className="recommendation-media__label">{copy.label}</p>
      <p>{copy.body}</p>
    </section>
  );
}
