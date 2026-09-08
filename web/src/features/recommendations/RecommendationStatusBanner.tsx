import type { RecommendationResultsResponse } from "../../api/api";

type Disclosure = RecommendationResultsResponse["release_disclosure"];

function formatReferenceDate(value: string) {
  return `${value.replaceAll("-", ".")} 기준`;
}

export function RecommendationStatusBanner({ disclosure }: { disclosure: Disclosure }) {
  const isPublicGlmAnalysis =
    disclosure.analysis_origin === "GLM_CODING_PLAN_PUBLIC_MODEL_DERIVED";
  return (
    <section
      className="recommendation-status-banner"
      data-analysis-origin={disclosure.analysis_origin}
      aria-labelledby="recommendation-analysis-origin"
    >
      <p className="eyebrow">분석 출처</p>
      <h2 id="recommendation-analysis-origin">
        {isPublicGlmAnalysis
          ? "GLM 공개 근거 모델 분석"
          : "공모전 데모용 모델 분석"}
      </h2>
      <p>
        {isPublicGlmAnalysis
          ? "권리 검수된 공개 관광 근거를 바탕으로 만든 GLM 분석이에요. 전문가 인증이나 실제 만족도 예측을 뜻하지 않아요."
          : "공개 관광 설명과 Odii 근거를 바탕으로 만든 모델 분석이에요. 전문가 인증이나 실제 만족도 예측을 뜻하지 않아요."}
      </p>
      <p className="recommendation-status-banner__date">
        {formatReferenceDate(disclosure.reference_date)}
      </p>
      <details className="recommendation-disclosure">
        <summary>분석 기준 정보</summary>
        <dl>
          <div><dt>model</dt><dd>{disclosure.model}</dd></div>
          <div><dt>prompt_schema_version</dt><dd>{disclosure.prompt_schema_version}</dd></div>
          <div><dt>profile_schema_version</dt><dd>{disclosure.profile_schema_version}</dd></div>
          <div><dt>config_sha256</dt><dd><code>{disclosure.config_sha256}</code></dd></div>
          <div><dt>source_bundle_sha256</dt><dd><code>{disclosure.source_bundle_sha256}</code></dd></div>
          <div><dt>release_sha256</dt><dd><code>{disclosure.release_sha256}</code></dd></div>
        </dl>
      </details>
    </section>
  );
}
