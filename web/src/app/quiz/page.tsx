import { SpaHost } from "../spa-host";

/**
 * `/quiz` — upstream 12-scenario taste-test UI (취향테스트.html) driven by
 * GET /v1/questionnaires/current through the SPA host.
 */
export default function QuizPage() {
  return <SpaHost />;
}
