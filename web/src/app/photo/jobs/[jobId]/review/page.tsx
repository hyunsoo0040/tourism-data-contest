import { SpaHost } from "../../../../spa-host";

/**
 * `/photo/jobs/[jobId]/review` — photo trait review route through the SPA
 * host; the client route table maps this path to PhotoJobRoute.
 */
export default function PhotoJobReviewPage() {
  return <SpaHost />;
}
