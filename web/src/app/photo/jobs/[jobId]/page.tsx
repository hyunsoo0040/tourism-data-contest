import { SpaHost } from "../../../spa-host";

/**
 * `/photo/jobs/[jobId]` — photo job polling route through the SPA host; the
 * client route table maps this path to PhotoJobRoute exactly as before.
 */
export default function PhotoJobPage() {
  return <SpaHost />;
}
