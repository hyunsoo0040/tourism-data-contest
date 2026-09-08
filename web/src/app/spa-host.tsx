"use client";

/**
 * Client SPA host for the IT-DA public + internal UI (07-02).
 *
 * Next.js provides routing entry points; this host renders the previous
 * single-page application's route table inside every route segment so all
 * reachable routes stay client-rendered with identical behavior. The route
 * table is the migrated `appRoutes` from `./routes` (same paths as the
 * react-router SPA).
 */
import { usePathname } from "next/navigation";

import { BrowserHistoryRouter, type RouteObject } from "./react-router-dom";

import { appRoutes } from "./routes";

export function SpaHost() {
  const pathname = usePathname();
  return <BrowserHistoryRouter initialPathname={pathname} routes={appRoutes as RouteObject[]} />;
}
