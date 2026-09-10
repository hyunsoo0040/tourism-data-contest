/**
 * In-repo react-router-dom compatibility surface for the IT-DA Next.js
 * App Router migration (07-02).
 *
 * The framework-agnostic feature modules and the test suite were written
 * against a small, stable react-router surface. This module re-implements
 * exactly that surface on top of a shared history abstraction:
 *
 * - `BrowserAppRouter` (this repo): mounts browser-history routing for the
 *   Next.js host (see src/app/spa-host.tsx).
 * - `MemoryRouter` / `createMemoryRouter` + `RouterProvider`: memory-history
 *   routing used by the Vitest suites, API-compatible with the previously
 *   pinned react-router-dom@7.18.1 subset.
 *
 * Navigation semantics preserved: `navigate(to | delta, { replace, state })`,
 * `location.state` round-trips through `history.state.usr` in browser mode
 * and entry state in memory mode, `<Link>` renders a real anchor, index and
 * nested child routes with `<Outlet>`, wildcard routes, and
 * `useSearchParams` setters that preserve SPA behavior.
 */
import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type AnchorHTMLAttributes,
  type ReactNode,
} from "react";

export type To = string | number | Partial<{ pathname: string; search: string; hash: string }>;

export type RouteObject = {
  path?: string;
  element?: ReactNode;
  index?: boolean;
  children?: RouteObject[];
};

export type LocationShape = {
  pathname: string;
  search: string;
  hash: string;
  state: unknown;
  key: string;
};

type HistoryEntry = { path: string; state: unknown; key: string };
type InitialEntry = string | Partial<Pick<LocationShape, "pathname" | "search" | "state">>;

export function joinPaths(base: string, path: string | undefined): string {
  if (path === undefined || path === "") return base === "" ? "/" : base;
  if (path.startsWith("/")) return path;
  const normalizedBase = base.endsWith("/") ? base.slice(0, -1) : base;
  return `${normalizedBase}/${path}`;
}

/** Flatten a route tree into [layoutChain, pattern, params] rows. */
type FlatRoute = {
  chain: RouteObject[];
  pattern: string;
  wildcard: boolean;
};

function flattenRoutes(routes: RouteObject[], base = "", chain: RouteObject[] = []): FlatRoute[] {
  const flat: FlatRoute[] = [];
  for (const route of routes) {
    if (route.index === true) {
      flat.push({ chain: [...chain, route], pattern: base === "" ? "/" : base, wildcard: false });
      continue;
    }
    const pattern = joinPaths(base, route.path);
    const wildcard = pattern.endsWith("/*") || route.path === "*";
    const nextChain = [...chain, route];
    if (route.children !== undefined && route.children.length > 0) {
      flat.push(...flattenRoutes(route.children, pattern, nextChain));
      if (route.element !== undefined) {
        flat.push({ chain: nextChain, pattern, wildcard });
      }
    } else {
      flat.push({ chain: nextChain, pattern, wildcard });
    }
  }
  return flat;
}

export type RouteMatch = {
  params: Record<string, string>;
  pathname: string;
  chain: RouteObject[];
};

function matchPathname(pattern: string, pathname: string): Record<string, string> | null {
  const wildcard = pattern.endsWith("/*");
  const patternSegments = (wildcard ? pattern.slice(0, -2) : pattern).split("/").filter(Boolean);
  const pathnameSegments = pathname.split("/").filter(Boolean);
  if (!wildcard && patternSegments.length !== pathnameSegments.length) return null;
  if (wildcard && pathnameSegments.length < patternSegments.length) return null;
  const params: Record<string, string> = {};
  for (let index = 0; index < patternSegments.length; index += 1) {
    const segment = patternSegments[index]!;
    const value = decodeURIComponent(pathnameSegments[index] ?? "");
    if (segment.startsWith(":")) {
      params[segment.slice(1)] = value;
    } else if (segment !== value) {
      return null;
    }
  }
  if (wildcard) params["*"] = pathnameSegments.slice(patternSegments.length).map(encodeURIComponent).join("/");
  return params;
}

export function matchRoutes(routes: RouteObject[], pathname: string): RouteMatch | null {
  const flat = flattenRoutes(routes);
  let best: { route: FlatRoute; params: Record<string, string>; score: number } | null = null;
  for (const route of flat) {
    const params = matchPathname(route.pattern, pathname);
    if (params === null) continue;
    const staticSegments = route.pattern
      .replace(/\/\*$/, "")
      .split("/")
      .filter(Boolean).length;
    const score = staticSegments * 10 + route.chain.length;
    if (best === null || score > best.score) best = { route, params, score };
  }
  if (best === null) return null;
  return { params: best.params, pathname, chain: best.route.chain };
}

type RouterInternals = {
  routes: RouteObject[];
  entries: HistoryEntry[];
  index: number;
  listeners: Set<() => void>;
  historyAction: "REPLACE" | "PUSH" | "POP";
};

export type ItdaRouter = {
  navigate: (to: To, options?: { replace?: boolean; state?: unknown }) => void;
  back: () => void;
  state: {
    location: LocationShape;
    matches: RouteMatch | null;
    /** "REPLACE" | "PUSH" | "POP" — mirrors react-router's history action. */
    historyAction: "REPLACE" | "PUSH" | "POP";
  };
};

function buildEntry(path: string, state: unknown): HistoryEntry {
  return {
    path,
    state,
    key: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`,
  };
}

function createRouterInternals(routes: RouteObject[], initialEntries: InitialEntry[], initialIndex: number): RouterInternals {
  const entries = (initialEntries.length > 0 ? initialEntries : ["/"]).map((entry) => {
    if (typeof entry === "object" && entry !== null) {
      const record = entry as Partial<{ pathname: string; search: string; state: unknown }>;
      return buildEntry(
        `${record.pathname ?? "/"}${record.search ?? ""}`,
        record.state ?? null,
      );
    }
    return buildEntry(String(entry), null);
  });
  const index = Math.min(Math.max(initialIndex, 0), entries.length - 1);
  return { routes, entries, index, listeners: new Set(), historyAction: "POP" };
}

function createItdaRouter(internals: RouterInternals): ItdaRouter {
  const currentLocation = (): LocationShape => {
    const entry = internals.entries[internals.index]!;
    const url = new URL(entry.path, "http://itda.local");
    return {
      pathname: url.pathname,
      search: url.search,
      hash: url.hash,
      state: entry.state,
      key: entry.key,
    };
  };
  const notify = () => {
    for (const listener of internals.listeners) listener();
  };
  const router: ItdaRouter = {
    navigate(to, options) {
      if (typeof to === "number") {
        const nextIndex = internals.index + to;
        if (nextIndex < 0 || nextIndex >= internals.entries.length) return;
        internals.index = nextIndex;
        internals.historyAction = "POP";
        notify();
        return;
      }
      const resolved =
        typeof to === "string"
          ? to
          : (() => {
              const current = new URL(internals.entries[internals.index]!.path, "http://itda.local");
              if (to.pathname !== undefined) current.pathname = to.pathname;
              if (to.search !== undefined) current.search = to.search;
              if (to.hash !== undefined) current.hash = to.hash;
              return `${current.pathname}${current.search}${current.hash}`;
            })();
      const entry = buildEntry(resolved, options?.state ?? null);
      if (options?.replace === true) {
        internals.entries[internals.index] = entry;
        internals.historyAction = "REPLACE";
      } else {
        internals.entries = [...internals.entries.slice(0, internals.index + 1), entry];
        internals.index += 1;
        internals.historyAction = "PUSH";
      }
      notify();
    },
    back() {
      router.navigate(-1);
    },
    get state() {
      const location = currentLocation();
      return {
        location,
        matches: matchRoutes(internals.routes, location.pathname),
        historyAction: internals.historyAction,
      };
    },
  };
  return router;
}

/** React state bridge: subscribes a component to router changes. */
function useRouterLocation(router: ItdaRouter): LocationShape {
  const [, setVersion] = useState(0);
  useEffect(() => {
    const internals = (router as unknown as { __internals: RouterInternals }).__internals;
    const listener = () => setVersion((version) => version + 1);
    internals.listeners.add(listener);
    return () => {
      internals.listeners.delete(listener);
    };
  }, [router]);
  return router.state.location;
}

const RouterContext = createContext<{
  /** Memory-router instance; null in browser-history mode. */
  router: ItdaRouter | null;
  location: LocationShape;
  params: Record<string, string>;
  outletDepth: number;
} | null>(null);

function useItdaRouterContext() {
  const context = useContext(RouterContext);
  if (context === null) throw new Error("react-router-dom shim used outside a router provider");
  return context;
}

/** Memory router used by tests; mirrors MemoryRouter's provider behavior. */
export function MemoryRouter({
  initialEntries = ["/"],
  initialIndex = initialEntries.length - 1,
  children,
  routes = [],
}: {
  initialEntries?: InitialEntry[];
  initialIndex?: number;
  children?: ReactNode;
  routes?: RouteObject[];
}) {
  const routerRef = useRef<ItdaRouter | null>(null);
  if (routerRef.current === null) {
    const internals = createRouterInternals(routes, initialEntries, initialIndex);
    const router = createItdaRouter(internals);
    (router as unknown as { __internals: RouterInternals }).__internals = internals;
    routerRef.current = router;
  }
  const router = routerRef.current!;
  const location = useRouterLocation(router);
  const matches = useMemo(
    () => matchRoutes(routes, location.pathname),
    [routes, location.pathname],
  );
  const value = useMemo(
    () => ({
      router,
      location,
      params: matches?.params ?? {},
      outletDepth: 0,
    }),
    [router, location, matches],
  );
  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>;
}

/** createMemoryRouter(routes, opts): test-compatible memory router factory. */
export function createMemoryRouter(
  routes: RouteObject[],
  options: { initialEntries?: InitialEntry[]; initialIndex?: number } = {},
): ItdaRouter {
  const initialEntries = options.initialEntries ?? ["/"];
  const internals = createRouterInternals(routes, initialEntries, options.initialIndex ?? initialEntries.length - 1);
  const router = createItdaRouter(internals);
  (router as unknown as { __internals: RouterInternals }).__internals = internals;
  return router;
}

export function RouterProvider({ router, children }: { router: ItdaRouter; children?: ReactNode }) {
  const location = useRouterLocation(router);
  const matches = useMemo(
    () => matchRoutes((router as unknown as { __internals: RouterInternals }).__internals.routes, location.pathname),
    [router, location.pathname],
  );
  const value = useMemo(
    () => ({ router, location, params: matches?.params ?? {}, outletDepth: 0 }),
    [router, location, matches],
  );
  return (
    <RouterContext.Provider value={value}>
      {matches === null ? null : (
        <MatchedChainContext.Provider value={matches}>
          <RouteOutlet depth={0} />
        </MatchedChainContext.Provider>
      )}
      {children}
    </RouterContext.Provider>
  );
}

/** Routes/Route JSX matching used by tests. */
export function Routes({ children }: { children?: ReactNode }) {
  const { location } = useItdaRouterContext();
  const routes = useMemo(() => routesFromChildren(children), [children]);
  const match = useMemo(() => matchRoutes(routes, location.pathname), [routes, location.pathname]);
  if (match === null) return null;
  return (
    <MatchedChainContext.Provider value={match}>
      <RouteOutlet depth={0} />
    </MatchedChainContext.Provider>
  );
}

const MatchedChainContext = createContext<RouteMatch | null>(null);

function RouteOutlet({ depth }: { depth: number }) {
  const match = useContext(MatchedChainContext);
  if (match === null) return null;
  const element = match.chain[depth]?.element;
  if (element === undefined) return null;
  if (depth + 1 < match.chain.length) {
    return (
      <OutletDepthContext.Provider value={depth + 1}>
        {element}
      </OutletDepthContext.Provider>
    );
  }
  return <>{element}</>;
}

const OutletDepthContext = createContext<number>(0);

export function Outlet(): ReactNode {
  const match = useContext(MatchedChainContext);
  const depth = useContext(OutletDepthContext);
  if (match === null) return null;
  return <RouteOutlet depth={depth} />;
}

/** Shared parent provider so <Outlet> inside RouterProvider chains works. */
let routesFromChildrenCache: WeakMap<object, RouteObject[]> | null = null;

function elementToRouteObject(child: ReactNode): RouteObject | null {
  if (typeof child !== "object" || child === null || !("props" in (child as object))) return null;
  const props = (child as { props: Record<string, unknown> }).props;
  return {
    path: typeof props.path === "string" ? props.path : undefined,
    element: (props.element as ReactNode) ?? undefined,
    index: props.index === true,
    children: Array.isArray(props.children)
      ? (props.children as ReactNode[]).map((child) => elementToRouteObject(child)).filter((r): r is RouteObject => r !== null)
      : props.children !== undefined && props.children !== null
        ? [elementToRouteObject(props.children as ReactNode)].filter((r): r is RouteObject => r !== null)
        : undefined,
  };
}

function routesFromChildren(children: ReactNode): RouteObject[] {
  if (Array.isArray(children)) {
    return children.map(elementToRouteObject).filter((r): r is RouteObject => r !== null);
  }
  const single = elementToRouteObject(children);
  return single === null ? [] : [single];
}

export function Route(_props: { path?: string; element?: ReactNode; index?: boolean; children?: ReactNode }): null {
  // Route elements are converted to route objects by <Routes>; never renders.
  return null;
}

export function useLocation(): LocationShape {
  const context = useContext(RouterContext);
  if (context !== null) return context.location;
  return {
    pathname: typeof window === "undefined" ? "/" : window.location.pathname,
    search: typeof window === "undefined" ? "" : window.location.search,
    hash: typeof window === "undefined" ? "" : window.location.hash,
    state: null,
    key: "default",
  };
}

export function useNavigate(): (to: To, options?: { replace?: boolean; state?: unknown }) => void {
  const context = useContext(RouterContext);
  return (to, options) => {
    if (context?.router !== null && context !== null) {
      context.router.navigate(to, options);
      return;
    }
    // Outside a provider (browser mode): drive window.history directly.
    if (typeof window === "undefined") return;
    if (typeof to === "number") {
      window.history.go(to);
      return;
    }
    const resolved =
      typeof to === "string"
        ? to
        : (() => {
            const current = new URL(window.location.href);
            if (to.pathname !== undefined) current.pathname = to.pathname;
            if (to.search !== undefined) current.search = to.search;
            if (to.hash !== undefined) current.hash = to.hash;
            return `${current.pathname}${current.search}${current.hash}`;
          })();
    const historyState = {
      ...((window.history.state as Record<string, unknown> | null) ?? {}),
      usr: options?.state ?? null,
    };
    if (options?.replace === true) {
      window.history.replaceState(historyState, "", resolved);
    } else {
      window.history.pushState(historyState, "", resolved);
    }
    window.dispatchEvent(new Event("itda:navigate"));
  };
}

export function useParams<T extends Record<string, string | undefined> = Record<string, string>>(): T {
  // Inside <Routes>, the matched chain carries the params for the rendered
  // depth; otherwise fall back to the provider-level match (route table).
  const match = useContext(MatchedChainContext);
  if (match !== null) return match.params as T;
  const context = useContext(RouterContext);
  return ((context?.params ?? {}) as unknown) as T;
}

export function useSearchParams(): [URLSearchParams, (init: URLSearchParams | string) => void] {
  const location = useLocation();
  const navigate = useNavigate();
  const params = useMemo(() => new URLSearchParams(location.search), [location.search]);
  const setParams = useCallbackSetParams(navigate, location);
  return [params, setParams];
}

function useCallbackSetParams(
  navigate: ReturnType<typeof useNavigate>,
  location: LocationShape,
): (init: URLSearchParams | string) => void {
  return (init: URLSearchParams | string) => {
    const next = typeof init === "string" ? init : init.toString();
    navigate(
      `${location.pathname}${next ? `?${next}` : ""}${location.hash}`,
      { replace: true },
    );
  };
}

type LinkProps = AnchorHTMLAttributes<HTMLAnchorElement> & {
  to: To;
  replace?: boolean;
  state?: unknown;
};

export function Link({ to, replace, state, onClick, ...rest }: LinkProps) {
  const navigate = useNavigate();
  if (typeof to !== "string") {
    throw new Error("Link shim supports string targets only");
  }
  return (
    <a
      {...rest}
      href={to}
      onClick={(event) => {
        onClick?.(event);
        if (event.defaultPrevented) return;
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0) {
          return;
        }
        event.preventDefault();
        navigate(to, { replace: replace === true, state });
        if (!to.includes("#")) window.scrollTo?.({ top: 0 });
      }}
    />
  );
}

export function Navigate({ to, replace }: { to: To; replace?: boolean }) {
  const navigate = useNavigate();
  useEffect(() => {
    navigate(to, { replace: replace === true });
  }, [navigate, replace, to]);
  return null;
}

/**
 * Browser-history router mounted by the Next.js host. Subscribes to popstate
 * and the shim's internal navigation event; exposes the same context as the
 * memory routers above.
 */
export function BrowserHistoryRouter({ routes, children, initialPathname }: {
  routes: RouteObject[];
  children?: ReactNode;
  initialPathname: string;
}) {
  const [location, setLocation] = useState<LocationShape>(() => ({
    pathname: initialPathname,
    search: "",
    hash: "",
    state: null,
    key: "initial",
  }));
  useEffect(() => {
    const update = () => setLocation(readBrowserLocation());
    window.addEventListener("popstate", update);
    window.addEventListener("itda:navigate", update);
    update();
    return () => {
      window.removeEventListener("popstate", update);
      window.removeEventListener("itda:navigate", update);
    };
  }, []);
  const matches = useMemo(() => matchRoutes(routes, location.pathname), [routes, location.pathname]);
  const value = useMemo(
    () => ({ router: null, location, params: matches?.params ?? {}, outletDepth: 0 }),
    [location, matches],
  );
  const match = matches;
  return (
    <RouterContext.Provider value={value}>
      {match === null ? null : (
        <MatchedChainContext.Provider value={match}>
          <RouteOutlet depth={0} />
        </MatchedChainContext.Provider>
      )}
      {children}
    </RouterContext.Provider>
  );
}

function readBrowserLocation(): LocationShape {
  if (typeof window === "undefined") {
    return { pathname: "/", search: "", hash: "", state: null, key: "ssr" };
  }
  const historyState = window.history.state as { usr?: unknown } | null;
  return {
    pathname: window.location.pathname,
    search: window.location.search,
    hash: window.location.hash,
    state: historyState?.usr ?? null,
    key: String((historyState as { key?: string } | null)?.key ?? ""),
  };
}
