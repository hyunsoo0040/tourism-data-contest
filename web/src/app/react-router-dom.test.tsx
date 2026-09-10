import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { hydrateRoot, type Root } from "react-dom/client";
import { renderToString } from "react-dom/server";
import { afterEach, describe, expect, it } from "vitest";

import {
  BrowserHistoryRouter,
  useLocation,
  useNavigate,
  type RouteObject,
} from "./react-router-dom";

const dashboardPath = "/internal/operations/daily-glm";
const originalUrl = window.location.href;
const originalState = window.history.state;

function LocationProbe() {
  const location = useLocation();
  const navigate = useNavigate();
  return (
    <>
      <output data-testid="location">{JSON.stringify(location)}</output>
      <button onClick={() => navigate("/quiz", { state: { questionOrdinal: 2 } })}>다음 질문</button>
      <button onClick={() => navigate("/quiz", { replace: true, state: { questionOrdinal: 3, editingProfile: true } })}>질문 보정</button>
      <button onClick={() => navigate("/next?view=history#detail", { state: { source: "dashboard" } })}>
        다음 화면
      </button>
    </>
  );
}

const routes: RouteObject[] = [
  { path: "/", element: <p>공개 홈</p> },
  { path: dashboardPath, element: <LocationProbe /> },
  { path: "/next", element: <LocationProbe /> },
  { path: "/quiz", element: <LocationProbe /> },
];

afterEach(() => {
  cleanup();
  window.history.replaceState(originalState, "", originalUrl);
});

describe("BrowserHistoryRouter 초기 경로", () => {
  it("같은 경로의 push/replace/pop에서 state와 Next.js 필드를 보존한다", () => {
    const first = { __NA: true, __PRIVATE_NEXTJS_INTERNALS_TREE: ["quiz"], usr: { questionOrdinal: 1 } };
    window.history.replaceState(first, "", "/quiz");
    render(<BrowserHistoryRouter routes={routes} initialPathname="/quiz" />);
    const length = window.history.length;
    fireEvent.click(screen.getByRole("button", { name: "다음 질문" }));
    expect(window.history.length).toBe(length + 1);
    expect(window.history.state).toEqual({ ...first, usr: { questionOrdinal: 2 } });
    expect(JSON.parse(screen.getByTestId("location").textContent!)).toMatchObject({ pathname: "/quiz", search: "", hash: "", state: { questionOrdinal: 2 } });
    fireEvent.click(screen.getByRole("button", { name: "질문 보정" }));
    expect(window.history.length).toBe(length + 1);
    expect(window.history.state).toEqual({ ...first, usr: { questionOrdinal: 3, editingProfile: true } });
    expect(JSON.parse(screen.getByTestId("location").textContent!).state).toEqual({ questionOrdinal: 3, editingProfile: true });
    act(() => {
      window.history.replaceState(first, "", "/quiz");
      window.dispatchEvent(new PopStateEvent("popstate", { state: first }));
    });
    expect(JSON.parse(screen.getByTestId("location").textContent!).state).toEqual({ questionOrdinal: 1 });
  });

  it("쿼리 없는 hydration에서 실제 질문 위치와 편집 모드를 복원한다", async () => {
    const element = <BrowserHistoryRouter routes={routes} initialPathname="/quiz" />;
    const container = document.createElement("div");
    container.innerHTML = renderToString(element);
    document.body.appendChild(container);
    window.history.replaceState({ __NA: true, usr: { questionOrdinal: 7, editingProfile: true } }, "", "/quiz");
    const errors: unknown[] = [];
    let root: Root | undefined;
    try {
      await act(async () => { root = hydrateRoot(container, element, { onRecoverableError: (error) => errors.push(error) }); });
      expect(errors).toEqual([]);
      expect(JSON.parse(container.querySelector("output")!.textContent!)).toMatchObject({
        pathname: "/quiz", search: "", hash: "", state: { questionOrdinal: 7, editingProfile: true },
      });
    } finally {
      await act(async () => root?.unmount());
      container.remove();
    }
  });
  it("브라우저 URL과 무관하게 전달받은 경로로 첫 HTML을 렌더링한다", () => {
    window.history.replaceState({ usr: { source: "browser" }, key: "browser-key" }, "", "/?private=query#fragment");
    const html = renderToString(<BrowserHistoryRouter routes={routes} initialPathname={dashboardPath} />);
    const container = document.createElement("div");
    container.innerHTML = html;
    expect(JSON.parse(container.querySelector("output")!.textContent!)).toEqual({
      pathname: dashboardPath, search: "", hash: "", state: null, key: "initial",
    });
    expect(container.textContent).not.toContain("공개 홈");
  });

  it("hydration 오류 없이 마운트 후 query, hash, history state를 반영한다", async () => {
    window.history.replaceState(null, "", "/");
    const element = <BrowserHistoryRouter routes={routes} initialPathname={dashboardPath} />;
    const container = document.createElement("div");
    container.innerHTML = renderToString(element);
    document.body.appendChild(container);
    window.history.replaceState({ usr: { source: "browser" }, key: "browser-key" }, "", `${dashboardPath}?days=30#history`);
    const errors: unknown[] = [];
    let root: Root | undefined;
    try {
      await act(async () => {
        root = hydrateRoot(container, element, { onRecoverableError: (error) => errors.push(error) });
      });
      expect(errors).toEqual([]);
      expect(JSON.parse(container.querySelector("output")!.textContent!)).toEqual({
        pathname: dashboardPath, search: "?days=30", hash: "#history",
        state: { source: "browser" }, key: "browser-key",
      });
    } finally {
      await act(async () => root?.unmount());
      container.remove();
    }
  });

  it("마운트 이후 내부 이동과 popstate를 계속 반영한다", () => {
    window.history.replaceState(null, "", dashboardPath);
    render(<BrowserHistoryRouter routes={routes} initialPathname={dashboardPath} />);
    fireEvent.click(screen.getByRole("button", { name: "다음 화면" }));
    expect(JSON.parse(screen.getByTestId("location").textContent!)).toMatchObject({
      pathname: "/next", search: "?view=history", hash: "#detail", state: { source: "dashboard" },
    });
    act(() => {
      window.history.replaceState(null, "", dashboardPath);
      window.dispatchEvent(new PopStateEvent("popstate"));
    });
    expect(JSON.parse(screen.getByTestId("location").textContent!)).toMatchObject({
      pathname: dashboardPath, search: "", hash: "", state: null,
    });
  });
});
