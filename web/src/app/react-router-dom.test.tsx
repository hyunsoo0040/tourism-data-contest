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
];

afterEach(() => {
  cleanup();
  window.history.replaceState(originalState, "", originalUrl);
});

describe("BrowserHistoryRouter 초기 경로", () => {
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
