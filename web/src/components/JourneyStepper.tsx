const STEPS = [
  { path: "/start", label: "여행 조건" },
  { path: "/quiz", label: "취향" },
  { path: "/profile", label: "기대 프로필" },
  { path: "/recommendations", label: "추천" },
] as const;

function activeIndex(pathname: string): number {
  // The optional photo subflow hangs off Profile: photo routes keep Profile
  // current and the stepper stays four steps (no fifth node).
  if (pathname === "/photo" || pathname.startsWith("/photo/")) return 2;
  const index = STEPS.findIndex(({ path }) => pathname.startsWith(path));
  return index === -1 ? 0 : index;
}

export function JourneyStepper({ pathname }: { pathname: string }) {
  const current = activeIndex(pathname);

  return (
    <nav className="journey-stepper" aria-label="여행 진행 단계">
      <ol>
        {STEPS.map((step, index) => {
          const state = index < current ? "complete" : index === current ? "current" : "future";
          const accessibleLabel = state === "complete" ? `${step.label}, 완료` : step.label;
          return (
            <li
              key={step.path}
              className={`journey-step journey-step--${state}`}
              aria-current={state === "current" ? "step" : undefined}
              aria-label={accessibleLabel}
            >
              <span className="journey-step__node" aria-hidden="true">
                {index + 1}
              </span>
              <span>{step.label}</span>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
