import { render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import fixture from "./__fixtures__/prepared-scenario.json";
import type { Detail } from "./api";
import { PlaceInformation } from "./PlaceInformation";

it("keeps the detail action available when no official introduction is present", () => {
  const detail = { ...fixture.details[0], evidence: [] } as unknown as Detail;
  render(<PlaceInformation detail={detail} action={<a href="/places/example">상세 보기</a>} />);
  expect(screen.getByText("확인된 장소 소개가 아직 없어요.")).toBeTruthy();
  expect(screen.getByRole("link", { name: "상세 보기" }).getAttribute("href")).toBe("/places/example");
  expect(screen.queryByText(/자료 확인/)).toBeNull();
});
