import { fireEvent, render, screen } from "@testing-library/react";
import { StrictMode } from "react";
import { describe, expect, it } from "vitest";
import { PlacePhotos, photoUrl } from "./PlacePhotos";

const photos = [1, 2].map(id => ({ url: `http://tong.visitkorea.or.kr/img/${id}.jpg`, attribution_ko: "한국관광공사 · 관광사진", license: "KOGL_TYPE_1" }));

describe("official place photographs", () => {
  it("reuses prepared image elements when switching gallery photos and detaches them on unmount", () => {
    const preparedImages = Object.fromEntries(photos.map(photo => {
      const url = photoUrl(photo.url)!;
      const image = document.createElement("img"); image.src = url;
      return [url, image];
    }));
    const view = render(<StrictMode><PlacePhotos name="영랑호" photos={photos} preparedImages={preparedImages} /></StrictMode>);
    const [first, second] = Object.values(preparedImages);
    expect(screen.getByRole("img")).toBe(first);
    fireEvent.click(screen.getByRole("button", { name: "영랑호 사진 2 보기" }));
    expect(screen.getByRole("img")).toBe(second);
    expect(first!.isConnected).toBe(false);
    view.unmount(); expect(second!.isConnected).toBe(false);
  });
  it("displays attributed HTTPS images and switches the selected photograph", () => {
    render(<PlacePhotos name="영랑호" photos={photos} />);
    expect(screen.getByRole("img").getAttribute("src")).toBe("https://tong.visitkorea.or.kr/img/1.jpg");
    expect(screen.getByText("한국관광공사 · 관광사진")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "영랑호 사진 2 보기" }));
    expect(screen.getByRole("img").getAttribute("src")).toBe("https://tong.visitkorea.or.kr/img/2.jpg");
    expect(screen.getByRole("link", { name: "원본 사진" }).getAttribute("href")).toContain("/2.jpg");
  });
  it("falls back to another actual photo and offers retry only after every image fails", () => {
    render(<PlacePhotos name="영랑호" photos={photos} />);
    fireEvent.error(screen.getByRole("img"));
    expect(screen.getByRole("img").getAttribute("src")).toContain("/2.jpg");
    fireEvent.error(screen.getByRole("img"));
    expect(screen.queryByRole("img")).toBeNull();
    expect(screen.getByText("사진을 불러오지 못했어요")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "사진 다시 불러오기" }));
    expect(screen.getByRole("img").getAttribute("src")).toContain("/1.jpg");
  });
  it("distinguishes unavailable information from places without verified photos", () => {
    const view = render(<PlacePhotos name="장소" photos={[]} loading />);
    expect(screen.getByRole("status").textContent).toContain("불러오고");
    view.rerender(<PlacePhotos name="장소" photos={[]} unavailable />);
    expect(screen.getByText("사진 정보를 확인하지 못했어요")).toBeTruthy();
    view.rerender(<PlacePhotos name="장소" photos={[]} />);
    expect(screen.getByText("확인된 공식 사진이 아직 없어요")).toBeTruthy();
    expect(screen.queryByRole("img")).toBeNull();
  });
  it("rejects unsafe image schemes and deduplicates images", () => {
    for (const url of ["javascript:alert(1)", "data:image/svg+xml,x", "http://example.com/a.jpg", "/tourism/../secret"]) expect(photoUrl(url)).toBeNull();
    render(<PlacePhotos name="장소" photos={[photos[0], photos[0]]} />);
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });
});

it.each([2, 3, 4])("shows Type%s rights and complete attribution even in compact captions", kind => {
  const restricted = { ...photos[0]!, license: `KOGL_TYPE_${kind}`, source_url: "https://data.visitkorea.or.kr/page/127841" };
  const view = render(<PlacePhotos name="백석봉" photos={[restricted, photos[1]!]} captionMode="source-only" />);
  expect(screen.getByText("한국관광공사 · 관광사진")).toBeTruthy();
  expect(screen.getByText(new RegExp(`공공누리 제${kind}유형`))).toBeTruthy();
  expect(screen.getByRole("link", { name: "출처" }).getAttribute("href")).toContain("127841");
  expect(screen.getByRole("link", { name: "원본 사진" })).toBeTruthy();
  expect(view.container.querySelector("[data-preserve-original=true]") !== null).toBe(kind >= 3);
  fireEvent.click(screen.getByRole("button", { name: "백석봉 사진 2 보기" }));
  expect(screen.queryByText(/변경금지/)).toBeNull();
});

it("preserves the full frame for a prepared Type3 image", () => {
  const photo = { ...photos[0]!, license: "KOGL_TYPE_3" };
  const image = new Image(); image.src = photoUrl(photo.url)!;
  render(<PlacePhotos name="백석봉" photos={[photo]} preparedImages={{ [image.src]: image }} />);
  expect(screen.getByRole("img")).toBe(image);
  expect(image.closest("[data-preserve-original=true]")).toBeTruthy();
});
