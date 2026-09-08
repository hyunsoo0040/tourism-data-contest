import type { Metadata, Viewport } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "IT-DA | 나의 여행 기대와 맞는 장소를 잇다",
  description:
    "질문과 간단한 사진으로, 지금 떠나고 싶은 여행의 분위기를 알려주세요. 그 감각에 어울리는 관광지를 추천해 드립니다.",
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ko">
      <body>{children}</body>
    </html>
  );
}
