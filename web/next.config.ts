import path from "node:path";
import type { NextConfig } from "next";

const backend = process.env.ITDA_BACKEND_ORIGIN ?? "http://127.0.0.1:8000";

const nextConfig: NextConfig = {
  ...(process.env.ITDA_NEXT_DIST_DIR ? { distDir: process.env.ITDA_NEXT_DIST_DIR } : process.env.ITDA_MOCK_UI === "1" ? { distDir: ".next-mock" } : {}),
  output: "standalone",
  devIndicators: false,
  outputFileTracingRoot: path.join(import.meta.dirname, ".."),
  async rewrites() {
    return [
      { source: "/v1/:path*", destination: `${backend}/v1/:path*` },
      { source: "/internal/evaluation/:path*", destination: `${backend}/internal/evaluation/:path*` },
      {
        source: "/internal/operations/daily-glm/api/:path*",
        destination: `${backend}/internal/operations/daily-glm/api/:path*`,
      },
      { source: "/internal/test-support/phase3/:path*", destination: `${backend}/internal/test-support/phase3/:path*` },
    ];
  },
};

export default nextConfig;
