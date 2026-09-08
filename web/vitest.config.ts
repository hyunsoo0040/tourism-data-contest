import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    include: ["src/**/*.test.{ts,tsx}"],
    passWithNoTests: true,
    setupFiles: ["./src/test/setup.ts"],
  },
  resolve: {
    alias: {
      "react-router-dom": new URL("./src/app/react-router-dom.tsx", import.meta.url).pathname,
    },
  },
});
