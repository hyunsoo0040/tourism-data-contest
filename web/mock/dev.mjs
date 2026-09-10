import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { mockServer } from "./server.mjs";

const port = Number(process.env.ITDA_MOCK_API_PORT ?? 8020);
const webPort = Number(process.env.ITDA_MOCK_WEB_PORT ?? 3012);
const api = mockServer();
api.on("error", (error) => { console.error(`Mock API: ${error.message}`); process.exit(1); });
api.listen(port, "127.0.0.1", () => {
  const child = spawn(process.execPath, ["node_modules/next/dist/bin/next", "dev", "-H", "127.0.0.1", "-p", String(webPort)], {
    cwd: fileURLToPath(new URL("..", import.meta.url)), stdio: "inherit",
    env: { ...process.env, ITDA_BACKEND_ORIGIN: `http://127.0.0.1:${port}`, ITDA_MOCK_UI: "1", NEXT_PUBLIC_ITDA_MOCK_UI: "1" },
  });
  console.log(`UI 목업: http://127.0.0.1:${webPort}/start (가상 데이터만 사용)`);
  const stop = () => { child.kill("SIGTERM"); api.close(); };
  process.on("SIGINT", stop); process.on("SIGTERM", stop);
  child.on("error", (error) => { console.error(error.message); api.close(); process.exitCode = 1; });
  child.on("exit", (code) => { api.close(); process.exitCode = code ?? 0; });
});
