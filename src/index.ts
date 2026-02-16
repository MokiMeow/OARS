import { buildServer } from "./api/server.js";

const port = Number.parseInt(process.env.PORT ?? "8080", 10);
const host = process.env.HOST ?? "0.0.0.0";

const app = buildServer();

let isShuttingDown = false;

async function gracefulShutdown(signal: string) {
  if (isShuttingDown) {
    return;
  }
  isShuttingDown = true;
  console.log(`\n${signal} received. Shutting down gracefully...`);
  try {
    await app.close();
    console.log("Server closed. Goodbye.");
  } catch (error) {
    console.error("Error during shutdown:", error);
    process.exitCode = 1;
  }
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

app
  .listen({ port, host })
  .then(() => {
    const isTls = Boolean(process.env.OARS_TLS_KEY_PATH && process.env.OARS_TLS_CERT_PATH);
    console.log(`OARS API listening on ${isTls ? "https" : "http"}://${host}:${port}`);
  })
  .catch((error) => {
    console.error("Failed to start OARS API:", error);
    process.exitCode = 1;
  });
