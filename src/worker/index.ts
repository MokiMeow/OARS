import { createPlatformContext } from "../core/services/platform-context.js";
import { createId } from "../lib/id.js";
import { retryDelaySecondsFromEnv } from "../core/backplane/execution-backplane.js";

function parseIntWithMin(value: string | undefined, fallback: number, min: number): number {
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed) || parsed < min) return fallback;
  return parsed;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const workerId = (process.env.OARS_WORKER_ID ?? createId("worker")).trim();
const pollIntervalMs = parseIntWithMin(process.env.OARS_BACKPLANE_POLL_INTERVAL_MS, 500, 50);
const claimLimit = parseIntWithMin(process.env.OARS_BACKPLANE_CLAIM_LIMIT, 5, 1);
const retryDelaySeconds = retryDelaySecondsFromEnv();

const context = createPlatformContext();

function requireBackplane(value: typeof context.executionBackplane) {
  if (!value) {
    throw new Error("Worker requires OARS_BACKPLANE_MODE=queue (execution backplane not configured).");
  }
  return value;
}
const backplane = requireBackplane(context.executionBackplane);

let isShuttingDown = false;

async function gracefulShutdown(signal: string) {
  if (isShuttingDown) {
    return;
  }
  isShuttingDown = true;
  console.log(`\n${signal} received. Worker shutting down gracefully...`);
  try {
    await backplane.close?.();
    await context.store.close?.();
    console.log("Worker closed. Goodbye.");
  } catch (error) {
    console.error("Error during shutdown:", error);
    process.exitCode = 1;
  }
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

async function runLoop() {
  console.log(`OARS worker ${workerId} started (poll=${pollIntervalMs}ms, claimLimit=${claimLimit}).`);

  while (!isShuttingDown) {
    try {
      const jobs = await backplane.claim(workerId, claimLimit);
      if (jobs.length === 0) {
        await sleep(pollIntervalMs);
        continue;
      }

      for (const job of jobs) {
        try {
          const result = await context.actionService.executeApprovedAction(job.actionId, job.requestId);
          if (result.state === "executed") {
            await backplane.complete(job.id, workerId);
          } else {
            await backplane.fail(
              job.id,
              workerId,
              result.error ?? `Action ended in state: ${result.state}`,
              retryDelaySeconds
            );
          }
        } catch (error) {
          const message = error instanceof Error ? error.message : "Unknown worker error.";
          await backplane.fail(job.id, workerId, message, retryDelaySeconds);
        }
      }
    } catch (error) {
      console.error("Worker loop error:", error);
      await sleep(Math.min(5_000, pollIntervalMs * 2));
    }
  }
}

runLoop().catch((error) => {
  console.error("Worker failed to start:", error);
  process.exitCode = 1;
});
