import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { buildServer } from "../src/api/server.js";
import { createPlatformContext } from "../src/core/services/platform-context.js";

function readInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function percentile(values: number[], p: number): number {
  if (values.length === 0) {
    return 0;
  }
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[index] ?? 0;
}

async function main(): Promise<void> {
  const requests = readInt("PERF_REQUESTS", 250);
  const concurrency = readInt("PERF_CONCURRENCY", 25);
  const p95ThresholdMs = readInt("PERF_P95_MS", 1000);

  const suffix = `perf-${Date.now()}-${process.pid}`;
  const dataFilePath = join("data", `${suffix}-state.json`);
  const keyFilePath = join("data", `${suffix}-keys.json`);
  const ledgerFilePath = join("data", `${suffix}-ledger.ndjson`);
  const vaultFilePath = join("data", `${suffix}-vault.json`);
  const queueFilePath = join("data", `${suffix}-siem-queue.json`);

  const context = createPlatformContext({
    dataFilePath,
    keyFilePath,
    ledgerFilePath,
    vaultFilePath,
    siemOptions: {
      autoStartRetry: false,
      queueFilePath
    }
  });
  const app = buildServer(context);

  const latencies: number[] = [];
  let index = 0;
  const worker = async () => {
    while (index < requests) {
      const current = index;
      index += 1;
      const started = process.hrtime.bigint();
      const response = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: {
          authorization: "Bearer dev_admin_token"
        },
        payload: {
          tenantId: "tenant_alpha",
          agentId: `perf_agent_${current}`,
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: `Performance smoke request ${current}`
          }
        }
      });
      const ended = process.hrtime.bigint();
      if (response.statusCode !== 202) {
        throw new Error(`Unexpected status code ${response.statusCode} at request index ${current}.`);
      }
      const durationMs = Number(ended - started) / 1_000_000;
      latencies.push(durationMs);
    }
  };

  try {
    const workers = Array.from({ length: concurrency }, () => worker());
    await Promise.all(workers);

    const p50 = percentile(latencies, 50);
    const p95 = percentile(latencies, 95);
    const p99 = percentile(latencies, 99);
    const avg = latencies.reduce((sum, value) => sum + value, 0) / Math.max(1, latencies.length);

    console.log(`perf_smoke requests=${requests} concurrency=${concurrency}`);
    console.log(`latency_ms p50=${p50.toFixed(2)} p95=${p95.toFixed(2)} p99=${p99.toFixed(2)} avg=${avg.toFixed(2)}`);

    if (p95 > p95ThresholdMs) {
      console.error(`p95 threshold exceeded: ${p95.toFixed(2)}ms > ${p95ThresholdMs}ms`);
      process.exitCode = 1;
    } else {
      console.log(`p95 threshold passed: ${p95.toFixed(2)}ms <= ${p95ThresholdMs}ms`);
    }
  } finally {
    await app.close();
    const cleanupPaths = [dataFilePath, keyFilePath, ledgerFilePath, vaultFilePath, queueFilePath];
    for (const filePath of cleanupPaths) {
      if (existsSync(filePath)) {
        rmSync(filePath, { force: true });
      }
    }
  }
}

void main();
