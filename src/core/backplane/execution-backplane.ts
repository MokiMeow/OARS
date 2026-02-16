import { createRequire } from "node:module";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { nowIso } from "../../lib/time.js";
import { createId } from "../../lib/id.js";
import type { Pool as PgPool } from "pg";

const require = createRequire(import.meta.url);
const { Pool } = require("pg") as { Pool: new (opts: { connectionString: string }) => PgPool };

export type ExecutionJobStatus = "pending" | "running" | "succeeded" | "failed" | "dead";

export interface ExecutionJobRecord {
  id: string;
  tenantId: string;
  actionId: string;
  requestId: string;
  status: ExecutionJobStatus;
  attemptCount: number;
  maxAttempts: number;
  availableAt: string;
  lockedAt: string | null;
  lockedBy: string | null;
  lastError: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface ExecutionBackplane {
  close?(): Promise<void>;
  enqueue(action: { tenantId: string; actionId: string; requestId: string }): Promise<ExecutionJobRecord>;
  claim(workerId: string, limit: number): Promise<ExecutionJobRecord[]>;
  complete(jobId: string, workerId: string): Promise<void>;
  fail(jobId: string, workerId: string, error: string, retryDelaySeconds: number): Promise<ExecutionJobRecord | null>;
}

function safeParseInt(value: string | undefined, fallback: number, min: number): number {
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed) || parsed < min) return fallback;
  return parsed;
}

function ensureDir(path: string): void {
  const dir = dirname(path);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
}

function atomicWriteJson(path: string, data: unknown): void {
  ensureDir(path);
  const tmp = `${path}.${createId("tmp")}`;
  writeFileSync(tmp, JSON.stringify(data, null, 2), "utf8");
  renameSync(tmp, path);
}

export class FileExecutionBackplane implements ExecutionBackplane {
  private readonly lockTimeoutSeconds: number;
  private readonly maxAttempts: number;

  constructor(
    private readonly filePath: string,
    options?: { lockTimeoutSeconds?: number | undefined; maxAttempts?: number | undefined }
  ) {
    this.lockTimeoutSeconds = options?.lockTimeoutSeconds ?? 60;
    this.maxAttempts = options?.maxAttempts ?? 1;
  }

  async enqueue(action: { tenantId: string; actionId: string; requestId: string }): Promise<ExecutionJobRecord> {
    const state = this.load();
    const existing = state.jobs.find(
      (job) => job.actionId === action.actionId && (job.status === "pending" || job.status === "running")
    );
    if (existing) {
      return existing;
    }

    const now = nowIso();
    const job: ExecutionJobRecord = {
      id: createId("job"),
      tenantId: action.tenantId,
      actionId: action.actionId,
      requestId: action.requestId,
      status: "pending",
      attemptCount: 0,
      maxAttempts: this.maxAttempts,
      availableAt: now,
      lockedAt: null,
      lockedBy: null,
      lastError: null,
      createdAt: now,
      updatedAt: now
    };
    state.jobs.push(job);
    this.save(state);
    return job;
  }

  async claim(workerId: string, limit: number): Promise<ExecutionJobRecord[]> {
    const state = this.load();
    const now = Date.now();
    const lockCutoff = now - this.lockTimeoutSeconds * 1000;

    for (const job of state.jobs) {
      if (job.status === "running" && job.lockedAt) {
        const lockedMs = Date.parse(job.lockedAt);
        if (!Number.isNaN(lockedMs) && lockedMs <= lockCutoff) {
          job.status = "pending";
          job.lockedAt = null;
          job.lockedBy = null;
          job.updatedAt = nowIso();
        }
      }
    }

    const eligible = state.jobs
      .filter((job) => job.status === "pending")
      .filter((job) => Date.parse(job.availableAt) <= now)
      .sort((a, b) => a.availableAt.localeCompare(b.availableAt));

    const claimed: ExecutionJobRecord[] = [];
    for (const job of eligible) {
      if (claimed.length >= Math.max(1, limit)) break;
      job.status = "running";
      job.attemptCount += 1;
      job.lockedAt = nowIso();
      job.lockedBy = workerId;
      job.updatedAt = nowIso();
      claimed.push(job);
    }

    if (claimed.length > 0) {
      this.save(state);
    }
    return claimed;
  }

  async complete(jobId: string, workerId: string): Promise<void> {
    const state = this.load();
    const job = state.jobs.find((entry) => entry.id === jobId);
    if (!job) return;
    if (job.lockedBy && job.lockedBy !== workerId) return;
    job.status = "succeeded";
    job.lockedAt = null;
    job.lockedBy = null;
    job.updatedAt = nowIso();
    this.save(state);
  }

  async fail(jobId: string, workerId: string, error: string, retryDelaySeconds: number): Promise<ExecutionJobRecord | null> {
    const state = this.load();
    const job = state.jobs.find((entry) => entry.id === jobId);
    if (!job) return null;
    if (job.lockedBy && job.lockedBy !== workerId) return null;
    job.lastError = error;
    job.lockedAt = null;
    job.lockedBy = null;
    job.updatedAt = nowIso();

    if (job.attemptCount >= job.maxAttempts) {
      job.status = "dead";
    } else {
      job.status = "pending";
      job.availableAt = new Date(Date.now() + Math.max(0, retryDelaySeconds) * 1000).toISOString();
    }

    this.save(state);
    return job;
  }

  private load(): { jobs: ExecutionJobRecord[] } {
    try {
      if (!existsSync(this.filePath)) {
        return { jobs: [] };
      }
      const raw = readFileSync(this.filePath, "utf8");
      const parsed = JSON.parse(raw) as unknown;
      if (!parsed || typeof parsed !== "object") return { jobs: [] };
      const jobs = (parsed as { jobs?: unknown }).jobs;
      return { jobs: Array.isArray(jobs) ? (jobs as ExecutionJobRecord[]) : [] };
    } catch {
      return { jobs: [] };
    }
  }

  private save(state: { jobs: ExecutionJobRecord[] }): void {
    atomicWriteJson(this.filePath, state);
  }
}

type PgRow<T> = { data: T };

export class PostgresExecutionBackplane implements ExecutionBackplane {
  private readonly pool: PgPool;
  private readonly lockTimeoutSeconds: number;
  private readonly maxAttempts: number;

  constructor(
    connectionString: string,
    options?: { lockTimeoutSeconds?: number | undefined; maxAttempts?: number | undefined }
  ) {
    this.pool = new Pool({ connectionString });
    this.lockTimeoutSeconds = options?.lockTimeoutSeconds ?? 60;
    this.maxAttempts = options?.maxAttempts ?? 1;
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  async enqueue(action: { tenantId: string; actionId: string; requestId: string }): Promise<ExecutionJobRecord> {
    const inflight = await this.pool.query<PgRow<ExecutionJobRecord>>(
      "SELECT data FROM oars_execution_jobs WHERE action_id=$1 AND status IN ('pending','running') LIMIT 1",
      [action.actionId]
    );
    const existing = inflight.rows[0]?.data;
    if (existing) {
      return existing;
    }

    const now = nowIso();
    const job: ExecutionJobRecord = {
      id: createId("job"),
      tenantId: action.tenantId,
      actionId: action.actionId,
      requestId: action.requestId,
      status: "pending",
      attemptCount: 0,
      maxAttempts: this.maxAttempts,
      availableAt: now,
      lockedAt: null,
      lockedBy: null,
      lastError: null,
      createdAt: now,
      updatedAt: now
    };

    await this.pool.query(
      `INSERT INTO oars_execution_jobs (id, tenant_id, action_id, request_id, status, attempt_count, max_attempts, available_at, locked_at, locked_by, last_error, created_at, updated_at, data)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb)`,
      [
        job.id,
        job.tenantId,
        job.actionId,
        job.requestId,
        job.status,
        job.attemptCount,
        job.maxAttempts,
        new Date(Date.parse(job.availableAt)),
        null,
        null,
        null,
        new Date(Date.parse(job.createdAt)),
        new Date(Date.parse(job.updatedAt)),
        JSON.stringify(job)
      ]
    );
    return job;
  }

  async claim(workerId: string, limit: number): Promise<ExecutionJobRecord[]> {
    const safeLimit = Math.min(50, Math.max(1, Math.floor(limit)));
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const result = await client.query<PgRow<ExecutionJobRecord>>(
        `WITH candidate AS (
           SELECT id
           FROM oars_execution_jobs
           WHERE (
             (status='pending' AND available_at <= NOW())
             OR
             (status='running' AND locked_at IS NOT NULL AND locked_at <= NOW() - ($1::text || ' seconds')::interval)
           )
           ORDER BY available_at ASC, created_at ASC
           LIMIT $2
           FOR UPDATE SKIP LOCKED
         )
         UPDATE oars_execution_jobs j
         SET status='running',
             attempt_count=j.attempt_count + 1,
             locked_at=NOW(),
             locked_by=$3,
             updated_at=NOW(),
             data=jsonb_set(
               jsonb_set(
                 jsonb_set(
                   jsonb_set(j.data, '{status}', '\"running\"'::jsonb, true),
                   '{attemptCount}', to_jsonb(j.attempt_count + 1), true
                 ),
                 '{lockedAt}', to_jsonb(NOW()::text), true
               ),
               '{lockedBy}', to_jsonb($3::text), true
             )
         FROM candidate
         WHERE j.id=candidate.id
         RETURNING j.data`,
        [String(this.lockTimeoutSeconds), safeLimit, workerId]
      );
      await client.query("COMMIT");
      return result.rows.map((row) => row.data);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async complete(jobId: string, workerId: string): Promise<void> {
    await this.pool.query(
      `UPDATE oars_execution_jobs
       SET status='succeeded',
           locked_at=NULL,
           locked_by=NULL,
           updated_at=NOW(),
           data=jsonb_set(jsonb_set(jsonb_set(data, '{status}', '\"succeeded\"'::jsonb, true), '{lockedAt}', 'null'::jsonb, true), '{lockedBy}', 'null'::jsonb, true)
       WHERE id=$1 AND (locked_by IS NULL OR locked_by=$2)`,
      [jobId, workerId]
    );
  }

  async fail(jobId: string, workerId: string, error: string, retryDelaySeconds: number): Promise<ExecutionJobRecord | null> {
    const delaySeconds = Math.max(0, Math.floor(retryDelaySeconds));
    const result = await this.pool.query<PgRow<ExecutionJobRecord>>(
      `UPDATE oars_execution_jobs
       SET status = CASE WHEN attempt_count >= max_attempts THEN 'dead' ELSE 'pending' END,
           available_at = CASE WHEN attempt_count >= max_attempts THEN available_at ELSE NOW() + ($3::text || ' seconds')::interval END,
           locked_at = NULL,
           locked_by = NULL,
           last_error = $4,
           updated_at = NOW(),
           data = jsonb_set(
             jsonb_set(
               jsonb_set(
                 jsonb_set(
                   jsonb_set(
                     data,
                     '{status}',
                     CASE WHEN attempt_count >= max_attempts THEN '\"dead\"'::jsonb ELSE '\"pending\"'::jsonb END,
                     true
                   ),
                   '{availableAt}',
                   CASE WHEN attempt_count >= max_attempts THEN data->'availableAt' ELSE to_jsonb((NOW() + ($3::text || ' seconds')::interval)::text) END,
                   true
                 ),
                 '{lockedAt}', 'null'::jsonb, true
               ),
               '{lockedBy}', 'null'::jsonb, true
             ),
             '{lastError}', to_jsonb($4::text), true
           )
       WHERE id=$1 AND (locked_by IS NULL OR locked_by=$2)
       RETURNING data`,
      [jobId, workerId, String(delaySeconds), error]
    );
    return result.rows[0]?.data ?? null;
  }
}

export function createExecutionBackplaneFromEnv(input?: {
  postgresUrl?: string | undefined;
  dataDir?: string | undefined;
}): ExecutionBackplane | null {
  const mode = (process.env.OARS_BACKPLANE_MODE ?? "inline").trim().toLowerCase();
  if (mode !== "queue") {
    return null;
  }

  const lockTimeoutSeconds = safeParseInt(process.env.OARS_BACKPLANE_LOCK_TIMEOUT_SECONDS, 60, 5);
  const maxAttempts = safeParseInt(process.env.OARS_BACKPLANE_MAX_ATTEMPTS, 1, 1);
  const driver = (process.env.OARS_BACKPLANE_DRIVER ?? "postgres").trim().toLowerCase();
  if (driver === "file") {
    const dataDir = input?.dataDir ?? "data";
    const filePath = process.env.OARS_BACKPLANE_FILE_PATH ?? join(dataDir, "execution-queue.json");
    return new FileExecutionBackplane(filePath, { lockTimeoutSeconds, maxAttempts });
  }

  const postgresUrl = input?.postgresUrl ?? process.env.OARS_POSTGRES_URL ?? process.env.DATABASE_URL;
  if (!postgresUrl) {
    throw new Error("OARS_BACKPLANE_MODE=queue requires OARS_POSTGRES_URL (or DATABASE_URL).");
  }
  return new PostgresExecutionBackplane(postgresUrl, { lockTimeoutSeconds, maxAttempts });
}

export function retryDelaySecondsFromEnv(): number {
  return safeParseInt(process.env.OARS_BACKPLANE_RETRY_DELAY_SECONDS, 15, 0);
}

