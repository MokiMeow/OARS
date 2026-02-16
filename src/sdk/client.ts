import { OarsHttpError, type OarsApiErrorBody } from "./errors.js";
import type { ActionResponse, ActionSubmission, ReceiptListResponse, ReceiptQuery, ReceiptVerificationResult, VerifyReceiptInput } from "./types.js";

export interface OarsClientOptions {
  baseUrl: string;
  token: string;
  fetchFn?: typeof fetch | undefined;
  userAgent?: string | undefined;
  timeoutMs?: number | undefined;
  maxRetries?: number | undefined;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function toUrl(baseUrl: string, path: string, query?: Record<string, unknown>): string {
  const url = new URL(path, baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null) {
        continue;
      }
      if (Array.isArray(value)) {
        for (const entry of value) {
          url.searchParams.append(key, String(entry));
        }
        continue;
      }
      url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

function shouldRetry(status: number): boolean {
  return status === 408 || status === 425 || status === 429 || status === 500 || status === 502 || status === 503 || status === 504;
}

export class OarsClient {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly fetchFn: typeof fetch;
  private readonly userAgent: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;

  constructor(options: OarsClientOptions) {
    this.baseUrl = options.baseUrl;
    this.token = options.token;
    this.fetchFn = options.fetchFn ?? fetch;
    this.userAgent = options.userAgent ?? "oars-sdk/0.1";
    this.timeoutMs = options.timeoutMs ?? 20_000;
    this.maxRetries = options.maxRetries ?? 2;
  }

  async submitAction(input: ActionSubmission, options?: { idempotencyKey?: string | undefined }): Promise<ActionResponse> {
    return this.requestJson("POST", "/v1/actions", {
      body: input,
      idempotencyKey: options?.idempotencyKey,
      retryMode: options?.idempotencyKey ? "safe" : "none"
    });
  }

  async getAction(actionId: string): Promise<{ action: Record<string, unknown>; receipts: Array<Record<string, unknown>> }> {
    return this.requestJson("GET", `/v1/actions/${encodeURIComponent(actionId)}`, {
      retryMode: "safe"
    });
  }

  async listReceipts(query: ReceiptQuery): Promise<ReceiptListResponse> {
    return this.requestJson("GET", "/v1/receipts", {
      query: query as unknown as Record<string, unknown>,
      retryMode: "safe"
    });
  }

  async verifyReceipt(input: VerifyReceiptInput): Promise<ReceiptVerificationResult> {
    return this.requestJson("POST", "/v1/receipts/verify", {
      body: input as unknown as Record<string, unknown>,
      retryMode: "safe"
    });
  }

  private async requestJson<T>(
    method: string,
    path: string,
    options?: {
      query?: Record<string, unknown> | undefined;
      body?: unknown;
      idempotencyKey?: string | undefined;
      retryMode?: "safe" | "none" | undefined;
    }
  ): Promise<T> {
    const url = toUrl(this.baseUrl, path, options?.query);
    const headers: Record<string, string> = {
      authorization: `Bearer ${this.token}`,
      accept: "application/json",
      "user-agent": this.userAgent
    };
    if (options?.idempotencyKey) {
      headers["idempotency-key"] = options.idempotencyKey;
    }

    const body = options?.body === undefined ? undefined : JSON.stringify(options.body);
    if (body !== undefined) {
      headers["content-type"] = "application/json";
    }

    const maxAttempts = options?.retryMode === "safe" ? Math.max(1, this.maxRetries + 1) : 1;
    let attempt = 0;
    let lastError: unknown;

    while (attempt < maxAttempts) {
      attempt += 1;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const response = await this.fetchFn(url, {
          method,
          headers,
          ...(body !== undefined ? { body } : {}),
          signal: controller.signal
        });

        if (response.ok) {
          return (await response.json()) as T;
        }

        let errorPayload: OarsApiErrorBody | null = null;
        try {
          errorPayload = (await response.json()) as OarsApiErrorBody;
        } catch {
          errorPayload = null;
        }

        if (options?.retryMode === "safe" && attempt < maxAttempts && shouldRetry(response.status)) {
          await sleep(200 * 2 ** (attempt - 1));
          continue;
        }

        if (errorPayload?.error?.code && errorPayload.error.message) {
          throw new OarsHttpError({
            status: response.status,
            code: errorPayload.error.code,
            message: errorPayload.error.message,
            ...(errorPayload.error.requestId ? { requestId: errorPayload.error.requestId } : {}),
            ...(errorPayload.error.details !== undefined ? { details: errorPayload.error.details } : {})
          });
        }
        throw new OarsHttpError({
          status: response.status,
          code: "http_error",
          message: `HTTP ${response.status}`
        });
      } catch (error) {
        lastError = error;
        const retryable = options?.retryMode === "safe" && attempt < maxAttempts;
        if (retryable) {
          await sleep(200 * 2 ** (attempt - 1));
          continue;
        }
        throw error;
      } finally {
        clearTimeout(timeout);
      }
    }

    throw lastError instanceof Error ? lastError : new Error("Request failed.");
  }
}
