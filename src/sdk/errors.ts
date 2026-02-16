export interface OarsApiErrorBody {
  error: {
    code: string;
    message: string;
    requestId?: string | undefined;
    details?: unknown;
  };
}

export class OarsHttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId?: string | undefined;
  readonly details?: unknown;

  constructor(input: { status: number; code: string; message: string; requestId?: string; details?: unknown }) {
    super(input.message);
    this.status = input.status;
    this.code = input.code;
    this.requestId = input.requestId;
    this.details = input.details;
  }
}

