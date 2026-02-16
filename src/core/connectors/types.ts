import type { ActionRecord } from "../types/domain.js";

export interface ConnectorExecutionResult {
  success: boolean;
  output: Record<string, unknown>;
  error: string | null;
}

export interface Connector {
  readonly toolId: string;
  execute(action: ActionRecord): Promise<ConnectorExecutionResult>;
}
