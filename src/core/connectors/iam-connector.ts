import type { Connector, ConnectorExecutionResult } from "./types.js";
import type { ActionRecord } from "../types/domain.js";

const supportedOps = new Set(["change_permissions", "rotate_keys"]);

export class IamConnector implements Connector {
  readonly toolId = "iam";

  async execute(action: ActionRecord): Promise<ConnectorExecutionResult> {
    if (!supportedOps.has(action.resource.operation)) {
      return {
        success: false,
        output: {},
        error: `Unsupported iam operation: ${action.resource.operation}`
      };
    }

    return {
      success: true,
      output: {
        operation: action.resource.operation,
        target: action.resource.target,
        status: "applied",
        changeRef: `iam_${action.id.slice(-10)}`
      },
      error: null
    };
  }
}
