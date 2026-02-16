import type { Connector, ConnectorExecutionResult } from "./types.js";
import type { ActionRecord } from "../types/domain.js";

const supportedOps = new Set(["create_page", "update_page"]);

export class ConfluenceConnector implements Connector {
  readonly toolId = "confluence";

  async execute(action: ActionRecord): Promise<ConnectorExecutionResult> {
    if (!supportedOps.has(action.resource.operation)) {
      return {
        success: false,
        output: {},
        error: `Unsupported confluence operation: ${action.resource.operation}`
      };
    }

    return {
      success: true,
      output: {
        space: action.resource.target,
        operation: action.resource.operation,
        pageId: `cf_${action.id.slice(-8)}`,
        status: "saved"
      },
      error: null
    };
  }
}

