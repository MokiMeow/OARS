import type { Connector, ConnectorExecutionResult } from "./types.js";
import type { ActionRecord } from "../types/domain.js";

export class JiraConnector implements Connector {
  readonly toolId = "jira";

  async execute(action: ActionRecord): Promise<ConnectorExecutionResult> {
    if (action.resource.operation !== "create_ticket") {
      return {
        success: false,
        output: {},
        error: `Unsupported jira operation: ${action.resource.operation}`
      };
    }

    return {
      success: true,
      output: {
        ticketId: `SEC-${action.id.slice(-6).toUpperCase()}`,
        project: action.resource.target,
        status: "created"
      },
      error: null
    };
  }
}
