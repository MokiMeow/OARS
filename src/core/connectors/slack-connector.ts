import type { Connector, ConnectorExecutionResult } from "./types.js";
import type { ActionRecord } from "../types/domain.js";

export class SlackConnector implements Connector {
  readonly toolId = "slack";

  async execute(action: ActionRecord): Promise<ConnectorExecutionResult> {
    if (action.resource.operation !== "send_message") {
      return {
        success: false,
        output: {},
        error: `Unsupported slack operation: ${action.resource.operation}`
      };
    }

    return {
      success: true,
      output: {
        channel: action.resource.target,
        messageStatus: "queued",
        messageId: `msg_${action.id.slice(-8)}`
      },
      error: null
    };
  }
}
