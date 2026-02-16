import { createPlatformContext } from "../src/core/services/platform-context.js";

function readArg(name: string): string | undefined {
  const prefix = `--${name}=`;
  const item = process.argv.find((entry) => entry.startsWith(prefix));
  return item ? item.slice(prefix.length) : undefined;
}

async function main(): Promise<void> {
  const reason = readArg("reason");
  const actor = readArg("actor") ?? process.env.OARS_BACKUP_ACTOR ?? "system.backup-job";
  const context = createPlatformContext({
    siemOptions: {
      autoStartRetry: false
    }
  });

  try {
    const result = context.backupRecoveryService.createBackup(actor, reason);
    await context.securityEventService.publish({
      tenantId: "platform",
      source: "admin",
      eventType: "backup.created",
      payload: {
        backupId: result.backupId,
        createdBy: actor,
        missingRequiredFileIds: result.missingRequiredFileIds,
        reason: result.reason
      }
    });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } finally {
    context.jwksService.stopAutoRefresh();
    context.securityEventService.stopSiemRetryScheduler();
  }
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Backup job failed.";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
