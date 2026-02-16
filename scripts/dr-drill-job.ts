import { createPlatformContext } from "../src/core/services/platform-context.js";

function readArg(name: string): string | undefined {
  const prefix = `--${name}=`;
  const item = process.argv.find((entry) => entry.startsWith(prefix));
  return item ? item.slice(prefix.length) : undefined;
}

async function main(): Promise<void> {
  const actor = readArg("actor") ?? process.env.OARS_BACKUP_ACTOR ?? "system.dr-drill-job";
  const reason = readArg("reason");
  const context = createPlatformContext({
    siemOptions: {
      autoStartRetry: false
    }
  });

  try {
    const report = context.backupRecoveryService.runBackupRestoreDrill(actor, reason);
    await context.securityEventService.publish({
      tenantId: "platform",
      source: "admin",
      eventType: "backup.drill.completed",
      payload: {
        drillId: report.drillId,
        backupId: report.backupId,
        status: report.status,
        triggeredBy: actor
      }
    });
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    if (report.status === "failed") {
      process.exitCode = 2;
    }
  } finally {
    context.jwksService.stopAutoRefresh();
    context.securityEventService.stopSiemRetryScheduler();
  }
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "DR drill job failed.";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
