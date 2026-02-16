import { createPlatformContext } from "../src/core/services/platform-context.js";

function readArg(name: string): string | undefined {
  const prefix = `--${name}=`;
  const item = process.argv.find((entry) => entry.startsWith(prefix));
  return item ? item.slice(prefix.length) : undefined;
}

function readBooleanArg(name: string, fallback: boolean): boolean {
  const raw = readArg(name);
  if (raw === undefined) {
    return fallback;
  }
  return raw.trim().toLowerCase() === "true";
}

async function main(): Promise<void> {
  const backupId = readArg("backupId");
  if (!backupId) {
    throw new Error("Missing --backupId argument.");
  }

  const actor = readArg("actor") ?? process.env.OARS_BACKUP_ACTOR ?? "system.restore-job";
  const reason = readArg("reason");
  const createPreRestoreSnapshot = readBooleanArg("createPreRestoreSnapshot", true);
  const pruneMissingFiles = readBooleanArg("pruneMissingFiles", false);
  const context = createPlatformContext({
    siemOptions: {
      autoStartRetry: false
    }
  });

  try {
    const result = context.backupRecoveryService.restoreBackup(backupId, actor, reason, {
      createPreRestoreSnapshot,
      pruneMissingFiles
    });
    process.stdout.write(
      `${JSON.stringify(
        {
          ...result,
          restartRequired: true
        },
        null,
        2
      )}\n`
    );
  } finally {
    context.jwksService.stopAutoRefresh();
    context.securityEventService.stopSiemRetryScheduler();
  }
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Restore job failed.";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
