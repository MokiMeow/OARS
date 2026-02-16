import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync
} from "node:fs";
import { dirname, extname, join, resolve, sep } from "node:path";
import { sha256Hex } from "../../lib/hash.js";
import { createId } from "../../lib/id.js";
import { nowIso } from "../../lib/time.js";
import { ImmutableLedgerService } from "./immutable-ledger-service.js";

export interface BackupManagedFileSpec {
  id: string;
  path: string;
  required?: boolean | undefined;
}

export interface BackupManifestFile {
  id: string;
  sourcePath: string;
  relativePath: string | null;
  required: boolean;
  exists: boolean;
  sizeBytes: number;
  sha256: string | null;
}

export interface BackupManifest {
  manifestVersion: 1;
  backupId: string;
  createdAt: string;
  createdBy: string;
  reason: string | null;
  files: BackupManifestFile[];
  manifestHash: string;
}

export interface BackupCreateResult extends BackupManifest {
  backupPath: string;
  missingRequiredFileIds: string[];
}

export interface BackupRestoreResult {
  backupId: string;
  restoredAt: string;
  restoredBy: string;
  reason: string | null;
  restoredFileIds: string[];
  skippedMissingFileIds: string[];
  deletedMissingFileIds: string[];
  preRestoreBackupId: string | null;
}

export interface RestoreOptions {
  createPreRestoreSnapshot?: boolean | undefined;
  pruneMissingFiles?: boolean | undefined;
}

export interface DisasterRecoveryDrillCheck {
  name: string;
  status: "passed" | "failed";
  details?: Record<string, unknown> | undefined;
  error?: string | undefined;
}

export interface DisasterRecoveryDrillReport {
  drillId: string;
  backupId: string;
  startedAt: string;
  completedAt: string;
  triggeredBy: string;
  reason: string | null;
  status: "passed" | "failed";
  checks: DisasterRecoveryDrillCheck[];
  reportPath: string;
}

interface BackupRecoveryServiceOptions {
  managedFiles: BackupManagedFileSpec[];
  backupRootPath?: string | undefined;
  drillReportsPath?: string | undefined;
  drillWorkspacePath?: string | undefined;
}

function checksumForUtf8File(filePath: string): { sha256: string; sizeBytes: number } {
  const raw = readFileSync(filePath, "utf8");
  return {
    sha256: sha256Hex(raw),
    sizeBytes: Buffer.byteLength(raw, "utf8")
  };
}

function normalizeBackupManifest(manifest: BackupManifest): BackupManifest {
  const normalizedFiles = manifest.files.map((file) => ({
    id: file.id,
    sourcePath: file.sourcePath,
    relativePath: file.relativePath,
    required: file.required,
    exists: file.exists,
    sizeBytes: file.sizeBytes,
    sha256: file.sha256
  }));
  return {
    manifestVersion: 1,
    backupId: manifest.backupId,
    createdAt: manifest.createdAt,
    createdBy: manifest.createdBy,
    reason: manifest.reason,
    files: normalizedFiles,
    manifestHash: sha256Hex(
      JSON.stringify({
        backupId: manifest.backupId,
        createdAt: manifest.createdAt,
        createdBy: manifest.createdBy,
        reason: manifest.reason,
        files: normalizedFiles
      })
    )
  };
}

function ensureDirectory(path: string): void {
  if (!existsSync(path)) {
    mkdirSync(path, { recursive: true });
  }
}

function isSafeId(value: string): boolean {
  return /^[a-zA-Z0-9_-]+$/.test(value);
}

function asErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message.trim().length > 0) {
    return error.message;
  }
  return "Unknown error.";
}

export class BackupRecoveryService {
  private readonly managedFiles: BackupManagedFileSpec[];
  private readonly backupRootPath: string;
  private readonly drillReportsPath: string;
  private readonly drillWorkspacePath: string;

  constructor(options: BackupRecoveryServiceOptions) {
    this.managedFiles = options.managedFiles.map((file) => ({
      id: file.id,
      path: file.path,
      required: file.required ?? false
    }));
    this.backupRootPath = options.backupRootPath ?? process.env.OARS_BACKUP_ROOT_PATH ?? "data/backups";
    this.drillReportsPath = options.drillReportsPath ?? process.env.OARS_DR_DRILL_REPORTS_PATH ?? "data/dr-drill-reports";
    this.drillWorkspacePath =
      options.drillWorkspacePath ?? process.env.OARS_DR_DRILL_WORKSPACE_PATH ?? "data/dr-drill-workspace";
  }

  runtimePaths(): {
    backupRootPath: string;
    drillReportsPath: string;
    drillWorkspacePath: string;
  } {
    return {
      backupRootPath: this.backupRootPath,
      drillReportsPath: this.drillReportsPath,
      drillWorkspacePath: this.drillWorkspacePath
    };
  }

  createBackup(createdBy: string, reason?: string): BackupCreateResult {
    const backupId = createId("bkp");
    const backupPath = this.resolveBackupPath(backupId);
    ensureDirectory(backupPath);

    const files: BackupManifestFile[] = [];
    for (const file of this.managedFiles) {
      if (!existsSync(file.path)) {
        files.push({
          id: file.id,
          sourcePath: file.path,
          relativePath: null,
          required: file.required ?? false,
          exists: false,
          sizeBytes: 0,
          sha256: null
        });
        continue;
      }

      const extension = extname(file.path) || ".dat";
      const relativePath = join("artifacts", `${file.id}${extension}`);
      const destinationPath = join(backupPath, relativePath);
      ensureDirectory(dirname(destinationPath));
      copyFileSync(file.path, destinationPath);
      const checksum = checksumForUtf8File(destinationPath);
      files.push({
        id: file.id,
        sourcePath: file.path,
        relativePath,
        required: file.required ?? false,
        exists: true,
        sizeBytes: checksum.sizeBytes,
        sha256: checksum.sha256
      });
    }

    const manifest = normalizeBackupManifest({
      manifestVersion: 1,
      backupId,
      createdAt: nowIso(),
      createdBy,
      reason: reason ?? null,
      files,
      manifestHash: ""
    });
    this.persistManifest(backupPath, manifest);

    return {
      ...manifest,
      backupPath,
      missingRequiredFileIds: files.filter((file) => file.required && !file.exists).map((file) => file.id)
    };
  }

  listBackups(limit = 25): BackupManifest[] {
    if (!existsSync(this.backupRootPath)) {
      return [];
    }

    const items: BackupManifest[] = [];
    for (const entry of readdirSync(this.backupRootPath, { withFileTypes: true })) {
      if (!entry.isDirectory()) {
        continue;
      }
      try {
        const backupPath = this.resolveBackupPath(entry.name);
        items.push(this.readManifest(backupPath));
      } catch {
        // Skip malformed backup folders.
      }
    }

    const safeLimit = Math.min(200, Math.max(1, limit));
    return items.sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, safeLimit);
  }

  restoreBackup(backupId: string, restoredBy: string, reason?: string, options?: RestoreOptions): BackupRestoreResult {
    const backupPath = this.resolveBackupPath(backupId);
    const manifest = this.readManifest(backupPath);
    const createPreRestoreSnapshot = options?.createPreRestoreSnapshot ?? true;
    const pruneMissingFiles = options?.pruneMissingFiles ?? false;
    const preRestoreBackupId = createPreRestoreSnapshot
      ? this.createBackup(restoredBy, `pre_restore_snapshot:${backupId}`).backupId
      : null;

    const restoredFileIds: string[] = [];
    const skippedMissingFileIds: string[] = [];
    const deletedMissingFileIds: string[] = [];
    for (const file of manifest.files) {
      if (!file.exists || !file.relativePath) {
        skippedMissingFileIds.push(file.id);
        if (pruneMissingFiles && existsSync(file.sourcePath)) {
          rmSync(file.sourcePath, { force: true });
          deletedMissingFileIds.push(file.id);
        }
        continue;
      }
      const artifactPath = join(backupPath, file.relativePath);
      if (!existsSync(artifactPath)) {
        throw new Error(`Backup artifact missing for file ${file.id}.`);
      }
      const checksum = checksumForUtf8File(artifactPath);
      if (checksum.sha256 !== file.sha256) {
        throw new Error(`Backup artifact checksum mismatch for file ${file.id}.`);
      }

      ensureDirectory(dirname(file.sourcePath));
      const tempPath = `${file.sourcePath}.restore-${createId("tmp")}.tmp`;
      copyFileSync(artifactPath, tempPath);
      renameSync(tempPath, file.sourcePath);
      restoredFileIds.push(file.id);
    }

    return {
      backupId,
      restoredAt: nowIso(),
      restoredBy,
      reason: reason ?? null,
      restoredFileIds,
      skippedMissingFileIds,
      deletedMissingFileIds,
      preRestoreBackupId
    };
  }

  runBackupRestoreDrill(triggeredBy: string, reason?: string): DisasterRecoveryDrillReport {
    const drillId = createId("drill");
    const startedAt = nowIso();
    const checks: DisasterRecoveryDrillCheck[] = [];
    const workspacePath = this.resolveDrillWorkspacePath(drillId);
    ensureDirectory(workspacePath);

    let backupId = "";
    let status: DisasterRecoveryDrillReport["status"] = "passed";
    try {
      const backup = this.createBackup(triggeredBy, reason ?? `drill:${drillId}`);
      backupId = backup.backupId;
      checks.push({
        name: "backup_created",
        status: "passed",
        details: {
          backupId: backup.backupId,
          missingRequiredFileIds: backup.missingRequiredFileIds
        }
      });

      const backupPath = this.resolveBackupPath(backup.backupId);
      const stagedFiles = new Map<string, string>();
      for (const file of backup.files) {
        if (!file.exists || !file.relativePath) {
          continue;
        }
        const sourceArtifactPath = join(backupPath, file.relativePath);
        const stagedPath = join(workspacePath, "staged", file.id, `${file.id}${extname(file.relativePath)}`);
        ensureDirectory(dirname(stagedPath));
        copyFileSync(sourceArtifactPath, stagedPath);
        stagedFiles.set(file.id, stagedPath);
      }

      let checksumMismatchCount = 0;
      for (const file of backup.files) {
        if (!file.exists || !file.relativePath || !file.sha256) {
          continue;
        }
        const stagedPath = stagedFiles.get(file.id);
        if (!stagedPath || !existsSync(stagedPath)) {
          checksumMismatchCount += 1;
          continue;
        }
        const checksum = checksumForUtf8File(stagedPath);
        if (checksum.sha256 !== file.sha256) {
          checksumMismatchCount += 1;
        }
      }
      checks.push({
        name: "artifact_checksums",
        status: checksumMismatchCount === 0 ? "passed" : "failed",
        details: {
          mismatchCount: checksumMismatchCount
        }
      });

      const statePath = stagedFiles.get("state");
      if (statePath && existsSync(statePath)) {
        const parsed = JSON.parse(readFileSync(statePath, "utf8")) as Record<string, unknown>;
        checks.push({
          name: "state_parse",
          status: "passed",
          details: {
            actions: Array.isArray(parsed.actions) ? parsed.actions.length : 0,
            approvals: Array.isArray(parsed.approvals) ? parsed.approvals.length : 0,
            receipts: Array.isArray(parsed.receipts) ? parsed.receipts.length : 0,
            securityEvents: Array.isArray(parsed.securityEvents) ? parsed.securityEvents.length : 0
          }
        });
      } else {
        checks.push({
          name: "state_parse",
          status: "failed",
          error: "State snapshot missing in backup."
        });
      }

      const ledgerPath = stagedFiles.get("immutable_ledger");
      if (ledgerPath && existsSync(ledgerPath)) {
        const verification = new ImmutableLedgerService(ledgerPath).verifyIntegrity();
        checks.push({
          name: "ledger_integrity",
          status: verification.isValid ? "passed" : "failed",
          details: {
            checkedEntries: verification.checkedEntries,
            lastSequence: verification.lastSequence,
            errorCount: verification.errors.length
          }
        });
      } else {
        checks.push({
          name: "ledger_integrity",
          status: "failed",
          error: "Immutable ledger snapshot missing in backup."
        });
      }

      const keyPath = stagedFiles.get("signing_keys");
      if (keyPath && existsSync(keyPath)) {
        const parsed = JSON.parse(readFileSync(keyPath, "utf8")) as { keys?: unknown };
        checks.push({
          name: "signing_key_parse",
          status: "passed",
          details: {
            keyCount: Array.isArray(parsed.keys) ? parsed.keys.length : 0
          }
        });
      } else {
        checks.push({
          name: "signing_key_parse",
          status: "failed",
          error: "Signing key snapshot missing in backup."
        });
      }
    } catch (error) {
      status = "failed";
      checks.push({
        name: "drill_execution",
        status: "failed",
        error: asErrorMessage(error)
      });
    } finally {
      const hasFailedChecks = checks.some((check) => check.status === "failed");
      if (hasFailedChecks) {
        status = "failed";
      }
      const completedAt = nowIso();
      const reportPath = this.resolveDrillReportPath(drillId);
      ensureDirectory(dirname(reportPath));
      const report: DisasterRecoveryDrillReport = {
        drillId,
        backupId,
        startedAt,
        completedAt,
        triggeredBy,
        reason: reason ?? null,
        status,
        checks,
        reportPath
      };
      writeFileSync(reportPath, JSON.stringify(report, null, 2), "utf8");
      rmSync(workspacePath, { recursive: true, force: true });
      return report;
    }
  }

  listDrillReports(limit = 25): DisasterRecoveryDrillReport[] {
    if (!existsSync(this.drillReportsPath)) {
      return [];
    }

    const items: DisasterRecoveryDrillReport[] = [];
    for (const entry of readdirSync(this.drillReportsPath, { withFileTypes: true })) {
      if (!entry.isFile() || !entry.name.endsWith(".json")) {
        continue;
      }
      const filePath = join(this.drillReportsPath, entry.name);
      try {
        const raw = readFileSync(filePath, "utf8");
        const parsed = JSON.parse(raw) as DisasterRecoveryDrillReport;
        items.push(parsed);
      } catch {
        // Ignore malformed reports to keep listing resilient.
      }
    }

    const safeLimit = Math.min(200, Math.max(1, limit));
    return items.sort((a, b) => b.startedAt.localeCompare(a.startedAt)).slice(0, safeLimit);
  }

  backupStorageStatus(): {
    backupRootPath: string;
    drillReportsPath: string;
    drillWorkspacePath: string;
    backupCount: number;
    latestBackupAt: string | null;
    drillCount: number;
    latestDrillAt: string | null;
    managedFiles: Array<{ id: string; path: string; required: boolean; exists: boolean; sizeBytes: number }>;
  } {
    const backups = this.listBackups(200);
    const drills = this.listDrillReports(200);
    return {
      backupRootPath: this.backupRootPath,
      drillReportsPath: this.drillReportsPath,
      drillWorkspacePath: this.drillWorkspacePath,
      backupCount: backups.length,
      latestBackupAt: backups[0]?.createdAt ?? null,
      drillCount: drills.length,
      latestDrillAt: drills[0]?.completedAt ?? null,
      managedFiles: this.managedFiles.map((file) => ({
        id: file.id,
        path: file.path,
        required: file.required ?? false,
        exists: existsSync(file.path),
        sizeBytes: existsSync(file.path) ? statSync(file.path).size : 0
      }))
    };
  }

  private persistManifest(backupPath: string, manifest: BackupManifest): void {
    const manifestPath = join(backupPath, "manifest.json");
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), "utf8");
  }

  private readManifest(backupPath: string): BackupManifest {
    const manifestPath = join(backupPath, "manifest.json");
    if (!existsSync(manifestPath)) {
      throw new Error(`Backup manifest not found at ${manifestPath}.`);
    }
    const raw = readFileSync(manifestPath, "utf8");
    const parsed = JSON.parse(raw) as Partial<BackupManifest>;
    if (parsed.manifestVersion !== 1 || !parsed.backupId || !parsed.createdAt || !parsed.createdBy) {
      throw new Error("Malformed backup manifest.");
    }

    const files = Array.isArray(parsed.files)
      ? parsed.files.map((file) => ({
          id: file.id ?? "",
          sourcePath: file.sourcePath ?? "",
          relativePath: file.relativePath ?? null,
          required: file.required ?? false,
          exists: file.exists ?? false,
          sizeBytes: file.sizeBytes ?? 0,
          sha256: file.sha256 ?? null
        }))
      : [];
    const manifest = normalizeBackupManifest({
      manifestVersion: 1,
      backupId: parsed.backupId,
      createdAt: parsed.createdAt,
      createdBy: parsed.createdBy,
      reason: parsed.reason ?? null,
      files,
      manifestHash: parsed.manifestHash ?? ""
    });
    if (parsed.manifestHash && parsed.manifestHash !== manifest.manifestHash) {
      throw new Error(`Backup manifest hash mismatch for ${parsed.backupId}.`);
    }
    return manifest;
  }

  private resolveBackupPath(backupId: string): string {
    if (!isSafeId(backupId)) {
      throw new Error("Invalid backup identifier.");
    }
    const root = resolve(this.backupRootPath);
    const backupPath = resolve(this.backupRootPath, backupId);
    if (backupPath !== root && !backupPath.startsWith(`${root}${sep}`)) {
      throw new Error("Backup path traversal denied.");
    }
    return backupPath;
  }

  private resolveDrillWorkspacePath(drillId: string): string {
    if (!isSafeId(drillId)) {
      throw new Error("Invalid drill identifier.");
    }
    const root = resolve(this.drillWorkspacePath);
    const workspacePath = resolve(this.drillWorkspacePath, drillId);
    if (workspacePath !== root && !workspacePath.startsWith(`${root}${sep}`)) {
      throw new Error("Drill workspace path traversal denied.");
    }
    return workspacePath;
  }

  private resolveDrillReportPath(drillId: string): string {
    if (!isSafeId(drillId)) {
      throw new Error("Invalid drill identifier.");
    }
    const root = resolve(this.drillReportsPath);
    const reportPath = resolve(this.drillReportsPath, `${drillId}.json`);
    if (reportPath !== root && !reportPath.startsWith(`${root}${sep}`)) {
      throw new Error("Drill report path traversal denied.");
    }
    return reportPath;
  }
}
