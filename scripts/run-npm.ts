import { spawnSync } from "node:child_process";

export function runNpm(args: string[], env?: Record<string, string | undefined>): void {
  const cmd = process.platform === "win32" ? (process.env.ComSpec ?? "cmd.exe") : "npm";
  const cmdArgs = process.platform === "win32" ? ["/d", "/s", "/c", "npm", ...args] : args;
  const result = spawnSync(cmd, cmdArgs, {
    stdio: "inherit",
    env: {
      ...process.env,
      ...(env ?? {})
    }
  });

  if (result.error) {
    throw result.error;
  }
  if (typeof result.status === "number" && result.status !== 0) {
    throw new Error(`npm ${args.join(" ")} failed with exit code ${result.status}`);
  }
}
