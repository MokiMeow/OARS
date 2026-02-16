import { runNpm } from "./run-npm.js";

interface GateStep {
  name: string;
  args: string[];
  env?: Record<string, string | undefined> | undefined;
}

const steps: GateStep[] = [
  { name: "Typecheck", args: ["run", "typecheck"] },
  { name: "Tests", args: ["test"] },
  { name: "Build", args: ["run", "build"] },
  {
    name: "Perf Smoke",
    args: ["run", "perf:smoke"],
    env: {
      PERF_REQUESTS: "120",
      PERF_CONCURRENCY: "12",
      PERF_P95_MS: "8000"
    }
  },
  { name: "Conformance", args: ["run", "conformance"] }
];

for (const step of steps) {
  process.stdout.write(`\n[release-gate] Running ${step.name}...\n`);
  try {
    runNpm(step.args, step.env);
  } catch (error) {
    process.stderr.write(
      `[release-gate] Failed at step: ${step.name}${error instanceof Error ? ` (${error.message})` : ""}\n`
    );
    process.exit(1);
  }
}

process.stdout.write("\n[release-gate] All gates passed.\n");
