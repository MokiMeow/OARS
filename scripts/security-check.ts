import { runNpm } from "./run-npm.js";

// High-signal checks that should remain fast and deterministic.
runNpm(["audit", "--audit-level=high"]);
runNpm(["run", "typecheck"]);
runNpm(["test"]);

