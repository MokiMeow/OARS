import { runNpm } from "./run-npm.js";

// CI runs the ordinary suite separately. Only repeat the two suites that were
// skipped there because they require a Docker-backed Postgres instance.
runNpm(["test", "--", "tests/postgres-api.test.ts", "tests/backplane-postgres-api.test.ts"], {
  OARS_DOCKER_TESTS: "1"
});

