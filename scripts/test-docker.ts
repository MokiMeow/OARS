import { runNpm } from "./run-npm.js";

runNpm(["test"], {
  OARS_DOCKER_TESTS: "1"
});

