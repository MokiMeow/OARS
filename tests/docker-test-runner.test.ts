import { expect, it, vi } from "vitest";
import { runNpm } from "../scripts/run-npm.js";

vi.mock("../scripts/run-npm.js", () => ({ runNpm: vi.fn() }));

it("runs only the Docker-backed suites instead of repeating ordinary tests", async () => {
  await import("../scripts/test-docker.js");
  expect(runNpm).toHaveBeenCalledExactlyOnceWith(
    ["test", "--", "tests/postgres-api.test.ts", "tests/backplane-postgres-api.test.ts"],
    { OARS_DOCKER_TESTS: "1" }
  );
});
