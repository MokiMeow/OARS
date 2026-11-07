import assert from "node:assert/strict";
import { describe, it } from "vitest";
import { canonicalStringify } from "../src/lib/canonical-json.js";
import { sha256Hex } from "../src/lib/hash.js";

describe("canonicalStringify", () => {
  it("preserves the existing ordering for ordinary nested JSON", () => {
    assert.equal(
      canonicalStringify({ z: 3, a: { z: false, a: [null, { z: 2, a: 1 }] } }),
      '{"a":{"a":[null,{"a":1,"z":2}],"z":false},"z":3}'
    );
  });

  it("preserves prototype-named keys as JSON data at every depth", () => {
    const payload = JSON.parse(
      '{"__proto__":{"polluted":true},"nested":[{"__proto__":null,"constructor":{"prototype":"data"}}]}'
    );
    const before = JSON.stringify(payload);
    const serialized = canonicalStringify(payload);
    assert.deepEqual(JSON.parse(serialized), payload);
    assert.equal(JSON.stringify(payload), before);
    assert.equal(Object.hasOwn(Object.prototype, "polluted"), false);
  });

  it("does not collapse distinct prototype-named values into the same hash", () => {
    const values = [null, false, 1, "value", [], { amount: 1 }, { amount: 2 }];
    const hashes = values.map((value) => {
      const payload = JSON.parse('{"input":{"__proto__":null,"amount":7}}');
      payload.input.__proto__ = value;
      return sha256Hex(canonicalStringify(payload));
    });
    hashes.push(sha256Hex(canonicalStringify({ input: { amount: 7 } })));
    assert.equal(new Set(hashes).size, hashes.length);
  });

  it("ignores inherited keys without dropping own prototype-named keys", () => {
    const payload = Object.create({ inherited: "not JSON data" }) as Record<string, unknown>;
    Object.defineProperty(payload, "__proto__", { value: { z: 2, a: 1 }, enumerable: true });
    payload.own = "included";
    assert.equal(canonicalStringify(payload), '{"__proto__":{"a":1,"z":2},"own":"included"}');
  });
});
