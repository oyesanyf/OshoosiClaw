"use strict";

const assert = require("node:assert");
const {
  deepEqual,
  PROTO_POLLUTION_KEYS,
  validateDocument,
  isSafeRelativeSourcePath,
} = require("./validate-findings.cjs");

function runTests() {
  console.log("Running validate-findings.cjs test suite...");

  // 1. Primitive deepEqual tests
  assert.strictEqual(deepEqual(1, 1), true, "Numbers should match");
  assert.strictEqual(deepEqual(1, 2), false, "Different numbers should not match");
  assert.strictEqual(deepEqual("test", "test"), true, "Strings should match");
  assert.strictEqual(deepEqual("a", "b"), false, "Different strings should not match");
  assert.strictEqual(deepEqual(null, null), true, "null should match null");
  assert.strictEqual(deepEqual(null, undefined), false, "null != undefined");

  // 2. Array deepEqual tests
  assert.strictEqual(deepEqual([1, 2, 3], [1, 2, 3]), true, "Identical arrays should match");
  assert.strictEqual(deepEqual([1, 2], [1, 2, 3]), false, "Arrays of different length should not match");
  assert.strictEqual(deepEqual([1, 2], [2, 1]), false, "Different array orders should not match");

  // 3. Object deepEqual tests
  assert.strictEqual(deepEqual({ a: 1, b: "x" }, { a: 1, b: "x" }), true, "Identical objects should match");
  assert.strictEqual(deepEqual({ a: 1 }, { a: 2 }), false, "Different property values should not match");

  // 4. Prototype Pollution Guard Tests
  assert.ok(PROTO_POLLUTION_KEYS.has("__proto__"), "Should include __proto__");
  assert.ok(PROTO_POLLUTION_KEYS.has("constructor"), "Should include constructor");
  assert.ok(PROTO_POLLUTION_KEYS.has("prototype"), "Should include prototype");

  // Objects with prototype-like keys should compare safely without throwing or polluting Object.prototype
  const maliciousObj1 = JSON.parse('{"__proto__": {"polluted": true}, "safeProp": 42}');
  const maliciousObj2 = JSON.parse('{"safeProp": 42}');
  assert.strictEqual(
    deepEqual(maliciousObj1, maliciousObj2),
    true,
    "deepEqual should filter out __proto__ keys when comparing"
  );
  assert.strictEqual(
    Object.prototype.polluted,
    undefined,
    "Object.prototype must not be polluted by comparing objects"
  );

  const constrObj1 = JSON.parse('{"constructor": {"prototype": {"injected": true}}, "val": 10}');
  const constrObj2 = JSON.parse('{"val": 10}');
  assert.strictEqual(
    deepEqual(constrObj1, constrObj2),
    true,
    "deepEqual should filter out constructor keys when comparing"
  );
  assert.strictEqual(
    Object.prototype.injected,
    undefined,
    "Object.prototype must not be polluted by constructor payload"
  );

  // 5. isSafeRelativeSourcePath tests
  assert.strictEqual(isSafeRelativeSourcePath("src/main.rs"), true, "Valid source path should pass");
  assert.strictEqual(isSafeRelativeSourcePath("../secret.txt"), false, "Path traversal should be rejected");
  assert.strictEqual(isSafeRelativeSourcePath("/etc/passwd"), false, "Absolute path should be rejected");

  console.log("PASS: All validate-findings unit tests passed successfully.");
}

runTests();
