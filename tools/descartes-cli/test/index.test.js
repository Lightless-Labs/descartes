import assert from "node:assert/strict";
import test from "node:test";
import {
  MIN_NODE_VERSION,
  SUPPORTED_NODE_RANGE,
  isSupportedNodeVersion,
  unsupportedNodeVersionMessage,
} from "../src/index.js";

test("Node.js version guard accepts only supported runtimes", () => {
  assert.equal(MIN_NODE_VERSION, "22.19.0");
  assert.equal(SUPPORTED_NODE_RANGE, ">=22.19.0");
  assert.equal(isSupportedNodeVersion("18.19.1"), false);
  assert.equal(isSupportedNodeVersion("20.20.2"), false);
  assert.equal(isSupportedNodeVersion("22.18.0"), false);
  assert.equal(isSupportedNodeVersion("22.19.0"), true);
  assert.equal(isSupportedNodeVersion("v22.20.0"), true);
  assert.equal(isSupportedNodeVersion("23.0.0"), true);
});

test("unsupported Node.js message names current version and supported range", () => {
  const message = unsupportedNodeVersionMessage("v20.20.2");
  assert.match(message, />=22\.19\.0/);
  assert.match(message, /v20\.20\.2/);
  assert.match(message, /Install Node 22\.19\.0\+/);
});
