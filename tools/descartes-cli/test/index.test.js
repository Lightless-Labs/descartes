import assert from "node:assert/strict";
import test from "node:test";
import {
  MIN_NODE_20_VERSION,
  MIN_NODE_22_VERSION,
  SUPPORTED_NODE_RANGE,
  isSupportedNodeVersion,
  unsupportedNodeVersionMessage,
} from "../src/index.js";

test("Node.js version guard accepts only supported runtimes", () => {
  assert.equal(MIN_NODE_20_VERSION, "20.18.1");
  assert.equal(MIN_NODE_22_VERSION, "22.9.0");
  assert.equal(SUPPORTED_NODE_RANGE, "^20.18.1 || >=22.9.0");
  assert.equal(isSupportedNodeVersion("18.19.1"), false);
  assert.equal(isSupportedNodeVersion("20.18.0"), false);
  assert.equal(isSupportedNodeVersion("20.18.1"), true);
  assert.equal(isSupportedNodeVersion("v20.19.0"), true);
  assert.equal(isSupportedNodeVersion("21.7.0"), false);
  assert.equal(isSupportedNodeVersion("22.8.0"), false);
  assert.equal(isSupportedNodeVersion("22.9.0"), true);
  assert.equal(isSupportedNodeVersion("23.0.0"), true);
});

test("unsupported Node.js message names current version and supported range", () => {
  const message = unsupportedNodeVersionMessage("v18.19.1");
  assert.match(message, /\^20\.18\.1 \|\| >=22\.9\.0/);
  assert.match(message, /v18\.19\.1/);
  assert.match(message, /Node 20 LTS 20\.18\.1\+ or Node 22\.9\.0\+/);
});
