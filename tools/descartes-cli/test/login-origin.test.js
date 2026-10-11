import assert from "node:assert/strict";
import test from "node:test";
import { classifyLoginOrigin, isLastDateStart, isLocalLoginHost, ttyClassOf } from "../src/tools/login-origin.js";

test("C0.4: tty classes are closed", () => {
  assert.deepEqual(["console", "ttys012", "pts/3", "tty7", "ttyS0", ":0", "", undefined, "weird!"].map(ttyClassOf),
    ["console", "ttys", "pts", "tty", "tty", "display", "none", "none", "unknown"]);
});

test("C0.4: origin classes from explicit patterns; remote hosts are returned raw only for remote rows", () => {
  const cases = [
    [{ tty: "console" }, "console", undefined],
    [{ tty: "ttys001" }, "local_tty", undefined],
    [{ tty: "pts/0", host: "" }, "local_tty", undefined],
    [{ tty: "tty7", host: ":0" }, "local_display", undefined],
    [{ tty: "pts/1", host: ":1.0" }, "local_display", undefined],
    [{ tty: "pts/3", host: ":pts/3:S.0" }, "local_tty", undefined],
    [{ tty: "pts/4", host: "tmux(1234).%0" }, "local_tty", undefined],
    [{ tty: "pts/5", host: "mosh [4321]" }, "remote_mosh", undefined],
    [{ tty: "pts/6", host: "203.0.113.7" }, "remote", "203.0.113.7"],
    [{ tty: "pts/7", host: "laptop.example:10.0" }, "remote", "laptop.example:10.0"],
    [{ tty: "weird", host: "" }, "unknown", undefined],
  ];
  for (const [input, origin, host] of cases) {
    assert.deepEqual(classifyLoginOrigin(input), { origin_class: origin, remote_host: host }, JSON.stringify(input));
  }
  assert.equal(isLocalLoginHost("mosh [1]", "pts/1"), false, "mosh is a remote login with an unrecorded host, never local");
  assert.equal(isLocalLoginHost(":0", "tty7"), true);
});

test("C0.4: a last row's empty host column is recognised by its date start", () => {
  assert.equal(isLastDateStart("Fri", "Sep"), true);
  assert.equal(isLastDateStart("Fri", "x"), false);
  assert.equal(isLastDateStart("100.64.1.1", "Sun"), false);
});
