import assert from "node:assert/strict";
import test from "node:test";
import {
  classifyCommandFailure,
  normalizeVmRequest,
  parseByteQuantity,
  parseLimaListJson,
  parseMultipassListJson,
  parseTartListJson,
  parseVirshList,
  parseVirtualBoxVms,
} from "../src/tools/vms.js";

test("normalizeVmRequest clamps vm limit", () => {
  assert.deepEqual(normalizeVmRequest({ vmLimit: 999 }), { vm_limit: 200 });
  assert.deepEqual(normalizeVmRequest({ vm_limit: 0 }), { vm_limit: 1 });
});

test("parseByteQuantity handles VM runtime units", () => {
  assert.equal(parseByteQuantity("4GiB"), 4294967296);
  assert.equal(parseByteQuantity("10G"), 10737418240);
  assert.equal(parseByteQuantity("500 MB"), 500000000);
});

test("parseTartListJson normalizes Tart VMs and installed-runtime list output", () => {
  const vms = parseTartListJson(JSON.stringify([
    { Name: "ventura", State: "running", Source: "ghcr.io/cirruslabs/macos-ventura-base", CPUs: 4, Memory: "8GiB", DiskSize: "50GiB", IPAddress: "192.168.64.10" },
    { name: "linux", state: "stopped" },
  ]));

  assert.deepEqual(vms, [
    {
      runtime: "tart",
      id: "ventura",
      name: "ventura",
      state: "running",
      backend: "apple_virtualization",
      cpus: 4,
      memory_bytes: 8589934592,
      disk_bytes: 53687091200,
      ips: ["192.168.64.10"],
      owner_hint: "ghcr.io/cirruslabs/macos-ventura-base",
      source_runtime: "tart",
      confidence: 1,
    },
    {
      runtime: "tart",
      id: "linux",
      name: "linux",
      state: "stopped",
      backend: "apple_virtualization",
      cpus: undefined,
      memory_bytes: undefined,
      disk_bytes: undefined,
      ips: [],
      owner_hint: undefined,
      source_runtime: "tart",
      confidence: 1,
    },
  ]);
  assert.deepEqual(parseTartListJson("[]"), []);
});

test("parseLimaListJson handles ndjson and VM fields", () => {
  const vms = parseLimaListJson(`${JSON.stringify({ name: "default", status: "Running", vmType: "vz", cpus: 2, memory: "4GiB", disk: "20GiB", ips: ["192.168.105.2"], dir: "/Users/me/.lima/default" })}\n`);

  assert.deepEqual(vms, [{
    runtime: "lima",
    id: "default",
    name: "default",
    state: "running",
    backend: "vz",
    cpus: 2,
    memory_bytes: 4294967296,
    disk_bytes: 21474836480,
    ips: ["192.168.105.2"],
    owner_hint: "/Users/me/.lima/default",
    source_runtime: "lima",
    confidence: 1,
  }]);
});

test("parseMultipassListJson normalizes Multipass list output", () => {
  const vms = parseMultipassListJson(JSON.stringify({ list: [{ name: "primary", state: "Running", ipv4: ["10.0.0.2"], release: "Ubuntu 24.04 LTS", cpus: "2", memory: "2G", disk: "10G" }] }));

  assert.deepEqual(vms, [{
    runtime: "multipass",
    id: "primary",
    name: "primary",
    state: "running",
    backend: "unknown",
    cpus: 2,
    memory_bytes: 2147483648,
    disk_bytes: 10737418240,
    ips: ["10.0.0.2"],
    owner_hint: "Ubuntu 24.04 LTS",
    source_runtime: "multipass",
    confidence: 1,
  }]);
});

test("parseVirtualBoxVms correlates running VM ids", () => {
  const vms = parseVirtualBoxVms(`"dev" {1111-2222}\n"old" {3333-4444}\n`, `"dev" {1111-2222}\n`);

  assert.deepEqual(vms, [
    { runtime: "virtualbox", id: "1111-2222", name: "dev", state: "running", backend: "unknown", source_runtime: "virtualbox", confidence: 1 },
    { runtime: "virtualbox", id: "3333-4444", name: "old", state: "stopped", backend: "unknown", source_runtime: "virtualbox", confidence: 1 },
  ]);
});

test("parseVirshList parses libvirt state rows", () => {
  const vms = parseVirshList(` Id   Name       State\n--------------------------\n 1    ubuntu     running\n -    windows    shut off\n`);

  assert.deepEqual(vms, [
    { runtime: "libvirt", id: "1", name: "ubuntu", state: "running", backend: "kvm_qemu", source_runtime: "libvirt", confidence: 1 },
    { runtime: "libvirt", id: undefined, name: "windows", state: "stopped", backend: "kvm_qemu", source_runtime: "libvirt", confidence: 1 },
  ]);
});

test("classifyCommandFailure distinguishes missing, daemon, permission, and unknown failures", () => {
  assert.equal(classifyCommandFailure({ status: "unable", code: "ENOENT", error: "spawn tart ENOENT" }), "missing");
  assert.equal(classifyCommandFailure({ status: "unable", error: "failed to connect to the hypervisor" }), "daemon_unavailable");
  assert.equal(classifyCommandFailure({ status: "unable", stderr: "permission denied" }), "permission_limited");
  assert.equal(classifyCommandFailure({ status: "unable", error: "weird failure" }), "unable");
});
