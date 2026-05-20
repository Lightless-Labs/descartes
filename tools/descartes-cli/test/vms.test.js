import assert from "node:assert/strict";
import test from "node:test";
import {
  classifyCommandFailure,
  mergeRuntimes,
  normalizeVmRequest,
  parseByteQuantity,
  parseLimaListJson,
  parseIncusOrLxcListJson,
  parseMultipassListJson,
  parseParallelsListJson,
  parsePodmanMachineListJson,
  parseQmList,
  parseTartListJson,
  parseVirshList,
  parseVirtualBoxVms,
  parseVmProcesses,
  parseVmrunList,
  parseXlList,
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

test("parseParallelsListJson normalizes Parallels JSON", () => {
  const vms = parseParallelsListJson(JSON.stringify([{ ID: "uuid", Name: "win", Status: "running", CPUs: 4, Memory: "8GiB", IP_ADDR: "10.211.55.3", Home: "/Users/me/Parallels/win.pvm" }]));

  assert.deepEqual(vms, [{
    runtime: "parallels",
    id: "uuid",
    name: "win",
    state: "running",
    backend: "parallels",
    cpus: 4,
    memory_bytes: 8589934592,
    disk_bytes: undefined,
    ips: ["10.211.55.3"],
    owner_hint: "/Users/me/Parallels/win.pvm",
    source_runtime: "parallels",
    confidence: 1,
  }]);
});

test("parseVmrunList treats vmrun output as running VMware VMs", () => {
  assert.deepEqual(parseVmrunList(`Total running VMs: 1\n/Users/me/VMs/dev.vmwarevm/dev.vmx\n`), [{
    runtime: "vmware",
    id: "/Users/me/VMs/dev.vmwarevm/dev.vmx",
    name: "dev",
    state: "running",
    backend: "vmware",
    owner_hint: "/Users/me/VMs/dev.vmwarevm/dev.vmx",
    source_runtime: "vmware",
    confidence: 1,
  }]);
});

test("parsePodmanMachineListJson normalizes podman machine VMs", () => {
  const vms = parsePodmanMachineListJson(JSON.stringify([{ Name: "podman-machine-default", Running: true, VMType: "applehv", CPUs: 4, Memory: "2GiB", DiskSize: "100GiB", LastUp: "2026-05-20" }]));

  assert.deepEqual(vms, [{
    runtime: "podman_machine",
    id: "podman-machine-default",
    name: "podman-machine-default",
    state: "running",
    backend: "applehv",
    cpus: 4,
    memory_bytes: 2147483648,
    disk_bytes: 107374182400,
    ips: [],
    owner_hint: "2026-05-20",
    source_runtime: "podman_machine",
    confidence: 1,
  }]);
});

test("parseIncusOrLxcListJson keeps only VM instances", () => {
  const vms = parseIncusOrLxcListJson(JSON.stringify([
    { name: "vm1", type: "virtual-machine", status: "Running", config: { "limits.cpu": "2", "limits.memory": "4GiB" }, devices: { root: { size: "20GiB" } }, state: { network: { eth0: { addresses: [{ address: "10.0.3.2" }] } } }, project: "default" },
    { name: "ct1", type: "container", status: "Running" },
  ]), { runtime: "incus" });

  assert.deepEqual(vms, [{
    runtime: "incus",
    id: "vm1",
    name: "vm1",
    state: "running",
    backend: "qemu",
    cpus: 2,
    memory_bytes: 4294967296,
    disk_bytes: 21474836480,
    ips: ["10.0.3.2"],
    owner_hint: "default",
    source_runtime: "incus",
    confidence: 1,
  }]);
});

test("parseQmList and parseXlList normalize server hypervisor tables", () => {
  assert.deepEqual(parseQmList(`VMID NAME STATUS MEM(MB) BOOTDISK(GB) PID\n100 debian running 2048 32.00 1234\n`), [{
    runtime: "proxmox",
    id: "100",
    name: "debian",
    state: "running",
    backend: "kvm_qemu",
    memory_bytes: 2147483648,
    disk_bytes: 34359738368,
    resource_snapshot: { pid: 1234 },
    source_runtime: "proxmox",
    confidence: 1,
  }]);

  assert.deepEqual(parseXlList(`Name ID Mem VCPUs State Time(s)\ndomain-0 0 8192 4 r----- 100.0\n`), [{
    runtime: "xen",
    id: "0",
    name: "domain-0",
    state: "running",
    backend: "xen",
    cpus: 4,
    memory_bytes: 8589934592,
    source_runtime: "xen",
    confidence: 1,
  }]);
});

test("mergeRuntimes prefers available runtime evidence over missing probes", () => {
  assert.deepEqual(mergeRuntimes([
    { runtime: "utm", installed: false, available: false, support_status: "missing" },
    { runtime: "utm", installed: true, available: true, support_status: "ok" },
  ]), [{ runtime: "utm", installed: true, available: true, support_status: "ok" }]);
});

test("parseVmProcesses identifies running QEMU/VMware/UTM processes with redacted args", () => {
  const vms = parseVmProcesses(`  PID  PPID  %CPU %MEM   RSS COMM ARGS\n 1000     1   5.5  2.1 1000 qemu-system-aarch64 qemu-system-aarch64 -name linux -drive token=secret\n 1001     1   1.0  1.5 2000 vmware-vmx /Users/me/VMs/dev.vmwarevm/dev.vmx\n 1002     1   2.0  3.0 3000 UTM /Applications/UTM.app/Contents/MacOS/UTM /Users/me/test.utm\n`);

  assert.equal(vms.length, 3);
  assert.equal(vms[0].runtime, "qemu");
  assert.equal(vms[0].name, "linux");
  assert.equal(vms[0].owner_hint.includes("token=[REDACTED]"), true);
  assert.deepEqual(vms[1].resource_snapshot, { pid: 1001, cpu_percent: 1, memory_percent: 1.5, rss_bytes: 2048000 });
  assert.equal(vms[2].runtime, "utm");
});

test("classifyCommandFailure distinguishes missing, daemon, permission, and unknown failures", () => {
  assert.equal(classifyCommandFailure({ status: "unable", code: "ENOENT", error: "spawn tart ENOENT" }), "missing");
  assert.equal(classifyCommandFailure({ status: "unable", error: "failed to connect to the hypervisor" }), "daemon_unavailable");
  assert.equal(classifyCommandFailure({ status: "unable", stderr: "permission denied" }), "permission_limited");
  assert.equal(classifyCommandFailure({ status: "unable", error: "weird failure" }), "unable");
});
