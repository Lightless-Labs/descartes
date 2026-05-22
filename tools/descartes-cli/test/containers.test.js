import assert from "node:assert/strict";
import test from "node:test";
import {
  classifyCommandFailure,
  correlateContainerHostProcessHints,
  normalizeContainerRequest,
  parseByteQuantity,
  parseColimaListJson,
  parseColimaStatusJson,
  parseDockerPsJsonLines,
  parseDockerStatsJsonLines,
  parseLimaListJson,
  parseMemoryUsagePair,
  parsePercent,
  parsePodmanMachineListJson,
  parsePodmanPsJson,
  parsePodmanStatsJson,
} from "../src/tools/containers.js";

test("normalizeContainerRequest clamps limits and preserves booleans", () => {
  assert.deepEqual(normalizeContainerRequest({ containerLimit: 999, hostLimit: 0, includeStopped: false, collectStats: false }), {
    container_limit: 200,
    host_limit: 1,
    include_stopped: false,
    collect_stats: false,
  });
});

test("parsePercent and parseByteQuantity handle runtime units", () => {
  assert.equal(parsePercent("12.34%"), 12.34);
  assert.equal(parsePercent("n/a"), undefined);
  assert.equal(parseByteQuantity("1.5GiB"), 1610612736);
  assert.equal(parseByteQuantity("10 MB"), 10000000);
  assert.deepEqual(parseMemoryUsagePair("23.5MiB / 1.944GiB"), {
    memory_usage_bytes: 24641536,
    memory_limit_bytes: 2087354106,
  });
});

test("parseDockerPsJsonLines normalizes and bounds Docker containers", () => {
  const stdout = [
    JSON.stringify({ ID: "abc123", Image: "postgres:16", Command: "postgres -c password=secret", Names: "db", State: "running", Status: "Up 2 minutes", Ports: "127.0.0.1:5432->5432/tcp", Networks: "bridge,app", Mounts: "pgdata,config", CreatedAt: "2026-05-20 10:00:00" }),
    JSON.stringify({ ID: "def456", Image: "redis:7", Command: "redis-server", Names: "cache", State: "exited", Status: "Exited (0)" }),
  ].join("\n");

  assert.deepEqual(parseDockerPsJsonLines(stdout, { limit: 1 }), [{
    runtime: "docker",
    id: "abc123",
    name: "db",
    image: "postgres:16",
    command: "postgres -c password=secret",
    state: "running",
    status: "Up 2 minutes",
    ports: "127.0.0.1:5432->5432/tcp",
    networks: ["bridge", "app"],
    mounts: ["pgdata", "config"],
    created_at: "2026-05-20 10:00:00",
    source_runtime: "docker",
    confidence: 1,
  }]);
  assert.equal(parseDockerPsJsonLines(stdout, { includeStopped: false }).length, 1);
});

test("parseDockerStatsJsonLines indexes Docker stats by id and name", () => {
  const stats = parseDockerStatsJsonLines(JSON.stringify({ ID: "abc123", Container: "abc123", Name: "db", CPUPerc: "7.5%", MemUsage: "23.5MiB / 1.944GiB", MemPerc: "1.18%", NetIO: "1kB / 2kB", BlockIO: "0B / 0B", PIDs: "12" }));

  assert.deepEqual(stats.get("db"), {
    cpu_percent: 7.5,
    memory_percent: 1.18,
    memory_usage_bytes: 24641536,
    memory_limit_bytes: 2087354106,
    net_io: "1kB / 2kB",
    block_io: "0B / 0B",
    pids: 12,
  });
});

test("parsePodmanPsJson normalizes Podman container arrays", () => {
  const stdout = JSON.stringify([
    { Id: "aaa", Image: "localhost/app:latest", Command: ["/app", "--serve"], Names: ["app"], State: "running", Status: "Up", Networks: ["podman"], CreatedAt: "now" },
    { Id: "bbb", Image: "busybox", Command: ["true"], Names: ["done"], State: "exited", Status: "Exited" },
  ]);

  assert.deepEqual(parsePodmanPsJson(stdout, { includeStopped: false }), [{
    runtime: "podman",
    id: "aaa",
    name: "app",
    image: "localhost/app:latest",
    command: "/app --serve",
    state: "running",
    status: "Up",
    ports: undefined,
    networks: ["podman"],
    created_at: "now",
    source_runtime: "podman",
    confidence: 1,
  }]);
});

test("parsePodmanStatsJson parses flexible stats field names", () => {
  const stats = parsePodmanStatsJson(JSON.stringify([{ ID: "aaa", Name: "app", CPU: "3.1%", MemPerc: "4.2%", MemUsage: "12MiB", NetIO: "3kB / 4kB", PIDS: "5" }]));

  assert.deepEqual(stats.get("app"), {
    cpu_percent: 3.1,
    memory_percent: 4.2,
    memory_usage_bytes: 12582912,
    net_io: "3kB / 4kB",
    block_io: undefined,
    pids: 5,
  });
});

test("parseColimaStatusJson and parseColimaListJson normalize container host context", () => {
  assert.deepEqual(parseColimaStatusJson(JSON.stringify({ name: "default", status: "Running", runtime: "docker", arch: "aarch64", cpus: 4, memory: 8, disk: "60GiB", address: "192.168.5.2" })), {
    runtime: "colima",
    name: "default",
    state: "running",
    container_runtime: "docker",
    arch: "aarch64",
    cpus: 4,
    memory_bytes: 8589934592,
    disk_bytes: 64424509440,
    address: "192.168.5.2",
    source_runtime: "colima",
    vm_correlation: { runtime: "colima", name: "default", confidence: 1 },
    confidence: 1,
  });

  assert.equal(parseColimaListJson(JSON.stringify([{ name: "default", status: "Stopped", runtime: "containerd" }]))[0].state, "stopped");
});

test("parsePodmanMachineListJson returns container host context with VM correlation", () => {
  assert.deepEqual(parsePodmanMachineListJson(JSON.stringify([{ Name: "podman-machine-default", Running: true, VMType: "applehv", CPUs: 4, Memory: "2GiB", DiskSize: "100GiB", IPAddress: "192.168.127.2" }])), [{
    runtime: "podman_machine",
    name: "podman-machine-default",
    state: "running",
    container_runtime: "podman",
    arch: undefined,
    cpus: 4,
    memory_bytes: 2147483648,
    disk_bytes: 107374182400,
    address: "192.168.127.2",
    source_runtime: "podman_machine",
    vm_correlation: { runtime: "podman_machine", name: "podman-machine-default", confidence: 1 },
    confidence: 1,
  }]);
});

test("correlateContainerHostProcessHints attaches process resource snapshots to matching hosts", () => {
  const correlation = correlateContainerHostProcessHints([
    { runtime: "lima", name: "docker", state: "running", vm_correlation: { runtime: "lima", name: "docker", confidence: 1 } },
    { runtime: "podman_machine", name: "podman-machine-default", state: "running", vm_correlation: { runtime: "podman_machine", name: "podman-machine-default", confidence: 1 } },
    { runtime: "colima", name: "vz-default", state: "running", vm_correlation: { runtime: "colima", name: "vz-default", confidence: 1 } },
  ], [
    { runtime: "qemu", name: "docker", state: "running", owner_hint: "qemu-system-aarch64 /Users/me/.lima/docker/diffdisk", resource_snapshot: { pid: 200, cpu_percent: 10, memory_percent: 5, rss_bytes: 1000 } },
    { runtime: "apple_virtualization", name: "podman-machine-default", state: "running", owner_hint: "VirtualizationService --vm-name podman-machine-default", resource_snapshot: { pid: 201, cpu_percent: 4, memory_percent: 2, rss_bytes: 500 } },
    { runtime: "apple_virtualization", name: "vz-default", state: "running", owner_hint: "com.apple.Virtualization.VirtualMachine /Users/me/.colima/_lima/vz-default/lima.yaml", resource_snapshot: { pid: 203, cpu_percent: 7, memory_percent: 3, rss_bytes: 700 } },
    { runtime: "apple_virtualization", name: "unmatched", state: "running", resource_snapshot: { pid: 202, cpu_percent: 1, memory_percent: 1, rss_bytes: 100 } },
  ]);

  assert.equal(correlation.correlated_host_process_count, 3);
  assert.equal(correlation.uncorrelated_host_process_hint_count, 1);
  assert.deepEqual(correlation.hosts[0].resource_snapshot, { pid: 200, cpu_percent: 10, memory_percent: 5, rss_bytes: 1000 });
  assert.equal(correlation.hosts[0].process_correlation.source, "container_host_process_scan");
  assert.deepEqual(correlation.hosts[1].resource_snapshot, { pid: 201, cpu_percent: 4, memory_percent: 2, rss_bytes: 500 });
  assert.equal(correlation.hosts[1].process_correlation.runtime, "apple_virtualization");
  assert.deepEqual(correlation.hosts[2].resource_snapshot, { pid: 203, cpu_percent: 7, memory_percent: 3, rss_bytes: 700 });
});

test("parseLimaListJson accepts ndjson-style limactl output", () => {
  const hosts = parseLimaListJson(`${JSON.stringify({ name: "docker", status: "Running", arch: "x86_64", containerd: true, cpus: 2, memory: "4GiB", disk: "20GiB", dir: "/Users/me/.lima/docker" })}\n`);

  assert.deepEqual(hosts, [{
    runtime: "lima",
    name: "docker",
    state: "running",
    container_runtime: "containerd",
    arch: "x86_64",
    cpus: 2,
    memory_bytes: 4294967296,
    disk_bytes: 21474836480,
    directory: "/Users/me/.lima/docker",
    source_runtime: "lima",
    vm_correlation: { runtime: "lima", name: "docker", confidence: 1 },
    confidence: 1,
  }]);
});

test("classifyCommandFailure distinguishes missing, daemon, permission, and unknown failures", () => {
  assert.equal(classifyCommandFailure({ status: "unable", code: "ENOENT", error: "spawn docker ENOENT" }), "missing");
  assert.equal(classifyCommandFailure({ status: "unable", error: "Cannot connect to the Docker daemon" }), "daemon_unavailable");
  assert.equal(classifyCommandFailure({ status: "unable", stderr: "permission denied while trying to connect to socket" }), "permission_limited");
  assert.equal(classifyCommandFailure({ status: "unable", error: "weird failure" }), "unable");
});
