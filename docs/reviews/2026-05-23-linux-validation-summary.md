# Linux Validation Summary

**Date received:** 2026-05-23
**Scope:** Linux ARM64 and Linux x86_64 install/package/direct-collector validation
**Validation commit:** `eccea4332ce87ab32bcb0bda95ba8790cd22d0e0`
**Validated package version:** `0.0.30`
**Credentialed triage:** skipped; no dedicated validation credential was available

## Summary

Validation completed on four Linux hosts:

| Target | Distro | Arch | Kernel | Node/npm | Descartes | Tests |
|---|---|---:|---|---|---:|---:|
| ARM64 | Ubuntu 24.04.4 LTS | `aarch64` | `6.17.0-23-generic` | `v22.21.1` / `10.9.4` | `0.0.30` | 121 pass / 0 fail |
| ARM64 | Debian 13 trixie | `aarch64` | `6.12.86+deb13-arm64` | `v22.21.1` / `10.9.4` | `0.0.30` | 121 pass / 0 fail |
| ARM64 | Fedora 42 Cloud | `aarch64` | `6.14.0-63.fc42.aarch64` | `v22.21.1` / `10.9.4` | `0.0.30` | 121 pass / 0 fail |
| x86_64 | Debian 13 trixie, Scaleway | `x86_64` | `6.12.86+deb13-cloud-amd64` | `v22.21.1` / `10.9.4` | `0.0.30` | 121 pass / 0 fail |

Results:

- Public GitHub install succeeded everywhere with a writable npm prefix.
- `descartes --help` and `descartes --version` worked everywhere.
- Installed package included `docs/reference/collectors.md`.
- Isolated-XDG no-auth triage failed cleanly everywhere with missing-credentials messaging and exit status 1.
- `npm test` passed everywhere.
- `npm run pack:dry-run` included runtime collector source files and collector docs, and excluded tests/local artifacts.
- Direct collector smoke suites completed everywhere with no thrown collector and no malformed JSON.

## Direct collector status

| Collector | Ubuntu ARM64 | Debian ARM64 | Fedora ARM64 | Debian x86_64 |
|---|---|---|---|---|
| `collect_all` | ok | ok | ok | ok |
| `system` | ok | ok | ok | ok |
| `processes` | ok | ok | ok | ok |
| `disks` | ok | ok | ok | ok |
| `network` | ok | ok | ok | ok |
| `services` | ok | ok | ok | ok |
| `recent_logs` | ok | ok | ok | ok |
| `containers` | unknown | unknown | ok | unknown |
| `vms` | warning | unknown | ok | unknown |
| `scheduled_jobs` | warning | warning | warning | warning |
| `time_sync` | ok | ok | ok | ok |
| `certificates` | ok | ok | warning | ok |
| `inspect_process_self` | ok | ok | ok | ok |
| `inspect_parent_tree_self` | ok | ok | ok | ok |
| `sample_load_memory_swap` | ok | ok | ok | ok |

Normal graceful degradation observed:

- Missing Docker/Podman/Colima/Lima/libvirt-style runtimes were represented as missing/unknown instead of crashing.
- Fedora ARM64 naturally had Podman available; container/VM collectors returned `ok` with zero containers/VMs.
- Ubuntu ARM64 had LXC present but unavailable; VM collector returned warning rather than failing.
- `systemctl --user` was unavailable in non-login VM sessions and was represented as a scheduled-job unavailable source.
- Missing `crontab`, `chronyc`, and `ntpq` were represented as unavailable or optional where appropriate.
- Certificate warnings reflected expired certificate material found by the collector; no parser failure was reported.

## Counts and summaries

| Target | Services | Containers | VMs | Scheduled jobs | Time sync | Certificates |
|---|---:|---:|---:|---:|---|---:|
| Ubuntu ARM64 | 163 total / 0 failed | 0 | 0 | 32 total, 10 returned | synchronized, NTP enabled | 292 seen, 10 returned |
| Debian ARM64 | 113 total / 0 failed | 0 | 0 | 14 total, 10 returned | synchronized, NTP enabled | 300 seen, 10 returned |
| Fedora ARM64 | 121 total / 0 failed | 0 | 0 | 5 total, 5 returned | synchronized, NTP enabled | 740 seen, 10 returned |
| Debian x86_64 | 121 total / 0 failed | 0 | 0 | 14 total, 10 returned | synchronized, NTP enabled | 300 seen, 10 returned |

## Caveats

1. The run validated public `0.0.30`, not `0.0.31+`. The review-finding fixes in `0.0.31` were not present in this validation run.
2. Credentialed/model-led triage was skipped because no dedicated validation credential was available.
3. x86_64 coverage used one Debian 13 Scaleway VM; broader x86_64 distro coverage remains optional.
4. The Scaleway host was IPv6-only. GitHub/codeload access for npm required an SSH reverse HTTP CONNECT proxy. Future x86 validation on IPv6-only hosts may need IPv4, NAT64, or a proxy.

## Follow-up decision

This run substantially closes the true Linux x86_64 direct-collector/runtime gap for `0.0.30`, and refreshes ARM64 direct-collector coverage across three distros. Because `0.0.31` changed safety behavior and has now been pushed after this report, a short rerun should at minimum verify public GitHub install/version, `npm test`, no-auth behavior, and the sanitized direct collector smoke suite on one Linux x86_64 host. Credentialed model-led validation remains separate and depends on scoped credentials.
