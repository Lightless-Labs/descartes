---
title: "macOS codesign/notarize fails in ephemeral CI: missing Developer ID intermediate + a diagnostic that lied for weeks"
date: 2026-07-07
category: build-errors
module: macos-notifier-release
problem_type: build_error
component: tooling
symptoms:
  - "codesign fails with errSecInternalComponent and \"Warning: unable to build chain to self-signed root\""
  - "security find-identity -v -p codesigning reports \"0 valid identities found\" even though the p12 imports cleanly with a paired private key"
  - "The same identity validates and signs on a provisioned developer Mac but never inside the ephemeral CI VM"
  - "CI logs print \"Intermediate already present\" as a false positive because security find-certificate -a exits 0 on zero matches"
root_cause: incomplete_setup
resolution_type: environment_setup
severity: high
related_components:
  - development_workflow
  - tooling
tags:
  - macos
  - codesign
  - notarization
  - developer-id
  - keychain
  - buildkite
  - tart
  - ci
---

# macOS codesign/notarize fails in ephemeral CI: missing Developer ID intermediate + a diagnostic that lied for weeks

## Problem

A tag-triggered release job that Developer ID signs and notarizes a macOS `.app` inside a
fresh, ephemeral macOS VM (cirruslabs `macos-sequoia-base` under Tart) failed at `codesign`
for weeks. The identity was present and paired, yet the OS reported it as invalid and refused
to build a signing chain. The same certificate signed fine on a provisioned developer Mac,
which sent the investigation down several dead ends.

Concretely: the Descartes `release-macos-notifier` Buildkite job could not sign
`DescartesNotifier.app`, so no notarized release artifact could be produced.

## Symptoms

- `codesign` exits with `errSecInternalComponent` and prints
  `Warning: unable to build chain to self-signed root for signer ...`.
- `security find-identity -v -p codesigning` reports `0 valid identities found`, while
  `security find-identity -p codesigning "$KEYCHAIN"` (without `-v`) *does* list the
  `Developer ID Application: ...` identity. The p12 imports cleanly and the private key is
  paired.
- The exact same p12 and identity validate (`1 valid identities found`) and sign on a
  developer's provisioned Mac, but never in the ephemeral CI VM or a clean disposable keychain.
- CI logs cheerfully print `Intermediate already present in ephemeral keychain` — a **false
  positive**. Nothing had been imported.

## What Didn't Work

Each of these consumed real time and was wrong. They are listed so the next person can skip them.

- **Blaming the p12 / password / clock.** The p12 imported cleanly with a paired private key,
  the identity was detected by name, and clock skew was ruled out. `codesign` still failed.
  The failure is chain-building, not key material.
- **`openssl pkcs12` to extract the cert/issuer.** `openssl pkcs12 -passin file:...` could not
  read the p12 inside the guest even though `security import` with the same password succeeded.
  Fix was to stop using `openssl pkcs12` and instead export from the keychain with
  `security find-certificate -a -p` and parse the PEM — but this was a side-quest, not the root
  cause.
- **Installing/trusting "Apple Root CA - G2" (three separate commits: `52880f2`, `d9d0e8a`,
  `6d91156`).** A red herring. Modern Developer ID leaves chain leaf → **Developer ID
  Certification Authority (OU=G2)** → the *classic* **Apple Root CA** (NOT "Apple Root CA - G2").
  The classic root already ships and is trusted on every genuine macOS image. Worse,
  `add-trusted-cert` into `/System/Library/Keychains/SystemRootCertificates.keychain` can never
  succeed — that store is on the SIP-protected read-only system volume.
- **Importing the G2 intermediate into a search-listed *ephemeral* keychain (build #63).** This
  put the correct, verified intermediate right next to the leaf in a keychain on the user search
  list — and `codesign` *still* failed with the same "unable to build chain" error. A
  session-modified custom keychain search list is not reliably consulted by `trustd`, which is
  what `codesign` resolves its chain through.
- **A documented "hard stop" from local disposable-keychain experiments.** Local tests
  "proved" that adding G1/G2 intermediates and roots to a disposable keychain didn't help, so
  the hypothesis was abandoned. Those experiments were **poisoned by the diagnostic masking bug
  below**: the presence checks reported success when nothing was there, so the experiment never
  tested what it claimed to test. This conclusion was later retracted.

## Solution

Two independent things were both required, plus fixing the diagnostic that had been lying.

### 1. Fresh CI images do not carry the Developer ID intermediate — download and import it

macOS system stores ship only roots plus the legacy **G1** Developer ID CA. The **G2**
intermediate that issues modern leaves is installed by Xcode/developer tooling on provisioned
machines — which is exactly why signing works locally and never in CI. The release p12 contains
only the leaf. So the job must fetch the intermediate from Apple PKI, verify its subject against
the leaf's issuer, and import it:

```bash
# Pick the generation from the leaf's actual issuer (OU=G2 for leaves issued since ~2021).
if [[ "$issuer" == *"OU=G2"* ]]; then
  intermediate_url="https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer"
else
  intermediate_url="https://www.apple.com/certificateauthority/DeveloperIDCA.cer"   # G1
fi
curl -fsSL --max-time 30 "$intermediate_url" -o "$intermediate_der"
# Verify subject matches the leaf issuer before trusting the download, then:
security import "$intermediate_der" -k "$KEYCHAIN_PATH" -T /usr/bin/codesign
```

### 2. The intermediate must live in the SYSTEM keychain, not just a search-listed one

Step 1 alone is insufficient (proven by build #63). `codesign` builds its chain through
`trustd`, which does not reliably consult a session-modified custom keychain search list on a
fresh image. Provisioned Macs and GitHub-hosted runners both carry the Apple intermediates
**system-wide**. Mirror that — install the plain certificate into the system keychain with **no
trust-settings changes** (it chains to an already-trusted root, so it needs no trust of its own):

```bash
# NOTE: add-certificates (plural, certificate only), NOT add-trusted-cert.
sudo -n security add-certificates -k /Library/Keychains/System.keychain "$intermediate_der"
```

After this, `security find-identity -v -p codesigning` reported the identity valid for the first
time ever, `codesign` succeeded, `notarytool` returned **Accepted**, `stapler` stapled the
ticket, and `spctl --assess` reported `source=Notarized Developer ID`.

### 3. Fix the presence check that masked everything for weeks

`security find-certificate -a -c <name> -p <keychain>` **exits 0 even when nothing matches**
(without `-a` it exits `44`). Every `-a`-based presence check therefore reported success
unconditionally — including for a certificate name that did not exist — so "already present"
log lines were false positives and local experiments silently tested nothing. Replace exit-code
checks with **output parsing** of the actual certificate subject (matching both CN and OU so G1
and G2 are distinguished):

```bash
keychain_contains_certificate_subject() {  # returns 0/1 by INSPECTING output, never exit code
  security find-certificate -a -p "$keychain" > "$cert_bundle" 2>/dev/null && [[ -s "$cert_bundle" ]] || return 1
  # parse each PEM cert; succeed only if a subject contains BOTH the CN and OU fragments
  python3 parse_and_match.py "$cert_bundle" "CN=Developer ID Certification Authority" "OU=G2"
}
```

The final working implementation is `scripts/release-macos-notifier-buildkite.sh`
(`extract_leaf_cert_issuer`, `keychain_contains_certificate_subject`,
`import_developer_id_intermediate`). Key commits: `35ea623` (download G2 intermediate +
output-parsed presence checks + delete the root-CA trust code), `11efb13` (install intermediate
into the System keychain + real chain diagnostics).

**Resolution proof:** Buildkite build #67 (tag `v0.0.47` at commit `f9cac87`) passed end-to-end:
`codesign` valid → `notarytool` **Accepted** → stapled → `spctl` "Notarized Developer ID" →
`DescartesNotifier.app.zip` + `.sha256` published as artifacts.

## Why This Works

A Developer ID Application signature needs a complete chain: **leaf → Developer ID
Certification Authority (G2) → Apple Root CA**. On a fresh CI image only the endpoints exist —
the leaf (from the p12) and the classic Apple Root CA (shipped with macOS). The **middle link is
absent**, so the chain cannot be built and the identity is deemed invalid.

Two facts explain the whole saga:

1. **`codesign`/`find-identity -v` only read the keychain search list; they do not fetch missing
   issuers over the network.** This is the opposite of `security verify-cert` (plain form), which
   *does* perform AIA network fetches — which is why `verify-cert` could "pass" while `codesign`
   failed. That discrepancy pointed straight at a missing *local* intermediate but was misread
   for weeks.
2. **`trustd` resolves the chain from system-wide trust state, not a session's custom search
   list.** A search-listed ephemeral keychain is not enough; the intermediate has to be where the
   system trust machinery actually looks — `/Library/Keychains/System.keychain`. Because the
   intermediate chains to an already-trusted root, it is added as a plain certificate with no
   trust-settings changes (which also sidesteps the SIP-protected root store entirely).

The reason this was so hard to diagnose is the third fact: the presence check built on
`find-certificate -a`'s exit code always said "present," so both CI logs and local repros
reported a state that was never true. **The diagnostic instrument was broken, so it confirmed
whatever hypothesis was being tested.** Every conclusion drawn through it — including a
documented hard stop — was unreliable until the check was rewritten to parse output.

## Prevention

- **Test the failure path of your own diagnostics.** Before trusting a presence/health check,
  assert it returns *false* for something known-absent. This one bug (`find-certificate -a` exits
  0 on no match) invalidated weeks of reasoning. A single "absent → not detected" assertion would
  have caught it on day one.
  ```bash
  # In the ephemeral keychain, a nonexistent cert MUST report absent:
  keychain_contains_certificate_subject "CN=Does Not Exist" "OU=Nope" && echo "BUG: check lies"
  ```
- **Use `security verify-cert -L` (local-only) as the honest chain check in CI.** Plain
  `verify-cert` fetches missing issuers over the network (AIA) and can pass where `codesign`
  fails; `-L` restricts to local certificates and matches what `codesign` actually sees.
- **Provision CA intermediates the way Xcode/GitHub runners do: system-wide, certificate-only.**
  If signing works on a developer Mac but not in clean CI, suspect a missing intermediate in the
  *system* trust store before suspecting key material, clocks, or secret transport. Install with
  `security add-certificates -k /Library/Keychains/System.keychain` — never `add-trusted-cert`,
  and never target `SystemRootCertificates.keychain` (SIP read-only).
- **Know the chain shape.** Modern Developer ID leaf → `Developer ID Certification Authority`
  `OU=G2` → classic `Apple Root CA`. Intermediates: G2 =
  `https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer`, G1 = `.../DeveloperIDCA.cer`.
  Match on CN **and** OU so G1 and G2 are not confused. Full Xcode is not required to notarize —
  `notarytool`/`stapler` ship with the Command Line Tools.
- **Lock the frontmatter checks into a test.** `tools/descartes-cli/test/package-metadata.test.js`
  asserts the intermediate import happens and that `add-trusted-cert` is absent from the script,
  so a regression to the red-herring approach fails CI.

### Secondary infra bugs found en route (each independently release-blocking)

- **Shared-directory automount race.** tart-ci's macOS command hook ran
  `cd "/Volumes/My Shared Files/checkout"` immediately after the first successful SSH, racing the
  guest's asynchronous mount of the directory share. Fixed in
  `github.com/Lightless-Labs/tart-ci#v0.2.4` (`11fc336`): poll `test -d <workdir>` over SSH before
  running the command.
- **Concurrent-VM cap.** macOS hosts allow at most 2 concurrent macOS guests; an overlapping main
  build + tag build tried to boot 3 VMs. Fixed by sharing one Buildkite concurrency group
  (`big-cabbage/tart-ci`, limit 2) across CI and release jobs.
- **In-guest artifact upload with no agent token.** `buildkite-agent artifact upload` in the guest
  failed with "Missing agent-access-token". Fixed by gating on `BUILDKITE_AGENT_ACCESS_TOKEN` and
  relying on the pipeline's rsync-back + host `artifact_paths` (`f9cac87`).
- **`:latest` image pin caused surprise multi-GB re-pulls** (~1h image-lock waits) whenever
  upstream moved the tag. Fixed by pinning the image digest (`452edb0`).

## Related Issues

- `scripts/release-macos-notifier-buildkite.sh` — the final working implementation.
- `docs/HANDOFF.md` — the six 2026-07-07 "Current session update" entries narrate the full arc;
  older entries preserve the failed theories.
- `docs/plans/2026-05-30-native-macos-notifications.md` — 2026-07-07 addenda, including the
  retraction of the "hard stop" and the local-notifications platform-requirements note.
- `todos/2026-07-07-rcodesign-investigation.md` — follow-up to remove this failure class entirely
  via keychain-free signing (`rcodesign`).
- Related memory: `macos-codesign-ci-gotchas`, `descartes-macos-notarization-status`.
