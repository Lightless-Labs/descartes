import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  extractPemCertificates,
  normalizeCertificateRequest,
  parseCertificateBundle,
  selectCertificatesForReturn,
  summarizeCertificates,
} from "../src/tools/certificates.js";

test("normalizeCertificateRequest clamps bounded options", () => {
  assert.deepEqual(normalizeCertificateRequest({ warningDays: 0, certificateLimit: 9999 }), {
    warning_days: 1,
    certificate_limit: 500,
  });
  assert.deepEqual(normalizeCertificateRequest({}), {
    warning_days: 30,
    certificate_limit: 80,
  });
});

test("extractPemCertificates returns certificate blocks only", () => {
  const cert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
  const key = "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----";
  assert.deepEqual(extractPemCertificates(`${key}\n${cert}\n${cert}`), [cert, cert]);
});

test("parseCertificateBundle parses PEM certificate validity without private keys", (t) => {
  try {
    execFileSync("openssl", ["version"], { stdio: "ignore" });
  } catch {
    t.skip("openssl is not available for generating a temporary test certificate");
    return;
  }

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "descartes-cert-test-"));
  try {
    const keyPath = path.join(tmp, "key.pem");
    const certPath = path.join(tmp, "cert.pem");
    execFileSync("openssl", [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-subj",
      "/CN=descartes.test",
      "-days",
      "5",
      "-keyout",
      keyPath,
      "-out",
      certPath,
    ], { stdio: "ignore" });

    const parsed = parseCertificateBundle(fs.readFileSync(certPath), {
      source: "fixture",
      sourceKind: "service_certificate",
      sourcePath: certPath,
      warningDays: 30,
      now: new Date(),
    });

    assert.equal(parsed.errors.length, 0);
    assert.equal(parsed.certificates.length, 1);
    assert.equal(parsed.certificates[0].subject, "descartes.test");
    assert.equal(parsed.certificates[0].source_kind, "service_certificate");
    assert.equal(parsed.certificates[0].expiring_soon, true);
    assert.equal(parsed.certificates[0].expired, false);
    assert(parsed.certificates[0].not_after);
    assert(parsed.certificates[0].fingerprint_sha256_prefix);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("summarizeCertificates distinguishes operational expiry from trust-store expiry", () => {
  const sourceResults = [
    {
      id: "trust",
      status: "ok",
      certificates: [{ source_kind: "trust_store", expired: true, expiring_soon: false, not_after: "2026-01-01T00:00:00.000Z" }],
      invalid_count: 1,
    },
    {
      id: "service",
      status: "ok",
      certificates: [{ source_kind: "service_certificate", expired: false, expiring_soon: true, not_after: "2026-02-01T00:00:00.000Z" }],
      invalid_count: 0,
    },
    { id: "missing", status: "missing", certificates: [], invalid_count: 0 },
  ];

  assert.deepEqual(summarizeCertificates(sourceResults, sourceResults.flatMap((source) => source.certificates)), {
    source_count: 3,
    available_source_count: 2,
    missing_source_count: 1,
    unable_source_count: 0,
    certificate_count: 2,
    returned_certificate_count: 2,
    expired_count: 1,
    expiring_soon_count: 1,
    operational_expired_count: 0,
    operational_expiring_soon_count: 1,
    invalid_count: 1,
    earliest_expiry: "2026-01-01T00:00:00.000Z",
  });
});

test("selectCertificatesForReturn prioritizes operational expired and expiring certificates", () => {
  const selected = selectCertificatesForReturn([
    { source: "a", source_path: "a", index: 0, source_kind: "trust_store", expired: true, not_after: "2020-01-01T00:00:00.000Z" },
    { source: "b", source_path: "b", index: 0, source_kind: "service_certificate", expiring_soon: true, not_after: "2026-05-01T00:00:00.000Z" },
    { source: "c", source_path: "c", index: 0, source_kind: "service_certificate", expired: true, not_after: "2025-01-01T00:00:00.000Z" },
  ], 2);

  assert.equal(selected[0].source, "c");
  assert.equal(selected[1].source, "a");
});
