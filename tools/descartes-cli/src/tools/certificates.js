import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";

const execFileAsync = promisify(execFile);
const DEFAULT_WARNING_DAYS = 30;
const DEFAULT_CERTIFICATE_LIMIT = 80;
const MAX_CERTIFICATE_LIMIT = 500;
const MAX_FILES_PER_SOURCE = 250;
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_COMMAND_BUFFER = 8 * 1024 * 1024;
const DAY_MS = 24 * 60 * 60 * 1000;

function clampInteger(value, fallback, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(number)));
}

function truncate(value, max = 2048) {
  if (typeof value !== "string") return value;
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

export function normalizeCertificateRequest(options = {}) {
  return {
    warning_days: clampInteger(options.warningDays ?? options.warning_days, DEFAULT_WARNING_DAYS, 1, 3650),
    certificate_limit: clampInteger(options.certificateLimit ?? options.certificate_limit, DEFAULT_CERTIFICATE_LIMIT, 1, MAX_CERTIFICATE_LIMIT),
  };
}

export function extractPemCertificates(text) {
  return String(text ?? "").match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
}

function summarizeDistinguishedName(value) {
  const text = String(value ?? "").replace(/\n/g, ", ").trim();
  if (!text) return undefined;
  const cn = text.match(/(?:^|,\s*)CN\s*=\s*([^,]+)/i);
  if (cn) return truncate(cn[1].trim(), 160);
  const first = text.split(/,\s*/).find(Boolean);
  return truncate(first || text, 160);
}

function toIsoDate(value) {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toISOString() : undefined;
}

function fingerprintPrefix(value) {
  return String(value ?? "").replace(/:/g, "").slice(0, 16) || undefined;
}

export function certificateRecordFromX509(cert, { source, sourceKind, sourcePath, index = 0, now = new Date(), warningDays = DEFAULT_WARNING_DAYS } = {}) {
  const notBefore = toIsoDate(cert.validFrom);
  const notAfter = toIsoDate(cert.validTo);
  const expiryMs = notAfter ? new Date(notAfter).getTime() : NaN;
  const daysUntilExpiry = Number.isFinite(expiryMs) ? Math.ceil((expiryMs - now.getTime()) / DAY_MS) : undefined;
  const expired = Number.isFinite(daysUntilExpiry) ? daysUntilExpiry < 0 : undefined;
  const expiringSoon = Number.isFinite(daysUntilExpiry) ? daysUntilExpiry >= 0 && daysUntilExpiry <= warningDays : undefined;

  return {
    source,
    source_kind: sourceKind,
    source_path: sourcePath,
    index,
    subject: summarizeDistinguishedName(cert.subject),
    issuer: summarizeDistinguishedName(cert.issuer),
    not_before: notBefore,
    not_after: notAfter,
    days_until_expiry: daysUntilExpiry,
    expired,
    expiring_soon: expiringSoon,
    fingerprint_sha256_prefix: fingerprintPrefix(cert.fingerprint256),
    serial_number_prefix: truncate(String(cert.serialNumber ?? "").replace(/:/g, "").slice(0, 16), 32) || undefined,
  };
}

export function parseCertificateBundle(contents, options = {}) {
  const blocks = extractPemCertificates(contents);
  const inputs = blocks.length > 0 ? blocks : [contents];
  const certificates = [];
  const errors = [];

  for (const [index, input] of inputs.entries()) {
    if (!input || String(input).trim() === "") continue;
    try {
      certificates.push(certificateRecordFromX509(new crypto.X509Certificate(input), { ...options, index }));
    } catch (error) {
      errors.push({ index, error: error instanceof Error ? error.message : String(error) });
    }
  }

  return { certificates, errors };
}

function commonSources() {
  const sources = [
    { id: "etc_ssl_certs", kind: "trust_store", type: "path", path: "/etc/ssl/certs", depth: 1, platforms: ["linux", "darwin"] },
    { id: "etc_ssl_cert_pem", kind: "trust_store", type: "path", path: "/etc/ssl/cert.pem", depth: 0, platforms: ["linux", "darwin"] },
    { id: "usr_local_share_ca_certificates", kind: "trust_store", type: "path", path: "/usr/local/share/ca-certificates", depth: 1, platforms: ["linux"] },
    { id: "pki_tls_certs", kind: "mixed_store", type: "path", path: "/etc/pki/tls/certs", depth: 1, platforms: ["linux"] },
    { id: "letsencrypt_live", kind: "service_certificate", type: "path", path: "/etc/letsencrypt/live", depth: 2, platforms: ["linux", "darwin"] },
    { id: "nginx_ssl", kind: "service_certificate", type: "path", path: "/etc/nginx/ssl", depth: 1, platforms: ["linux"] },
    { id: "apache_ssl", kind: "service_certificate", type: "path", path: "/etc/apache2/ssl", depth: 1, platforms: ["linux"] },
    { id: "httpd_ssl", kind: "service_certificate", type: "path", path: "/etc/httpd/ssl", depth: 1, platforms: ["linux"] },
    { id: "homebrew_openssl_certs", kind: "trust_store", type: "path", path: "/opt/homebrew/etc/openssl@3/certs", depth: 1, platforms: ["darwin"] },
    { id: "homebrew_ca_certificates", kind: "trust_store", type: "path", path: "/opt/homebrew/etc/ca-certificates/cert.pem", depth: 0, platforms: ["darwin"] },
  ];

  if (process.platform === "darwin") {
    sources.push(
      { id: "macos_system_roots", kind: "trust_store", type: "command", command: "security", args: ["find-certificate", "-a", "-p", "/System/Library/Keychains/SystemRootCertificates.keychain"] },
      { id: "macos_system_keychain", kind: "keychain", type: "command", command: "security", args: ["find-certificate", "-a", "-p", "/Library/Keychains/System.keychain"] }
    );
  }

  return sources.filter((source) => !source.platforms || source.platforms.includes(process.platform));
}

function looksLikeCertificateFile(filePath) {
  const base = path.basename(filePath).toLowerCase();
  if (["cert.pem", "fullchain.pem", "chain.pem", "privkey.pem"].includes(base)) return base !== "privkey.pem";
  return /\.(pem|crt|cer|cert|bundle|chain)$/i.test(base);
}

async function listCertificateFiles(rootPath, maxDepth, state = { files: [], skipped: 0, visited: new Set() }) {
  if (state.files.length >= MAX_FILES_PER_SOURCE) return state;
  let stats;
  try {
    stats = await fs.stat(rootPath);
  } catch (error) {
    throw error;
  }

  let realPath;
  try {
    realPath = await fs.realpath(rootPath);
    if (state.visited.has(realPath)) return state;
    state.visited.add(realPath);
  } catch {
    // Keep going with stat/read errors represented by the caller.
  }

  if (stats.isFile()) {
    if (looksLikeCertificateFile(rootPath) || maxDepth === 0) state.files.push({ path: rootPath, size: stats.size });
    return state;
  }

  if (!stats.isDirectory()) return state;
  if (maxDepth < 0) return state;

  const entries = await fs.readdir(rootPath, { withFileTypes: true });
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    if (state.files.length >= MAX_FILES_PER_SOURCE) {
      state.skipped += 1;
      continue;
    }
    const entryPath = path.join(rootPath, entry.name);
    if (entry.isDirectory() || entry.isSymbolicLink()) {
      if (maxDepth > 0) {
        try {
          await listCertificateFiles(entryPath, maxDepth - 1, state);
        } catch {
          state.skipped += 1;
        }
      }
    } else if (entry.isFile() && looksLikeCertificateFile(entryPath)) {
      state.files.push({ path: entryPath, size: undefined });
    }
  }
  return state;
}

async function collectPathSource(source, request) {
  try {
    const listed = await listCertificateFiles(source.path, source.depth);
    const certificates = [];
    const parseErrors = [];
    let oversized_file_count = 0;
    let unreadable_file_count = 0;

    for (const file of listed.files) {
      let stats;
      try {
        stats = await fs.stat(file.path);
        if (!stats.isFile()) continue;
        if (stats.size > MAX_FILE_BYTES) {
          oversized_file_count += 1;
          continue;
        }
        const contents = await fs.readFile(file.path);
        const parsed = parseCertificateBundle(contents, {
          source: source.id,
          sourceKind: source.kind,
          sourcePath: file.path,
          warningDays: request.warning_days,
        });
        certificates.push(...parsed.certificates);
        parseErrors.push(...parsed.errors.map((error) => ({ ...error, path: file.path })));
      } catch (error) {
        unreadable_file_count += 1;
        parseErrors.push({ path: file.path, error: error instanceof Error ? error.message : String(error) });
      }
    }

    return {
      id: source.id,
      kind: source.kind,
      type: "path",
      path: source.path,
      status: "ok",
      file_count: listed.files.length,
      skipped_file_count: listed.skipped,
      oversized_file_count,
      unreadable_file_count,
      certificate_count: certificates.length,
      invalid_count: parseErrors.length,
      certificates,
      errors: parseErrors.slice(0, 10),
    };
  } catch (error) {
    const code = error?.code;
    return {
      id: source.id,
      kind: source.kind,
      type: "path",
      path: source.path,
      status: code === "ENOENT" ? "missing" : "unable",
      error: error instanceof Error ? error.message : String(error),
      code,
      certificate_count: 0,
      invalid_count: 0,
      certificates: [],
    };
  }
}

async function runFixedCommand(command, args) {
  const argv = [command, ...args];
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: 5000,
      maxBuffer: MAX_COMMAND_BUFFER,
    });
    return { status: "ok", stdout, stderr: truncate(stderr), command: { argv, read_only: true } };
  } catch (error) {
    return {
      status: "unable",
      error: error instanceof Error ? error.message : String(error),
      code: error?.code,
      stdout: truncate(error?.stdout ?? "", 4096),
      stderr: truncate(error?.stderr ?? "", 2048),
      command: { argv, read_only: true },
    };
  }
}

async function collectCommandSource(source, request) {
  const command = await runFixedCommand(source.command, source.args);
  const parsed = command.status === "ok"
    ? parseCertificateBundle(command.stdout, {
      source: source.id,
      sourceKind: source.kind,
      sourcePath: source.args.at(-1),
      warningDays: request.warning_days,
    })
    : { certificates: [], errors: [] };

  return {
    id: source.id,
    kind: source.kind,
    type: "command",
    status: command.status,
    command: command.command,
    stderr: command.stderr,
    error: command.error,
    certificate_count: parsed.certificates.length,
    invalid_count: parsed.errors.length,
    certificates: parsed.certificates,
    errors: parsed.errors.slice(0, 10),
  };
}

function operationalCertificate(record) {
  return ["service_certificate", "mixed_store"].includes(record.source_kind);
}

export function summarizeCertificates(sourceResults, returnedCertificates = []) {
  const certificates = sourceResults.flatMap((source) => source.certificates ?? []);
  const expired = certificates.filter((certificate) => certificate.expired);
  const expiringSoon = certificates.filter((certificate) => certificate.expiring_soon);
  const operationalExpired = expired.filter(operationalCertificate);
  const operationalExpiringSoon = expiringSoon.filter(operationalCertificate);
  const sortedByExpiry = certificates
    .filter((certificate) => certificate.not_after)
    .sort((left, right) => new Date(left.not_after).getTime() - new Date(right.not_after).getTime());

  return {
    source_count: sourceResults.length,
    available_source_count: sourceResults.filter((source) => source.status === "ok").length,
    missing_source_count: sourceResults.filter((source) => source.status === "missing").length,
    unable_source_count: sourceResults.filter((source) => source.status === "unable").length,
    certificate_count: certificates.length,
    returned_certificate_count: returnedCertificates.length,
    expired_count: expired.length,
    expiring_soon_count: expiringSoon.length,
    operational_expired_count: operationalExpired.length,
    operational_expiring_soon_count: operationalExpiringSoon.length,
    invalid_count: sourceResults.reduce((sum, source) => sum + (source.invalid_count ?? 0), 0),
    earliest_expiry: sortedByExpiry[0]?.not_after,
  };
}

export function selectCertificatesForReturn(certificates, limit) {
  return [...certificates]
    .sort((left, right) => {
      const leftPriority = (left.expired ? 0 : left.expiring_soon ? 1 : 2) + (operationalCertificate(left) ? -0.5 : 0);
      const rightPriority = (right.expired ? 0 : right.expiring_soon ? 1 : 2) + (operationalCertificate(right) ? -0.5 : 0);
      if (leftPriority !== rightPriority) return leftPriority - rightPriority;
      const leftTime = left.not_after ? new Date(left.not_after).getTime() : Number.POSITIVE_INFINITY;
      const rightTime = right.not_after ? new Date(right.not_after).getTime() : Number.POSITIVE_INFINITY;
      if (leftTime !== rightTime) return leftTime - rightTime;
      return `${left.source}:${left.source_path}:${left.index}`.localeCompare(`${right.source}:${right.source_path}:${right.index}`);
    })
    .slice(0, limit);
}

function envelopeStatus(result) {
  if (result.status === "unsupported") return "unknown";
  if (result.summary?.operational_expired_count > 0 || result.summary?.operational_expiring_soon_count > 0) return "warning";
  if (result.summary?.available_source_count > 0) return "ok";
  if (result.summary?.unable_source_count > 0) return "unable";
  return "unknown";
}

function reviewHint(result) {
  const status = envelopeStatus(result);
  if (status === "warning") return "threshold_crossed";
  if (status === "unable") return "missing_permission";
  if (status === "unknown") return "ambiguous";
  return "none";
}

export async function collectCertificateEvidence(options = {}) {
  const request = normalizeCertificateRequest(options);
  return timedEnvelope(async () => {
    const sourceDefinitions = commonSources();
    const sourceResults = [];
    for (const source of sourceDefinitions) {
      sourceResults.push(source.type === "command"
        ? await collectCommandSource(source, request)
        : await collectPathSource(source, request));
    }

    const allCertificates = sourceResults.flatMap((source) => source.certificates ?? []);
    const returnedCertificates = selectCertificatesForReturn(allCertificates, request.certificate_limit);
    const summary = summarizeCertificates(sourceResults, returnedCertificates);
    for (const source of sourceResults) delete source.certificates;

    return {
      platform: process.platform,
      status: sourceDefinitions.length === 0 ? "unsupported" : "ok",
      request,
      summary,
      sources: sourceResults,
      certificates: returnedCertificates,
      note: "Certificate evidence is read-only and bounded. Certificate subjects, issuers, paths, and fingerprints are sensitive diagnostic artifacts; private keys are intentionally not read.",
    };
  }, (result) => evidenceEnvelope({
    id: "certificates",
    status: envelopeStatus(result),
    source: "certificates",
    result,
    confidence: result?.summary?.available_source_count > 0 ? 0.8 : 0.35,
    reviewHint: reviewHint(result),
    tool: "collect_certificates",
    target: `warning_days=${request.warning_days};certificate_limit=${request.certificate_limit}`,
  }));
}
