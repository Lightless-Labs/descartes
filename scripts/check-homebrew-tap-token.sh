#!/usr/bin/env bash
set -euo pipefail

TAP_REPO="${HOMEBREW_TAP_REPO:-Lightless-Labs/homebrew-tap}"
FORMULA_PATH="${HOMEBREW_TAP_FORMULA_PATH:-Formula/descartes.rb}"
GITHUB_API_URL="${DESCARTES_GITHUB_API_URL:-https://api.github.com}"
TOKEN_SOURCE=""
TAP_TOKEN=""

usage() {
  cat <<'EOF'
Usage: scripts/check-homebrew-tap-token.sh

Preflight the token used by the macOS notifier release job's Homebrew tap bump.
The check is read-only: it verifies that the effective token can read the tap
formula and that GitHub reports write/push permission on Lightless-Labs/homebrew-tap.
It does not create commits, change the formula, or print token values.

Token selection matches the release job:
  1. HOMEBREW_TAP_GITHUB_TOKEN from the environment, when set.
  2. HOMEBREW_TAP_GITHUB_TOKEN fetched from Doppler, when DOPPLER_TOKEN is present.
  3. GITHUB_TOKEN from the environment.
  4. GITHUB_TOKEN fetched from Doppler, when DOPPLER_TOKEN is present.

Doppler fetches use project lightless-labs-descartes / config prd_notarisation by
default. A dedicated tap token intentionally overrides the broader release token.

Optional environment overrides:
  HOMEBREW_TAP_REPO=owner/repo
  HOMEBREW_TAP_FORMULA_PATH=Formula/descartes.rb
  DOPPLER_PROJECT=lightless-labs-descartes
  DOPPLER_CONFIG=prd_notarisation
  DESCARTES_GITHUB_API_URL=https://api.github.com
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

command -v python3 >/dev/null || { echo "error: python3 is required" >&2; exit 2; }

fetch_optional_doppler_secret() {
  local name="$1"
  if [[ -z "${DOPPLER_TOKEN:-}" || -n "${!name:-}" ]]; then
    return 0
  fi
  local project="${DOPPLER_PROJECT:-lightless-labs-descartes}"
  local config="${DOPPLER_CONFIG:-prd_notarisation}"
  local value
  if ! value="$(DOPPLER_BOOTSTRAP_TOKEN="$DOPPLER_TOKEN" DOPPLER_PROJECT_NAME="$project" DOPPLER_CONFIG_NAME="$config" DOPPLER_SECRET_NAME="$name" python3 <<'PY'
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

name = os.environ.get("DOPPLER_SECRET_NAME", "")
token = os.environ.get("DOPPLER_BOOTSTRAP_TOKEN", "")
project = os.environ.get("DOPPLER_PROJECT_NAME", "")
config = os.environ.get("DOPPLER_CONFIG_NAME", "")
if not name or not token or not project or not config:
    print("missing Doppler fetch environment", file=sys.stderr)
    sys.exit(2)

auth = base64.b64encode(f"{token}:".encode()).decode()
qs = urllib.parse.urlencode({"project": project, "config": config, "name": name})
req = urllib.request.Request(
    f"https://api.doppler.com/v3/configs/config/secret?{qs}",
    headers={
        "Authorization": f"Basic {auth}",
        "Accept": "application/json",
        "User-Agent": "descartes-homebrew-tap-token-check/1",
    },
)
try:
    with urllib.request.urlopen(req, timeout=20) as res:
        payload = json.load(res)
except urllib.error.HTTPError as exc:
    body = exc.read(300).decode(errors="replace")
    print(f"Doppler read failed for {name}: HTTP {exc.code}: {body}", file=sys.stderr)
    sys.exit(2)
except Exception as exc:
    print(f"Doppler read failed for {name}: {exc}", file=sys.stderr)
    sys.exit(2)

value = payload.get("value", {})
if isinstance(value, dict):
    secret_value = value.get("computed") or value.get("raw") or value.get("value")
else:
    secret_value = value
if not isinstance(secret_value, str) or not secret_value:
    print(f"Doppler read returned no value for {name}", file=sys.stderr)
    sys.exit(2)
print(secret_value, end="")
PY
)"; then
    echo "note: optional Doppler secret not available: $name" >&2
    return 0
  fi
  if [[ -n "$value" ]]; then
    printf -v "$name" '%s' "$value"
    export "$name"
  fi
}

select_token() {
  if [[ -n "${HOMEBREW_TAP_GITHUB_TOKEN:-}" ]]; then
    TAP_TOKEN="$HOMEBREW_TAP_GITHUB_TOKEN"
    TOKEN_SOURCE="HOMEBREW_TAP_GITHUB_TOKEN"
    return 0
  fi

  # Match the release job: even when GITHUB_TOKEN is already present, an optional
  # Doppler-provided HOMEBREW_TAP_GITHUB_TOKEN overrides it with a narrower tap token.
  fetch_optional_doppler_secret HOMEBREW_TAP_GITHUB_TOKEN
  if [[ -n "${HOMEBREW_TAP_GITHUB_TOKEN:-}" ]]; then
    TAP_TOKEN="$HOMEBREW_TAP_GITHUB_TOKEN"
    TOKEN_SOURCE="HOMEBREW_TAP_GITHUB_TOKEN from Doppler"
    return 0
  fi

  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    TAP_TOKEN="$GITHUB_TOKEN"
    TOKEN_SOURCE="GITHUB_TOKEN"
    return 0
  fi

  fetch_optional_doppler_secret GITHUB_TOKEN
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    TAP_TOKEN="$GITHUB_TOKEN"
    TOKEN_SOURCE="GITHUB_TOKEN from Doppler"
    return 0
  fi

  echo "error: no Homebrew tap token available; set HOMEBREW_TAP_GITHUB_TOKEN, GITHUB_TOKEN, or DOPPLER_TOKEN" >&2
  exit 2
}

select_token

TAP_TOKEN="$TAP_TOKEN" TOKEN_SOURCE="$TOKEN_SOURCE" TAP_REPO="$TAP_REPO" FORMULA_PATH="$FORMULA_PATH" GITHUB_API_URL="$GITHUB_API_URL" python3 <<'PY'
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
repo = os.environ["TAP_REPO"]
formula_path = os.environ["FORMULA_PATH"]
token = os.environ["TAP_TOKEN"]
source = os.environ["TOKEN_SOURCE"]


def fail(message, code=1):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(code)


def get_json(path):
    url = f"{api}{path}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "descartes-homebrew-tap-token-check/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            return json.loads(res.read())
    except urllib.error.HTTPError as exc:
        body = exc.read(300).decode(errors="replace")
        fail(f"GitHub API request failed for {path}: HTTP {exc.code}: {body}")
    except Exception as exc:
        fail(f"GitHub API request failed for {path}: {exc}")


repo_payload = get_json(f"/repos/{repo}")
permissions = repo_payload.get("permissions")
if not isinstance(permissions, dict):
    fail(
        f"GitHub did not return a permissions object for {repo}; cannot prove tap write access"
    )
if not (permissions.get("push") is True or permissions.get("admin") is True or permissions.get("maintain") is True):
    fail(
        f"{source} can access {repo} but does not report push/write permission; "
        "set HOMEBREW_TAP_GITHUB_TOKEN or widen GITHUB_TOKEN before the next release tag"
    )

encoded_path = urllib.parse.quote(formula_path, safe="/")
contents = get_json(f"/repos/{repo}/contents/{encoded_path}")
if contents.get("type") not in (None, "file") or not contents.get("sha"):
    fail(f"{formula_path} was readable but did not look like a file response")

print(
    f"Homebrew tap token check OK: {source} can read {repo}/{formula_path} "
    f"and reports push/write permission on {repo}."
)
PY
