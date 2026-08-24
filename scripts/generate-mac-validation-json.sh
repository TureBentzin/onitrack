#!/usr/bin/env bash
set -euo pipefail

readonly REPO="beeper/mac-registration-provider"
readonly VERSION="${MAC_REGISTRATION_PROVIDER_VERSION:-v0.3.0}"
readonly WORK_DIR="${MAC_REGISTRATION_PROVIDER_DIR:-$HOME/Downloads/onitrack-mac-registration-provider}"
readonly OUTPUT="${1:-$PWD/validation.json}"

usage() {
  cat <<'EOF'
Usage:
  generate-mac-validation-json.sh [output-json-path]

Runs on plain macOS, outside Nix. It downloads Beeper's
mac-registration-provider if needed, then generates short-lived validation JSON
for Onitrack IDS registration.

Environment:
  MAC_REGISTRATION_PROVIDER_VERSION  release tag to use, default v0.3.0
  MAC_REGISTRATION_PROVIDER_DIR      download/cache dir, default ~/Downloads/onitrack-mac-registration-provider
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: this script must run on macOS" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl is required" >&2
  exit 1
fi

mkdir -p "$WORK_DIR"
chmod 700 "$WORK_DIR"

provider="$WORK_DIR/mac-registration-provider"
if [[ ! -x "$provider" ]]; then
  arch="$(uname -m)"
  case "$arch" in
    arm64) asset="mac-registration-provider-arm64" ;;
    x86_64) asset="mac-registration-provider-amd64" ;;
    *)
      echo "error: unsupported Mac architecture: $arch" >&2
      exit 1
      ;;
  esac

  url="https://github.com/${REPO}/releases/download/${VERSION}/${asset}"
  echo "downloading $url" >&2
  curl --fail --location --output "$provider" "$url"
  chmod 700 "$provider"
fi

tmp_output="${OUTPUT}.tmp.$$"
cleanup() {
  rm -f "$tmp_output"
}
trap cleanup EXIT

umask 077
"$provider" -once -json > "$tmp_output"

python3 - "$tmp_output" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
required = ["validation_data", "valid_until", "device_info"]
missing = [key for key in required if key not in data]
if missing:
    raise SystemExit(f"missing keys: {', '.join(missing)}")
device = data["device_info"]
device_required = ["hardware_version", "software_version", "software_build_id"]
device_missing = [key for key in device_required if key not in device]
if device_missing:
    raise SystemExit(f"missing device_info keys: {', '.join(device_missing)}")
PY

mv "$tmp_output" "$OUTPUT"
chmod 600 "$OUTPUT"
echo "wrote $OUTPUT" >&2
echo "use it soon: validation JSON is short-lived" >&2
