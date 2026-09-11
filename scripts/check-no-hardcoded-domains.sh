#!/usr/bin/env bash
# Fail if product sources contain org lab hostnames or known lab password fingerprints.
# SECURITY.md / this script may mention the fingerprint for documentation / detection.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Domain / host fingerprints + lab password pattern historically present in comments.
PATTERN='mxhash\.com|k8s\.mxhash|gitea\.mxhash|harbor\.mxhash|upload\.mxhash|[Ww]elcomeback'

hits="$(
  grep -rEIn "$PATTERN" "$ROOT" \
    --include='*.yaml' --include='*.yml' --include='*.j2' --include='*.json' --include='*.tf' --include='*.md' --include='*.sh' --include='*.py' \
    --exclude-dir=.git \
    --exclude-dir=workspace \
    --exclude-dir=.ansible \
    --exclude-dir=scripts \
    --exclude-dir=tests \
    --exclude-dir=.github \
    --exclude='SECURITY.md' \
    --exclude='push-gitea.sh' \
    --exclude='push-github.sh' \
    --exclude='git-publish-lib.sh' \
    || true
)"

# Drop comment-only YAML/Jinja noise lines (leading # after optional spaces)
hits="$(printf '%s\n' "$hits" | grep -vE ':[0-9]+:[[:space:]]*#' || true)"

if [[ -n "${hits}" ]]; then
  echo "$hits" >&2
  echo "ERROR: org fingerprint found in atlas-k8s-addons product sources" >&2
  exit 1
fi

echo "OK: no org hostname hardcodes in atlas-k8s-addons product sources"
