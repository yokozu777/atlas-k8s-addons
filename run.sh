#!/usr/bin/env bash
# Standalone runner for atlas-k8s-addons.
#
# Prerequisites: live Kubernetes API (sibling atlas-k8s-core or equivalent),
# SSH to the first host in `k8s_master_hosts` if controller_kubeconfig is absent.
#
# Usage:
#   cp inventory-example.yml inventory.yml   # edit hosts
#   # edit group_vars/all/atlas-k8s-addons.yml (replace CHANGEME / LB IPs / DNS / CA URL)
#   # optional: cp examples/secrets.example.yml ~/k8s-addons-secrets.yml && edit
#   ansible-galaxy collection install -r requirements.yml
#   ./run.sh                                 # full addons stack
#   ./run.sh --tags 130_validate_vars
#   ./run.sh --tags 120_controller_tooling
#   ./run.sh --tags 140_fetch_kubeconfig
#   ./run.sh --tags 210_helm_bootstrap,220_calico
#   ./run.sh --check -v
#
# Env overrides:
#   INVENTORY                     inventory path (default: ./inventory.yml or inventory-example.yml)
#   PLAYBOOK                      playbook path (default: playbooks/cluster_addons.yaml)
#   EXTRA_VARS_FILE               optional ansible -e @file (e.g. vaulted secrets)
#   SSH_KEY / ANSIBLE_PRIVATE_KEY_FILE
#   CLUSTER_WORKSPACE_ID          workspace dir name under ./workspace
#   CLUSTER_WORKSPACE_ROOT        full workspace path (overrides ID-based default)
#   ANSIBLE_CONFIG                default: ./ansible.cfg
#
# Vars: group_vars/all/atlas-k8s-addons.yml + optional host_vars/<host>.yml
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

export ANSIBLE_CONFIG="${ANSIBLE_CONFIG:-${ROOT}/ansible.cfg}"
export GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-ssh -o StrictHostKeyChecking=no}"

if [[ -n "${SSH_KEY:-}" ]]; then
  export ANSIBLE_PRIVATE_KEY_FILE="${ANSIBLE_PRIVATE_KEY_FILE:-${SSH_KEY}}"
elif [[ -z "${ANSIBLE_PRIVATE_KEY_FILE:-}" ]]; then
  for candidate in "${HOME}/.ssh/id_ed25519" "${HOME}/.ssh/id_rsa"; do
    if [[ -f "${candidate}" ]]; then
      export ANSIBLE_PRIVATE_KEY_FILE="${candidate}"
      break
    fi
  done
fi

if [[ -n "${INVENTORY:-}" ]]; then
  :
elif [[ -f "${ROOT}/inventory.yml" ]]; then
  INVENTORY="${ROOT}/inventory.yml"
else
  INVENTORY="${ROOT}/inventory-example.yml"
fi

PLAYBOOK="${PLAYBOOK:-${ROOT}/playbooks/cluster_addons.yaml}"

CLUSTER_WORKSPACE_ID="${CLUSTER_WORKSPACE_ID:-k8s.example.com}"
export CLUSTER_WORKSPACE_PARENT="${CLUSTER_WORKSPACE_PARENT:-${ROOT}/workspace}"
export CLUSTER_WORKSPACE_ROOT="${CLUSTER_WORKSPACE_ROOT:-${CLUSTER_WORKSPACE_PARENT}/${CLUSTER_WORKSPACE_ID}}"
mkdir -p "${CLUSTER_WORKSPACE_ROOT}"

if [[ ! -f "${INVENTORY}" ]]; then
  echo "error: inventory not found: ${INVENTORY}" >&2
  echo "hint: cp inventory-example.yml inventory.yml && edit hosts" >&2
  exit 1
fi

if [[ ! -f "${PLAYBOOK}" ]]; then
  echo "error: playbook not found: ${PLAYBOOK}" >&2
  exit 1
fi

if ! command -v ansible-playbook >/dev/null 2>&1; then
  echo "error: ansible-playbook not found in PATH" >&2
  exit 1
fi

EXTRA_VARS=()
if [[ -n "${EXTRA_VARS_FILE:-}" ]]; then
  if [[ ! -f "${EXTRA_VARS_FILE}" ]]; then
    echo "error: EXTRA_VARS_FILE not found: ${EXTRA_VARS_FILE}" >&2
    exit 1
  fi
  EXTRA_VARS+=(-e "@${EXTRA_VARS_FILE}")
fi

echo "inventory: ${INVENTORY}"
echo "playbook:  ${PLAYBOOK}"
echo "ssh key:   ${ANSIBLE_PRIVATE_KEY_FILE:-<(none — password/agent auth)>}"
echo "workspace: ${CLUSTER_WORKSPACE_ROOT}"
if [[ -n "${EXTRA_VARS_FILE:-}" ]]; then
  echo "extra:     @${EXTRA_VARS_FILE}"
fi

exec ansible-playbook \
  -i "${INVENTORY}" \
  "${PLAYBOOK}" \
  "${EXTRA_VARS[@]}" \
  "$@"
