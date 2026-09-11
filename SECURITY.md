# Security

## Reporting

If you discover a security issue in this repository, please open a private report with the maintainers (do not file a public issue with exploit details or credentials).

## Secrets in this repo

Do **not** commit:

- real registry / Helm / OIDC / database credentials
- cluster kubeconfigs with client keys
- SSH private keys
- deprecated monolithic `secrets.yml` / `*.vault` with live values
- live inventory with production hosts (`inventory.yml`, local `hosts`)

Prefer `group_vars/all/atlas-k8s-addons.secrets.yml` with Ansible Vault (trackable; do **not** gitignore). Standalone operators may also use `EXTRA_VARS_FILE` / `examples/secrets.example.yml` **outside** the tree. A monolithic `secrets.yml` is deprecated and must not hold live credentials in git.


## Git history note (pre-publish)

The initial import tree (`7539672` / “fix”) included **lab credential strings** in commented Keycloak task examples (`Welcomeback1*` password pattern) and org hostnames (`*.mxhash.com`, `gitea.mxhash.com` remote / README links). Working-tree product sources are scrubbed; those blobs remain reachable in git history until rewritten.

Product sources (`roles/`, `playbooks/`, `group_vars/`, examples, inventory example, runner) must stay free of org hostnames, lab credentials, and non-English operator-facing copy (comments / generated report text). Lab overlays belong in the orchestrator inventory, not in this repository’s defaults.

Guardrails: `scripts/check-no-hardcoded-domains.sh` and `tests/test_k8s_addons_layout.py` (fingerprint + Cyrillic scans).

Before making this repository public:

1. **Rotate / revoke** any lab passwords or tokens that match historical comment examples (and any reused credentials).
2. Rewrite history (`git filter-repo` / BFG) to purge sensitive blobs, or publish from a fresh orphan branch that contains only the cleaned tree.
3. Assume commented lab passwords are compromised for as long as those commits remain reachable on any remote.
