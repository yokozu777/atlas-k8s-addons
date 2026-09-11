# atlas-k8s-addons

Ansible playbooks for Kubernetes **platform addons** after control-plane bootstrap:
controller tooling, Helm bootstrap, CNI (Calico), monitoring, ingress, storage (Rook),
service mesh, identity, and related charts.

**Canonical playbook:** `playbooks/cluster_addons.yaml`  
**Runner:** `./run.sh`  
**Vars catalog:** `group_vars/all/atlas-k8s-addons.yml`  
**Secrets overlay:** `group_vars/all/atlas-k8s-addons.secrets.yml` (prefer Ansible Vault)  
**License:** Apache-2.0 (see `LICENSE`)

Control-plane bootstrap (kubeadm, LB, join) lives in sibling **atlas-k8s-core**.  
This repository assumes a reachable API and either a controller kubeconfig or SSH to the first master.

```
  Ansible controller (localhost)
         |
         +-- workspace/<cluster>/controller-state/
         |      kubeconfig · helm · certs · manifests · reports
         |
         +-- helm repo add / upgrade --install   (roles 210–999)
         |
         +-- SSH --> first k8s_master   (140_fetch_kubeconfig if needed)
                        |
                        v
                   live cluster API
```

Role pipeline (high level):

```
  tooling --> validate --> fetch_kubeconfig --> helm_bootstrap --> calico
         |
         v
  monitoring --> rook/CSI --> metallb/ingress/certs --> logging
         |
         v
  istio/tracing --> security --> gitops/id --> vault/consul
         |
         v
  cluster_report --> (optional debug_tooling on nodes)
```

Install **atlas-k8s-core** first (or an equivalent kubeadm cluster). Nodes stay NotReady until Calico (`220_calico`) lands here.  
Orchestrated path: **external orchestrator** phase `k8s-addons`.

## Compatibility

Targeted at:
- Ansible controller with Python 3 (Helm / kubectl / venv installed by `120_controller_tooling`)
- A live Kubernetes API compatible with the chart catalog in `group_vars/all/atlas-k8s-addons.yml`
- Cluster nodes reachable over SSH for kubeconfig fetch and optional `999_debug_tooling`

Inventory contract (default group names):

| Group (default) | Targeting var | Used by |
|-----------------|---------------|---------|
| `k8s_masters` | `k8s_master_hosts` | Validate (≥1), `140_fetch_kubeconfig`, `999_debug_tooling` |
| `k8s_workers` | `k8s_worker_hosts` | `999_debug_tooling` (optional for most Helm roles) |

Optional parent group `k8s` may nest the groups (see `inventory-example.yml`). Prefer the **same hosts** as atlas-k8s-core for a given cluster.

- `k8s_masters` ≥ 1 (required by `130_validate_vars` via `k8s_master_hosts`)
- `k8s_workers` group **must exist** (may be empty for chart-only runs; used by `999_debug_tooling`)

To use different inventory group names (single group each):

```yaml
# group_vars/all/atlas-k8s-addons.yml
k8s_master_hosts: my_k8s_masters
k8s_worker_hosts: my_k8s_workers
```

Keep playbook targeting, validate, and (if used) `provision_hosts_file` children keys aligned with those names.

Every host should set `ansible_host` and a stable **`hostname:`** (prefer FQDN).

`120_controller_tooling` and `140_fetch_kubeconfig` are duplicated from **atlas-k8s-core** for addons-only runs (shared task/template files must stay identical — orchestrator parity tests).

## Quickstart

### Prerequisites

- Ansible 2.14+ recommended
- `ansible-galaxy collection install -r requirements.yml` (`kubernetes.core`)
- Live cluster from **atlas-k8s-core** (or equivalent) with API VIP / endpoint reachable from the controller
- SSH to the first master if `controller_kubeconfig` is absent
- Replace every `CHANGEME` and site IPs in `group_vars/all/atlas-k8s-addons.yml` (prefer Ansible Vault)
- Outbound access to public Helm upstreams when `use_internal_helm_repo: none` (default)
- `dns_server_ip`, MetalLB pool, and ingress LB IPs sized for your LAN
- `pod_subnet` / `vip_address` must match the live cluster (same as core)
- OS bootstrap and kubeadm join are **out of scope** — provide a working control plane first

### Clone

```bash
git clone <atlas-k8s-addons-url>
cd atlas-k8s-addons
ansible-galaxy collection install -r requirements.yml
```

### Inventory

```bash
cp inventory-example.yml inventory.yml
vi inventory.yml
```

Set `ansible_host` and **`hostname:`** on every node (prefer FQDN). Reuse core inventory hosts when possible.

### Variables

**SoT:** `group_vars/all/atlas-k8s-addons.yml` — operator surface that must satisfy `130_validate_vars`  
(identity, workspace, Helm catalog, namespaces, ingress hosts, secret aggregates).  
Deep chart knobs live in `roles/*/defaults/main.yml` when not listed in `group_vars/all/atlas-k8s-addons.yml`.

Minimum settings for a real deploy:

```yaml
dns_domain_suffix: example.com
cluster_domain: k8s.example.com          # must match CLUSTER_WORKSPACE_ID
vip_address: 192.168.1.210               # same API VIP as core
pod_subnet: 172.16.0.0/16                # same as core / Calico
dns_server_ip: 192.168.1.53              # RFC2136 target for external-dns
metallb_ip_pool: "192.168.1.150-192.168.1.199"
ingress_lb_ip: 192.168.1.199
istio_ingress_lb_ip: 192.168.1.198
pki_ca_url: "https://ca.example.com:8443/roots.pem"
use_internal_helm_repo: none             # or nginx|nexus for air-gapped
```

`cluster_workspace_id` must equal `k8s_cluster_domain` (validate contract). Prefer letting `./run.sh` set absolute `CLUSTER_WORKSPACE_*` paths.

Chart toggles: empty `*_chart_version` → Helm without `--version` (latest from the repo);  
`*_chart_state: present|skip|absent` — `present` install/upgrade, `skip` not in BOM (no-op, no uninstall), `absent` intentional teardown. Default is `present`. Lab catalog sets `sentry_chart_state: skip`.

Secrets: `group_vars/all/atlas-k8s-addons.yml` ships inert `CHANGEME` placeholders so validate works out of the box. For real deploys use a vault overlay:

```bash
cp examples/secrets.example.yml ~/k8s-addons-secrets.yml
# edit, optionally: ansible-vault encrypt ~/k8s-addons-secrets.yml
EXTRA_VARS_FILE=~/k8s-addons-secrets.yml ./run.sh
```

### Run

```bash
./run.sh --tags 130_validate_vars   # catalog contract check (localhost)
./run.sh                           # full addons stack (needs live cluster)
```

Recommended staged tags (same order as the playbook):

```bash
./run.sh --tags 120_controller_tooling
./run.sh --tags 140_fetch_kubeconfig
./run.sh --tags 210_helm_bootstrap,220_calico
./run.sh --tags 310_prometheus,320_blackbox,330_prometheus_adapter,340_calico_metrics
./run.sh --tags 410_snapshotter,420_rook_operator,430_rook_cluster,440_rook_csi_drivers,450_thanos
./run.sh --tags 510_metallb,520_envoy_gateway,530_external_dns,540_cert_manager,550_trust_manager,560_apply_ingress
./run.sh --tags 610_elasticsearch_prepare,620_elasticsearch,630_kibana_prepare,640_kibana,650_fluentbit
./run.sh --tags 710_istio,720_external_dns_istio,730_tracing,740_kiali
./run.sh --tags 800_chaos_mesh,810_falco,820_kyverno,830_policy_reporter,840_trivy
./run.sh --tags 910_cloudnative_pg,920_keycloak,930_keycloak_realm,940_apiserver_oidc,941_k8s_oidc,942_pinniped,950_mailu,954_opencost,960_oauth2_proxy,961_apply_oidc_ingress,962_headlamp
# Do not combine --tags 930_keycloak_realm,940_apiserver_oidc,941_k8s_oidc,942_pinniped with --limit k8s_masters:
# that skips localhost 930/941/942. Play 940 still targets masters via hosts.
./run.sh --tags 970_consul,971_vault,972_external_secrets
# Do not combine --tags 971_vault with --limit localhost or --limit k8s_masters:
# that skips helm/unseal or the SSH key plays.
./run.sh --tags 980_argocd,982_argocd_rollouts
./run.sh --tags 990_rook_ceph_dashboard,992_kibana_dashboards,994_sentry,996_cluster_report
```

`210_helm_bootstrap` also imports `140_fetch_kubeconfig` when run alone (`--tags 210_helm_bootstrap`).
`941_k8s_oidc` does the same when OIDC is enabled (`--tags 941_k8s_oidc`).
`942_pinniped` imports kubeconfig as well (`--tags 942_pinniped`): chart, controller CLI, and `{{ controller_kubeconfig }}.pinniped`. The download page at `https://pinniped-login.<cluster>` (Keycloak OIDC via Envoy) is published only after `961_apply_oidc_ingress`. Use the tag set on the line above (includes 961), not `942_pinniped` alone, if you need that URL. Users keep the `pinniped` CLI on their PATH.

Or manually:

```bash
ansible-playbook -i inventory.yml playbooks/cluster_addons.yaml
```

### `./run.sh` environment

| Variable | Default | Meaning |
|----------|---------|---------|
| `INVENTORY` | `inventory.yml` or `inventory-example.yml` | Inventory path |
| `PLAYBOOK` | `playbooks/cluster_addons.yaml` | Playbook path |
| `EXTRA_VARS_FILE` | — | Optional `-e @file` (vaulted secrets) |
| `SSH_KEY` / `ANSIBLE_PRIVATE_KEY_FILE` | `~/.ssh/id_ed25519` or `id_rsa` | SSH private key |
| `CLUSTER_WORKSPACE_ID` | `k8s.example.com` | Workspace dir name (must match `k8s_cluster_domain`) |
| `CLUSTER_WORKSPACE_PARENT` | `./workspace` (absolute via runner) | Parent of workspace |
| `CLUSTER_WORKSPACE_ROOT` | `<parent>/<id>` | Controller workspace (kubeconfig, Helm, reports) |
| `ANSIBLE_CONFIG` | `./ansible.cfg` | Ansible config |

All extra CLI arguments are forwarded to `ansible-playbook`.

## Architecture (role order)

`playbooks/cluster_addons.yaml`:

```
  tooling --> validate --> kubeconfig --> helm --> calico
         |
         v
  310–450 monitoring/storage --> 510–560 ingress/certs --> 610–840 logging/mesh/security
         |
         v
  910–972 platform apps --> 996_report --> 999_debug (optional)
```

1. **110_workspace** (localhost, tag `110_workspace`) — controller workspace directories  
2. **120_controller_tooling** — Helm binary, CA trust, Python venv on the controller  
3. **130_validate_vars** — inventory + Helm/secrets/ingress/namespace/workspace contract  
4. **140_fetch_kubeconfig** — pull `/etc/kubernetes/admin.conf` via SSH if missing  
5. **210_helm_bootstrap** — per-repo `helm repo add --force-update` from `helm_repos` / `helm_repo_upstreams` (short HTTP timeout). A stale index is a warning; missing index on greenfield is fatal. 
6. **220_calico** — CNI (nodes become Ready)  
7. **310–340** — Prometheus stack, blackbox, adapter, Calico metrics  
8. **410–450** — CSI snapshotter, Rook operator / cluster / CSI drivers, then Thanos (`450_thanos`: Receive + Query + Store + Compactor; Prometheus `remote_write`, no sidecar)  
9. **510–560** — MetalLB, Envoy Gateway, external-dns, cert-manager, trust-manager, Gateway API routes  
10. **610–650** — Elasticsearch, Kibana, Fluent Bit  
11. **710–740** — Istio (mesh-wide Telemetry → `otel-tracing`), Istio external-dns, tracing (Jaeger 2 all-in-one → Elasticsearch, OTel in front), Kiali (UI via Envoy OIDC like Grafana; CR stays anonymous)  
12. **800–840** — Chaos Mesh, Falco, Kyverno (engine only; no ClusterPolicy), Policy Reporter UI (Envoy OIDC like Grafana/Kiali), Trivy Operator (`840_trivy`: Helm `aquasecurity/trivy-operator`, scans `kube-system`, Grafana gnet 17813 + 16337 via 310)  
13. **910–972** — CloudNativePG, Keycloak, realm, kube-apiserver OIDC (`940_apiserver_oidc` on masters after Keycloak), kubectl OIDC (`941_k8s_oidc`: Group `k8s-admins` → `cluster-admin`, `{{ controller_kubeconfig }}.oidc`; kubelogin on the client PATH; controller stays on `admin.conf`), Pinniped (`942_pinniped`: Supervisor+Concierge, Keycloak confidential client `pinniped-supervisor`, controller `{{ controller_kubeconfig }}.pinniped` via `pinniped get kubeconfig`; download UI `pinniped-login.<cluster>` behind Envoy OIDC; 940/941 remain break-glass), Mailu (`950_mailu`: Helm `mailu/mailu`, web via Envoy OIDC/`proxyAuth`, SMTP/IMAP on MetalLB `mailu_mx_host`; HTTPRoute after 961), OpenCost (`954_opencost`: Helm `opencost/opencost`, UI via Envoy OIDC like Grafana/Kiali, Grafana gnet 22208 via 310), oauth2-proxy, OIDC HTTPRoute (`961_apply_oidc_ingress` after 960), Headlamp (after 961), Consul (Vault KV, 3 servers), Vault (OIDC via Keycloak group `vault-admins`, userpass `vault_admin` break-glass, unseal keys on masters), External Secrets (`ClusterSecretStore/vault`)  
14. **980 / 982** — Argo CD (OIDC client `argocd`; login gated by realm role `argocd-access` on group `/argocd-admins`; RBAC uses `groups` claim; local admin break-glass), Argo Rollouts (controller + CRDs; dashboard via Envoy OIDC like Grafana/Kiali)  
15. **990–994** — Rook dashboard tweaks, Kibana dashboards, Sentry (default `absent`)  
16. **996_cluster_report** — credentials YAML/MD under `controller_reports_dir`  
17. **999_debug_tooling** — optional break-glass CLI on masters/workers  

Admin kubeconfig on the controller (default):

`$CLUSTER_WORKSPACE_ROOT/controller-state/kubeconfig/admin.conf`

Helm client config / chart index cache: `controller_helm_config_dir` (`HELM_CONFIG_HOME` + `HELM_CACHE_HOME`).

## Identity, networking, and Helm client

| Variable | Default (catalog) | Purpose |
|----------|-------------------|---------|
| `dns_domain_suffix` | `example.com` | Apex DNS / Helm nginx hostname suffix |
| `cluster_domain` / `k8s_cluster_domain` | `k8s.example.com` | Cluster identity + workspace id + `*_host` FQDNs |
| `vip_address` | `192.168.1.210` | API VIP (must match core) |
| `pod_subnet` | `172.16.0.0/16` | Calico / cluster pod CIDR |
| `dns_server_ip` | `192.168.1.53` | RFC2136 target for external-dns |
| `metallb_ip_pool` | `192.168.1.150-192.168.1.199` | L2 address pool |
| `ingress_lb_ip` | `192.168.1.199` | Envoy Gateway LoadBalancer IP |
| `istio_ingress_lb_ip` | `192.168.1.198` | Istio ingress gateway LB IP |
| `use_internal_helm_repo` | `none` | `none` \| `nexus` \| `nginx` |
| `get_snapshotter` | `github` | `github` \| `private-git` \| `internal-nginx` |
| `nexus_host` / `nexus_base_url` | placeholders | Required non-empty even when mode is `none` |

Ingress hostnames (`falco_host`, `grafana_host`, …) default to `<svc>.{{ k8s_cluster_domain }}`.  
`k8s_secrets` / `k8s_users` aggregates feed role templates — keep them in sync with the top-level password vars.

## Controller workspace (00)

Role **110_workspace** creates dirs under `cluster_workspace_root` (kubeconfig, manifests, Helm config/cache, certs, staging, reports, layout stubs). Prefer absolute paths from `./run.sh` so validate path-prefix checks succeed. The role re-resolves `CLUSTER_WORKSPACE_*` from the environment and realigns `controller_*` (and Helm/Keycloak/Kibana aliases) under the active root.

| Variable | Purpose |
|----------|---------|
| `cluster_workspace_id` | Must equal `k8s_cluster_domain` |
| `cluster_workspace_parent` | Parent directory (default `./workspace`) |
| `cluster_workspace_root` | Full workspace root |
| `controller_kubeconfig` | Admin kubeconfig path |
| `controller_helm_config_dir` | Helm config + cache parent |
| `keycloak_tf_workspace` | Staging dir for Keycloak realm Terraform |
| `provision_hosts_file` | Provision inventory for Rook OSDs (`430_rook_cluster`) |

Rook storage nodes: copy `examples/provision_hosts.example.yml`, set real WWNs, and point `provision_hosts_file` at it (children group name must match `k8s_worker_hosts`).

## Helm bootstrap and CNI (30–31)

| Stage | Tag | Notes |
|-------|-----|-------|
| Helm repos | `210_helm_bootstrap` | Adds every entry in `helm_repos` (paths must match `helm_repo_upstreams`) with `helm repo add --force-update` (retries, short `HELM_REQUEST_TIMEOUT`). A stale `HELM_REPOSITORY_CACHE` index is a warning, not a playbook failure; missing index on greenfield is fatal. Envoy Gateway (`520_envoy_gateway`) is OCI (`envoy_gateway_chart_oci`, default `oci://docker.io/envoyproxy/gateway-helm`) and is not listed there. helm-nginx cannot proxy OCI; air-gapped sites set `envoy_gateway_chart_oci` to their own registry. Controller trust is `120_controller_tooling`. |
| Calico | `220_calico` | CNI; align `calico_chart_version` / dataplane knobs with defaults |

With `use_internal_helm_repo: nginx` or `nexus`, set a reachable `pki_ca_url` so `120_controller_tooling` installs trust before `helm repo add`.

## Platform stages (32–97)

Roles are mostly **localhost Helm/kubectl** against `controller_kubeconfig`. Prometheus Operator CRDs (`310_prometheus`) run before Rook ServiceMonitors. Grafana folder **Cluster addons** is provisioned from Helm `grafana.dashboards` (gated on `*_chart_state`): Envoy Gateway instead of nginx ingress, Ceph mixin (not gnet 2842), CNPG, Elasticsearch, Blackbox, Thanos, Consul, Falco, Keycloak 26 Micrometer, External DNS, Argo CD. Calico Typha JSON is extracted from the official projectcalico ConfigMap at `310_prometheus` apply (not gnet; Felix stays gnet 12175). Kibana (`992_kibana_dashboards`) imports eleven Atlas Lens dashboards (tags `atlas`/`logs`; `noc` on overview, cluster, pipeline) plus data views `kube-logs-*` / `host-logs-*` (time field `@timestamp`) and Stack Management ES-query rules (`consumer: stackAlerts`, empty actions, no Slack/email connector): namespace/apiserver/Ceph plus Falco (`atlas_severity` error|warn, threshold 50 / 5m) and one silent-node `count < 1` / 15m window checked every 5m per unique inventory host (`k8s_master_hosts` + `k8s_worker_hosts`; re-run tag `78` after scale). Default Kibana route is Atlas logs cluster (`uiSettings.overrides.defaultRoute`; Helm tags `630_kibana_prepare`+`640_kibana`). Overview is noise/heartbeat, not CPU/Ceph metrics (Grafana). Time restore is Last 1h on all dashboards; overview/cluster/pipeline auto-refresh every 1m. Lens click opens Discover (`OPEN_IN_DISCOVER_DRILLDOWN`). Discover saved searches: kube/host desks plus `atlas_severity: error`, error+warn, `atlas_heartbeat: true`, Falco `log_processed.rule: *`. Falco pie is JSON rules only. Calico Audit webhook is grepped out of the pipeline. Host `_HOSTNAME` is `NODE_NAME` on all `host*` (journal, syslog, heartbeat; modify then Lua `stamp_hostname`). Rule windows are real 5m/15m (`excludeHitsFromPreviousRun: false`). Existing rules with a non-`stackAlerts` consumer are DELETE+POST. Fluent Bit stamps `atlas_severity` after an early C regex gate (`fluentbit_early_severity_gate`: keep error/warn/crit or CRI files in `fluentbit_kube_full_namespaces` — falco/logging/kube-system) and does not open `fluentbit_kube_tail_exclude_namespaces` (rook-ceph / rook-ceph-cluster / chaos-mesh; Ceph health is Grafana). Journal input is PRIORITY 0–4. Lua drops leftover info when `fluentbit_index_info_logs: false` except allowlist ns and heartbeat. JSON logs land in `log_processed` (copied back to `log` for `log.keyword`). Falco stdout is JSON (`falco.json_output: true`). Host `MESSAGE` is a dynamic keyword (Lens terms on `MESSAGE`, not `.keyword`); if today’s index already mapped `MESSAGE` as text, terms wait for the next daily `host-logs-*`. Syslog and journal inputs can duplicate the same line. Live mapping PUT only adds safe fields (`atlas_*`, `log` text+keyword). Kubernetes Audit is not collected (`kube-audit-*` is out of scope). Catch-up: `--tags 630_kibana_prepare,640_kibana,650_fluentbit,992_kibana_dashboards`. Regenerated ndjson: `python3 roles/992_kibana_dashboards/files/generate_dashboards.py`. Kiali has no official `kiali_*` Grafana JSON — the Kiali CR links Istio dashboards already in Cluster addons. kube-proxy / AIX / MacOS default dashboards are off (Calico dataplane, Linux nodes). Sentry/Trivy/Starboard/nginx gnetIds are not imported. Kyverno and Policy Reporter dashboards come from the chart sidecar (`grafana_dashboard=1`); Argo CD / Kyverno / Policy Reporter use ServiceMonitors (operator watches those namespaces). Thanos (`450_thanos`, thanos-community chart) runs after Rook CSI so `ceph-bucket` exists; Prometheus remote-writes to Receive (Grafana default stays Prometheus; Query is an extra datasource). Mesh order is **`710_istio` → `720_external_dns_istio` → `730_tracing` → `740_kiali`** (Istio creates `istio-system` before the Kiali CR; tracing before Kiali’s Jaeger wait). `710_istio` registers the `otel-tracing` extension provider and applies a mesh-wide `Telemetry/mesh-default` in `istio_namespace` (`istio_tracing_sampling_percentage`, lab default 100). That export policy is independent of application sidecar injection: empty Jaeger with no injected business pods is expected; enable `istio-injection` on app namespaces when ready. Tracing is Istio → OTel → Jaeger 2 (Helm chart 4.x all-in-one) writing traces to the logging Elasticsearch; spanmetrics stay on OTel → Prometheus. Consul (`970_consul`) is Vault KV storage only (`consul_server_replicas: 3`, no Connect/client). Vault init/unseal keys SoT is `/root/vault-init-keys.txt` on `k8s_masters` (controller-state is a cache). `971_vault` fetches and redistributes those keys via SSH plays on `k8s_masters` (not `delegate_to` from localhost). Do not pass `--limit localhost` or `--limit k8s_masters` with `--tags 971_vault` — that drops helm/unseal or the key plays. Helm 4 `upgrade --install` passes `--take-ownership --force-conflicts` because SSA conflicts with field manager `vault-k8s` on the injector webhook `caBundle`; do not delete `MutatingWebhookConfiguration/vault-agent-injector-cfg`. `971_vault` waits for Consul, then creates userpass `vault_admin` from secrets. `972_external_secrets` waits for unsealed Vault and applies `ClusterSecretStore/vault` (kubernetes auth role `eso`, policy `eso-read` — not the admin user; waits until the store is Ready). Set `*_chart_state: skip` to omit a chart from the BOM without editing the playbook or uninstalling drift; use `absent` only for intentional teardown. Grafana dashboards and ingress routes follow the same `present` gate.

Credentials report (`996_cluster_report`):

```bash
./run.sh --tags 996_cluster_report
ls -l "$CLUSTER_WORKSPACE_ROOT/controller-state/reports/"
```

## Greenfield checklist

| Check | Expectation |
|-------|-------------|
| Core | atlas-k8s-core (or equivalent) API healthy via VIP |
| Validate | `./run.sh --tags 130_validate_vars` succeeds |
| Kubeconfig | `$CLUSTER_WORKSPACE_ROOT/controller-state/kubeconfig/admin.conf` exists |
| Helm | `210_helm_bootstrap` adds repos without TLS errors |
| CNI | Nodes Ready after `220_calico` |
| Ingress | MetalLB IP + Envoy Gateway service; hosts resolve to LB |
| Secrets | Real values via vault / `EXTRA_VARS_FILE` (no `CHANGEME` in prod) |
| Report | Optional `996_cluster_report` MD/YAML under `controller_reports_dir` |

Example:

```bash
export KUBECONFIG="$CLUSTER_WORKSPACE_ROOT/controller-state/kubeconfig/admin.conf"
kubectl get nodes -o wide
kubectl get pods -A
kubectl get svc -n envoy-gateway-system
```

## Troubleshooting

### Validate fails: missing control-plane / worker groups

`groups[k8s_master_hosts]` must be non-empty; the group named by `k8s_worker_hosts` must exist (may be empty). Fix inventory (or targeting vars) and re-run:

```bash
./run.sh --tags 130_validate_vars
```

### Validate fails: workspace id / path contract

`cluster_workspace_id` must equal `k8s_cluster_domain`, and `controller_*` paths must live under `cluster_workspace_root`. Prefer:

```bash
CLUSTER_WORKSPACE_ID=k8s.example.com ./run.sh --tags 130_validate_vars
```

(matching `cluster_domain` / `k8s_cluster_domain` in `group_vars/all/atlas-k8s-addons.yml`).

### Validate fails: secrets / ingress hosts / namespaces

Ensure every key asserted in `roles/130_validate_vars/tasks/secrets.yml`, `ingress_hosts.yml`, and `namespaces_addons.yml` is set. Start from `group_vars/all/atlas-k8s-addons.yml` + `examples/secrets.example.yml`.

### Validate fails: `helm_repos` vs `helm_repo_upstreams`

Every `helm_repos[].name` must exist in `helm_repo_upstreams` with matching `path` / `nexus_path`. Do not trim one list without the other.

### Controller missing `admin.conf`

```bash
./run.sh --tags 140_fetch_kubeconfig
ls -l "$CLUSTER_WORKSPACE_ROOT/controller-state/kubeconfig/admin.conf"
```

Confirm SSH to the first master (`k8s_control_plane_ssh_*`) and that `/etc/kubernetes/admin.conf` exists on that node.

### Helm repo add fails (TLS / 404)

With `use_internal_helm_repo: none`, the controller needs outbound HTTPS to public chart hosts. For air-gapped labs switch to `nginx`/`nexus`, set `pki_ca_url`, and supply a reachable mirror — do not bake org hostnames into this repo’s defaults. The Envoy Gateway chart is OCI (helm-nginx does not proxy it): leave `envoy_gateway_chart_oci` at `oci://docker.io/envoyproxy/gateway-helm`, or point it at any OCI registry you operate.

### Nodes NotReady after core

Expected until CNI. Run:

```bash
./run.sh --tags 210_helm_bootstrap,220_calico
kubectl get nodes
```

### MetalLB / ingress address conflicts

`metallb_ip_pool`, `ingress_lb_ip`, and `istio_ingress_lb_ip` must be free on the LAN and not collide with the API VIP. Re-run the edge tags after fixing IPs.

### external-dns does not update records

Confirm `dns_server_ip`, TSIG secrets in `k8s_secrets`, and that BIND (or your RFC2136 server) accepts updates for `k8s_cluster_domain` / apex zones.

### Chart install fails mid-stack

Re-run the failing role tag after fixing values (`*_chart_version`, resources, storage classes). Use `*_chart_state: skip` when the product is not in the BOM; use `absent` only when you intend a full teardown of that release (Helm uninstall if the release or namespace is still on the cluster).

### `./run.sh --tags 130_validate_vars` and the Helm play

The Helm/platform play has **no play-level role tags** (those would inherit onto every role and break per-tag runs). Venv interpreter + `gather_facts` run only from tagged `pre_tasks`, so validate/tooling-only tags skip them. If you hit a missing venv interpreter on a platform tag, create tooling first:

```bash
./run.sh --tags 120_controller_tooling
```

### SSH host key changed after VM recreate

```bash
ssh-keygen -f ~/.ssh/known_hosts -R '192.168.1.225'
```

## Testing / CI

Local checks (same gates as GitHub Actions):

```bash
./tests/run_ci.sh
# or piecemeal:
scripts/check-no-hardcoded-domains.sh
python3 -m unittest discover -s tests -v
ansible-playbook --syntax-check -i inventory-example.yml playbooks/cluster_addons.yaml
ansible-lint --profile min
```

CI workflow: `.github/workflows/ci.yml` (unit tests, syntax-check, ansible-lint `min`, org-hostname scan, publish hygiene greps).

Optional stricter lint locally: `ansible-lint --profile basic` (many legacy style findings; not a merge gate yet).

Optional catalog contract (not a CI gate): `./run.sh --tags 130_validate_vars`.

Contract / hygiene tests live in `tests/test_k8s_addons_layout.py` (entrypoints, fingerprints, Cyrillic scrub, README shape, targeting, workspace).

## Project structure

```
atlas-k8s-addons/
├── playbooks/
│   └── cluster_addons.yaml
├── run.sh
├── ansible.cfg
├── requirements.yml
├── inventory-example.yml
├── group_vars/
│   └── all/
│       └── atlas-k8s-addons.yml
├── examples/
│   ├── hosts.example.yml
│   ├── secrets.example.yml
│   ├── standalone.minimal.yml
│   └── provision_hosts.example.yml
├── host_vars/
│   └── example.yml
├── roles/
│   ├── 110_workspace/
│   ├── 120_controller_tooling/
│   ├── 130_validate_vars/
│   ├── 140_fetch_kubeconfig/
│   ├── 210_helm_bootstrap/ … 996_cluster_report/
│   ├── 999_debug_tooling/
│   └── common/
├── filter_plugins/
├── scripts/
│   └── check-no-hardcoded-domains.sh
├── tests/
│   ├── run_ci.sh
│   └── test_k8s_addons_layout.py
├── .github/workflows/ci.yml
├── .ansible-lint
├── requirements-dev.txt
├── LICENSE
└── SECURITY.md
```

## Integrations

External orchestrators can call the same playbook with their own inventory and group/host vars. Set inventory groups (or override `k8s_master_hosts` / `k8s_worker_hosts`) and knobs from `group_vars/all/atlas-k8s-addons.yml` as needed (domains, LB IPs, Helm mode, chart states, secrets).

Org-specific lab overlays (domains, mirrors, CA, chart credentials) belong in the orchestrator inventory — not in this repository’s defaults.

Suggested tag sequence for split runs: validate → controller tooling → fetch kubeconfig → Helm + Calico → observability → storage → edge → logging → mesh → platform services → report.

Control-plane bootstrap: sibling **atlas-k8s-core**.

## Security

See [`SECURITY.md`](SECURITY.md) for reporting, secret-handling, fingerprint guards, and the pre-publish git history note. Do not commit real credentials, vault files, kubeconfigs, or live inventories (`inventory.yml` and local workspace paths are gitignored). `group_vars/all/atlas-k8s-addons.yml` ships inert `CHANGEME` placeholders for validate-only smoke — rotate before any real deploy.

## Contributing

1. Keep `playbooks/cluster_addons.yaml` as the only supported playbook entry.  
2. Document new operator-facing variables in `group_vars/all/atlas-k8s-addons.yml` and role `defaults/`.  
3. Extend `tests/test_k8s_addons_layout.py` for layout/contract changes.  
4. Keep `./tests/run_ci.sh` green before opening a PR.  
5. Update this README when behaviour, tags, or inventory contracts change.  
6. Keep product sources free of org lab hostnames and Cyrillic operator copy (see `scripts/check-no-hardcoded-domains.sh` and fingerprint tests).  
7. Keep duplicated `120_controller_tooling` / `140_fetch_kubeconfig` in lockstep with **atlas-k8s-core**.

## Support

Open an issue in the repository for bugs and questions.
