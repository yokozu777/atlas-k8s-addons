"""Layout / hygiene / entrypoint / fingerprint smoke tests for atlas-k8s-addons."""

from __future__ import annotations

import json
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

_CYRILLIC_RE = re.compile(r"[А-Яа-яЁё]")


class K8sAddonsHygieneTest(unittest.TestCase):
    def test_license_and_security_exist(self) -> None:
        self.assertTrue((REPO_ROOT / "LICENSE").is_file())
        self.assertTrue((REPO_ROOT / "SECURITY.md").is_file())
        self.assertTrue((REPO_ROOT / ".gitignore").is_file())
        self.assertTrue((REPO_ROOT / ".dockerignore").is_file())

    def test_playbook_exists(self) -> None:
        self.assertTrue((REPO_ROOT / "playbooks" / "cluster_addons.yaml").is_file())

    def test_mesh_role_order_in_playbook(self) -> None:
        """Istio creates istio-system; Kiali CR and Jaeger wait require later tags."""
        text = (REPO_ROOT / "playbooks" / "cluster_addons.yaml").read_text(encoding="utf-8")
        roles = re.findall(r"^\s+- role: (710_istio|720_external_dns_istio|730_tracing|740_kiali)\s*$", text, re.M)
        self.assertEqual(
            roles,
            ["710_istio", "720_external_dns_istio", "730_tracing", "740_kiali"],
            "mesh role order in cluster_addons.yaml",
        )

    def test_argocd_rollouts_role_order_in_playbook(self) -> None:
        """Argo Rollouts follows Argo CD in the heavy-charts play."""
        text = (REPO_ROOT / "playbooks" / "cluster_addons.yaml").read_text(encoding="utf-8")
        roles = re.findall(r"^\s+- role: (980_argocd|982_argocd_rollouts)\s*$", text, re.M)
        self.assertEqual(
            roles,
            ["980_argocd", "982_argocd_rollouts"],
            "argocd/rollouts role order in cluster_addons.yaml",
        )

    def test_kyverno_engine_only_after_falco(self) -> None:
        """Kyverno engine (no policies, no ingress) follows Falco; Policy Reporter UI is 58."""
        text = (REPO_ROOT / "playbooks" / "cluster_addons.yaml").read_text(encoding="utf-8")
        roles = re.findall(
            r"^\s+- role: (810_falco|820_kyverno|830_policy_reporter|910_cloudnative_pg)\s*$",
            text,
            re.M,
        )
        self.assertEqual(
            roles,
            ["810_falco", "820_kyverno", "830_policy_reporter", "910_cloudnative_pg"],
            "falco/kyverno/policy-reporter/cnpg role order in cluster_addons.yaml",
        )
        helm = (
            REPO_ROOT / "roles" / "820_kyverno" / "templates" / "kyverno.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("Engine only", helm)
        self.assertNotIn("nginx", helm.lower())
        self.assertNotIn("kind: ClusterPolicy", helm)
        self.assertNotRegex(helm, r"(?m)^ingress:")
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("kyverno_namespace: kyverno", catalog)
        self.assertIn("kyverno_chart_state: present", catalog)
        self.assertIn("name: kyverno", catalog)
        self.assertNotRegex(
            catalog,
            r"(?m)^  - name: kyverno\n",
            "kyverno must not be in k8s_ingress_apps",
        )
        tasks = (REPO_ROOT / "roles" / "820_kyverno" / "tasks" / "main.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("kyverno/kyverno", tasks)
        self.assertIn("kyverno.io", tasks)
        self.assertIn("admission-controller", tasks)
        self.assertNotIn("helm_chart_absent_ingress_app_names:", tasks)

    def test_trivy_operator_kube_system_no_ingress(self) -> None:
        """Trivy Operator Helm after Policy Reporter; kube-system only; no UI/ingress."""
        text = (REPO_ROOT / "playbooks" / "cluster_addons.yaml").read_text(encoding="utf-8")
        roles = re.findall(
            r"^\s+- role: (830_policy_reporter|840_trivy|910_cloudnative_pg)\s*$",
            text,
            re.M,
        )
        self.assertEqual(
            roles,
            ["830_policy_reporter", "840_trivy", "910_cloudnative_pg"],
            "policy_reporter/trivy/cnpg role order in cluster_addons.yaml",
        )
        helm = (
            REPO_ROOT / "roles" / "840_trivy" / "templates" / "trivy_values.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn('targetNamespaces: "kube-system"', helm)
        self.assertIn("serviceMonitor:", helm)
        self.assertIn("headless: false", helm)
        self.assertIn("nodeCollector:", helm)
        self.assertIn("node-role.kubernetes.io/control-plane", helm)
        self.assertIn("scanJobTolerations:", helm)
        self.assertIn("trivyOperator:", helm)
        self.assertIn("metricsVulnIdEnabled: true", helm)
        self.assertNotIn("nginx", helm.lower())
        self.assertNotRegex(helm, r"(?m)^ingress:")
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("trivy_namespace: trivy-system", catalog)
        self.assertIn('trivy_chart_version: "0.36.0"', catalog)
        self.assertIn("trivy_chart_state: present", catalog)
        self.assertIn("# --- 840_trivy ---", catalog)
        self.assertNotRegex(
            catalog,
            r"(?m)^  - name: trivy\n",
            "trivy must not be in k8s_ingress_apps",
        )
        self.assertLess(
            catalog.index("# --- 950_mailu ---"),
            catalog.index("# --- 840_trivy ---"),
            "catalog documents 83 before 84",
        )
        self.assertLess(
            catalog.index("# --- 840_trivy ---"),
            catalog.index("# --- 960_oauth2_proxy ---"),
            "catalog documents 84 before 72",
        )
        tasks = (REPO_ROOT / "roles" / "840_trivy" / "tasks" / "main.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("aquasecurity/trivy-operator", tasks)
        self.assertIn("aquasecurity.github.io", tasks)
        self.assertIn("deploy/trivy-operator", tasks)
        self.assertNotIn("helm_chart_absent_ingress_app_names:", tasks)
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("840_trivy", readme)

    def test_opencost_helm_oidc_ui(self) -> None:
        """OpenCost Helm after Trivy; UI via Envoy OIDC; chart Ingress off."""
        text = (REPO_ROOT / "playbooks" / "cluster_addons.yaml").read_text(encoding="utf-8")
        roles = re.findall(
            r"^\s+- role: (840_trivy|954_opencost|960_oauth2_proxy)\s*$",
            text,
            re.M,
        )
        self.assertEqual(
            roles,
            ["840_trivy", "954_opencost", "960_oauth2_proxy"],
            "trivy/opencost/oauth2 role order in cluster_addons.yaml",
        )
        helm = (
            REPO_ROOT / "roles" / "954_opencost" / "templates" / "opencost_values.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("prometheus-kube-prometheus-prometheus", helm)
        self.assertIn("namespaceName: \"{{ monitoring_namespace }}\"", helm)
        self.assertIn("port: 9090", helm)
        self.assertIn('clusterName: "{{ k8s_dns_domain }}"', helm)
        self.assertIn('defaultClusterId: "{{ k8s_cluster_domain }}"', helm)
        self.assertNotIn('clusterName: "{{ k8s_cluster_domain }}"', helm)
        self.assertIn("mcp:", helm)
        self.assertIn("enabled: false", helm)
        self.assertNotIn("nginx", helm.lower())
        self.assertNotRegex(helm, r"(?m)^ingress:\n  enabled: true")
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("opencost_namespace: opencost", catalog)
        self.assertIn('opencost_chart_version: "2.5.30"', catalog)
        self.assertIn("opencost_chart_state: present", catalog)
        self.assertIn("# --- 954_opencost ---", catalog)
        self.assertIn("opencost_host: \"opencost.{{ k8s_cluster_domain }}\"", catalog)
        opencost_app = re.search(
            r"(?m)^  - name: opencost\n(?:    .+\n)+",
            catalog,
        )
        self.assertIsNotNone(opencost_app, "opencost ingress missing")
        self.assertIn("oidc_auth: true", opencost_app.group(0))
        self.assertIn("port: 9090", opencost_app.group(0))
        self.assertIn("service: opencost", opencost_app.group(0))
        helm_repos_block = catalog.split("helm_repos:", 1)[1].split(
            "k8s_platform_namespaces:", 1
        )[0]
        helm_upstreams_block = catalog.split("helm_repo_upstreams:", 1)[1].split(
            "helm_repos:", 1
        )[0]
        self.assertRegex(helm_repos_block, r"name:\s*opencost")
        self.assertRegex(helm_upstreams_block, r"name:\s*opencost")
        self.assertLess(
            catalog.index("# --- 840_trivy ---"),
            catalog.index("# --- 954_opencost ---"),
            "catalog documents 84 before 85",
        )
        self.assertLess(
            catalog.index("# --- 954_opencost ---"),
            catalog.index("# --- 960_oauth2_proxy ---"),
            "catalog documents 85 before 72",
        )
        tasks = (REPO_ROOT / "roles" / "954_opencost" / "tasks" / "main.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("opencost/opencost", tasks)
        self.assertIn("deploy/opencost", tasks)
        self.assertIn("helm_chart_absent_ingress_app_names:", tasks)
        self.assertIn("- opencost", tasks)
        report = (
            REPO_ROOT / "roles" / "996_cluster_report" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("id: opencost", report)
        opencost_report = report.split("id: opencost", 1)[1].split("id:", 1)[0]
        self.assertIn("auth: oauth2", opencost_report)
        self.assertIn("envoy-gateway", opencost_report)
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("954_opencost", readme)
        self.assertIn("opencost/opencost", readme)
        prom = (
            REPO_ROOT / "roles" / "310_prometheus" / "templates" / "prometheus.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("{{ opencost_namespace }}", prom)
        dash = (
            REPO_ROOT
            / "roles"
            / "310_prometheus"
            / "templates"
            / "grafana-dashboards.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("grafana_gnet('opencost', 22208, 7)", dash)

    def test_policy_reporter_ui_uses_gateway_not_chart_ingress(self) -> None:
        """Policy Reporter UI uses Envoy OIDC HTTPRoute; chart ingress stays off."""
        helm = (
            REPO_ROOT
            / "roles"
            / "830_policy_reporter"
            / "templates"
            / "policy-reporter.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("enabled: true", helm)
        self.assertIn("enabled: false", helm)
        self.assertRegex(helm, r"(?m)^ui:\n  enabled: true\s*$")
        self.assertRegex(helm, r"(?m)^  ingress:\n    enabled: false\s*$")
        self.assertRegex(helm, r"(?m)^  httproute:\n    enabled: false\s*$")
        self.assertRegex(helm, r"(?m)^plugin:\n  kyverno:\n    enabled: true\s*$")
        self.assertNotIn("openIDConnect:", helm)
        self.assertNotIn("nginx", helm.lower())
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        reporter_app = re.search(
            r"(?m)^  - name: policy-reporter\n(?:    .+\n)+",
            catalog,
        )
        self.assertIsNotNone(reporter_app, "policy-reporter ingress missing")
        self.assertIn("oidc_auth: true", reporter_app.group(0))
        self.assertIn("port: 8080", reporter_app.group(0))
        self.assertIn("service: policy-reporter-ui", reporter_app.group(0))
        self.assertIn("policy_reporter_host", catalog)
        self.assertIn("policy_reporter_namespace: policy-reporter", catalog)
        self.assertIn("kyverno.github.io/policy-reporter", catalog)
        tasks = (
            REPO_ROOT / "roles" / "830_policy_reporter" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("policy-reporter/policy-reporter", tasks)
        self.assertIn("helm_chart_absent_ingress_app_names:", tasks)
        self.assertIn("policy-reporter-ui", tasks)
        report = (
            REPO_ROOT / "roles" / "996_cluster_report" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("id: policy_reporter", report)
        reporter_report = report.split("id: policy_reporter", 1)[1].split("id:", 1)[0]
        self.assertIn("auth: oauth2", reporter_report)
        self.assertIn("envoy-gateway", reporter_report)
        self.assertNotIn("HTTPRoute without oidc_auth", reporter_report)

    def test_mailu_helm_uses_gateway_oidc_not_chart_ingress(self) -> None:
        """Mailu web uses Envoy OIDC HTTPRoute; chart Ingress stays off; mail on MetalLB."""
        helm = (
            REPO_ROOT / "roles" / "950_mailu" / "templates" / "mailu_values.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertRegex(helm, r"(?m)^ingress:\n  enabled: false\s*$")
        self.assertIn("tlsFlavorOverride: mail", helm)
        self.assertIn("header: X-Auth-Request-Email", helm)
        self.assertIn('whitelist: "{{ pod_subnet }}"', helm)
        self.assertIn('create: "true"', helm)
        self.assertIn('sessionTimeout: "2592000"', helm)
        self.assertIn("permanentSessionLifetime: 2592000", helm)
        self.assertIn("type: LoadBalancer", helm)
        self.assertRegex(helm, r"(?m)^  hostPort:\n    enabled: false\s*$")
        self.assertIn("submission: true", helm)
        self.assertIn("size: 20Gi", helm)
        self.assertIn("storageClass: ceph-filesystem", helm)
        self.assertIn("accessModes: [ReadWriteMany]", helm)
        self.assertIn('dnsPolicy: "None"', helm)
        self.assertIn("mailu_unbound_cluster_ip", helm)
        self.assertNotIn('"1.1.1.1"', helm)
        self.assertNotIn("mailu_incluster_services", helm)
        self.assertNotIn("hostAliases:", helm)
        self.assertNotIn("10.0.0.10", helm.split("admin:", 1)[1].split("webmail:", 1)[0])
        admin_block = helm.split("admin:", 1)[1].split("webmail:", 1)[0]
        self.assertIn("timeoutSeconds: 5", admin_block)
        self.assertIn("failureThreshold: 6", admin_block)
        self.assertIn("initContainers:", admin_block)
        self.assertIn("name: wait-redis", admin_block)
        self.assertIn("mailu-redis-master.", admin_block)
        self.assertIn("nc -z", admin_block)
        self.assertIn("single_pvc: true", helm)
        self.assertNotIn("ingress-nginx", helm)
        self.assertNotIn("nginx", helm.lower().replace("mailu/nginx", ""))
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        mailu_app = re.search(
            r"(?m)^  - name: mailu\n(?:    .+\n)+",
            catalog,
        )
        self.assertIsNotNone(mailu_app, "mailu ingress missing")
        self.assertIn("oidc_auth: true", mailu_app.group(0))
        self.assertNotIn("backend_tls:", mailu_app.group(0))
        self.assertNotIn("backend_ca_secret:", mailu_app.group(0))
        self.assertIn("port: 80", mailu_app.group(0))
        self.assertNotIn("port: 443", mailu_app.group(0))
        self.assertIn("service: mailu-front", mailu_app.group(0))
        self.assertIn("mailu_host: \"mail.{{ k8s_cluster_domain }}\"", catalog)
        self.assertIn("mailu_mx_host: \"smtp.{{ k8s_cluster_domain }}\"", catalog)
        self.assertIn("mailu_namespace: mailu", catalog)
        self.assertIn('mailu_chart_version: "2.7.3"', catalog)
        self.assertIn("sessionTimeout = permanentSessionLifetime", catalog)
        self.assertIn("mailu_unbound_cluster_ip: 10.0.0.53", catalog)
        self.assertIn("mailu_unbound_image:", catalog)
        self.assertIn("mailu.github.io/helm-charts", catalog)
        self.assertIn("name: mailu", catalog)
        helm_repos_block = catalog.split("helm_repos:", 1)[1].split(
            "k8s_platform_namespaces:", 1
        )[0]
        helm_upstreams_block = catalog.split("helm_repo_upstreams:", 1)[1].split(
            "helm_repos:", 1
        )[0]
        self.assertRegex(helm_repos_block, r"name:\s*mailu")
        self.assertRegex(helm_upstreams_block, r"name:\s*mailu")
        tasks = (REPO_ROOT / "roles" / "950_mailu" / "tasks" / "main.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("mailu/mailu", tasks)
        self.assertIn("helm_chart_absent_ingress_app_names:", tasks)
        self.assertIn("- mailu", tasks)
        self.assertIn("deployment/mailu-front", tasks)
        self.assertIn("deployment/mailu-admin", tasks)
        self.assertIn("deployment/mailu-rspamd", tasks)
        self.assertIn("deployment/mailu-webmail", tasks)
        self.assertIn("deployment/mailu-unbound", tasks)
        self.assertIn("mailu-unbound.yaml", tasks)
        self.assertNotIn("mailu_incluster_services", tasks)
        self.assertLess(
            tasks.index("mailu-unbound.yaml"),
            tasks.index("helm upgrade --install mailu"),
        )
        cert = (
            REPO_ROOT / "roles" / "950_mailu" / "templates" / "mailu-certificate.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("kind: Certificate", cert)
        self.assertIn("kind: ClusterIssuer", cert)
        self.assertIn("{{ mailu_host }}", cert)
        self.assertIn("{{ mailu_mx_host }}", cert)
        mx = (
            REPO_ROOT / "roles" / "950_mailu" / "templates" / "mailu-mx.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("kind: DNSEndpoint", mx)
        self.assertIn("recordType: MX", mx)
        self.assertIn("{{ mailu_domain }}", mx)
        self.assertIn("{{ mailu_mx_host }}", mx)
        self.assertIn("kind: DNSEndpoint", tasks)
        self.assertIn("mailu-mx.yaml", tasks)
        unbound = (
            REPO_ROOT / "roles" / "950_mailu" / "templates" / "mailu-unbound.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("kind: Deployment", unbound)
        self.assertIn("kind: Service", unbound)
        self.assertIn("forward-zone", unbound)
        self.assertIn("domain-insecure", unbound)
        self.assertIn("mailu_unbound_cluster_ip", unbound)
        self.assertIn("cluster_dns_ip", unbound)
        edns_tasks = (
            REPO_ROOT / "roles" / "530_external_dns" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("external-dns-apex", edns_tasks)
        self.assertIn("dnsendpoints.externaldns.k8s.io", edns_tasks)
        apex = (
            REPO_ROOT
            / "roles"
            / "530_external_dns"
            / "templates"
            / "external-dns-apex.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("- crd", apex)
        self.assertNotIn("- service", apex)
        self.assertIn("--rfc2136-zone={{ dns_domain_suffix }}", apex)
        self.assertIn("external_dns_apex_tsig_secret", apex)
        self.assertIn("--managed-record-types=A", apex)
        self.assertIn("--managed-record-types=AAAA", apex)
        self.assertIn("--managed-record-types=CNAME", apex)
        self.assertIn("--managed-record-types=MX", apex)
        self.assertIn("--managed-record-types=TXT", apex)
        self.assertIn("external_dns_apex_txt_owner_id", catalog)
        oidc = (
            REPO_ROOT
            / "roles"
            / "961_apply_oidc_ingress"
            / "templates"
            / "oidc-securitypolicy.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("kind: BackendTLSPolicy", oidc)
        self.assertIn("ing.backend_tls", oidc)
        self.assertIn("gateway.networking.k8s.io/v1alpha3", oidc)
        absent = (
            REPO_ROOT / "roles" / "common" / "tasks" / "helm_chart_absent.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("kind: BackendTLSPolicy", absent)
        playbook = (REPO_ROOT / "playbooks" / "cluster_addons.yaml").read_text(
            encoding="utf-8"
        )
        mailu_roles = re.findall(
            r"^\s+- role: (840_trivy|942_pinniped|950_mailu|954_opencost|960_oauth2_proxy|961_apply_oidc_ingress|962_headlamp)\s*$",
            playbook,
            re.M,
        )
        self.assertEqual(
            mailu_roles,
            [
                "840_trivy",
                "942_pinniped",
                "950_mailu",
                "954_opencost",
                "960_oauth2_proxy",
                "961_apply_oidc_ingress",
                "962_headlamp",
            ],
            "Mailu Helm before OIDC HTTPRoute (961) in cluster_addons.yaml",
        )
        self.assertLess(
            catalog.index("# --- 942_pinniped ---"),
            catalog.index("# --- 950_mailu ---"),
            "catalog documents 82 before 83",
        )
        self.assertLess(
            catalog.index("# --- 950_mailu ---"),
            catalog.index("# --- 960_oauth2_proxy ---"),
            "catalog documents 83 before 72",
        )
        report = (
            REPO_ROOT / "roles" / "996_cluster_report" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("id: mailu", report)
        mailu_report = report.split("id: mailu", 1)[1].split("id:", 1)[0]
        self.assertIn("auth: oauth2", mailu_report)
        self.assertIn("envoy-gateway", mailu_report)
        self.assertIn("mailu_mx_host", mailu_report)
        self.assertIn("external-dns-apex", mailu_report)
        self.assertNotIn("MX in BIND is manual", mailu_report)
        self.assertNotIn("HTTPRoute without oidc_auth", mailu_report)
        secrets = (
            REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.secrets.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("mailu_secret_key:", secrets)
        self.assertIn("mailu_initial_password:", secrets)
        self.assertIn("external_dns_apex_tsig_secret:", secrets)
        example = (REPO_ROOT / "examples" / "secrets.example.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("mailu_secret_key:", example)
        self.assertIn("mailu_initial_password:", example)
        self.assertIn("external_dns_apex_tsig_secret:", example)
        validate_hosts = (
            REPO_ROOT / "roles" / "130_validate_vars" / "tasks" / "ingress_hosts.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("mailu_host", validate_hosts)
        self.assertIn("mailu_mx_host", validate_hosts)
        validate_ns = (
            REPO_ROOT / "roles" / "130_validate_vars" / "tasks" / "namespaces_addons.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("mailu_namespace", validate_ns)
        validate_secrets = (
            REPO_ROOT / "roles" / "130_validate_vars" / "tasks" / "secrets.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("k8s_secrets.mailu_secret_key", validate_secrets)
        self.assertIn("k8s_secrets.mailu_initial_password", validate_secrets)
        self.assertIn("k8s_secrets.external_dns_apex_tsig_secret", validate_secrets)
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("950_mailu", readme)

    def test_argocd_rollouts_uses_gateway_not_chart_ingress(self) -> None:
        """Rollouts dashboard uses Envoy OIDC HTTPRoute; chart ingress stays off."""
        helm = (
            REPO_ROOT
            / "roles"
            / "982_argocd_rollouts"
            / "templates"
            / "argo-rollouts.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("enabled: true", helm)
        self.assertIn("enabled: false", helm)
        self.assertRegex(helm, r"(?m)^dashboard:\n  enabled: true\s*$")
        self.assertRegex(helm, r"(?m)^  ingress:\n    enabled: false\s*$")
        self.assertNotIn("openid:", helm)
        self.assertNotIn("nginx", helm.lower())
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        rollouts_app = re.search(
            r"(?m)^  - name: argo-rollouts-dashboard\n(?:    .+\n)+",
            catalog,
        )
        self.assertIsNotNone(rollouts_app, "argo-rollouts-dashboard ingress missing")
        self.assertIn("oidc_auth: true", rollouts_app.group(0))
        self.assertIn("port: 3100", rollouts_app.group(0))
        self.assertIn("service: argo-rollouts-dashboard", rollouts_app.group(0))
        self.assertIn("argo_rollouts_host", catalog)
        self.assertIn("argo_rollouts_namespace", catalog)
        tasks = (
            REPO_ROOT / "roles" / "982_argocd_rollouts" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("argo/argo-rollouts", tasks)
        self.assertIn("argo-rollouts-dashboard", tasks)
        report = (
            REPO_ROOT / "roles" / "996_cluster_report" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("id: argo_rollouts", report)
        rollouts_report = report.split("id: argo_rollouts", 1)[1].split("id:", 1)[0]
        self.assertIn("auth: oauth2", rollouts_report)
        self.assertIn("envoy-gateway", rollouts_report)
        self.assertNotIn("HTTPRoute without oidc_auth", rollouts_report)

    def test_thanos_role_order_in_playbook(self) -> None:
        """Thanos needs Rook RGW (ceph-bucket); keep CSI tag, insert before MetalLB."""
        text = (REPO_ROOT / "playbooks" / "cluster_addons.yaml").read_text(encoding="utf-8")
        roles = re.findall(
            r"^\s+- role: (430_rook_cluster|440_rook_csi_drivers|450_thanos|510_metallb)\s*$",
            text,
            re.M,
        )
        self.assertEqual(
            roles,
            ["430_rook_cluster", "440_rook_csi_drivers", "450_thanos", "510_metallb"],
            "storage/thanos role order in cluster_addons.yaml",
        )

    def test_platform_play_has_no_inherited_role_tags(self) -> None:
        """Play-level role tags inherit onto every role and break per-tag Jenkins runs."""
        text = (REPO_ROOT / "playbooks" / "cluster_addons.yaml").read_text(encoding="utf-8")
        header = (
            "- hosts: localhost\n"
            "  connection: local\n"
            "  gather_facts: false\n"
            "  strategy: linear"
        )
        parts = text.split(header)
        self.assertGreaterEqual(
            len(parts),
            3,
            "expected platform A and platform B strategy: linear plays",
        )
        for idx, body_and_rest in enumerate(parts[1:], start=1):
            body = body_and_rest.split("- hosts:", 1)[0]
            self.assertNotRegex(
                body.split("pre_tasks:", 1)[0],
                r"(?m)^\s+tags:\s*$",
                f"platform play {idx} must not set play-level tags "
                "(Ansible inherits them onto all roles)",
            )
            self.assertIn("pre_tasks:", body, f"platform play {idx}")
            self.assertIn("ansible_python_interpreter:", body, f"platform play {idx}")
            self.assertNotIn(
                "ansible_python_interpreter: \"{{ controller_python_venv }}/bin/python\"",
                body.split("pre_tasks:", 1)[0],
                f"platform play {idx} interpreter must stay in pre_tasks",
            )
            self.assertIn("become: false", body, f"platform play {idx} must not sudo on localhost")

    def test_list_tasks_tags_isolate_single_platform_role(self) -> None:
        """--tags 210_helm_bootstrap must not schedule later platform roles (vault/argocd/…)."""
        inv = REPO_ROOT / "inventory-example.yml"
        playbook = REPO_ROOT / "playbooks" / "cluster_addons.yaml"
        proc = subprocess.run(
            [
                "ansible-playbook",
                str(playbook),
                "-i",
                str(inv),
                "--tags",
                "210_helm_bootstrap",
                "--list-tasks",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        self.assertEqual(proc.returncode, 0, out)
        self.assertIn("210_helm_bootstrap", out)
        for role in (
            "220_calico",
            "310_prometheus",
            "450_thanos",
            "971_vault",
            "980_argocd",
        ):
            self.assertNotIn(f"{role} :", out, f"--tags 210_helm_bootstrap must not list {role}:\n{out}")

    def test_list_tasks_tags_960_does_not_apply_oidc_ingress(self) -> None:
        """--tags 960_oauth2_proxy must not schedule 961 OIDC HTTPRoute apply."""
        inv = REPO_ROOT / "inventory-example.yml"
        playbook = REPO_ROOT / "playbooks" / "cluster_addons.yaml"
        proc = subprocess.run(
            [
                "ansible-playbook",
                str(playbook),
                "-i",
                str(inv),
                "--tags",
                "960_oauth2_proxy",
                "--list-tasks",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        self.assertEqual(proc.returncode, 0, out)
        self.assertIn("960_oauth2_proxy", out)
        self.assertNotIn(
            "961_apply_oidc_ingress :",
            out,
            f"--tags 960_oauth2_proxy must not list 961_apply_oidc_ingress:\n{out}",
        )
        oauth2_tasks = (
            REPO_ROOT / "roles" / "960_oauth2_proxy" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("oidc-securitypolicy.yaml", oauth2_tasks)
        self.assertNotIn("helm_chart_absent_extra_manifests", oauth2_tasks)
        self.assertFalse(
            (REPO_ROOT / "roles" / "960_oauth2_proxy" / "templates" / "oidc-securitypolicy.yaml.j2").is_file(),
            "OIDC SecurityPolicy template must live in 961, not 960",
        )
        oidc_tasks = (
            REPO_ROOT / "roles" / "961_apply_oidc_ingress" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("oidc-securitypolicy.yaml.j2", oidc_tasks)
        self.assertIn("k8s_ingress_apps_oidc_active", oidc_tasks)
        self.assertNotIn("oauth2_proxy_chart_state", oidc_tasks)

    def test_helm_bootstrap_per_repo_update_allows_stale_index(self) -> None:
        """Per-repo add --force-update; stale cache warns, missing index is fatal."""
        main = (
            REPO_ROOT / "roles" / "210_helm_bootstrap" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        repo = (
            REPO_ROOT / "roles" / "210_helm_bootstrap" / "tasks" / "repo.yaml"
        ).read_text(encoding="utf-8")
        defaults = (
            REPO_ROOT / "roles" / "210_helm_bootstrap" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("file: repo.yaml", main)
        self.assertIn("210_helm_bootstrap", main)
        self.assertNotRegex(main, r"(?m)^  ansible.builtin.command: helm repo update\s*$")
        self.assertIn("helm repo add --force-update", repo)
        self.assertNotIn("cmd: helm repo update", repo)
        self.assertIn("until: helm_repo_add.rc == 0", repo)
        self.assertIn("helm_repo_update_retries", repo)
        self.assertIn("repository/{{ helm_repo.name }}-index.yaml", repo)
        self.assertIn("using stale index", repo)
        self.assertIn("Greenfield cannot continue", repo)
        self.assertIn("helm_repo_update_retries: 1", defaults)
        self.assertIn("helm_repo_update_delay: 5", defaults)
        self.assertIn("HELM_REQUEST_TIMEOUT", defaults)
        self.assertIn("HELM_REPOSITORY_CACHE", defaults)
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('upstream_url: "https://cloudnative-pg.io/charts"', catalog)
        self.assertIn("upstream_host: cloudnative-pg.io", catalog)
        self.assertNotIn("cloudnative-pg.github.io", catalog)
        self.assertIn('upstream_url: "https://external-secrets.io"', catalog)
        self.assertIn("upstream_host: external-secrets.io", catalog)
        self.assertNotIn("charts.external-secrets.io", catalog)

    def test_list_tasks_tags_971_vault_includes_ssh_key_plays(self) -> None:
        """--tags 971_vault runs controller install/unseal and SSH key collect/distribute."""
        inv = REPO_ROOT / "inventory-example.yml"
        playbook = REPO_ROOT / "playbooks" / "cluster_addons.yaml"
        proc = subprocess.run(
            [
                "ansible-playbook",
                str(playbook),
                "-i",
                str(inv),
                "--tags",
                "971_vault",
                "--list-tasks",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        self.assertEqual(proc.returncode, 0, out)
        for needle in ("keys_collect", "unseal:", "keys_distribute"):
            self.assertIn(needle, out, f"--tags 971_vault must list {needle}:\n{out}")
        self.assertNotIn(
            "972_external_secrets :",
            out,
            f"--tags 971_vault must not list 972_external_secrets:\n{out}",
        )

    def test_prometheus_adapter_resource_queries_skip_pod_cgroup(self) -> None:
        """HPA metrics.k8s.io must ignore cAdvisor pause/pod cgroup series."""
        text = (
            REPO_ROOT
            / "roles"
            / "330_prometheus_adapter"
            / "templates"
            / "prometheus-adapter.yaml.j2"
        ).read_text(encoding="utf-8")
        queries = re.findall(r"(?m)^\s+(?:containerQuery|nodeQuery):\s*>-\s*\n\s*(.+)$", text)
        self.assertEqual(
            len(queries),
            4,
            f"expected cpu+memory containerQuery and nodeQuery, got {queries}",
        )
        for query in queries:
            self.assertIn('container!=""', query, query)
            self.assertIn('container!="POD"', query, query)
            self.assertNotIn("id='/'", query, query)
            self.assertNotIn('id="/"', query, query)
        self.assertIn("resource: node", text)
        self.assertNotIn("instance:", text)
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("nodeQuery is unchanged", catalog)

    def test_eso_and_argocd_haproxy_images_use_mirrored_registries(self) -> None:
        """ESO vanity OCI and Argo redis-ha ECR Public bypass pull-through; pin Hub/GHCR."""
        eso_values = (
            REPO_ROOT
            / "roles"
            / "972_external_secrets"
            / "templates"
            / "external-secrets.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            eso_values.count("ghcr.io/external-secrets/external-secrets"),
            3,
        )
        self.assertNotIn("oci.external-secrets.io", eso_values)
        argocd = (
            REPO_ROOT / "roles" / "980_argocd" / "templates" / "argocd.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("haproxy:", argocd)
        self.assertIn("repository: docker.io/library/haproxy", argocd)
        self.assertIn("3.3.10-alpine", argocd)
        self.assertNotIn("ecr-public.aws.com", argocd)

    def test_argocd_server_and_reposerver_memory_request(self) -> None:
        """HPA target is % of request; 64Mi plus pod cgroup looked like 200% RAM."""
        text = (REPO_ROOT / "roles" / "980_argocd" / "templates" / "argocd.yaml.j2").read_text(
            encoding="utf-8"
        )
        for section in ("server", "repoServer"):
            match = re.search(
                rf"(?ms)^{section}:\n(.*?)(?=^[a-zA-Z]|\Z)",
                text,
            )
            self.assertIsNotNone(match, f"{section} block missing")
            requests = re.search(r"(?ms)^\s+requests:\n((?: .+\n)+)", match.group(1))
            self.assertIsNotNone(requests, f"{section}.resources.requests missing")
            self.assertRegex(
                requests.group(1),
                r"(?m)^\s+memory:\s*128Mi\s*$",
                f"{section} memory request must be 128Mi:\n{requests.group(1)}",
            )

    def test_fluentbit_es_retry_is_bounded_and_kube_tail_has_db(self) -> None:
        """Poison ES bulk must not retry forever; kube tail offsets survive DaemonSet restart."""
        j2 = (
            REPO_ROOT / "roles" / "650_fluentbit" / "templates" / "fluentbit.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertNotIn("Retry_Limit False", j2)
        self.assertEqual(j2.count("Retry_Limit {{ fluentbit_es_retry_limit }}"), 2)
        self.assertGreaterEqual(j2.count("Trace_Error"), 2)
        self.assertIn("fluentbit_kube.db", j2)
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("fluentbit_es_retry_limit: 5", catalog)

    def test_fluentbit_merge_log_key_memory_storage_and_metrics(self) -> None:
        """Parsed JSON under log_processed; memory chunks; dedicated Prometheus scrape/alerts."""
        j2 = (
            REPO_ROOT / "roles" / "650_fluentbit" / "templates" / "fluentbit.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("Merge_Log_Key log_processed", j2)
        self.assertNotIn("storage.path", j2)
        self.assertNotIn("storage.type filesystem", j2)
        self.assertGreaterEqual(j2.count("storage.type memory"), 3)
        self.assertGreaterEqual(j2.count("Buffer_Size 512k"), 2)
        self.assertRegex(
            j2,
            r"(?m)^livenessProbe:\n  httpGet:\n    path: /api/v1/health\s*$",
        )
        self.assertRegex(j2, r"(?m)^serviceMonitor:\n  enabled: false\s*$")
        sm = (
            REPO_ROOT
            / "roles"
            / "650_fluentbit"
            / "templates"
            / "fluentbit-servicemonitor.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("path: /api/v1/metrics/prometheus", sm)
        self.assertNotIn("path: /api/v1/metrics\n", sm)
        rule = (
            REPO_ROOT
            / "roles"
            / "650_fluentbit"
            / "templates"
            / "fluentbit-prometheusrule.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("FluentbitEsOutputRetries", rule)
        self.assertIn("fluentbit_output_retries_total", rule)
        self.assertIn("FluentbitDroppedRecords", rule)
        self.assertIn("fluentbit_output_dropped_records_total", rule)
        tasks = (REPO_ROOT / "roles" / "650_fluentbit" / "tasks" / "main.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("fluentbit-servicemonitor.yaml", tasks)
        self.assertIn("fluentbit-prometheusrule.yaml", tasks)

    def test_elasticsearch_ilm_templates_and_rook_rgw_slm(self) -> None:
        """ILM/templates before first kube-logs index; SLM default is Rook RGW OBC."""
        ilm = (
            REPO_ROOT / "roles" / "620_elasticsearch" / "tasks" / "logging_ilm.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("_ilm/policy/atlas-logs", ilm)
        self.assertIn("index.mapping.ignore_malformed", ilm)
        self.assertIn("log_processed", ilm)
        self.assertIn("kube-logs-*", ilm)
        self.assertIn("host-logs-*", ilm)
        self.assertRegex(ilm, r"(?m)^\s+hot:\s*$")
        self.assertIn("min_age: 0ms", ilm)
        self.assertIn("actions: {}", ilm)
        put = (
            REPO_ROOT / "roles" / "620_elasticsearch" / "tasks" / "elasticsearch_put.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("no_log: true", put)
        self.assertIn("Fail if {{ elasticsearch_put_title }} was rejected", put)
        self.assertNotRegex(
            put.split("Fail if", 1)[-1],
            r"(?m)^\s+no_log:\s*true\s*$",
            "ES error body must not be hidden on the fail task",
        )
        backend = (
            REPO_ROOT / "roles" / "620_elasticsearch" / "tasks" / "snapshot_backend.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("kind: ObjectBucketClaim", backend)
        self.assertIn("elasticsearch_s3_credentials_secret", backend)
        defaults = (
            REPO_ROOT / "roles" / "620_elasticsearch" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("elasticsearch_s3_credentials_secret: elastic-s3-credentials", defaults)
        slm = (
            REPO_ROOT / "roles" / "620_elasticsearch" / "tasks" / "logging_slm.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("_snapshot/", slm)
        self.assertIn("path_style_access", slm)
        self.assertIn("_slm/policy/", slm)
        values = (
            REPO_ROOT / "roles" / "620_elasticsearch" / "templates" / "elastic.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("s3.client.default.path_style_access", values)
        self.assertIn("elasticsearch_s3_credentials_secret", values)
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("elasticsearch_ilm_delete_after: 7d", catalog)
        self.assertIn("elasticsearch_snapshot_backend: rook-rgw", catalog)
        self.assertIn("atlas_severity", ilm)
        self.assertIn("atlas_heartbeat", ilm)
        self.assertIn("kube-logs-*/_mapping", ilm)
        self.assertIn("host-logs-*/_mapping", ilm)
        self.assertIn("elasticsearch_put_ok_statuses", put)
        secrets = (
            REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.secrets.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("elasticsearch_snapshot_s3_access_key:", secrets)
        tasks = (REPO_ROOT / "roles" / "620_elasticsearch" / "tasks" / "main.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("logging_ilm.yml", tasks)
        self.assertIn("logging_slm.yml", tasks)
        self.assertIn("snapshot_backend.yml", tasks)
        self.assertLess(tasks.index("snapshot_backend.yml"), tasks.index("elastic.yaml.j2"))

    def test_fluentbit_indexes_all_logs_with_atlas_severity(self) -> None:
        """Keep records, stamp atlas_severity; early gate before kubernetes/Lua."""
        j2 = (
            REPO_ROOT / "roles" / "650_fluentbit" / "templates" / "fluentbit.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn('record["atlas_severity"]', j2)
        self.assertIn("return 2, timestamp, record", j2)
        self.assertIn("Annotations Off", j2)
        self.assertIn("Tag host.heartbeat", j2)
        self.assertIn("atlas_heartbeat", j2)
        self.assertIn("spec.nodeName", j2)
        self.assertIn("os.getenv(\"NODE_NAME\")", j2)
        self.assertIn("fluentbit_index_info_logs", j2)
        self.assertIn("log_processed", j2)
        self.assertIn("restore_log", j2)
        self.assertNotIn("Name throttle", j2)
        self.assertIn("Interval_Sec 60", j2)
        self.assertIn("Flush_on_startup On", j2)
        self.assertIn("%[info%]", j2)
        self.assertIn("failed=false", j2)
        self.assertIn("HEALTH_ERR", j2)
        self.assertIn('record["MESSAGE"]', j2)
        self.assertNotIn("systemd_error", j2)
        self.assertIn("Set _HOSTNAME ${NODE_NAME}", j2)
        self.assertIn("function stamp_hostname", j2)
        self.assertIn("stamp_hostname(record)", j2)
        self.assertLess(
            j2.index("function stamp_hostname"),
            j2.index("function detect_host_log"),
        )
        self.assertLess(
            j2.index("Name modify"),
            j2.index("Set _HOSTNAME ${NODE_NAME}"),
        )
        self.assertIn("Match host*", j2[j2.index("Name modify"):j2.index("Set _HOSTNAME ${NODE_NAME}")])
        self.assertLess(
            j2.index("Set _HOSTNAME ${NODE_NAME}"),
            j2.index("call detect_host_log"),
        )
        self.assertLess(
            j2.index("Exclude log audit-logging.api.projectcalico.org"),
            j2.index("Keep_Log Off"),
        )
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("fluentbit_index_info_logs: true", catalog)
        self.assertIn("fluentbit_early_severity_gate: true", catalog)
        self.assertIn("fluentbit_kube_tail_exclude_namespaces:", catalog)
        self.assertIn("fluentbit_kube_full_namespaces:", catalog)
        self.assertIn("Path_Key filename", j2)
        self.assertIn("Exclude_Path", j2)
        self.assertIn("/var/log/containers/*_{{ ns }}_*.log", j2)
        self.assertIn("Logical_Op or", j2)
        self.assertIn("Systemd_Filter PRIORITY=4", j2)
        self.assertIn("Systemd_Filter_Type Or", j2)
        self.assertIn("Match host.syslog", j2)
        self.assertIn("Buffer_Size 32k", j2)
        self.assertNotIn("Buffer_Size 0", j2)
        self.assertIn("local FULL_NS", j2)
        self.assertIn('["{{ ns }}"] = true', j2)
        self.assertIn("kube-system", j2)
        self.assertIn("is_full_ns", j2)
        self.assertLess(j2.index("Logical_Op or"), j2.index("Name kubernetes"))
        self.assertLess(
            j2.index("Exclude log audit-logging.api.projectcalico.org"),
            j2.index("Logical_Op or"),
        )

    def test_kibana_atlas_log_dashboards_and_alerts(self) -> None:
        """Eleven Lens dashboards from the generator; ES-query rules; no Audit index."""
        files_dir = REPO_ROOT / "roles" / "992_kibana_dashboards" / "files"
        gen = files_dir / "generate_dashboards.py"
        self.assertTrue(gen.is_file())
        proc = subprocess.run(
            [sys.executable, str(gen), "--check"],
            cwd=str(files_dir),
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse((files_dir / "k8s-dashboard.ndjson").exists())
        self.assertFalse((files_dir / "hosts-dashboard.ndjson").exists())
        titles = []
        keyword_hits = []
        catalog_namespaces: list[str] = []
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        in_ns = False
        for line in catalog.splitlines():
            if line.startswith("kibana_logs_system_namespaces:"):
                in_ns = True
                continue
            if in_ns:
                stripped = line.strip()
                if stripped.startswith("- "):
                    catalog_namespaces.append(stripped[2:].strip().strip("\"'"))
                elif stripped.startswith("#") or stripped == "":
                    continue
                else:
                    break
        tenant_obj = json.loads(
            (files_dir / "atlas-logs-tenant.ndjson").read_text(encoding="utf-8").splitlines()[0]
        )
        tenant_kqls = []
        for panel in json.loads(tenant_obj["attributes"]["panelsJSON"]):
            query = (
                panel.get("embeddableConfig", {})
                .get("attributes", {})
                .get("state", {})
                .get("query", {})
                .get("query", "")
            )
            if "NOT kubernetes.namespace_name" in query:
                tenant_kqls.append(re.findall(r'"([^"]+)"', query))
        self.assertTrue(catalog_namespaces)
        self.assertTrue(tenant_kqls)
        for names in tenant_kqls:
            self.assertEqual(names, catalog_namespaces)
        tenant_text = (files_dir / "atlas-logs-tenant.ndjson").read_text(encoding="utf-8")
        self.assertIn("kubernetes.namespace_name: *", tenant_text)
        self.assertIn("metallb-system", catalog)
        self.assertIn("oauth2-proxy", catalog)
        self.assertIn("cnpg-system", catalog)
        for path in sorted(files_dir.glob("atlas-*.ndjson")):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("kube-audit", text)
            self.assertNotIn('"type":"markdown"', text)
            self.assertNotIn("MESSAGE.keyword", text)
            self.assertNotIn("/app/discover#/", text)
            self.assertNotIn("MESSAGE: *I/O error*", text)
            self.assertNotIn("log: *osd*", text)
            if re.search(r"kubernetes\.[A-Za-z0-9_/]+\.keyword", text):
                keyword_hits.append(path.name)
            for needle in (
                "_HOSTNAME.keyword",
                "PRIORITY.keyword",
                "SYSLOG_IDENTIFIER.keyword",
                "_SYSTEMD_UNIT.keyword",
                "stream.keyword",
            ):
                if needle in text:
                    keyword_hits.append(f"{path.name}:{needle}")
            for line in text.splitlines():
                obj = json.loads(line)
                if obj.get("type") == "dashboard":
                    titles.append(obj["attributes"]["title"])
        self.assertEqual(keyword_hits, [])
        self.assertEqual(
            sorted(titles),
            [
                "Atlas logs Calico",
                "Atlas logs GitOps",
                "Atlas logs cluster",
                "Atlas logs control plane",
                "Atlas logs edge",
                "Atlas logs nodes",
                "Atlas logs overview",
                "Atlas logs pipeline",
                "Atlas logs security",
                "Atlas logs storage",
                "Atlas logs tenant",
            ],
        )
        for path in sorted(files_dir.glob("atlas-logs-*.ndjson")):
            text = path.read_text(encoding="utf-8")
            dash_lines = [
                json.loads(line)
                for line in text.splitlines()
                if line and json.loads(line).get("type") == "dashboard"
            ]
            self.assertTrue(dash_lines, path.name)
            controls = json.loads(
                dash_lines[0]["attributes"]["controlGroupInput"]["panelsJSON"]
            )
            fields = [
                body.get("explicitInput", {}).get("fieldName")
                for body in controls.values()
            ]
            self.assertIn("atlas_severity", fields, path.name)
        cluster = (files_dir / "atlas-logs-cluster.ndjson").read_text(encoding="utf-8")
        self.assertIn('"type":"search"', cluster)
        self.assertIn("kubernetes.pod_name", cluster)
        self.assertIn("MESSAGE", cluster)
        self.assertIn("atlas_severity: error", cluster)
        self.assertIn("atlas_severity: (error or warn)", cluster)
        self.assertIn("atlas_heartbeat: true", cluster)
        self.assertIn("log_processed.rule: *", cluster)
        self.assertIn("OPEN_IN_DISCOVER_DRILLDOWN", cluster)
        self.assertIn("#BD271E", cluster)
        self.assertIn("colorMapping", cluster)
        landing_files = {
            "atlas-logs-overview.ndjson",
            "atlas-logs-cluster.ndjson",
            "atlas-logs-pipeline.ndjson",
        }
        for path in sorted(files_dir.glob("atlas-logs-*.ndjson")):
            dash_obj = next(
                json.loads(line)
                for line in path.read_text(encoding="utf-8").splitlines()
                if line and json.loads(line).get("type") == "dashboard"
            )
            attrs = dash_obj["attributes"]
            self.assertTrue(attrs["timeRestore"], path.name)
            self.assertEqual(attrs["timeFrom"], "now-1h", path.name)
            self.assertEqual(attrs["timeTo"], "now", path.name)
            refresh = attrs.get("refreshInterval")
            if path.name in landing_files:
                self.assertEqual(
                    refresh, {"pause": False, "value": 60000}, path.name
                )
            else:
                self.assertIsNone(refresh, path.name)
            tag_ids = {
                ref["id"]
                for ref in dash_obj.get("references", [])
                if ref.get("type") == "tag"
            }
            self.assertIn("atlas-tag-atlas", tag_ids, path.name)
            self.assertIn("atlas-tag-logs", tag_ids, path.name)
            if path.name in landing_files:
                self.assertIn("atlas-tag-noc", tag_ids, path.name)
            else:
                self.assertNotIn("atlas-tag-noc", tag_ids, path.name)
        data_views = (files_dir / "atlas-data-views.ndjson").read_text(encoding="utf-8")
        self.assertIn('"type":"tag"', data_views)
        self.assertIn('"name":"atlas"', data_views)
        self.assertIn('"name":"logs"', data_views)
        self.assertIn('"name":"noc"', data_views)
        kibana_values = (
            REPO_ROOT / "roles" / "630_kibana_prepare" / "templates" / "kibana.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'defaultRoute: "/app/dashboards#/view/atlas-logs-cluster"',
            kibana_values,
        )
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("eleven Atlas Lens dashboards", readme)
        self.assertNotIn("ten Atlas Lens dashboards", readme)
        security = (files_dir / "atlas-logs-security.ndjson").read_text(encoding="utf-8")
        self.assertIn("log_processed.rule", security)
        self.assertIn("log_processed.priority", security)
        self.assertIn("log.keyword", security)
        nodes_obj = json.loads(
            (files_dir / "atlas-logs-nodes.ndjson").read_text(encoding="utf-8").splitlines()[0]
        )
        message_fields: set[str] = set()
        for panel in json.loads(nodes_obj["attributes"]["panelsJSON"]):
            layers = (
                panel.get("embeddableConfig", {})
                .get("attributes", {})
                .get("state", {})
                .get("datasourceStates", {})
                .get("formBased", {})
                .get("layers", {})
            )
            for layer in layers.values():
                for col in layer.get("columns", {}).values():
                    field = col.get("sourceField")
                    if field:
                        message_fields.add(field)
        self.assertIn("MESSAGE", message_fields)
        self.assertNotIn("MESSAGE.keyword", message_fields)
        tasks = (
            REPO_ROOT / "roles" / "992_kibana_dashboards" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("atlas-*.ndjson", tasks)
        self.assertIn("k8s-dashboard", tasks)
        self.assertIn("alerts.yml", tasks)
        self.assertIn("json.success", tasks)
        self.assertIn("json.errors", tasks)
        alerts = (
            REPO_ROOT / "roles" / "992_kibana_dashboards" / "tasks" / "alerts.yml"
        ).read_text(encoding="utf-8")
        ensure = (
            REPO_ROOT / "roles" / "992_kibana_dashboards" / "tasks" / "ensure_alert.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("/api/alerting/rule/", alerts)
        self.assertIn("/api/alerting/rule/", ensure)
        self.assertIn("GET Atlas Kibana log alert", ensure)
        self.assertIn("method: GET", ensure)
        self.assertIn("method: POST", ensure)
        self.assertIn("method: PUT", ensure)
        self.assertIn('rule_type_id: ".es-query"', ensure)
        self.assertIn("consumer: stackAlerts", ensure)
        self.assertIn("when consumer is not stackAlerts", ensure)
        self.assertIn("!= 'stackAlerts'", ensure)
        self.assertIn("method: DELETE", ensure)
        self.assertNotIn("consumer: alerts", ensure)
        self.assertNotIn("consumer: alerts", alerts)
        self.assertIn("actions: []", ensure)
        self.assertIn("atlas-logs-silent-node", alerts)
        self.assertIn("atlas-logs-ns-error-spike", alerts)
        self.assertIn("k8s_master_hosts", alerts)
        self.assertIn("k8s_worker_hosts", alerts)
        self.assertNotIn("groups['k8s_masters']", alerts)
        self.assertNotIn("aggType: cardinality", alerts)
        self.assertNotIn('threshold: "{{ [', alerts)
        self.assertNotIn("- {{ kibana_alert_ns_error_threshold | int }}", alerts)
        self.assertIn("to_json | from_json", alerts)
        self.assertIn("kibana_alert_threshold_ns", alerts)
        self.assertIn('threshold: "{{ kibana_alert_threshold_ns }}"', alerts)
        self.assertIn("excludeHitsFromPreviousRun: false", alerts)
        self.assertNotIn("excludeHitsFromPreviousRun: true", alerts)
        self.assertIn("schedule: 5m", alerts)
        self.assertIn("| unique", alerts)
        self.assertIn('"kubernetes.namespace_name":"falco"', alerts)
        self.assertIn('"atlas_severity":["error","warn"]', alerts)
        self.assertIn('"atlas_severity":"error"', alerts)
        self.assertIn("log_processed.rule", alerts)
        self.assertNotIn("kube-audit", alerts)
        falco = (
            REPO_ROOT / "roles" / "810_falco" / "templates" / "falco_values.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("json_output: true", falco)
        self.assertIn("kibana_logs_system_namespaces:", catalog)
        self.assertIn("kibana_alert_ns_error_threshold: 200", catalog)
        self.assertIn("kibana_alert_falco_threshold: 50", catalog)
        defaults = (
            REPO_ROOT / "roles" / "992_kibana_dashboards" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("kibana_alert_ns_error_threshold: 200", defaults)
        self.assertIn("kibana_alert_apiserver_error_threshold: 50", defaults)
        self.assertIn("kibana_alert_falco_threshold: 50", defaults)
        self.assertIn("kibana_alert_ceph_error_threshold: 50", defaults)
        self.assertNotIn("kibana_alert_expected_node_count", catalog)
        ilm = (
            REPO_ROOT / "roles" / "620_elasticsearch" / "tasks" / "logging_ilm.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("MESSAGE:", ilm)
        self.assertIn("ignore_above: 32766", ilm)
        self.assertIn("ignore_above: 1024", ilm)

    def test_elasticsearch_wait_ready_uses_authenticate_not_401(self) -> None:
        """ES ready is reserved-user authenticate, not unauthenticated HTTP 401."""
        wait = (
            REPO_ROOT / "roles" / "620_elasticsearch" / "tasks" / "wait_ready.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("/_security/_authenticate", wait)
        self.assertIn("no_log: true", wait)
        defaults = (
            REPO_ROOT / "roles" / "620_elasticsearch" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("elasticsearch_wait_retries:", defaults)
        self.assertIn("elasticsearch_wait_delay:", defaults)
        tasks = (
            REPO_ROOT / "roles" / "620_elasticsearch" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("wait_ready.yml", tasks)
        self.assertNotIn("status_code: 401", tasks)
        kibana = (
            REPO_ROOT / "roles" / "640_kibana" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        tracing = (
            REPO_ROOT / "roles" / "730_tracing" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("status_code: 401", kibana)
        self.assertNotIn("status_code: 401", tracing)
        self.assertIn("tasks_from: wait_ready.yml", kibana)
        self.assertIn("tasks_from: wait_ready.yml", tracing)

    def test_thanos_community_chart_receive_and_prometheus_remote_write(self) -> None:
        """450_thanos uses thanos-community chart + Receive; Prometheus has no sidecar."""
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("name: thanos-community", catalog)
        self.assertIn("thanos-community.github.io/helm-charts", catalog)
        self.assertIn("thanos_chart_state: present", catalog)
        self.assertIn('thanos_chart_version: "0.32.0"', catalog)
        self.assertIn("thanos_obc_name: thanos-blocks", catalog)
        self.assertIn("thanos_receive_remote_write_url:", catalog)
        secrets = (
            REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.secrets.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("thanos_s3", secrets)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", secrets)
        values = (
            REPO_ROOT / "roles" / "450_thanos" / "templates" / "thanos.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("receive:", values)
        self.assertIn("query:", values)
        self.assertIn("storegateway:", values)
        self.assertIn("compactor:", values)
        self.assertIn("kube-prometheus-stack:", values)
        self.assertRegex(values, r"(?m)^kube-prometheus-stack:\n  enabled: false\s*$")
        self.assertIn("createSecret: false", values)
        self.assertNotIn("bitnami", values.lower())
        tasks = (REPO_ROOT / "roles" / "450_thanos" / "tasks" / "main.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("thanos-community/thanos", tasks)
        self.assertIn("objstore.yml", tasks)
        objstore = (REPO_ROOT / "roles" / "450_thanos" / "tasks" / "objstore.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("kind: ObjectBucketClaim", objstore)
        self.assertIn("bucket_lookup_type: path", objstore)
        self.assertIn("type: S3", objstore)
        self.assertIn("thanos_s3_endpoint_port", objstore)
        self.assertIn("insecure_skip_verify", objstore)
        self.assertIn("default(thanos_s3_region, true)", objstore)
        self.assertNotIn("BUCKET_PORT", objstore)
        prom = (
            REPO_ROOT / "roles" / "310_prometheus" / "templates" / "prometheus.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("remoteWrite:", prom)
        self.assertIn("thanos_receive_remote_write_url", prom)
        self.assertIn("additionalDataSources:", prom)
        self.assertIn("name: Thanos", prom)
        self.assertIn("isDefault: false", prom)
        self.assertNotIn("thanosService", prom)
        self.assertNotIn("objectStorageConfig", prom)
        self.assertNotIn("\n    thanos:", prom)

    def test_envoy_gateway_replaces_ingress_nginx(self) -> None:
        """520_envoy_gateway is OCI Helm; north-south is Gateway API, not ingress-nginx."""
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("envoy_gateway_namespace: envoy-gateway-system", catalog)
        self.assertIn("oci://docker.io/envoyproxy/gateway-helm", catalog)
        self.assertIn('envoy_gateway_chart_version: "v1.8.3"', catalog)
        self.assertNotIn("name: ingress-nginx", catalog)
        self.assertNotIn("ingress_nginx_namespace", catalog)
        playbook = (REPO_ROOT / "playbooks" / "cluster_addons.yaml").read_text(
            encoding="utf-8"
        )
        roles = re.findall(
            r"^\s+- role: (510_metallb|520_envoy_gateway|530_external_dns)\s*$",
            playbook,
            re.M,
        )
        self.assertEqual(roles, ["510_metallb", "520_envoy_gateway", "530_external_dns"])
        self.assertNotIn("41_ingress_nginx", playbook)
        self.assertTrue(
            (REPO_ROOT / "roles" / "520_envoy_gateway" / "tasks" / "main.yaml").is_file()
        )
        self.assertFalse((REPO_ROOT / "roles" / "41_ingress_nginx").exists())
        tasks = (
            REPO_ROOT / "roles" / "520_envoy_gateway" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("envoy_gateway_chart_oci", tasks)
        self.assertIn("--set crds.enabled=true", tasks)
        routes = (
            REPO_ROOT
            / "roles"
            / "560_apply_ingress"
            / "templates"
            / "gateway-routes.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("kind: HTTPRoute", routes)
        self.assertIn("kind: TLSRoute", routes)
        self.assertIn("kind: Gateway", routes)
        self.assertIn("kind: EnvoyPatchPolicy", routes)
        self.assertIn("max_request_headers_kb", routes)
        self.assertIn("name: tcp-443", routes)
        self.assertIn("name: tcp-80", routes)
        self.assertIn(
            "/default_filter_chain/filters/0/typed_config/max_request_headers_kb",
            routes,
        )
        self.assertIn(".*https-.*", routes)
        self.assertNotIn("kind: Backend", routes)
        self.assertNotIn("insecureSkipVerify", routes)
        self.assertIn("port: {{ ing.port }}", routes)
        self.assertIn("https-{{ ing.name", routes)
        self.assertIn("oidc_auth", routes)
        self.assertNotIn("kind: ClientTrafficPolicy", routes)
        self.assertNotIn("bufferLimit", routes)
        self.assertNotIn(
            'hostname: "*.{{ k8s_cluster_domain }}"',
            routes,
        )
        self.assertNotIn("ingressClassName", routes)
        self.assertNotIn("nginx.ingress.kubernetes.io", routes)
        apply45 = (
            REPO_ROOT / "roles" / "560_apply_ingress" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("Ensure namespaces for gateway routes", apply45)
        self.assertIn("Wait for wildcard Certificate Ready", apply45)
        self.assertIn("Wait for Envoy Gateway Programmed", apply45)
        self.assertIn("Wait for Envoy Gateway LoadBalancer IP", apply45)
        self.assertIn("delete clienttrafficpolicy", apply45)
        self.assertIn("delete backend rook-ceph-mgr-dashboard", apply45)
        self.assertIn("Wait for EnvoyPatchPolicy max-headers Programmed", apply45)
        self.assertIn("Fail if EnvoyPatchPolicy max-headers is not Programmed", apply45)
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        self.assertRegex(
            catalog,
            r"(?s)name: rook-ceph-mgr-dashboard\n.*?port: 7000\n",
            "Rook dashboard HTTPRoute must use Service.port 7000",
        )
        self.assertNotIn("service_port_name:", catalog)
        rook_app = re.search(
            r"(?ms)^  - name: rook-ceph-mgr-dashboard\n(?:    .+\n)+",
            catalog,
        )
        self.assertIsNotNone(rook_app, "rook-ceph-mgr-dashboard app missing")
        self.assertNotIn("8443", rook_app.group(0))
        eg_tasks = (
            REPO_ROOT / "roles" / "520_envoy_gateway" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("crd/envoypatchpolicies.gateway.envoyproxy.io", eg_tasks)
        self.assertIn("Wait for Envoy Gateway Programmed", eg_tasks)
        eg_values = (
            REPO_ROOT
            / "roles"
            / "520_envoy_gateway"
            / "templates"
            / "envoy-gateway.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("enableEnvoyPatchPolicy: true", eg_values)
        self.assertIn("XDSNameSchemeV2", eg_values)
        sm = (
            REPO_ROOT
            / "roles"
            / "520_envoy_gateway"
            / "templates"
            / "envoy-gateway-servicemonitor.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("kind: ServiceMonitor", sm)
        self.assertIn("kind: PodMonitor", sm)
        self.assertIn("/stats/prometheus", sm)
        dns = (
            REPO_ROOT
            / "roles"
            / "530_external_dns"
            / "templates"
            / "external-dns.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("gateway-httproute", dns)
        self.assertIn("gateway-tlsroute", dns)
        self.assertNotRegex(dns, r"(?m)^\s+- ingress\s*$")
        for rel in (
            "roles/960_oauth2_proxy/templates/oauth2.yaml.j2",
            "roles/962_headlamp/templates/headlamp_values.yaml.j2",
            "roles/950_mailu/templates/mailu_values.yaml.j2",
            "roles/840_trivy/templates/trivy_values.yaml.j2",
            "roles/954_opencost/templates/opencost_values.yaml.j2",
            "roles/971_vault/templates/vault.yaml.j2",
            "roles/740_kiali/templates/kiali.yaml.j2",
            "roles/730_tracing/templates/jaeger.yaml.j2",
            "roles/810_falco/templates/falco_values.yaml.j2",
            "roles/800_chaos_mesh/templates/chaos_mesh_values.yaml.j2",
            "roles/982_argocd_rollouts/templates/argo-rollouts.yaml.j2",
            "roles/820_kyverno/templates/kyverno.yaml.j2",
            "roles/830_policy_reporter/templates/policy-reporter.yaml.j2",
        ):
            text = (REPO_ROOT / rel).read_text(encoding="utf-8")
            self.assertNotIn("ingressClassName: nginx", text, rel)
            self.assertNotIn("class_name: nginx", text, rel)
            self.assertNotIn("class: nginx", text, rel)
        oidc = (
            REPO_ROOT
            / "roles"
            / "961_apply_oidc_ingress"
            / "templates"
            / "oidc-securitypolicy.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("kind: SecurityPolicy", oidc)
        self.assertIn("oidc:", oidc)
        self.assertIn("authorizationEndpoint:", oidc)
        self.assertIn("tokenEndpoint:", oidc)
        self.assertIn("endSessionEndpoint:", oidc)
        self.assertIn("http://keycloak-http.", oidc)
        self.assertIn("remoteJWKS:", oidc)
        self.assertIn("claimToHeaders:", oidc)
        self.assertIn("backendRefs:", oidc)
        self.assertIn("disableTokenEncryption: true", oidc)
        self.assertIn("kind: BackendTLSPolicy", oidc)
        self.assertIn("ing.backend_tls", oidc)
        self.assertNotIn(
            "{{ oidc_issuer_url }}/protocol/openid-connect/certs",
            oidc,
        )
        self.assertNotIn("extAuth:", oidc)
        self.assertFalse(
            (
                REPO_ROOT
                / "roles"
                / "960_oauth2_proxy"
                / "templates"
                / "oauth2-extauth.yaml.j2"
            ).is_file()
        )
        grafana = (
            REPO_ROOT / "roles" / "310_prometheus" / "templates" / "prometheus.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("https://{{ grafana_host }}/logout", grafana)
        self.assertIn("envoy_gateway_namespace", grafana)
        self.assertNotIn("role: ingress", grafana)
        self.assertIn("static_configs:", grafana)
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("oidc_auth: true", catalog)
        self.assertNotIn("oauth2_auth:", catalog)
        self.assertNotIn("tls_secret:", catalog)
        self.assertNotIn("proxy_buffer_size:", catalog)
        self.assertIn("envoy_gateway_oidc_client_secret", catalog)
        self.assertIn("vault_oidc_client_secret", catalog)
        kiali_app = re.search(
            r"(?m)^  - name: kiali\n(?:    .+\n)+",
            catalog,
        )
        self.assertIsNotNone(kiali_app, "kiali ingress missing")
        self.assertIn("oidc_auth: true", kiali_app.group(0))
        kiali_cr = (
            REPO_ROOT / "roles" / "740_kiali" / "templates" / "kiali.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn('strategy: "anonymous"', kiali_cr)
        self.assertNotIn("openid", kiali_cr)
        self.assertIn("datasource_uid: prometheus", kiali_cr)
        self.assertIn('url: "https://{{ grafana_host }}"', kiali_cr)
        for title in (
            "Istio Service Dashboard",
            "Istio Workload Dashboard",
            "Istio Mesh Dashboard",
            "Istio Control Plane Dashboard",
        ):
            self.assertIn(title, kiali_cr)
        self.assertNotIn("Istio Performance Dashboard", kiali_cr)
        self.assertNotIn("Istio Wasm Extension Dashboard", kiali_cr)

    def test_alertmanager_gateway_oidc_and_smtp_email(self) -> None:
        """Alertmanager: chart Ingress off; Envoy OIDC HTTPRoute; SMTP email; Watchdog to null."""
        helm = (
            REPO_ROOT / "roles" / "310_prometheus" / "templates" / "prometheus.yaml.j2"
        ).read_text(encoding="utf-8")
        am = helm.split("alertmanager:", 1)[1].split("prometheus:", 1)[0]
        self.assertIn("enabled: true", am)
        self.assertIn("ingress:\n    enabled: false", am)
        self.assertIn("email_configs:", am)
        self.assertIn("smtp_smarthost:", am)
        self.assertIn("alertmanager_mail.host", am)
        self.assertIn("k8s_secrets.alertmanager_smtp_password", am)
        self.assertIn("insecure_skip_verify", am)
        self.assertIn("alertname = Watchdog", am)
        self.assertIn('receiver: "null"', am)
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'alertmanager_host: "alertmanager.{{ k8s_cluster_domain }}"',
            catalog,
        )
        self.assertIn("alertmanager_mail:", catalog)
        am_app = re.search(
            r"(?m)^  - name: prometheus-kube-prometheus-alertmanager\n(?:    .+\n)+",
            catalog,
        )
        self.assertIsNotNone(am_app, "alertmanager ingress missing")
        self.assertIn("oidc_auth: true", am_app.group(0))
        self.assertIn("port: 9093", am_app.group(0))
        self.assertIn("alertmanager_smtp_password: \"{{ alertmanager_smtp_password }}\"", catalog)
        secrets = (
            REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.secrets.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("alertmanager_smtp_password:", secrets)
        example = (REPO_ROOT / "examples" / "secrets.example.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("alertmanager_smtp_password:", example)
        self.assertIn("alertmanager_mail:", example)
        validate_hosts = (
            REPO_ROOT / "roles" / "130_validate_vars" / "tasks" / "ingress_hosts.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("alertmanager_host", validate_hosts)
        validate_secrets = (
            REPO_ROOT / "roles" / "130_validate_vars" / "tasks" / "secrets.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("k8s_secrets.alertmanager_smtp_password", validate_secrets)
        self.assertIn("alertmanager_mail.host", validate_secrets)
        report = (
            REPO_ROOT / "roles" / "996_cluster_report" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("id: alertmanager", report)
        am_report = report.split("id: alertmanager", 1)[1].split("id:", 1)[0]
        self.assertIn("host_var: alertmanager_host", am_report)
        self.assertIn("auth: oauth2", am_report)
        self.assertIn("alertmanager_mail.to", am_report)

    def test_grafana_cluster_addons_dashboards_and_scrape(self) -> None:
        """Custom Grafana folder is Cluster addons; empty nginx/sentry/trivy/old SPI gone; SM for Argo/Kyverno."""
        prom = (
            REPO_ROOT / "roles" / "310_prometheus" / "templates" / "prometheus.yaml.j2"
        ).read_text(encoding="utf-8")
        dash = (
            REPO_ROOT
            / "roles"
            / "310_prometheus"
            / "templates"
            / "grafana-dashboards.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("{% include 'grafana-dashboards.yaml.j2' %}", prom)
        self.assertIn("folder: 'Cluster addons'", prom)
        self.assertIn("name: cluster-addons", prom)
        self.assertIn("/var/lib/grafana/dashboards/cluster-addons", prom)
        self.assertIn("searchNamespace: ALL", prom)
        self.assertIn("folderAnnotation: grafana_folder", prom)
        self.assertIn('job_name: "blackbox"', prom)
        self.assertIn("regex: '/auth(/.*)'", prom)
        self.assertNotIn("provider-site", prom)
        self.assertNotIn("test777", prom)
        self.assertNotIn("test777", dash)
        self.assertRegex(prom, r"(?m)^kubeProxy:\n  enabled: false\s*$")
        self.assertRegex(
            prom,
            r"(?ms)^nodeExporter:\n  enabled: true\n  operatingSystems:\n"
            r"    linux:\n      enabled: true\n"
            r"    aix:\n      enabled: false\n"
            r"    darwin:\n      enabled: false\s*$",
        )
        for ns_var in (
            "{{ argocd_namespace }}",
            "{{ kyverno_namespace }}",
            "{{ policy_reporter_namespace }}",
        ):
            self.assertIn(ns_var, prom)
        self.assertNotIn("{{ argocd_namespace }}|{{ chaos_mesh_namespace }}", prom)
        self.assertNotIn(
            "({{ metallb_namespace }}|{{ chaos_mesh_namespace }}|{{ rook_cluster_namespace }})",
            prom,
        )
        self.assertIn(
            "({{ metallb_namespace }}|{{ rook_cluster_namespace }})",
            prom,
        )
        for dropped in (
            "gnetId: 1860",
            "gnetId: 14314",
            "gnetId: 12575",
            "gnetId: 9614",
            "gnetId: 13941",
            "gnetId: 17813",
            "gnetId: 16337",
            "gnetId: 17878",
            "gnetId: 2842",
            "gnetId: 11829",
            "gnetId: 14127",
            "gnetId: 7752",
            "gnetId: 16165",
            "7645/revisions/255",
        ):
            self.assertNotIn(dropped, prom)
            self.assertNotIn(dropped, dash)
        self.assertNotIn("16165", dash)
        self.assertNotIn("9551", dash)
        self.assertNotIn("istio-performance", dash)
        self.assertIn("grafana_gnet('vault', 12904, 2)", dash)
        self.assertIn("target_label: container", prom)
        for needle in (
            "envoy_gateway_chart_state",
            "falco_chart_state",
            "keycloak_chart_state",
            "cnpg_chart_state",
            "envoyproxy/gateway/v1.8.3",
            "ceph/ceph/main/monitoring/ceph-mixin",
            "osds-overview.json",
            "keycloak-grafana-dashboard/main",
            "cloudnative-pg/grafana-dashboards/main",
            "thanos-io/thanos/main/examples/dashboards",
            "argoproj/argo-cd/master/examples/dashboard.json",
            "argoproj/argo-rollouts/master/examples/dashboard.json",
            "oauth2-proxy",
            "external-secrets/external-secrets/main/docs/snippets/dashboard.json",
            "grafana_gnet('chaos_mesh', 15918, 1)",
            "jaegertracing/jaeger/main/monitoring/jaeger-mixin",
            "grafana_gnet('opentelemetry', 15983, 30)",
            "grafana_gnet('trivy', 17813, 2)",
            "grafana_gnet('trivy', 16337, 16)",
            "grafana_gnet('opencost', 22208, 7)",
            "istio/istio/",
            "{{ istio_chart_version }}",
            "grafana_gnet('metallb', 20162, 6)",
            "grafana_gnet('blackbox', 7587, 3)",
            "falcosecurity/charts/master",
            "projectcalico/calico",
            "typha-dashboard.json",
            "{{ calico_chart_version }}",
            "kiali_chart_state",
            "name: DS_PROMETHEUS",
            "name: DS_PROMXY",
            "name: datasource",
            "name: DS_SIGNCL-PROMETHEUS",
            "value: prometheus",
            "grafana_raw_prefix('istio')",
            "grafana_raw_prefix('ceph')",
            "grafana_raw_prefix('envoy')",
            "grafana_raw_prefix('thanos')",
            "grafana_raw_prefix('falco')",
            "grafana_raw_prefix('cnpg')",
            "grafana_raw_prefix('keycloak')",
            "grafana_raw_prefix('argocd')",
            "grafana_raw_prefix('argo_rollouts')",
            "grafana_raw_prefix('external_secrets')",
            "grafana_raw_prefix('jaeger')",
        ):
            self.assertIn(needle, dash)
        self.assertNotIn("value: Prometheus", dash)
        self.assertIn("{% macro grafana_raw_prefix(entity)", dash)
        self.assertNotIn("url: https://raw.githubusercontent.com/", dash)
        self.assertNotIn("grafana_raw_prefix('calico')", dash)
        self.assertNotIn("grafana_raw_prefix('metallb')", dash)
        oauth2_block = re.search(
            r"{% if oauth2_proxy_chart_state[^\n]*\n(?:.*\n)*?{% endif %}",
            dash,
        )
        self.assertIsNotNone(oauth2_block, "oauth2_proxy_chart_state dashboard gate missing")
        self.assertIn("oauth2-proxy", oauth2_block.group(0))
        self.assertNotIn("url:", oauth2_block.group(0))
        self.assertNotIn("gnetId", oauth2_block.group(0))
        kiali_block = re.search(
            r"{% if kiali_chart_state[^\n]*\n(?:.*\n)*?{% endif %}",
            dash,
        )
        self.assertIsNotNone(kiali_block, "kiali_chart_state dashboard gate missing")
        self.assertIn("kiali", kiali_block.group(0))
        self.assertNotIn("url:", kiali_block.group(0))
        self.assertNotIn("gnetId", kiali_block.group(0))
        prom_tasks = (
            REPO_ROOT / "roles" / "310_prometheus" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("extract_calico_typha_dashboard.py", prom_tasks)
        self.assertIn("calico_grafana_dashboards_manifest_url", prom_tasks)
        self.assertIn("grafana_folder='Cluster addons'", prom_tasks)
        self.assertIn("grafana-dashboard-calico-typha", prom_tasks)
        prom_defaults = (
            REPO_ROOT / "roles" / "310_prometheus" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("projectcalico/calico/{{ calico_chart_version }}", prom_defaults)
        self.assertIn("manifests/grafana-dashboards.yaml", prom_defaults)
        self.assertIn("grafana_dashboard_source", prom_defaults)
        self.assertIn("calico_typha", prom_defaults)
        self.assertIn("grafana_dashboard_infra_base", prom_defaults)
        self.assertIn("https://raw.githubusercontent.com", prom_defaults)
        self.assertFalse(
            any((REPO_ROOT / "roles" / "310_prometheus").rglob("*.json")),
            "do not vendor Typha/Felix Grafana JSON in git",
        )
        calico_sm = (
            REPO_ROOT
            / "roles"
            / "340_calico_metrics"
            / "templates"
            / "calico-metrics.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("targetLabel: job", calico_sm)
        self.assertIn("replacement: typha_metrics", calico_sm)
        eso_values = (
            REPO_ROOT
            / "roles"
            / "972_external_secrets"
            / "templates"
            / "external-secrets.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("serviceMonitor:", eso_values)
        self.assertIn("enabled: true", eso_values)
        eso_tasks = (
            REPO_ROOT / "roles" / "972_external_secrets" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "-f {{ k8s_manifests_dir }}/external-secrets.yaml",
            eso_tasks,
        )
        rollouts = (
            REPO_ROOT
            / "roles"
            / "982_argocd_rollouts"
            / "templates"
            / "argo-rollouts.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("serviceMonitor:\n      enabled: true", rollouts)
        chaos_values = (
            REPO_ROOT
            / "roles"
            / "800_chaos_mesh"
            / "templates"
            / "chaos_mesh_values.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("scrape:\n      enabled: false", chaos_values)
        chaos_sm = (
            REPO_ROOT
            / "roles"
            / "800_chaos_mesh"
            / "templates"
            / "chaos-mesh-servicemonitor.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("kind: ServiceMonitor", chaos_sm)
        es_exporter = (
            REPO_ROOT
            / "roles"
            / "620_elasticsearch"
            / "templates"
            / "elasticsearch-exporter.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertRegex(es_exporter, r"(?m)^serviceMonitor:\n  enabled: true\s*$")
        es_tasks = (
            REPO_ROOT / "roles" / "620_elasticsearch" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("elasticsearch-exporter-servicemonitor.yaml.j2", es_tasks)
        self.assertNotIn(
            "kubectl --validate=false apply -f {{ k8s_manifests_dir }}/elasticsearch-exporter-servicemonitor.yaml",
            es_tasks,
        )
        self.assertIn("- name: elasticsearch-exporter", es_tasks)
        self.assertIn(
            "kubectl delete servicemonitor elasticsearch-exporter",
            es_tasks,
        )
        self.assertFalse(
            (
                REPO_ROOT
                / "roles"
                / "620_elasticsearch"
                / "templates"
                / "elasticsearch-exporter-servicemonitor.yaml.j2"
            ).is_file()
        )
        otel = (
            REPO_ROOT
            / "roles"
            / "730_tracing"
            / "templates"
            / "open-telemetry.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("serviceMonitor:", otel)
        self.assertIn("ports:", otel)
        self.assertRegex(otel, r"(?ms)^ports:\n  metrics:\n    enabled: true\s*$")
        self.assertRegex(otel, r"(?m)^serviceMonitor:\n  enabled: true\s*$")
        self.assertIn("- {{ argo_rollouts_namespace }}", prom)
        self.assertIn("- {{ chaos_mesh_namespace }}", prom)
        for pinned in (
            "falco-5.0.0",
            "v0.37.2",
            "v3.1.0",
            "v20.2.1",
            "cluster-v0.0.5",
            "keycloak-grafana-dashboard/26.2.0",
            "datasource: Prometheus",
        ):
            self.assertNotIn(pinned, dash)
        argocd = (
            REPO_ROOT / "roles" / "980_argocd" / "templates" / "argocd.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertGreaterEqual(argocd.count("serviceMonitor:\n      enabled: true"), 5)
        self.assertIn("argocd-server-metrics", argocd)
        self.assertIn("argocd-application-controller-metrics", argocd)
        self.assertIn("argocd-repo-server-metrics", argocd)
        self.assertIn("argocd-applicationset-controller-metrics", argocd)
        self.assertIn("argocd-notifications-controller-metrics", argocd)
        self.assertIn("addPrometheusAnnotations: false", argocd)
        kyverno = (
            REPO_ROOT / "roles" / "820_kyverno" / "templates" / "kyverno.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertGreaterEqual(kyverno.count("serviceMonitor:\n    enabled: true"), 4)
        self.assertRegex(kyverno, r"(?m)^grafana:\n  enabled: true\s*$")
        reporter = (
            REPO_ROOT
            / "roles"
            / "830_policy_reporter"
            / "templates"
            / "policy-reporter.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertRegex(reporter, r"(?m)^metrics:\n  enabled: true\s*$")
        self.assertRegex(reporter, r"(?m)^monitoring:\n  enabled: true\s*$")
        self.assertIn("grafana_dashboard", reporter)
        self.assertRegex(reporter, r"(?m)^grafana:\n  dashboards:\n    enabled: true\s*$")
        keycloak = (
            REPO_ROOT / "roles" / "920_keycloak" / "templates" / "keycloak.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("KC_HTTP_METRICS_HISTOGRAMS_ENABLED", keycloak)

    def test_grafana_dashboard_source_switch(self) -> None:
        """Catalog github/grafana defaults; prefix macro; validate keys/enum/infra_base."""
        github_native = (
            "istio",
            "ceph",
            "envoy",
            "thanos",
            "falco",
            "cnpg",
            "keycloak",
            "argocd",
            "argo_rollouts",
            "external_secrets",
            "jaeger",
            "calico_typha",
        )
        grafana_native = (
            "calico",
            "metallb",
            "vault",
            "fluentbit",
            "cert_manager",
            "elasticsearch",
            "blackbox",
            "consul",
            "external_dns",
            "chaos_mesh",
            "opentelemetry",
            "trivy",
            "opencost",
        )
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('grafana_dashboard_infra_base: ""', catalog)
        src_block = re.search(
            r"(?ms)^grafana_dashboard_source:\n((?:[ \t]+.*\n)+)",
            catalog,
        )
        self.assertIsNotNone(src_block, "grafana_dashboard_source mapping missing")
        mapping = src_block.group(1)
        for key in github_native:
            self.assertRegex(
                mapping,
                rf"(?m)^  {key}: github\s*$",
                f"catalog default {key} must be github",
            )
            self.assertNotRegex(mapping, rf"(?m)^  {key}: grafana\s*$")
        for key in grafana_native:
            self.assertRegex(
                mapping,
                rf"(?m)^  {key}: grafana\s*$",
                f"catalog default {key} must be grafana",
            )
            self.assertNotRegex(mapping, rf"(?m)^  {key}: github\s*$")
            self.assertNotRegex(mapping, rf"(?m)^  {key}: infra\s*$")
        dash = (
            REPO_ROOT
            / "roles"
            / "310_prometheus"
            / "templates"
            / "grafana-dashboards.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("{% macro grafana_raw_prefix(entity)", dash)
        self.assertIn("{% macro grafana_gnet(entity, gnet_id, revision, emit_revision=true)", dash)
        self.assertIn("https://raw.githubusercontent.com", dash)
        self.assertIn("grafana_dashboard_infra_base", dash)
        self.assertIn("src == 'infra'", dash)
        self.assertIn("/api/dashboards/{{ gnet_id }}/revisions/{{ revision }}/download", dash)
        self.assertIn("gnetId: {{ gnet_id }}", dash)
        self.assertNotIn("url: https://raw.githubusercontent.com/", dash)
        for key in github_native:
            if key == "calico_typha":
                self.assertIn("grafana_dashboard_source.calico_typha", dash)
                continue
            self.assertIn(f"grafana_raw_prefix('{key}')", dash)
        for key in grafana_native:
            self.assertNotIn(f"grafana_raw_prefix('{key}')", dash)
            self.assertIn(f"grafana_gnet('{key}'", dash)
        for gnet in (
            "grafana_gnet('calico', 3244, 1)",
            "grafana_gnet('calico', 12175, 7)",
            "grafana_gnet('metallb', 20162, 6)",
            "grafana_gnet('vault', 12904, 2)",
            "grafana_gnet('fluentbit', 18855, 1)",
            "grafana_gnet('cert_manager', 20340, 1, emit_revision=false)",
            "grafana_gnet('elasticsearch', 14191, 1)",
            "grafana_gnet('blackbox', 7587, 3)",
            "grafana_gnet('consul', 13396, 3)",
            "grafana_gnet('external_dns', 15038, 3)",
            "grafana_gnet('chaos_mesh', 15918, 1)",
            "grafana_gnet('opentelemetry', 15983, 30)",
            "grafana_gnet('trivy', 17813, 2)",
            "grafana_gnet('trivy', 16337, 16)",
            "grafana_gnet('opencost', 22208, 7)",
        ):
            self.assertIn(gnet, dash)
        validate_main = (
            REPO_ROOT / "roles" / "130_validate_vars" / "tasks" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("include_tasks: grafana_dashboards.yml", validate_main)
        validate = (
            REPO_ROOT / "roles" / "130_validate_vars" / "tasks" / "grafana_dashboards.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("grafana_dashboard_github_native_keys", validate)
        self.assertIn("grafana_dashboard_grafana_native_keys", validate)
        self.assertIn("in grafana_dashboard_source_github_native_values", validate)
        self.assertIn("in grafana_dashboard_source_grafana_native_values", validate)
        self.assertIn("must be grafana or infra", validate)
        self.assertIn(
            "'infra' in (grafana_dashboard_source | dict2items | map(attribute='value') | list)",
            validate,
        )
        self.assertIn("grafana_dashboard_infra_base", validate)
        defaults = (
            REPO_ROOT / "roles" / "130_validate_vars" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        for key in github_native:
            self.assertIn(f"- {key}", defaults)
        for key in grafana_native:
            self.assertIn(f"- {key}", defaults)
        self.assertIn("- github", defaults)
        self.assertIn("- infra", defaults)
        self.assertIn("- grafana", defaults)

    def test_extract_calico_typha_dashboard_rewrites_demo_uids(self) -> None:
        """Official Calico ConfigMap Typha JSON is extracted; demo datasource UIDs become prometheus."""
        script = (
            REPO_ROOT
            / "roles"
            / "310_prometheus"
            / "files"
            / "extract_calico_typha_dashboard.py"
        )
        src = """
apiVersion: v1
kind: ConfigMap
data:
  felix-dashboard.json: |-
    {"uid": "beft70ojnzsw0e", "title": "Calico: Felix"}
  typha-dashboard.json: |-
    {"title": "Calico Typha", "uid": "calico-typha-dashboard", "panels": [{"datasource": {"uid": "calico-demo-prometheus"}}, {"datasource": {"uid": "P11C5FC3F3B681947"}}]}
"""
        with tempfile.TemporaryDirectory() as tmp:
            src_path = Path(tmp) / "grafana-dashboards.yaml"
            dst_path = Path(tmp) / "typha-dashboard.json"
            src_path.write_text(src, encoding="utf-8")
            subprocess.run(
                ["python3", str(script), str(src_path), str(dst_path)],
                check=True,
            )
            data = json.loads(dst_path.read_text(encoding="utf-8"))
        self.assertEqual(data["title"], "Calico Typha")
        blob = json.dumps(data)
        self.assertIn('"uid": "prometheus"', blob)
        self.assertNotIn("calico-demo-prometheus", blob)
        self.assertNotIn("P11C5FC3F3B681947", blob)
        self.assertNotIn("beft70ojnzsw0e", blob)

    def test_rook_cluster_pins_objectstore_and_ceph_bucket_sc(self) -> None:
        """RGW + StorageClass ceph-bucket must be SoT in values, not an implicit chart default."""
        values = (
            REPO_ROOT
            / "roles"
            / "430_rook_cluster"
            / "templates"
            / "rook_cluster_values.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("cephObjectStores:", values)
        self.assertIn("name: ceph-objectstore", values)
        self.assertIn("name: ceph-bucket", values)
        self.assertIn("securePort:", values)
        self.assertIn("sslCertificateRef:", values)
        self.assertRegex(values, r"(?m)^\s+enabled: true\s*$")
        tls_tasks = (REPO_ROOT / "roles" / "430_rook_cluster" / "tasks" / "rgw_tls.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("rook_rgw_https_secret", tls_tasks)
        self.assertIn("openssl", tls_tasks)
        main_tasks = (REPO_ROOT / "roles" / "430_rook_cluster" / "tasks" / "main.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("rgw_tls.yml", main_tasks)

    def test_rook_cephfs_storageclass_sets_csi_secrets(self) -> None:
        """CephFS SC must pin CSI secrets; fstype xfs is RBD copypasta and must stay off."""
        values = (
            REPO_ROOT
            / "roles"
            / "430_rook_cluster"
            / "templates"
            / "rook_cluster_values.yaml.j2"
        ).read_text(encoding="utf-8")
        cephfs = values.split("cephFileSystems:", 1)[1].split(
            "cephFileSystemVolumeSnapshotClass:", 1
        )[0]
        self.assertIn("name: ceph-filesystem", cephfs)
        self.assertIn(
            "csi.storage.k8s.io/provisioner-secret-name: rook-csi-cephfs-provisioner",
            cephfs,
        )
        self.assertIn(
            "csi.storage.k8s.io/node-stage-secret-name: rook-csi-cephfs-node",
            cephfs,
        )
        self.assertIn("rook_cluster_namespace", cephfs)
        self.assertNotIn("fstype: xfs", cephfs)
        self.assertIn("csi.storage.k8s.io/fstype: ext4", values)

    def test_keycloak_kc26_default_scopes_omit_openid(self) -> None:
        """KC 26: Admin API has no openid client scope; basic replaces the old slot."""
        tf = (
            REPO_ROOT / "roles" / "930_keycloak_realm" / "templates" / "main.tf.j2"
        ).read_text(encoding="utf-8")
        locals_block = re.search(
            r"(?s)kc26_oidc_builtin_default_scopes = \[(.*?)\]",
            tf,
        )
        self.assertIsNotNone(locals_block, "kc26_oidc_builtin_default_scopes missing")
        builtins = locals_block.group(1)
        for name in ("basic", "profile", "email", "roles", "web-origins"):
            self.assertIn(f'"{name}"', builtins)
        self.assertNotIn('"openid"', builtins)

        expected = {
            "oauth2_proxy_defaults": 'concat(local.kc26_oidc_builtin_default_scopes, ["aud-oauth2-proxy"])',
            "envoy_gateway_defaults": 'concat(local.kc26_oidc_builtin_default_scopes, ["aud-envoy-gateway"])',
            "vault_defaults": 'concat(local.kc26_oidc_builtin_default_scopes, ["aud-vault"])',
            "argocd_defaults": 'concat(local.kc26_oidc_builtin_default_scopes, ["aud-argocd"])',
            "kubernetes_defaults": 'concat(local.kc26_oidc_builtin_default_scopes, ["aud-kubernetes"])',
        }
        for resource, assignment in expected.items():
            block = re.search(
                rf'(?s)resource "keycloak_openid_client_default_scopes" "{resource}".*?\n  \}}',
                tf,
            )
            self.assertIsNotNone(block, f"{resource} missing")
            body = block.group(0)
            self.assertIn(assignment, body)
            self.assertNotIn('"openid"', body)
        self.assertNotIn("aud-kasten", tf)

        securitypolicy = (
            REPO_ROOT
            / "roles"
            / "961_apply_oidc_ingress"
            / "templates"
            / "oidc-securitypolicy.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("\n      - openid\n", securitypolicy)
        bootstrap = (
            REPO_ROOT / "roles" / "971_vault" / "templates" / "vault-bootstrap.sh.j2"
        ).read_text(encoding="utf-8")
        self.assertIn('"oidc_scopes": "openid,profile,email"', bootstrap)
        argocd = (
            REPO_ROOT / "roles" / "980_argocd" / "templates" / "argocd.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("requestedScopes:\n        - openid", argocd)

    def test_keycloak_realm_import_skips_resources_without_importer(self) -> None:
        """Provider 5.8.0 cannot import default_scopes or group_memberships; apply reconciles."""
        tasks = (
            REPO_ROOT / "roles" / "930_keycloak_realm" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        loop = re.search(
            r"(?s)name: Terraform import existing Keycloak resources.*?loop:\n((?:            - \{ address: .+\n)+)",
            tasks,
        )
        self.assertIsNotNone(loop, "terraform import loop missing")
        addrs = loop.group(1)
        self.assertNotIn("keycloak_openid_client_default_scopes.", addrs)
        self.assertNotIn("keycloak_group_memberships.", addrs)
        for identity in (
            "keycloak_openid_client.oauth2_proxy_client",
            "keycloak_openid_client.envoy_gateway_client",
            "keycloak_openid_client.vault_client",
            "keycloak_openid_client.argocd_client",
            "keycloak_openid_client.kubernetes_client",
            "keycloak_group.vault_admins",
            "keycloak_group.argocd_admins",
            "keycloak_group.k8s_admins",
            "keycloak_openid_group_membership_protocol_mapper.vault_groups",
            "keycloak_openid_group_membership_protocol_mapper.argocd_groups",
            "keycloak_openid_group_membership_protocol_mapper.kubernetes_groups",
            "keycloak_openid_client.pinniped_supervisor_client",
            "keycloak_openid_client_scope.aud_pinniped_supervisor_scope",
            "keycloak_openid_audience_protocol_mapper.aud_pinniped_supervisor_mapper",
            "keycloak_openid_group_membership_protocol_mapper.pinniped_supervisor_groups",
            "keycloak_role.argocd_access",
            "keycloak_group_roles.argocd_admins_roles",
        ):
            self.assertIn(identity, addrs)

    def test_keycloak_realm_uses_preinstalled_terraform_provider_mirror(self) -> None:
        """71 init uses -plugin-dir when the local/krang mirror has keycloak provider."""
        tasks = (
            REPO_ROOT / "roles" / "930_keycloak_realm" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "registry.terraform.io/keycloak/keycloak",
            tasks,
        )
        self.assertIn('"-plugin-dir={{ keycloak_tf_plugin_dir }}"', tasks)
        self.assertIn("TF_PLUGIN_CACHE_DIR", tasks)
        self.assertIn("plugin_paths:", tasks)
        self.assertIn("- \"{{ keycloak_tf_plugin_dir }}\"", tasks)
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("keycloak_tf_plugin_dir:", catalog)
        self.assertIn("keycloak_tf_plugin_cache_dir:", catalog)
        self.assertIn('keycloak_tf_provider_version: "5.8.0"', catalog)
        defaults = (
            REPO_ROOT / "roles" / "930_keycloak_realm" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("keycloak_tf_plugin_dir:", defaults)
        self.assertIn("keycloak_tf_plugin_cache_dir:", defaults)
        self.assertIn("keycloak_tf_provider_version:", defaults)
        tf = (
            REPO_ROOT / "roles" / "930_keycloak_realm" / "templates" / "main.tf.j2"
        ).read_text(encoding="utf-8")
        self.assertIn('version = "{{ keycloak_tf_provider_version }}"', tf)
        self.assertIn("keycloak_oidc_username: admin", catalog)
        self.assertIn(
            'keycloak_oidc_user_email: "admin-oidc@{{ dns_domain_suffix }}"',
            catalog,
        )
        self.assertIn("keycloak_oidc_user_first_name: Admin", catalog)
        self.assertIn("keycloak_oidc_user_last_name: OIDC", catalog)
        self.assertIn('username    = "{{ keycloak_oidc_username }}"', tf)
        self.assertIn('email       = "{{ keycloak_oidc_user_email }}"', tf)
        self.assertIn(
            'first_name     = "{{ keycloak_oidc_user_first_name }}"',
            tf,
        )
        self.assertIn(
            'last_name      = "{{ keycloak_oidc_user_last_name }}"',
            tf,
        )
        self.assertNotIn("admin-oidc@{{ dns_domain_suffix }}", tf)
        self.assertIn("keycloak_oidc_username: admin", defaults)
        self.assertIn("keycloak_oidc_user_email:", defaults)

    def test_debug_tooling_binaries_stage_on_controller(self) -> None:
        """98 downloads calicoctl/istioctl/etcdctl on krang, then copies to nodes."""
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("debug_tooling_binary_source: github", catalog)
        self.assertIn('debug_tooling_binary_infra_base: ""', catalog)
        defaults = (
            REPO_ROOT / "roles" / "999_debug_tooling" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("debug_tooling_binary_source: github", defaults)
        validate_main = (
            REPO_ROOT / "roles" / "130_validate_vars" / "tasks" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("include_tasks: debug_tooling.yml", validate_main)
        validate = (
            REPO_ROOT / "roles" / "130_validate_vars" / "tasks" / "debug_tooling.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("debug_tooling_binary_source", validate)
        self.assertIn("debug_tooling_binary_infra_base", validate)
        calico = (
            REPO_ROOT / "roles" / "common" / "tasks" / "install_calicoctl_binary.yaml"
        ).read_text(encoding="utf-8")
        istio = (
            REPO_ROOT / "roles" / "common" / "tasks" / "install_istioctl_binary.yaml"
        ).read_text(encoding="utf-8")
        etcd = (
            REPO_ROOT / "roles" / "common" / "tasks" / "install_etcdctl_binary.yaml"
        ).read_text(encoding="utf-8")
        for body in (calico, istio, etcd):
            self.assertIn("delegate_to: localhost", body)
            self.assertIn("become: false", body)
            self.assertIn("controller_tls_environment", body)
            self.assertIn("debug_tooling_binary_source", body)
            self.assertIn("debug_tooling_binary_infra_base", body)
            self.assertIn("controller_staging_dir", body)
        self.assertIn("projectcalico/calico/releases/download", calico)
        self.assertIn("istio/istio/releases/download", istio)
        self.assertIn("etcd-io/etcd/releases/download", etcd)
        self.assertIn("https://github.com/projectcalico/calico/releases/download/", calico)
        self.assertIn("https://github.com/istio/istio/releases/download/", istio)
        self.assertIn("https://github.com/etcd-io/etcd/releases/download/", etcd)

    def test_vault_helm_uses_take_ownership_and_force_conflicts(self) -> None:
        """Helm 4 SSA vs vault-k8s on injector MWC caBundle; do not drop either flag."""
        text = (REPO_ROOT / "roles" / "971_vault" / "tasks" / "main.yaml").read_text(
            encoding="utf-8"
        )
        chunks = re.split(r"(?m)^\s+- name:", text)
        helming = next((c for c in chunks if c.lstrip().startswith("Helming vault\n")), None)
        self.assertIsNotNone(helming, "Helming vault task missing in 971_vault/tasks/main.yaml")
        self.assertIn("--take-ownership", helming)
        self.assertIn("--force-conflicts", helming)

    def test_vault_oidc_uses_keycloak_not_envoy_securitypolicy(self) -> None:
        """Vault UI/CLI use auth/oidc + Keycloak client vault; HTTPRoute stays without oidc_auth."""
        tf = (
            REPO_ROOT / "roles" / "930_keycloak_realm" / "templates" / "main.tf.j2"
        ).read_text(encoding="utf-8")
        self.assertIn('client_id                    = "vault"', tf)
        self.assertIn(
            "https://{{ vault_host }}/ui/vault/auth/oidc/oidc/callback",
            tf,
        )
        self.assertIn("http://localhost:8250/oidc/callback", tf)
        self.assertIn('name     = "vault-admins"', tf)
        self.assertIn('claim_name          = "groups"', tf)
        bootstrap = (
            REPO_ROOT / "roles" / "971_vault" / "templates" / "vault-bootstrap.sh.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("enable_auth oidc oidc", bootstrap)
        self.assertIn("oidc_discovery_ca_pem", bootstrap)
        self.assertIn("vault_cmd_stdin write auth/oidc/role/default", bootstrap)
        self.assertIn('"bound_audiences": "vault"', bootstrap)
        self.assertIn('"bound_claims"', bootstrap)
        self.assertIn('"groups": ["vault-admins"]', bootstrap)
        self.assertNotIn("'bound_claims={", bootstrap)
        self.assertNotIn("kubectl cp", bootstrap)
        self.assertIn("tee /tmp/vault-oidc-ca.pem", bootstrap)
        self.assertIn("vault-admins", bootstrap)
        self.assertIn("listing-visibility=unauth", bootstrap)
        self.assertIn('"oidc_scopes": "openid,profile,email"', bootstrap)
        vault_defaults = re.search(
            r'(?s)resource "keycloak_openid_client_default_scopes" "vault_defaults".*?\n  \}',
            tf,
        )
        self.assertIsNotNone(vault_defaults, "vault_defaults missing")
        self.assertIn(
            'concat(local.kc26_oidc_builtin_default_scopes, ["aud-vault"])',
            vault_defaults.group(0),
        )
        self.assertNotIn('"openid"', vault_defaults.group(0))
        unseal = (REPO_ROOT / "roles" / "971_vault" / "tasks" / "unseal.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("VAULT_OIDC_CLIENT_SECRET", unseal)
        self.assertIn("vault-oidc-ca.pem", unseal)
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        vault_app = re.search(
            r"(?m)^  - name: vault\n(?:    .+\n)+",
            catalog,
        )
        self.assertIsNotNone(vault_app, "vault ingress app missing")
        self.assertNotIn("oidc_auth", vault_app.group(0))
        self.assertIn("vault_oidc_client_secret", catalog)
        secrets = (
            REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.secrets.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("vault_oidc_client_secret:", secrets)
        example = (REPO_ROOT / "examples" / "secrets.example.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("vault_oidc_client_secret:", example)
        report = (
            REPO_ROOT / "roles" / "996_cluster_report" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("group vault-admins", report)
        self.assertIn("password_key: vault_oidc_client_secret", report)
        imports = (
            REPO_ROOT / "roles" / "930_keycloak_realm" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("keycloak_openid_client.envoy_gateway_client", imports)
        self.assertIn("keycloak_openid_client.vault_client", imports)
        self.assertIn("keycloak_group.vault_admins", imports)

    def test_argocd_oidc_uses_keycloak_not_envoy_securitypolicy(self) -> None:
        """Argo CD UI/CLI use native OIDC + Keycloak client argocd; HTTPRoute stays without oidc_auth."""
        tf = (
            REPO_ROOT / "roles" / "930_keycloak_realm" / "templates" / "main.tf.j2"
        ).read_text(encoding="utf-8")
        self.assertIn('client_id                    = "argocd"', tf)
        self.assertIn("https://{{ argocd_host }}/auth/callback", tf)
        self.assertIn("http://localhost:8085/auth/callback", tf)
        self.assertIn('name     = "argocd-admins"', tf)
        helm = (
            REPO_ROOT / "roles" / "980_argocd" / "templates" / "argocd.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("oidc.config:", helm)
        self.assertIn("clientID: argocd", helm)
        self.assertIn("$oidc.keycloak.clientSecret", helm)
        self.assertIn("rootCA:", helm)
        self.assertIn("lookup('file', k8s_manifests_dir ~ '/internal-ca.pem')", helm)
        self.assertNotIn("k8s_ca_cert_path", helm)
        self.assertIn("logoutURL:", helm)
        self.assertIn("{{token}}", helm)
        self.assertIn("{{logoutRedirectURL}}", helm)
        self.assertIn("g, argocd-admins, role:admin", helm)
        self.assertIn("scopes: '[groups]'", helm)
        self.assertRegex(helm, r"(?m)^dex:\n  enabled: false\s*$")
        argocd_client = re.search(
            r'(?s)resource "keycloak_openid_client" "argocd_client" \{.*?\n  \}\n',
            tf,
        )
        self.assertIsNotNone(argocd_client, "argocd_client missing")
        self.assertIn("direct_access_grants_enabled              = false", argocd_client.group(0))
        self.assertIn(
            "oauth2_device_authorization_grant_enabled = false",
            argocd_client.group(0),
        )
        self.assertIn("valid_post_logout_redirect_uris", argocd_client.group(0))
        self.assertIn("ignore_changes", argocd_client.group(0))
        self.assertIn("authentication_flow_binding_overrides", argocd_client.group(0))
        argocd_defaults = re.search(
            r'(?s)resource "keycloak_openid_client_default_scopes" "argocd_defaults".*?\n  \}',
            tf,
        )
        self.assertIsNotNone(argocd_defaults, "argocd_defaults missing")
        self.assertIn(
            'concat(local.kc26_oidc_builtin_default_scopes, ["aud-argocd"])',
            argocd_defaults.group(0),
        )
        self.assertNotIn('"openid"', argocd_defaults.group(0))
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        argocd_app = re.search(
            r"(?m)^  - name: argocd-server-ingress\n(?:    .+\n)+",
            catalog,
        )
        self.assertIsNotNone(argocd_app, "argocd-server-ingress missing")
        self.assertNotIn("oidc_auth", argocd_app.group(0))
        self.assertIn("argocd_oidc_client_secret", catalog)
        secrets = (
            REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.secrets.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("argocd_oidc_client_secret:", secrets)
        example = (REPO_ROOT / "examples" / "secrets.example.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("argocd_oidc_client_secret:", example)
        report = (
            REPO_ROOT / "roles" / "996_cluster_report" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("group argocd-admins", report)
        self.assertIn("password_key: argocd_oidc_client_secret", report)
        kc71_dir = REPO_ROOT / "roles" / "930_keycloak_realm"
        kc71_tasks = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted((kc71_dir / "tasks").glob("*.y*ml"))
        )
        kc71_py = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted((kc71_dir / "files").glob("*.py"))
        )
        kc71 = kc71_tasks + "\n" + kc71_py
        self.assertIn("argocd-browser", kc71)
        self.assertIn("argocd-identify", kc71)
        self.assertIn("argocd-admins-gate", kc71)
        self.assertIn("argocd-admins", kc71)
        self.assertIn("argocd-access", kc71)
        self.assertIn("keycloak_openid_client.argocd_client", kc71_tasks)
        self.assertIn("keycloak_group.argocd_admins", kc71_tasks)
        self.assertIn("keycloak_role.argocd_access", kc71_tasks)
        self.assertNotIn("combine({", kc71_tasks)
        self.assertIn("clients/", kc71_py)
        self.assertIn("json.dumps", kc71_py)
        self.assertIn("clone_executions(kc, SOURCE_BROWSER, IDENTIFY)", kc71_py)
        self.assertNotIn("auth-cookie) is None", kc71_py)
        self.assertIn("timeout=30", kc71_py)
        self.assertIn("authentication/flows/", kc71_py)
        self.assertIn("flowId", kc71_py)
        self.assertIn("unbind did not stick", kc71_py)
        self.assertIn("bind did not stick", kc71_py)
        self.assertIn("exc.status == 404", kc71_py)
        self.assertIn("dest_cfg_id == src_cfg_id", kc71_py)
        self.assertIn("created private config", kc71_py)
        self.assertIn("except Exception", kc71_py)
        self.assertIn("status file write failed", kc71_py)
        self.assertIn("did not rebind", kc71_py)
        self.assertIn("still shares", kc71_py)
        self.assertIn("authenticatorConfig", kc71_py)
        self.assertIn("may be shared with built-in browser", kc71_py)
        self.assertIn("exit code", kc71_py)
        self.assertNotRegex(
            kc71_py,
            r"dest_cfg_id == src_cfg_id:\n\s+return\n",
            "shared dest config id must POST a private copy, not return",
        )
        self.assertNotIn("Deny login unless user is in group", kc71)
        self.assertIn("realm role argocd-access", kc71_py)
        self.assertIn("KEYCLOAK_FLOW_STATUS_FILE", kc71)
        self.assertIn("argocd-browser-ensure.status", kc71)
        flow_yml = (kc71_dir / "tasks" / "argocd_browser_flow.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("default(1)", flow_yml)
        self.assertNotIn("kc_argocd_browser_ensure", flow_yml)
        self.assertIn("ansible.builtin.slurp:", flow_yml)
        self.assertIn("ansible.builtin.fail:", flow_yml)
        ensure_task = None
        slurp_task = None
        fail_task = None
        for chunk in re.split(r"(?m)^- name: ", flow_yml):
            if chunk.startswith("Ensure argocd-browser identify wrapper"):
                ensure_task = chunk
            elif chunk.startswith("Read argocd-browser flow ensure status"):
                slurp_task = chunk
            elif chunk.startswith("Fail if argocd-browser flow ensure failed"):
                fail_task = chunk
        self.assertIsNotNone(ensure_task, "ensure argocd-browser command task missing")
        self.assertIn("no_log: true", ensure_task)
        self.assertIn("ansible_python_interpreter", ensure_task)
        self.assertIn("KEYCLOAK_FLOW_STATUS_FILE", ensure_task)
        self.assertIn("failed_when: false", ensure_task)
        self.assertIn("changed_when: false", ensure_task)
        self.assertIsNotNone(slurp_task, "slurp argocd-browser status task missing")
        self.assertIn("| trim", slurp_task)
        self.assertIn("| last", slurp_task)
        self.assertIn("CHANGED", slurp_task)
        self.assertNotIn("'CHANGED' in", slurp_task)
        self.assertIsNotNone(fail_task, "fail argocd-browser task missing")
        self.assertNotIn(".rc", fail_task)
        self.assertIn("content is not defined", fail_task)
        self.assertIn("ERROR", fail_task)
        self.assertIn("status file missing", fail_task)
        self.assertIn("no_log", fail_task)
        self.assertNotRegex(
            fail_task,
            r"else 'status file missing'\s*$",
            "fail msg must explain write/no_log, not a bare status file missing",
        )
        self.assertIn("exhaustive = false", tf)
        self.assertIn("realm role argocd-access", report)
        validate = (
            REPO_ROOT / "roles" / "130_validate_vars" / "tasks" / "secrets.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("k8s_secrets.argocd_oidc_client_secret", validate)

        ca_common = (
            REPO_ROOT / "roles" / "common" / "tasks" / "download_internal_ca.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("ansible.builtin.get_url:", ca_common)
        self.assertIn("pki_ca_url", ca_common)
        self.assertIn("validate_certs: false", ca_common)
        self.assertIn("force: true", ca_common)
        self.assertIn("internal-ca.pem", ca_common)
        self.assertIn("checksum_algorithm: sha256", ca_common)
        self.assertEqual(ca_common.count("checksum_algorithm: sha256"), 2)
        self.assertIn("changed_when:", ca_common)
        self.assertNotIn("checksum_dest", ca_common)
        self.assertIn("download_internal_ca_after", ca_common)
        retrieve_task = None
        download_ca_task = None
        for chunk in re.split(r"(?m)^- name: ", ca_common):
            if chunk.startswith("Retrieve Internal CA from PKI"):
                retrieve_task = chunk
            elif chunk.startswith("Download Internal CA bundle"):
                download_ca_task = chunk
        self.assertIsNotNone(retrieve_task, "Retrieve Internal CA from PKI task missing")
        self.assertIn("ansible.builtin.get_url:", retrieve_task)
        self.assertIn("changed_when: false", retrieve_task)
        self.assertIsNotNone(
            download_ca_task, "Download Internal CA bundle recap task missing"
        )
        self.assertIn("ansible.builtin.stat:", download_ca_task)
        self.assertIn("download_internal_ca_after", download_ca_task)
        self.assertIn("download_internal_ca_before.stat.checksum", download_ca_task)
        self.assertIn("changed_when:", download_ca_task)
        vault_unseal = (
            REPO_ROOT / "roles" / "971_vault" / "tasks" / "unseal.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("download_internal_ca.yaml", vault_unseal)
        self.assertIn("vault-oidc-ca.pem", vault_unseal)
        self.assertIn("Load Internal CA for", vault_unseal)
        self.assertNotIn("Download Internal CA for", vault_unseal)
        for role in (
            "980_argocd",
            "320_blackbox",
            "540_cert_manager",
        ):
            tasks = (REPO_ROOT / "roles" / role / "tasks" / "main.yaml").read_text(
                encoding="utf-8"
            )
            self.assertIn(
                "download_internal_ca.yaml",
                tasks,
                f"{role} must include download_internal_ca",
            )
            self.assertIn("internal-ca.pem", tasks, f"{role} must use internal-ca.pem")
            self.assertIn("Load Internal CA for", tasks, f"{role} include name")
            self.assertNotIn(
                "Download Internal CA for",
                tasks,
                f"{role} include must not reuse Download recap name",
            )
            if role == "980_argocd":
                self.assertLess(
                    tasks.index("download_internal_ca.yaml"),
                    tasks.index("src: argocd.yaml.j2"),
                    "980_argocd must download Internal CA before templating helm values",
                )
            absent_files = re.search(
                r"helm_chart_absent_local_files:\n(?:          - [^\n]+\n)+",
                tasks,
            )
            self.assertIsNotNone(
                absent_files,
                f"{role} helm_chart_absent_local_files missing",
            )
            self.assertNotIn(
                "internal-ca.pem",
                absent_files.group(0),
                f"{role} must not delete shared internal-ca.pem on helm absent",
            )

    def test_kasten_removed_from_bom(self) -> None:
        """Kasten K10 is not a BOM chart: no role, helm repo, ingress, OIDC, scrape, or gnet."""
        self.assertFalse((REPO_ROOT / "roles" / "56_kasten").exists())
        playbook = (REPO_ROOT / "playbooks" / "cluster_addons.yaml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("56_kasten", playbook)
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("kasten", catalog)
        self.assertNotIn("kasten-io", catalog)
        self.assertNotIn("kasten_chart_state", catalog)
        self.assertNotIn("kasten_oidc_client_secret", catalog)
        self.assertNotIn("profile: kasten", catalog)
        secrets = (
            REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.secrets.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("kasten", secrets)
        example = (REPO_ROOT / "examples" / "secrets.example.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("kasten", example)
        tf = (
            REPO_ROOT / "roles" / "930_keycloak_realm" / "templates" / "main.tf.j2"
        ).read_text(encoding="utf-8")
        self.assertNotIn("kasten", tf)
        self.assertNotIn("aud-kasten", tf)
        imports = (
            REPO_ROOT / "roles" / "930_keycloak_realm" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("kasten", imports)
        routes = (
            REPO_ROOT
            / "roles"
            / "560_apply_ingress"
            / "templates"
            / "gateway-routes.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertNotIn("kasten", routes)
        self.assertNotIn("/k10/", routes)
        prom = (
            REPO_ROOT / "roles" / "310_prometheus" / "templates" / "prometheus.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertNotIn("k10-http-sd", prom)
        self.assertNotIn("k10-pods", prom)
        dash = (
            REPO_ROOT
            / "roles"
            / "310_prometheus"
            / "templates"
            / "grafana-dashboards.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertNotIn("kasten", dash)
        self.assertNotIn("21065", dash)
        rook = (
            REPO_ROOT / "roles" / "440_rook_csi_drivers" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("kasten", rook)
        self.assertNotIn("k10.kasten.io", rook)
        report = (
            REPO_ROOT / "roles" / "996_cluster_report" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("kasten", report)
        validate = (
            REPO_ROOT / "roles" / "130_validate_vars" / "tasks" / "secrets.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("kasten", validate)
        addons_vars = (
            REPO_ROOT / "roles" / "130_validate_vars" / "tasks" / "vars_cluster_addons.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("kasten", addons_vars)
        defaults = (
            REPO_ROOT / "roles" / "130_validate_vars" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("kasten", defaults)
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("kasten", readme.lower())
        gen = (
            REPO_ROOT
            / "roles"
            / "992_kibana_dashboards"
            / "files"
            / "generate_dashboards.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("kasten", gen.lower())

    def test_vault_role_does_not_become_on_delegated_remote(self) -> None:
        """Controller-side delegate_to must be fact-host with become: false (no sudo in krang)."""
        tasks_dir = REPO_ROOT / "roles" / "971_vault" / "tasks"
        allowed = "{{ k8s_cluster_fact_host }}"
        for path in sorted(tasks_dir.glob("*.yml")) + sorted(tasks_dir.glob("*.yaml")):
            text = path.read_text(encoding="utf-8")
            chunks = re.split(r"(?m)^- name:", text)
            for chunk in chunks[1:]:
                if "delegate_to:" not in chunk:
                    continue
                match = re.search(r"(?m)^\s+delegate_to:\s*(.+?)\s*$", chunk)
                self.assertIsNotNone(match, f"{path.name}: delegate_to unparseable")
                target = match.group(1).strip().strip("\"'")
                self.assertEqual(
                    target,
                    allowed,
                    f"{path.name}: delegate_to {target} must be {allowed}",
                )
                self.assertRegex(
                    chunk,
                    r"(?m)^\s+become:\s*false\s*$",
                    f"{path.name}: delegate_to {target} must set become: false",
                )

    def test_vault_key_plays_order_in_playbook(self) -> None:
        """SSH key collect/distribute wrap controller unseal and stay before ESO."""
        text = (REPO_ROOT / "playbooks" / "cluster_addons.yaml").read_text(encoding="utf-8")
        consul = text.index("970_consul")
        collect = text.index("keys_collect.yml")
        unseal = text.index("tasks_from: unseal.yml")
        distribute = text.index("keys_distribute.yml")
        eso = text.index("972_external_secrets")
        self.assertLess(consul, collect, "970_consul must precede keys_collect")
        self.assertLess(collect, unseal, "keys_collect must precede unseal")
        self.assertLess(unseal, distribute, "unseal must precede keys_distribute")
        self.assertLess(distribute, eso, "keys_distribute must precede 972_external_secrets")

    def test_gitignore_covers_inventory_and_workspace(self) -> None:
        text = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        for needle in (
            "inventory.yml",
            "workspace/",
            "secrets.yml",
            "!roles/**/tasks/secrets.yml",
            "kubeconfig",
            "!roles/**/templates/kubeconfig*.j2",
        ):
            self.assertIn(needle, text)
        dockerignore = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")
        self.assertIn("!roles/**/tasks/secrets.yml", dockerignore)
        self.assertIn("!roles/**/templates/kubeconfig*.j2", dockerignore)

    def test_readme_has_no_org_urls(self) -> None:
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("mxhash", readme.lower())
        self.assertNotIn("gitea.", readme.lower())
        self.assertNotIn("Welcomeback", readme)
        self.assertIn("SECURITY.md", readme)
        self.assertIn("LICENSE", readme)
        self.assertIn("atlas-k8s-core", readme)

    def test_playbook_header_is_orchestrator_neutral(self) -> None:
        text = (REPO_ROOT / "playbooks" / "cluster_addons.yaml").read_text(encoding="utf-8")
        self.assertNotIn("clusterctl", text)
        self.assertNotIn("platform.yml", text)
        self.assertNotIn("mxhash", text.lower())
        self.assertIn("110_workspace", text)

    def test_no_lab_password_comments_in_roles(self) -> None:
        hits = _scan_product_sources_for(("Welcomeback",), case_sensitive=True)
        self.assertEqual(hits, [], f"lab password residue: {hits}")

    def test_no_org_fingerprint_in_product_sources(self) -> None:
        # Align with atlas-k8s-core: ban generic gitea./harbor. host prefixes, not only *.mxhash.
        needles = ("mxhash", "gitea.", "harbor.", "welcomeback", "upload.mxhash")
        hits = _scan_product_sources_for(needles)
        self.assertEqual(hits, [], f"org fingerprint in product sources: {hits}")

        for needle in ("vars-file.yml", "platform.yml", "clusters/<id>", "atlas-clusterctl"):
            overlay_hits = _scan_product_sources_for((needle,), case_sensitive=True)
            self.assertEqual(
                overlay_hits,
                [],
                f"orchestrator path in product sources ({needle}): {overlay_hits}",
            )

    def test_no_cyrillic_in_product_sources(self) -> None:
        hits = _scan_product_sources_for_regex(_CYRILLIC_RE)
        self.assertEqual(hits, [], f"Cyrillic residue in product sources: {hits[:20]}")

    def test_no_obvious_secret_material_in_product_sources(self) -> None:
        needles = ("Welcomeback", "BEGIN OPENSSH PRIVATE", "BEGIN RSA PRIVATE", "AKIA", "gldt-")
        hits = _scan_product_sources_for(needles, case_sensitive=True)
        self.assertEqual(hits, [], f"secret-like material found: {hits}")

    def test_kubernetes_oidc_client_and_roles_79_81(self) -> None:
        tf = (
            REPO_ROOT / "roles" / "930_keycloak_realm" / "templates" / "main.tf.j2"
        ).read_text(encoding="utf-8")
        self.assertIn('resource "keycloak_openid_client" "kubernetes_client"', tf)
        self.assertIn("PUBLIC", tf)
        self.assertIn("S256", tf)
        self.assertIn('name     = "k8s-admins"', tf)
        self.assertIn("http://localhost:8000", tf)
        self.assertIn("http://127.0.0.1:18000", tf)
        tasks = (REPO_ROOT / "roles" / "930_keycloak_realm" / "tasks" / "main.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("keycloak_openid_client.kubernetes_client", tasks)
        self.assertIn("keycloak_group.k8s_admins", tasks)
        self.assertNotIn("keycloak_openid_client_default_scopes.kubernetes_defaults", tasks)
        self.assertIn("keycloak_openid_client.pinniped_supervisor_client", tasks)
        self.assertNotIn("keycloak_openid_client_default_scopes.pinniped_supervisor_defaults", tasks)
        self.assertNotIn("kc_oidc_clients.results[6]", tasks)
        self.assertIn("selectattr('item', 'equalto', 'pinniped-supervisor')", tasks)
        self.assertIn("pinniped-supervisor", tasks)
        playbook = (REPO_ROOT / "playbooks" / "cluster_addons.yaml").read_text(encoding="utf-8")
        oidc_roles = re.findall(
            r"^\s+- role: (930_keycloak_realm|941_k8s_oidc|940_apiserver_oidc|942_pinniped|960_oauth2_proxy|961_apply_oidc_ingress)\s*$",
            playbook,
            re.M,
        )
        self.assertEqual(
            oidc_roles,
            [
                "930_keycloak_realm",
                "940_apiserver_oidc",
                "941_k8s_oidc",
                "942_pinniped",
                "960_oauth2_proxy",
                "961_apply_oidc_ingress",
            ],
            "OIDC role order in cluster_addons.yaml",
        )
        self.assertNotIn("73_k8s_oidc", playbook)
        self.assertFalse((REPO_ROOT / "roles" / "73_k8s_oidc").is_dir())
        oidc_tasks = (REPO_ROOT / "roles" / "941_k8s_oidc" / "tasks" / "main.yaml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("int128/kubelogin", oidc_tasks)
        self.assertNotIn("kubectl-oidc_login", oidc_tasks)
        self.assertIn("kube_apiserver_oidc_enabled", oidc_tasks)
        self.assertIn("oidc-k8s-admins.yaml.j2", oidc_tasks)
        self.assertIn("controller_ca_cert_path", oidc_tasks)
        self.assertIn("140_fetch_kubeconfig", oidc_tasks)
        self.assertIn("import_role", oidc_tasks)
        kubeconfig = (
            REPO_ROOT / "roles" / "941_k8s_oidc" / "templates" / "kubeconfig.oidc.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("oidc-login", kubeconfig)
        self.assertIn("get-token", kubeconfig)
        self.assertIn("--oidc-issuer-url={{ kube_oidc_issuer_url }}", kubeconfig)
        self.assertIn("--oidc-client-id={{ kube_oidc_client_id }}", kubeconfig)
        self.assertIn("--certificate-authority-data={{ k8s_oidc_issuer_ca_data }}", kubeconfig)
        self.assertNotIn("controller_bin_dir", kubeconfig)
        self.assertNotIn("- name: PATH", kubeconfig)
        self.assertIn("kubectl-oidc_login", kubeconfig)
        self.assertIn("interactiveMode: Always", kubeconfig)
        self.assertNotIn("IfAvailable", kubeconfig)
        crb = (
            REPO_ROOT / "roles" / "941_k8s_oidc" / "templates" / "oidc-k8s-admins.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("kind: ClusterRoleBinding", crb)
        self.assertIn("name: cluster-admin", crb)
        self.assertIn("kind: Group", crb)
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("kube_apiserver_oidc_enabled: false", catalog)
        self.assertIn('kube_oidc_issuer_url: "{{ oidc_issuer_url | default(\'\') }}"', catalog)
        self.assertLess(
            catalog.index("# --- 940_apiserver_oidc ---"),
            catalog.index("# --- 941_k8s_oidc ---"),
            "catalog documents 81 before 79",
        )
        self.assertLess(
            catalog.index("# --- 941_k8s_oidc ---"),
            catalog.index("# --- 942_pinniped ---"),
            "catalog documents 79 before 82",
        )
        self.assertLess(
            catalog.index("# --- 942_pinniped ---"),
            catalog.index("# --- 960_oauth2_proxy ---"),
            "catalog documents 82 before 72",
        )
        self.assertLess(
            catalog.index("# --- 960_oauth2_proxy ---"),
            catalog.index("# --- 961_apply_oidc_ingress ---"),
            "catalog documents 960 before 961",
        )
        k8s_client = re.search(
            r'(?s)resource "keycloak_openid_client" "kubernetes_client" \{.*?access_type\s+=\s+"(\w+)"',
            tf,
        )
        self.assertIsNotNone(k8s_client, "kubernetes_client missing")
        self.assertEqual(k8s_client.group(1), "PUBLIC")
        pinniped_client = re.search(
            r'(?s)resource "keycloak_openid_client" "pinniped_supervisor_client" \{.*?access_type\s+=\s+"(\w+)"',
            tf,
        )
        self.assertIsNotNone(pinniped_client, "pinniped_supervisor_client missing")
        self.assertEqual(pinniped_client.group(1), "CONFIDENTIAL")
        self.assertIn('https://{{ pinniped_host }}/callback', tf)
        self.assertIn(
            'concat(local.kc26_oidc_builtin_default_scopes, ["aud-pinniped-supervisor"])',
            tf,
        )
        self.assertNotIn('["aud-pinniped-supervisor", "offline_access"]', tf)
        self.assertNotIn("pinniped-admins", tf)
        self.assertNotIn("pinniped_admins", tf)
        self.assertNotIn("kubelogin_version", catalog)
        self.assertIn(
            "ternary(k8s_master_hosts | default('k8s_masters'), 'localhost')",
            playbook,
        )
        self.assertIn(
            'become: "{{ kube_apiserver_oidc_enabled | default(false) | bool }}"',
            playbook,
        )
        apiserver = (REPO_ROOT / "roles" / "940_apiserver_oidc" / "tasks" / "main.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("control-plane", apiserver)
        self.assertIn("apiserver", apiserver)
        self.assertIn("upload-config", apiserver)
        self.assertIn("kube_oidc_need_rewrite", apiserver)
        self.assertIn("kube_oidc_need_ca_reload", apiserver)
        self.assertIn("oidc_merge_cluster_config", apiserver)
        self.assertIn("crictl", apiserver)
        self.assertIn("not (kube_oidc_need_rewrite | bool)", apiserver)
        self.assertNotIn("failed_when: false", apiserver)
        self.assertNotIn("to_nice_yaml", apiserver)
        self.assertNotIn("merge_extra_args.j2", apiserver)
        self.assertNotIn("changed_when: kube_oidc_apiserver_phase.rc == 0", apiserver)
        self.assertFalse(
            (REPO_ROOT / "roles" / "940_apiserver_oidc" / "templates" / "merge_extra_args.j2").is_file()
        )
        self.assertFalse(
            (REPO_ROOT / "roles" / "940_apiserver_oidc" / "templates" / "oidc_pod_has_flags.j2").is_file()
        )
        ca_tasks = (
            REPO_ROOT / "roles" / "940_apiserver_oidc" / "tasks" / "install_oidc_ca.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("pki_ca_url", ca_tasks)
        self.assertIn("kube_oidc_ca_file", ca_tasks)
        self.assertIn("kube_oidc_ca_download_ok", ca_tasks)
        self.assertIn("failed_when: false", ca_tasks)
        self.assertIn("item.status_code | default(0) | int", ca_tasks)
        self.assertIn("kube_oidc_ca_url_list", ca_tasks)
        self.assertIn("Remove stale OIDC CA staging files", ca_tasks)
        self.assertNotIn("map(attribute='status_code')", ca_tasks)
        self.assertTrue((REPO_ROOT / "filter_plugins" / "oidc_kubeadm.py").is_file())
        validate = (
            REPO_ROOT / "roles" / "130_validate_vars" / "tasks" / "vars_cluster_addons.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("kube_apiserver_oidc_enabled", validate)
        self.assertIn("940_apiserver_oidc/defaults/main.yml", validate)
        self.assertIn("default(oidc_issuer_url, true)", validate)
        self.assertLess(
            validate.index("oidc_issuer_url | default('') | length > 0"),
            validate.index("kube_oidc_issuer_url | default('') | length > 0"),
            "assert oidc_issuer_url (leaf SoT) before derived kube_oidc_issuer_url",
        )
        report_defaults = (
            REPO_ROOT / "roles" / "996_cluster_report" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("71+81+79", report_defaults)
        self.assertIn("client PATH", report_defaults)
        self.assertIn("admin.conf", report_defaults)

    def test_pinniped_supervisor_concierge_keycloak(self) -> None:
        """82 is a local official chart (not Bitnami); Keycloak upstream; 81/79 stay."""
        chart_dir = REPO_ROOT / "roles" / "942_pinniped" / "chart"
        chart = (chart_dir / "Chart.yaml").read_text(encoding="utf-8")
        self.assertIn("appVersion: v0.47.0", chart)
        self.assertNotIn("charts.bitnami.com", chart.lower())
        self.assertNotIn("oci://", chart)
        self.assertNotIn("dependencies:", chart)
        self.assertNotIn("repository:", chart)
        self.assertTrue((chart_dir / "crds" / "supervisor.yaml").is_file())
        self.assertTrue((chart_dir / "crds" / "concierge.yaml").is_file())
        source = (chart_dir / "files" / "SOURCE.txt").read_text(encoding="utf-8")
        self.assertIn("https://get.pinniped.dev/v0.47.0/", source)
        for rel in (
            "files/upstream/supervisor-resources.yaml",
            "files/upstream/concierge-resources.yaml",
        ):
            body = (chart_dir / rel).read_text(encoding="utf-8")
            self.assertNotIn("{{", body)
            self.assertNotIn("bitnami", body.lower())
        templates = chart_dir / "templates"
        self.assertIn(
            '.Files.Get "files/upstream/supervisor-resources.yaml"',
            (templates / "00-upstream-supervisor.yaml").read_text(encoding="utf-8"),
        )
        self.assertIn(
            '.Files.Get "files/upstream/concierge-resources.yaml"',
            (templates / "01-upstream-concierge.yaml").read_text(encoding="utf-8"),
        )
        try:
            helm = subprocess.run(
                [
                    "helm",
                    "template",
                    "pinniped",
                    str(chart_dir),
                    "--namespace",
                    "pinniped",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            helm = None
        if helm is not None:
            self.assertEqual(helm.returncode, 0, helm.stderr)
            self.assertIn("kind: Deployment", helm.stdout)
            self.assertIn("name: pinniped-supervisor", helm.stdout)
            self.assertIn("name: pinniped-concierge", helm.stdout)
            self.assertIn("name: pinniped-login", helm.stdout)
            self.assertIn("pinniped-cli-linux-amd64", helm.stdout)
            self.assertNotIn("kind: Namespace", helm.stdout)
            self.assertNotIn("namespace: pinniped-supervisor", helm.stdout)
            self.assertNotIn("namespace: pinniped-concierge", helm.stdout)
            self.assertIn("namespace: pinniped", helm.stdout)
            self.assertIn("runAsNonRoot: true", helm.stdout)
            self.assertIn("containerPort: 8080", helm.stdout)
            self.assertIn("listen 8080", helm.stdout)
            self.assertIn("mode: disabled", helm.stdout)
            self.assertNotIn("mode: auto", helm.stdout)
        oidc_idp = (templates / "13-atlas-oidcidentityprovider.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("kind: OIDCIdentityProvider", oidc_idp)
        self.assertIn("issuer: {{ .Values.keycloakIssuer | quote }}", oidc_idp)
        self.assertIn("username: preferred_username", oidc_idp)
        self.assertIn("groups: groups", oidc_idp)
        self.assertIn("additionalScopes:", oidc_idp)
        self.assertIn("- offline_access", oidc_idp)
        self.assertIn("- email", oidc_idp)
        self.assertIn("- profile", oidc_idp)
        self.assertNotIn("- groups", oidc_idp)
        jwt = (templates / "15-atlas-jwtauthenticator.yaml").read_text(encoding="utf-8")
        self.assertIn("kind: JWTAuthenticator", jwt)
        self.assertIn("issuer: {{ .Values.federationIssuer | quote }}", jwt)
        self.assertIn("audience: {{ .Values.federationIssuer | quote }}", jwt)
        secret = (templates / "12-atlas-oidc-client-secret.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("type: secrets.pinniped.dev/oidc-client", secret)
        values = (
            REPO_ROOT / "roles" / "942_pinniped" / "templates" / "values.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn('keycloakIssuer: "{{ oidc_issuer_url }}"', values)
        self.assertIn('federationIssuer: "https://{{ pinniped_host }}"', values)
        self.assertIn('pinnipedNamespace: "{{ pinniped_namespace }}"', values)
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("clusterctl", catalog)
        self.assertNotIn("tls_secret:", catalog)
        self.assertIn("pinniped_chart_state: present", catalog)
        self.assertIn("pinniped_version: v0.47.0", catalog)
        self.assertIn("pinniped_namespace: pinniped", catalog)
        self.assertIn("pinniped_https_secret:", catalog)
        self.assertNotIn("pinniped_supervisor_namespace", catalog)
        self.assertNotIn("pinniped_concierge_namespace", catalog)
        helm_repos_block = catalog.split("helm_repos:", 1)[1].split(
            "k8s_platform_namespaces:", 1
        )[0]
        helm_upstreams_block = catalog.split("helm_repo_upstreams:", 1)[1].split(
            "helm_repos:", 1
        )[0]
        self.assertNotRegex(helm_repos_block, r"name:\s*(pinniped|bitnami)")
        self.assertNotRegex(helm_upstreams_block, r"name:\s*(pinniped|bitnami)")
        self.assertNotIn("charts.bitnami.com", catalog)
        pinniped_app = re.search(
            r"(?m)^  - name: pinniped-supervisor\n(?:    .+\n)+",
            catalog,
        )
        self.assertIsNotNone(pinniped_app, "pinniped-supervisor ingress missing")
        self.assertIn("ssl_passthrough: true", pinniped_app.group(0))
        self.assertNotIn("oidc_auth", pinniped_app.group(0))
        self.assertIn("service: \"{{ pinniped_supervisor_service }}\"", pinniped_app.group(0))
        self.assertIn("port: 443", pinniped_app.group(0))
        login_app = re.search(
            r"(?m)^  - name: pinniped-login\n(?:    .+\n)+",
            catalog,
        )
        self.assertIsNotNone(login_app, "pinniped-login ingress missing")
        self.assertIn("oidc_auth: true", login_app.group(0))
        self.assertNotIn("ssl_passthrough", login_app.group(0))
        self.assertIn("port: 80", login_app.group(0))
        self.assertIn("pinniped_login_host: \"pinniped-login.{{ k8s_cluster_domain }}\"", catalog)
        self.assertIn("k8s_oidc_group: k8s-admins", catalog)
        self.assertIn("k8s_oidc_clusterrolebinding: oidc-k8s-admins", catalog)
        tasks = (REPO_ROOT / "roles" / "942_pinniped" / "tasks" / "main.yaml").read_text(
            encoding="utf-8"
        )
        cli_tasks = (
            REPO_ROOT / "roles" / "942_pinniped" / "tasks" / "install_cli.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("{{ role_path }}/chart", tasks)
        self.assertNotIn("bitnami", tasks.lower())
        self.assertNotIn("helm_repos", tasks)
        self.assertIn("helm_chart_absent.yaml", tasks)
        self.assertIn("pinniped-supervisor", tasks)
        self.assertIn("pinniped-login", tasks)
        self.assertIn("pinniped_namespace", tasks)
        self.assertNotIn("pinniped_concierge_namespace", tasks)
        self.assertNotIn("pinniped_supervisor_namespace", tasks)
        self.assertIn("certificate.cert-manager.io/", tasks)
        self.assertIn("jwtauthenticator.authentication.concierge.pinniped.dev/", tasks)
        self.assertIn("federationdomain.config.supervisor.pinniped.dev/", tasks)
        self.assertIn("oidcidentityprovider.idp.supervisor.pinniped.dev/", tasks)
        self.assertIn("apiservice/v1alpha1.login.concierge.pinniped.dev", tasks)
        self.assertIn("get kubeconfig", tasks)
        self.assertIn("--pinniped-cli-path pinniped", tasks)
        self.assertIn("mktemp", tasks)
        self.assertIn("-o \"$tmp\"", tasks)
        self.assertIn("trap 'rm -f \"$tmp\"' EXIT", tasks)
        self.assertNotIn("rollout restart", tasks)
        self.assertNotIn('impersonationProxy":{"mode":"disabled"}', tasks)
        self.assertIn("openid-configuration", tasks)
        self.assertIn("controller_ca_cert_path", tasks)
        self.assertNotIn("kubeconfig.pinniped.j2", tasks)
        self.assertFalse(
            (REPO_ROOT / "roles" / "942_pinniped" / "templates" / "kubeconfig.pinniped.j2").is_file()
        )
        self.assertNotIn("kube_apiserver_oidc_enabled", tasks)
        self.assertNotIn("int128/kubelogin", tasks)
        self.assertNotIn("get.pinniped.dev", tasks)
        self.assertNotIn("get.pinniped.dev", cli_tasks)
        self.assertIn("github.com/vmware/pinniped/releases", cli_tasks)
        self.assertIn("vmware/pinniped/releases/download", cli_tasks)
        self.assertIn("controller_bin_dir", cli_tasks)
        html = (
            REPO_ROOT
            / "roles"
            / "942_pinniped"
            / "chart"
            / "files"
            / "login"
            / "index.html"
        ).read_text(encoding="utf-8")
        self.assertIn("github.com/vmware/pinniped/releases", html)
        self.assertIn("pinniped-cli-linux-amd64", html)
        self.assertIn("pinniped-cli-darwin-arm64", html)
        self.assertIn("pinniped-cli-windows-amd64.exe", html)
        self.assertIn("/kubeconfig.yaml", html)
        self.assertIn("k8s-admins", html)
        self.assertIn("Without that binary on PATH", html)
        login_cm = (templates / "20-login-configmap.yaml").read_text(encoding="utf-8")
        self.assertIn('fail "missing files/login/index.html"', login_cm)
        self.assertIn('fail "missing files/login/default.conf"', login_cm)
        login_deploy = (templates / "21-login-deployment.yaml").read_text(encoding="utf-8")
        self.assertIn("checksum/config", login_deploy)
        self.assertIn("runAsNonRoot: true", login_deploy)
        self.assertIn("containerPort: 8080", login_deploy)
        self.assertIn("listen 8080", (chart_dir / "files" / "login" / "default.conf").read_text(encoding="utf-8"))
        crb = (
            REPO_ROOT / "roles" / "942_pinniped" / "templates" / "pinniped-k8s-admins.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("name: {{ k8s_oidc_clusterrolebinding }}", crb)
        self.assertNotIn("name: pinniped-k8s-admins", crb)
        self.assertNotIn("kind: ClusterRoleBinding", tasks.split("helm_chart_absent_local_files:", 1)[0].split("helm_chart_absent_cluster_resources:", 1)[-1])
        pinniped_defaults = (
            REPO_ROOT / "roles" / "942_pinniped" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("k8s_oidc_group: k8s-admins", pinniped_defaults)
        self.assertIn("k8s_oidc_clusterrolebinding: oidc-k8s-admins", pinniped_defaults)
        self.assertIn("pinniped_namespace: pinniped", pinniped_defaults)
        self.assertNotIn("pinniped_supervisor_namespace", pinniped_defaults)
        self.assertNotIn("pinniped_concierge_namespace", pinniped_defaults)
        supervisor_tpl = (templates / "00-upstream-supervisor.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'replace "namespace: pinniped-supervisor"',
            supervisor_tpl,
        )
        self.assertIn(".Values.pinnipedNamespace", supervisor_tpl)
        concierge_tpl = (templates / "01-upstream-concierge.yaml").read_text(encoding="utf-8")
        self.assertIn('replace "    mode: auto" "    mode: disabled"', concierge_tpl)
        self.assertIn('replace "namespace: pinniped-concierge"', concierge_tpl)
        login_svc = (templates / "22-login-service.yaml").read_text(encoding="utf-8")
        self.assertIn("name: {{ .Values.loginUi.serviceName }}", login_svc)
        self.assertIn("port: 80", login_svc)
        playbook = (REPO_ROOT / "playbooks" / "cluster_addons.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("- 942_pinniped", playbook)
        apiserver = (
            REPO_ROOT / "roles" / "940_apiserver_oidc" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("pinniped", apiserver.lower())
        oidc_tasks = (REPO_ROOT / "roles" / "941_k8s_oidc" / "tasks" / "main.yaml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("pinniped", oidc_tasks.lower())
        secrets = (
            REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.secrets.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("pinniped_supervisor_client_secret:", secrets)
        example = (REPO_ROOT / "examples" / "secrets.example.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("pinniped_supervisor_client_secret:", example)
        self.assertIn(
            "pinniped_supervisor_client_secret: \"{{ pinniped_supervisor_client_secret }}\"",
            catalog,
        )
        validate = (
            REPO_ROOT / "roles" / "130_validate_vars" / "tasks" / "secrets.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("k8s_secrets.pinniped_supervisor_client_secret", validate)
        report = (
            REPO_ROOT / "roles" / "996_cluster_report" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("id: pinniped", report)
        self.assertIn(".pinniped", report)
        self.assertIn("pinniped_login_host", report)
        self.assertIn("namespace_var: pinniped_namespace", report)
        self.assertIn("https://{{ pinniped_host }}", report)
        self.assertIn("password_key: pinniped_supervisor_client_secret", report)
        self.assertIn("admin.conf", report)
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("942_pinniped", readme)
        self.assertIn("published only after `961_apply_oidc_ingress`", readme)
        self.assertNotIn("clusterctl", readme)
        svc = (templates / "11-atlas-https-service.yaml").read_text(encoding="utf-8")
        self.assertIn("port: 443", svc)
        self.assertIn("targetPort: 8443", svc)


class K8sAddonsEntrypointTest(unittest.TestCase):
    def test_run_sh_is_executable_and_documents_env(self) -> None:
        path = REPO_ROOT / "run.sh"
        self.assertTrue(path.is_file())
        mode = path.stat().st_mode
        self.assertTrue(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        text = path.read_text(encoding="utf-8")
        for needle in (
            "cluster_addons.yaml",
            "CLUSTER_WORKSPACE_ROOT",
            "EXTRA_VARS_FILE",
            "inventory-example.yml",
        ):
            self.assertIn(needle, text)

    def test_inventory_example_has_required_groups(self) -> None:
        text = (REPO_ROOT / "inventory-example.yml").read_text(encoding="utf-8")
        self.assertIn("k8s_masters:", text)
        self.assertIn("k8s_workers:", text)
        self.assertIn("k8s.example.com", text)
        self.assertNotIn("mxhash", text.lower())

    def test_group_vars_catalog_covers_validate_surface(self) -> None:
        path = REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml"
        secrets_path = REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.secrets.yml"
        self.assertTrue(path.is_file())
        self.assertTrue(secrets_path.is_file())
        text = path.read_text(encoding="utf-8")
        secrets = secrets_path.read_text(encoding="utf-8")
        for needle in (
            "use_internal_helm_repo: none",
            "helm_repos:",
            "helm_repo_upstreams:",
            "k8s_secrets:",
            "k8s_ingress_apps:",
            "k8s_platform_namespaces:",
            "dns_server_ip:",
            "metallb_ip_pool:",
            "k8s_master_hosts:",
            "cluster_workspace_id:",
            "controller_workspace:",
            "debug_tooling_install_dir:",
            "debug_tooling_calicoctl_enabled:",
            "debug_tooling_binary_source: github",
            "k8s.example.com",
        ):
            self.assertIn(needle, text)
        self.assertIn("grafana_admin_password:", secrets)
        self.assertIn("CHANGEME", secrets)
        self.assertNotIn("grafana_admin_password: \"CHANGEME\"", text)
        self.assertNotIn("mxhash", text.lower())
        self.assertNotIn("Welcomeback", text)
        self.assertNotIn("platform.yml", text)
        self.assertNotIn("clusterctl", text)

    def test_examples_and_host_vars_exist(self) -> None:
        self.assertTrue((REPO_ROOT / "examples" / "secrets.example.yml").is_file())
        self.assertTrue((REPO_ROOT / "examples" / "hosts.example.yml").is_file())
        self.assertTrue((REPO_ROOT / "examples" / "standalone.minimal.yml").is_file())
        self.assertTrue((REPO_ROOT / "examples" / "provision_hosts.example.yml").is_file())
        self.assertTrue((REPO_ROOT / "host_vars" / "example.yml").is_file())
        secrets = (REPO_ROOT / "examples" / "secrets.example.yml").read_text(encoding="utf-8")
        self.assertIn("EXTRA_VARS_FILE", secrets)
        self.assertIn("kibana_encryption_key", secrets)
        self.assertIn("argocd_admin_password_bcrypt", secrets)
        provision = (REPO_ROOT / "examples" / "provision_hosts.example.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("k8s_workers:", provision)
        self.assertIn("wwn:", provision)
        self.assertNotIn("mxhash", provision.lower())

    def test_workspace_role_and_catalog(self) -> None:
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(encoding="utf-8")
        for needle in (
            "cluster_workspace_root:",
            "cluster_workspace_parent:",
            "controller_kubeconfig:",
            "controller_helm_cache_dir:",
            "provision_tf_state_local_dir:",
            "build_workdir:",
            "control_plane_endpoint:",
            "k8s_cluster_name:",
            "provision_hosts_file:",
            "110_workspace re-resolves",
        ):
            self.assertIn(needle, catalog)
        defaults = (
            REPO_ROOT / "roles" / "110_workspace" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("cluster_workspace_root:", defaults)
        self.assertIn("CLUSTER_WORKSPACE_ROOT", defaults)
        self.assertIn("CLUSTER_WORKSPACE_PARENT", defaults)
        self.assertIn("controller_workspace:", defaults)
        self.assertIn("controller_helm_cache_dir:", defaults)
        validate = (
            REPO_ROOT / "roles" / "110_workspace" / "tasks" / "validate.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("Resolve cluster workspace root", validate)
        self.assertIn("Align controller paths under resolved workspace root", validate)
        self.assertIn("CLUSTER_WORKSPACE_PARENT", validate)
        self.assertIn("controller_helm_cache_dir", validate)
        self.assertIn("k8s_kibana_chart_dir", validate)
        create_dirs = (
            REPO_ROOT / "roles" / "110_workspace" / "tasks" / "create_dirs.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn(".ansible_facts_cache", create_dirs)
        self.assertIn("controller_workspace", create_dirs)
        self.assertIn("controller_helm_cache_dir", create_dirs)
        self.assertNotIn("provision_tf_state_repo_dir", create_dirs)
        playbook = (REPO_ROOT / "playbooks" / "cluster_addons.yaml").read_text(encoding="utf-8")
        self.assertIn("tags: [110_workspace]", playbook)
        self.assertLess(
            playbook.index("110_workspace"),
            playbook.index("130_validate_vars"),
        )
        rook_defaults = (
            REPO_ROOT / "roles" / "430_rook_cluster" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("provision_hosts_file:", rook_defaults)
        self.assertIn("provision_rook_data_disk_index:", rook_defaults)
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("realigns `controller_*`", readme)
        self.assertIn("provision_hosts.example.yml", readme)

    def test_readme_quickstart_uses_run_sh(self) -> None:
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("./run.sh", readme)
        self.assertIn("Quickstart", readme)
        self.assertIn("group_vars/all/atlas-k8s-addons.yml", readme)
        self.assertIn("inventory-example.yml", readme)
        self.assertIn("130_validate_vars", readme)
        self.assertNotIn("standalone.example.yml", readme)

    def test_inventory_group_targeting(self) -> None:
        playbook = (REPO_ROOT / "playbooks" / "cluster_addons.yaml").read_text(encoding="utf-8")
        for needle in ("k8s_master_hosts", "k8s_worker_hosts"):
            self.assertIn(needle, playbook)
        self.assertIn("k8s_master_hosts | default('k8s_masters')", playbook)
        self.assertIn("k8s_worker_hosts | default('k8s_workers')", playbook)
        self.assertNotIn("hosts: k8s_masters:k8s_workers", playbook)
        self.assertNotIn("hosts: k8s_masters\n", playbook)
        self.assertNotIn("hosts: k8s_workers\n", playbook)

        validate = (
            REPO_ROOT / "roles" / "130_validate_vars" / "tasks" / "inventory_masters.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("groups[k8s_master_hosts]", validate)
        self.assertIn("k8s_worker_hosts in groups", validate)
        defaults = (
            REPO_ROOT / "roles" / "130_validate_vars" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("k8s_master_hosts: k8s_masters", defaults)
        self.assertIn("k8s_worker_hosts: k8s_workers", defaults)

        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(encoding="utf-8")
        self.assertIn("k8s_master_hosts: k8s_masters", catalog)
        self.assertIn("k8s_worker_hosts: k8s_workers", catalog)
        self.assertIn("groups.get(k8s_master_hosts", catalog)

        hardcoded = _scan_product_sources_for(
            ("groups['k8s_masters']", "groups['k8s_workers']", "groups.get('k8s_masters'", "groups.get('k8s_workers'"),
            case_sensitive=True,
        )
        role_hits = [h for h in hardcoded if h.startswith("roles/") or h.startswith("playbooks/")]
        self.assertEqual(role_hits, [], f"hardcoded group keys remain: {role_hits}")

        fetch = (
            REPO_ROOT / "roles" / "140_fetch_kubeconfig" / "tasks" / "fetch.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("k8s_master_hosts={{ k8s_master_hosts }}", fetch)

        report = (
            REPO_ROOT / "roles" / "996_cluster_report" / "tasks" / "build_report.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("groups.get(k8s_master_hosts", report)
        self.assertIn("groups.get(k8s_worker_hosts", report)

        rook = (
            REPO_ROOT
            / "roles"
            / "430_rook_cluster"
            / "templates"
            / "rook_storage_nodes.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("k8s_worker_hosts", rook)

        debug_defaults = (
            REPO_ROOT / "roles" / "999_debug_tooling" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("k8s_master_hosts", debug_defaults)
        self.assertIn('debug_tooling_helm_hosts: "{{ k8s_master_hosts }}"', debug_defaults)

        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("k8s_master_hosts", readme)
        self.assertIn("k8s_worker_hosts", readme)
        self.assertNotIn("currently asserts the literal", readme)

    def test_rook_cluster_mon_max_pg_per_osd_via_cephconfig(self) -> None:
        """TOO_MANY_PGS on 3-OSD labs: raise mon warn threshold via cephConfig, not configOverride."""
        values = (
            REPO_ROOT
            / "roles"
            / "430_rook_cluster"
            / "templates"
            / "rook_cluster_values.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("cephConfig:", values)
        self.assertIn("mon_max_pg_per_osd:", values)
        self.assertIn("rook_mon_max_pg_per_osd", values)
        self.assertNotRegex(
            values,
            r"(?m)^configOverride:.*mon_max_pg_per_osd",
            "use cephClusterSpec.cephConfig, not configOverride",
        )
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('rook_mon_max_pg_per_osd: "500"', catalog)
        defaults = (
            REPO_ROOT / "roles" / "430_rook_cluster" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn('rook_mon_max_pg_per_osd: "500"', defaults)

    def test_readme_is_standalone_first(self) -> None:
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("./run.sh", readme)
        self.assertIn("Quickstart", readme)
        self.assertIn("group_vars/all/atlas-k8s-addons.yml", readme)
        self.assertIn("inventory-example.yml", readme)
        self.assertIn("Troubleshooting", readme)
        self.assertIn("Greenfield checklist", readme)
        self.assertIn("Contributing", readme)
        self.assertIn("Project structure", readme)
        self.assertIn("Architecture (role order)", readme)
        self.assertIn("110_workspace", readme)
        self.assertIn("atlas-k8s-core", readme)
        self.assertIn("kubernetes.core", readme)
        self.assertIn("k8s_master_hosts", readme)
        self.assertIn("k8s_worker_hosts", readme)
        self.assertIn("Targeting var", readme)
        self.assertNotIn("./cluster ", readme)
        self.assertNotIn("./cluster\n", readme)
        self.assertNotIn("clusterctl", readme)
        self.assertNotIn("mxhash", readme.lower())
        self.assertNotIn("gitea.", readme.lower())
        self.assertIn("Org-specific lab overlays", readme)
        quick = readme.index("## Quickstart")
        integ = readme.index("## Integrations")
        self.assertLess(quick, integ)
        for earlier, later in (
            ("## Greenfield checklist", "## Troubleshooting"),
            ("## Troubleshooting", "## Testing / CI"),
            ("## Testing / CI", "## Project structure"),
            ("## Project structure", "## Integrations"),
            ("## Integrations", "## Security"),
            ("## Security", "## Contributing"),
        ):
            self.assertLess(readme.index(earlier), readme.index(later), f"{earlier} before {later}")
        self.assertIn("./tests/run_ci.sh", readme)
        self.assertIn("ansible-lint", readme)
        self.assertIn(".github/workflows/ci.yml", readme)
        self.assertIn("ansible-lint --profile min", readme)


class FingerprintGuardTest(unittest.TestCase):
    """Contracts that keep the tree publishable (step 2)."""

    def test_ci_entrypoints_executable(self) -> None:
        for rel in (
            "run.sh",
            "tests/run_ci.sh",
            "scripts/check-no-hardcoded-domains.sh",
        ):
            path = REPO_ROOT / rel
            self.assertTrue(path.is_file(), rel)
            self.assertTrue(
                path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH),
                f"{rel} must be executable",
            )

    def test_domain_check_script_passes(self) -> None:
        path = REPO_ROOT / "scripts" / "check-no-hardcoded-domains.sh"
        proc = subprocess.run(
            [str(path)],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("OK:", proc.stdout)

    def test_credentials_report_template_is_english(self) -> None:
        text = (
            REPO_ROOT / "roles" / "996_cluster_report" / "templates" / "cluster-credentials.md.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("## Where to look", text)
        self.assertIn("## DNS (operator)", text)
        self.assertNotRegex(text, _CYRILLIC_RE)


class PublishHygieneTest(unittest.TestCase):
    """Contracts that must hold before publishing the repo (step 6)."""

    def test_license_and_security_files(self) -> None:
        self.assertTrue((REPO_ROOT / "LICENSE").is_file())
        self.assertTrue((REPO_ROOT / "SECURITY.md").is_file())
        self.assertTrue((REPO_ROOT / "README.md").is_file())
        self.assertTrue((REPO_ROOT / ".ansible-lint").is_file())
        self.assertTrue((REPO_ROOT / ".github" / "workflows" / "ci.yml").is_file())
        self.assertTrue((REPO_ROOT / "requirements-dev.txt").is_file())

    def test_ci_workflow_matches_local_runner(self) -> None:
        workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        for needle in (
            "unittest discover -s tests",
            "ansible-playbook --syntax-check",
            "cluster_addons.yaml",
            "ansible-lint --profile min",
            "check-no-hardcoded-domains.sh",
        ):
            self.assertIn(needle, workflow)
        run_ci = (REPO_ROOT / "tests" / "run_ci.sh").read_text(encoding="utf-8")
        self.assertIn("ansible-lint --profile min", run_ci)
        self.assertIn("check-no-hardcoded-domains.sh", run_ci)
        self.assertIn("CI checks passed.", run_ci)
        self.assertNotIn("optional until CI", run_ci)

    def test_chart_state_present_skip_absent_contract(self) -> None:
        """present installs; skip is no-op; absent tears down; enum is validated."""
        defaults = (
            REPO_ROOT / "roles" / "130_validate_vars" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        allowed = re.search(
            r"^k8s_chart_state_allowed:\n((?:  - \w+\n)+)",
            defaults,
            re.M,
        )
        self.assertIsNotNone(allowed, "k8s_chart_state_allowed missing")
        self.assertEqual(
            re.findall(r"  - (\w+)", allowed.group(1)),
            ["present", "skip", "absent"],
        )
        listed = re.search(
            r"^k8s_chart_state_vars:\n((?:  - [a-z0-9_]+\n)+)",
            defaults,
            re.M,
        )
        self.assertIsNotNone(listed, "k8s_chart_state_vars missing")
        listed_vars = re.findall(r"  - ([a-z0-9_]+)", listed.group(1))
        self.assertIn("jaeger_chart_state", listed_vars)
        self.assertIn("opentelemetry_collector_chart_state", listed_vars)
        self.assertIn("sentry_chart_state", listed_vars)
        catalog = (REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml").read_text(
            encoding="utf-8"
        )
        catalog_vars = re.findall(r"^([a-z0-9_]+_chart_state):", catalog, re.M)
        self.assertEqual(
            set(listed_vars),
            set(catalog_vars),
            "130_validate_vars k8s_chart_state_vars must match catalog *_chart_state keys",
        )
        self.assertIn("sentry_chart_state: skip", catalog)
        self.assertNotIn("sentry_chart_state: absent", catalog)

        validate_main = (
            REPO_ROOT / "roles" / "130_validate_vars" / "tasks" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("include_tasks: chart_state.yml", validate_main)
        chart_state = (
            REPO_ROOT / "roles" / "130_validate_vars" / "tasks" / "chart_state.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("k8s_chart_state_allowed", chart_state)
        self.assertIn("k8s_chart_state_vars", chart_state)

        forbidden = _scan_product_sources_for_regex(
            re.compile(r"_chart_state\s*\|\s*default\('present'\)\s*!=\s*'absent'")
        )
        self.assertEqual(
            forbidden,
            [],
            "install gates must be == 'present', not != 'absent'",
        )

        sentry = (REPO_ROOT / "roles" / "994_sentry" / "tasks" / "main.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("sentry_chart_state | default('present') == 'absent'", sentry)
        self.assertIn("sentry_chart_state | default('present') == 'present'", sentry)

        playbook = (REPO_ROOT / "playbooks" / "cluster_addons.yaml").read_text(
            encoding="utf-8"
        )
        for role, var in (
            ("610_elasticsearch_prepare", "elasticsearch_chart_state"),
            ("630_kibana_prepare", "kibana_chart_state"),
            ("930_keycloak_realm", "keycloak_chart_state"),
            ("940_apiserver_oidc", "keycloak_chart_state"),
            ("941_k8s_oidc", "keycloak_chart_state"),
            ("990_rook_ceph_dashboard", "rook_cluster_chart_state"),
            ("992_kibana_dashboards", "kibana_chart_state"),
        ):
            self.assertRegex(
                playbook,
                rf"- role: {role}\n\s+tags: {role}\n\s+when: {var} \| default\('present'\) == 'present'",
                f"{role} must skip unless {var} is present",
            )

        ingress_block = re.search(
            r"(?ms)^k8s_ingress_apps:\n(.*?)(?=\n# --- )",
            catalog,
        )
        self.assertIsNotNone(ingress_block, "k8s_ingress_apps block missing")
        required_ingress = {
            "kibana": "kibana_chart_state",
            "elasticsearch-master": "elasticsearch_chart_state",
            "prometheus-kube-prometheus-prometheus": "prometheus_chart_state",
            "prometheus-kube-prometheus-alertmanager": "prometheus_chart_state",
            "grafana-ingress": "prometheus_chart_state",
            "rook-ceph-mgr-dashboard": "rook_cluster_chart_state",
            "keycloak-http": "keycloak_chart_state",
            "argocd-server-ingress": "argocd_chart_state",
            "argo-rollouts-dashboard": "argo_rollouts_chart_state",
            "pinniped-supervisor": "pinniped_chart_state",
            "pinniped-login": "pinniped_chart_state",
            "mailu": "mailu_chart_state",
            "blackbox": "blackbox_exporter_chart_state",
            "oauth2-proxy": "oauth2_proxy_chart_state",
            "headlamp": "headlamp_chart_state",
            "vault": "vault_chart_state",
            "kiali": "kiali_chart_state",
            "jaeger": "jaeger_chart_state",
            "falco": "falco_chart_state",
            "policy-reporter": "policy_reporter_chart_state",
            "chaos-dashboard": "chaos_mesh_chart_state",
            "opencost": "opencost_chart_state",
        }
        apps: dict[str, str | None] = {}
        for match in re.finditer(
            r"(?m)^  - name: (\S+)\n((?:    .+\n)*)",
            ingress_block.group(1),
        ):
            body = match.group(2)
            var_match = re.search(r"chart_state_var: (\S+)", body)
            apps[match.group(1)] = var_match.group(1) if var_match else None
        for name, var in required_ingress.items():
            self.assertIn(name, apps, f"ingress app {name} missing")
            self.assertEqual(apps[name], var, f"{name} chart_state_var")

        apply45 = (
            REPO_ROOT / "roles" / "560_apply_ingress" / "tasks" / "main.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("k8s_ingress_apps_active", apply45)
        self.assertIn("item.chart_state_var", apply45)
        routes = (
            REPO_ROOT
            / "roles"
            / "560_apply_ingress"
            / "templates"
            / "gateway-routes.yaml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("k8s_ingress_apps_active", routes)
        self.assertNotIn("k8s_ingress_apps | default([])", routes)

        absent = (
            REPO_ROOT / "roles" / "common" / "tasks" / "helm_chart_absent.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("Probe Helm releases for absent fast-path", absent)
        self.assertIn("Probe namespaces for absent fast-path", absent)
        self.assertIn("helm_chart_absent_skip_cluster", absent)
        self.assertIn("when: not (helm_chart_absent_skip_cluster | bool)", absent)
        self.assertIn("Teardown Helm chart from the cluster", absent)
        self.assertLess(
            absent.index("Probe Helm releases for absent fast-path"),
            absent.index("Teardown Helm chart from the cluster"),
        )

        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("present|skip|absent", readme)
        self.assertIn("sentry_chart_state: skip", readme)

    def test_readme_mentions_ci_runner(self) -> None:
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("./tests/run_ci.sh", readme)
        self.assertIn("Testing / CI", readme)
        self.assertIn(".github/workflows/ci.yml", readme)
        self.assertIn("ansible-lint --profile min", readme)


_PRODUCT_SCAN_ROOTS = (
    REPO_ROOT / "roles",
    REPO_ROOT / "playbooks",
    REPO_ROOT / "group_vars",
    REPO_ROOT / "examples",
    REPO_ROOT / "host_vars",
    REPO_ROOT / "filter_plugins",
    REPO_ROOT / "inventory-example.yml",
    REPO_ROOT / "run.sh",
    REPO_ROOT / "requirements.yml",
    REPO_ROOT / "ansible.cfg",
    REPO_ROOT / "README.md",
)
_PRODUCT_SCAN_SUFFIXES = {".yml", ".yaml", ".j2", ".sh", ".cfg", ".md", ".py", ".tf"}


def _scan_product_sources_for(
    needles: tuple[str, ...],
    *,
    case_sensitive: bool = False,
) -> list[str]:
    hits: list[str] = []
    for root in _PRODUCT_SCAN_ROOTS:
        paths = [root] if root.is_file() else root.rglob("*")
        for path in paths:
            if not path.is_file():
                continue
            if path.suffix.lower() not in _PRODUCT_SCAN_SUFFIXES and path.name != "run.sh":
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            haystack = text if case_sensitive else text.lower()
            for needle in needles:
                probe = needle if case_sensitive else needle.lower()
                if probe in haystack:
                    hits.append(f"{path.relative_to(REPO_ROOT)}:{needle}")
    return hits


def _scan_product_sources_for_regex(pattern: re.Pattern[str]) -> list[str]:
    hits: list[str] = []
    for root in _PRODUCT_SCAN_ROOTS:
        paths = [root] if root.is_file() else root.rglob("*")
        for path in paths:
            if not path.is_file():
                continue
            if path.suffix.lower() not in _PRODUCT_SCAN_SUFFIXES and path.name != "run.sh":
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for i, line in enumerate(text.splitlines(), 1):
                if pattern.search(line):
                    hits.append(f"{path.relative_to(REPO_ROOT)}:{i}:{line.strip()[:100]}")
    return hits


if __name__ == "__main__":
    unittest.main()
