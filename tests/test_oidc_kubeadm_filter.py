"""Unit tests for filter_plugins/oidc_kubeadm.py."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "filter_plugins"))

import oidc_kubeadm  # noqa: E402


DESIRED = [
    {"name": "oidc-issuer-url", "value": "https://keycloak.example/auth/realms/org"},
    {"name": "oidc-client-id", "value": "kubernetes"},
    {"name": "oidc-username-claim", "value": "preferred_username"},
    {"name": "oidc-username-prefix", "value": "-"},
    {"name": "oidc-groups-claim", "value": "groups"},
    {"name": "oidc-ca-file", "value": "/etc/kubernetes/pki/oidc-ca.crt"},
]


CLUSTER_CONFIG = """
apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
kubernetesVersion: v1.32.2
apiServer:
  extraArgs:
    - name: profiling
      value: false
    - name: max-requests-inflight
      value: 2000
    - name: oidc-client-id
      value: old
  extraVolumes: []
controlPlaneEndpoint: 10.0.0.10:6443
"""


POD_EQUALS = """
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: kube-apiserver
      command:
        - kube-apiserver
        - --oidc-issuer-url=https://keycloak.example/auth/realms/org
        - --oidc-client-id=kubernetes
        - --oidc-username-claim=preferred_username
        - --oidc-username-prefix=-
        - --oidc-groups-claim=groups
        - --oidc-ca-file=/etc/kubernetes/pki/oidc-ca.crt
"""


POD_SPLIT = """
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: kube-apiserver
      command:
        - kube-apiserver
        - --oidc-issuer-url
        - https://keycloak.example/auth/realms/org
        - --oidc-client-id
        - kubernetes
        - --oidc-username-claim
        - preferred_username
        - --oidc-username-prefix
        - "-"
        - --oidc-groups-claim
        - groups
        - --oidc-ca-file
        - /etc/kubernetes/pki/oidc-ca.crt
"""


class OidcKubeadmFilterTest(unittest.TestCase):
    def test_merge_quotes_extra_args_values(self) -> None:
        dumped = oidc_kubeadm.oidc_merge_cluster_config(CLUSTER_CONFIG, DESIRED)
        self.assertIn('value: "false"', dumped)
        self.assertIn('value: "2000"', dumped)
        self.assertIn('value: "kubernetes"', dumped)
        self.assertIn('value: "-"', dumped)
        self.assertNotIn("to_nice_yaml", dumped)
        loaded = yaml.safe_load(dumped)
        by_name = {item["name"]: item["value"] for item in loaded["apiServer"]["extraArgs"]}
        self.assertEqual(by_name["profiling"], "false")
        self.assertIsInstance(by_name["profiling"], str)
        self.assertEqual(by_name["max-requests-inflight"], "2000")
        self.assertIsInstance(by_name["max-requests-inflight"], str)
        self.assertEqual(by_name["oidc-client-id"], "kubernetes")
        self.assertEqual(by_name["oidc-username-prefix"], "-")
        self.assertEqual(loaded["kubernetesVersion"], "v1.32.2")
        self.assertEqual(loaded["controlPlaneEndpoint"], "10.0.0.10:6443")

    def test_merge_quoted_false_stays_string(self) -> None:
        raw = """
apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
apiServer:
  extraArgs:
    - name: profiling
      value: "false"
"""
        dumped = oidc_kubeadm.oidc_merge_cluster_config(raw, DESIRED)
        loaded = yaml.safe_load(dumped)
        by_name = {item["name"]: item["value"] for item in loaded["apiServer"]["extraArgs"]}
        self.assertEqual(by_name["profiling"], "false")
        self.assertIsInstance(by_name["profiling"], str)

    def test_quotes_etcd_controller_scheduler_extra_args(self) -> None:
        raw = """
apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
apiServer:
  extraArgs:
    - name: profiling
      value: false
etcd:
  local:
    extraArgs:
      - name: snapshot-count
        value: 30000
      - name: quota-backend-bytes
        value: 4294967296
  external:
    extraArgs:
      - name: endpoints
        value: https://etcd.example:2379
controllerManager:
  extraArgs:
    - name: leader-elect
      value: true
scheduler:
  extraArgs:
    - name: leader-elect
      value: true
"""
        dumped = oidc_kubeadm.oidc_merge_cluster_config(raw, DESIRED)
        self.assertIn('value: "30000"', dumped)
        self.assertIn('value: "4294967296"', dumped)
        self.assertIn('value: "true"', dumped)
        loaded = yaml.safe_load(dumped)
        snapshot = loaded["etcd"]["local"]["extraArgs"][0]["value"]
        leader = loaded["controllerManager"]["extraArgs"][0]["value"]
        sched = loaded["scheduler"]["extraArgs"][0]["value"]
        self.assertEqual(snapshot, "30000")
        self.assertIsInstance(snapshot, str)
        self.assertEqual(leader, "true")
        self.assertIsInstance(leader, str)
        self.assertEqual(sched, "true")
        self.assertIsInstance(sched, str)
        self.assertIsInstance(loaded["etcd"]["local"]["extraArgs"][1]["value"], str)

    def test_cm_has_flags(self) -> None:
        missing = oidc_kubeadm.oidc_cm_has_flags(CLUSTER_CONFIG, DESIRED)
        self.assertFalse(missing)
        dumped = oidc_kubeadm.oidc_merge_cluster_config(CLUSTER_CONFIG, DESIRED)
        self.assertTrue(oidc_kubeadm.oidc_cm_has_flags(dumped, DESIRED))

    def test_pod_has_flags_equals_and_split(self) -> None:
        self.assertTrue(oidc_kubeadm.oidc_pod_has_flags(POD_EQUALS, DESIRED))
        self.assertTrue(oidc_kubeadm.oidc_pod_has_flags(POD_SPLIT, DESIRED))
        self.assertFalse(oidc_kubeadm.oidc_pod_has_flags("", DESIRED))
        self.assertFalse(
            oidc_kubeadm.oidc_pod_has_flags(
                POD_EQUALS.replace("kubernetes", "other"),
                DESIRED,
            )
        )


if __name__ == "__main__":
    unittest.main()
