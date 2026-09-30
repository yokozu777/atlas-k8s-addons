"""Unit tests for filter_plugins/helm_repo.py helm_repos_required."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "filter_plugins"))

import helm_repo  # noqa: E402


REPOS = [
    {"name": "hashicorp", "path": "helm.releases.hashicorp.com/"},
    {"name": "openbao", "path": "openbao-helm/"},
    {"name": "kong-z", "path": "kong-z/"},
    {"name": "prometheus-community", "path": "prometheus-community"},
]

CHART_STATES = {
    "hashicorp": ["consul_chart_state", "vault_chart_state"],
    "openbao": ["openbao_chart_state"],
    "prometheus-community": [
        "prometheus_chart_state",
        "blackbox_exporter_chart_state",
    ],
}


class HelmReposRequiredTest(unittest.TestCase):
    def _names(self, variables):
        selected = helm_repo.helm_repos_required(REPOS, CHART_STATES, variables)
        return [item["name"] for item in selected]

    def test_skips_hashicorp_when_consul_and_vault_are_not_present(self):
        names = self._names(
            {
                "consul_chart_state": "skip",
                "vault_chart_state": "skip",
                "openbao_chart_state": "present",
                "prometheus_chart_state": "present",
                "blackbox_exporter_chart_state": "skip",
            }
        )
        self.assertNotIn("hashicorp", names)
        self.assertIn("openbao", names)
        self.assertIn("prometheus-community", names)

    def test_keeps_hashicorp_when_one_chart_is_present(self):
        names = self._names(
            {
                "consul_chart_state": "skip",
                "vault_chart_state": "present",
                "openbao_chart_state": "skip",
                "prometheus_chart_state": "skip",
                "blackbox_exporter_chart_state": "skip",
            }
        )
        self.assertEqual(names, ["hashicorp", "kong-z"])

    def test_absent_does_not_require_the_repo(self):
        names = self._names(
            {
                "consul_chart_state": "absent",
                "vault_chart_state": "skip",
                "openbao_chart_state": "absent",
                "prometheus_chart_state": "absent",
                "blackbox_exporter_chart_state": "absent",
            }
        )
        self.assertEqual(names, ["kong-z"])

    def test_unmapped_repo_stays_and_unknown_state_counts_as_present(self):
        names = self._names({})
        self.assertEqual(
            names,
            ["hashicorp", "openbao", "kong-z", "prometheus-community"],
        )

    def test_role_defaults_map_hashicorp_to_consul_and_vault(self):
        defaults = yaml.safe_load(
            (REPO_ROOT / "roles" / "210_helm_bootstrap" / "defaults" / "main.yml").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            defaults["helm_repo_chart_states"]["hashicorp"],
            ["consul_chart_state", "vault_chart_state"],
        )


if __name__ == "__main__":
    unittest.main()
