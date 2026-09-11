"""Helm chart repo client URL resolver (none | nexus | nginx).

Keep helm_repo_client_url logic in sync with:
- atlas-infra-edge/filter_plugins/helm_repo.py
- atlas-k8s-core/filter_plugins/helm_repo.py (until PR-2 removes core copy)
"""

import re


def _slug(value):
    slug = re.sub(r"[^a-zA-Z0-9._-]", "-", value or "")
    return slug.replace(".", "-")


def _find_upstream(name, helm_repo_upstreams):
    for item in helm_repo_upstreams or []:
        if item.get("name") == name:
            return item
    return {}


def _public_uri(name, helm_repo_upstreams):
    item = _find_upstream(name, helm_repo_upstreams)
    return (item.get("upstream_url") or "").rstrip("/")


class FilterModule(object):
    def filters(self):
        return {
            "helm_repo_client_url": self.helm_repo_client_url,
        }

    def helm_repo_client_url(
        self,
        name,
        mode,
        nexus_base_url,
        nginx_ingress_domain,
        helm_repo_upstreams=None,
    ):
        mode = (mode or "none").strip()
        name = name or ""
        public = _public_uri(name, helm_repo_upstreams)

        if mode == "none":
            return public
        if mode == "nexus":
            item = _find_upstream(name, helm_repo_upstreams)
            base = (nexus_base_url or "").rstrip("/")
            path = (item.get("nexus_path") or name).strip("/")
            if base:
                return f"{base}/{path}" if path else base
            return public
        if mode == "nginx":
            domain = (nginx_ingress_domain or "").strip()
            if domain:
                return f"https://{_slug(name)}.{domain}"
        return public
