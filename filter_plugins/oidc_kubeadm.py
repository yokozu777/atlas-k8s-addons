"""Merge kubeadm ClusterConfiguration extraArgs; inspect kube-apiserver flags.

Keep extraArgs values as quoted YAML strings so kubeadm unmarshals them as
string (unquoted false/true/2000 would become bool/int).
"""

from __future__ import annotations

import yaml


class _QuotedStr(str):
    """Force double-quoted YAML scalars for kubeadm extraArgs values."""


def _quoted_str_representer(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", str(data), style='"')


class _OidcKubeadmDumper(yaml.SafeDumper):
    pass


_OidcKubeadmDumper.add_representer(_QuotedStr, _quoted_str_representer)


def extra_arg_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    if isinstance(value, bytes):
        return extra_arg_value(value.decode("utf-8"))
    if isinstance(value, int):
        return str(value)
    return str(value)


def extra_args_as_items(extra):
    items = []
    if extra is None:
        return items
    if isinstance(extra, dict):
        for key, value in extra.items():
            items.append({"name": str(key), "value": extra_arg_value(value)})
        return items
    for item in extra:
        if isinstance(item, dict):
            items.append(
                {
                    "name": str(item.get("name", "")),
                    "value": extra_arg_value(item.get("value", "")),
                }
            )
        else:
            items.append({"name": str(item), "value": ""})
    return items


def merge_extra_args(existing, desired):
    desired_items = extra_args_as_items(desired)
    oidc_names = {item["name"] for item in desired_items}
    kept = [item for item in extra_args_as_items(existing) if item["name"] not in oidc_names]
    return kept + desired_items


def quote_extra_args(items):
    return [{"name": item["name"], "value": _QuotedStr(item["value"])} for item in items]


def quote_extra_args_in_tree(node):
    """Force every extraArgs value (apiServer, etcd, controllerManager, scheduler) to a quoted string."""
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if key == "extraArgs":
                out[key] = quote_extra_args(extra_args_as_items(value))
            else:
                out[key] = quote_extra_args_in_tree(value)
        return out
    if isinstance(node, list):
        return [quote_extra_args_in_tree(item) for item in node]
    return node


def _dump_cluster_config(doc):
    kwargs = {
        "Dumper": _OidcKubeadmDumper,
        "default_flow_style": False,
        "allow_unicode": True,
        "indent": 2,
    }
    try:
        return yaml.dump(doc, sort_keys=False, **kwargs)
    except TypeError:
        return yaml.dump(doc, **kwargs)


def oidc_merge_cluster_config(raw_yaml, desired_extra_args):
    if raw_yaml is None or not str(raw_yaml).strip():
        raise ValueError("ClusterConfiguration YAML is empty")
    doc = yaml.safe_load(raw_yaml)
    if not isinstance(doc, dict):
        raise ValueError("ClusterConfiguration is not a mapping")
    api_server = dict(doc.get("apiServer") or {})
    api_server["extraArgs"] = merge_extra_args(api_server.get("extraArgs"), desired_extra_args)
    doc["apiServer"] = api_server
    return _dump_cluster_config(quote_extra_args_in_tree(doc))


def extra_args_from_cluster_config(raw_yaml):
    doc = yaml.safe_load(raw_yaml or "") or {}
    if not isinstance(doc, dict):
        return []
    api_server = doc.get("apiServer") or {}
    return extra_args_as_items(api_server.get("extraArgs"))


def oidc_cm_has_flags(raw_yaml, desired_extra_args):
    have = extra_args_from_cluster_config(raw_yaml)
    by_name = {item["name"]: item["value"] for item in have}
    for want in extra_args_as_items(desired_extra_args):
        if by_name.get(want["name"]) != want["value"]:
            return False
    return True


def _container_argv(container):
    cmd = list(container.get("command") or [])
    args = list(container.get("args") or [])
    return [str(item) for item in cmd + args]


def _is_apiserver_container(container, argv):
    name = str(container.get("name") or "")
    if name == "kube-apiserver":
        return True
    if argv and str(argv[0]).rstrip("/").endswith("kube-apiserver"):
        return True
    return False


def _command_has_flag(argv, name, value):
    eq = "--%s=%s" % (name, value)
    flag = "--%s" % name
    for index, item in enumerate(argv):
        if item == eq:
            return True
        if item == flag and index + 1 < len(argv) and argv[index + 1] == value:
            return True
    return False


def oidc_pod_has_flags(pod_text, desired_extra_args):
    if not pod_text or not str(pod_text).strip():
        return False
    pod = yaml.safe_load(pod_text)
    if not isinstance(pod, dict):
        return False
    containers = (pod.get("spec") or {}).get("containers") or []
    argv = []
    for container in containers:
        if not isinstance(container, dict):
            continue
        candidate = _container_argv(container)
        if _is_apiserver_container(container, candidate):
            argv.extend(candidate)
    if not argv and containers and isinstance(containers[0], dict):
        argv = _container_argv(containers[0])
    if not argv:
        return False
    for want in extra_args_as_items(desired_extra_args):
        if not _command_has_flag(argv, want["name"], want["value"]):
            return False
    return True


class FilterModule(object):
    def filters(self):
        return {
            "oidc_merge_cluster_config": oidc_merge_cluster_config,
            "oidc_cm_has_flags": oidc_cm_has_flags,
            "oidc_pod_has_flags": oidc_pod_has_flags,
        }
