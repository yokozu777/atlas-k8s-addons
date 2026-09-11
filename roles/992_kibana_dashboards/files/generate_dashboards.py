#!/usr/bin/env python3
"""Generate Kibana 9 Lens dashboard ndjson for Atlas cluster logs."""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from typing import Any

NS = uuid.UUID("8f3c0b1a-4d2e-4a6f-9c11-7b2e5d0a91e4")
OUT_DIR = Path(__file__).resolve().parent
REPO_ROOT = OUT_DIR.parents[2]
CATALOG = REPO_ROOT / "group_vars" / "all" / "atlas-k8s-addons.yml"


def load_system_namespaces() -> list[str]:
    names: list[str] = []
    in_block = False
    for line in CATALOG.read_text(encoding="utf-8").splitlines():
        if line.startswith("kibana_logs_system_namespaces:"):
            in_block = True
            continue
        if in_block:
            stripped = line.strip()
            if stripped.startswith("- "):
                names.append(stripped[2:].strip().strip("\"'"))
            elif stripped.startswith("#") or stripped == "":
                continue
            elif not line.startswith(" "):
                break
            else:
                break
    if not names:
        raise RuntimeError(f"kibana_logs_system_namespaces missing in {CATALOG}")
    return names


SYSTEM_NAMESPACES = load_system_namespaces()

TIME = "@timestamp"
K8S = "k8s"
HOST = "host"

DASHBOARD_MIGRATION = "10.2.0"
CORE_MIGRATION = "8.8.0"
SEARCH_MIGRATION = "10.2.0"
TAG_MIGRATION = "8.0.0"

TAG_ATLAS = "atlas-tag-atlas"
TAG_LOGS = "atlas-tag-logs"
TAG_NOC = "atlas-tag-noc"

KUBE_SEARCH_COLUMNS = [
    TIME,
    "atlas_severity",
    "kubernetes.namespace_name",
    "kubernetes.pod_name",
    "kubernetes.container_name",
    "log",
]
HOST_SEARCH_COLUMNS = [
    TIME,
    "_HOSTNAME",
    "SYSLOG_IDENTIFIER",
    "atlas_severity",
    "MESSAGE",
]


def uid(*parts: str) -> str:
    return str(uuid.uuid5(NS, "atlas-kibana:" + "/".join(parts)))


def dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=True, separators=(",", ":"))


def _layer_refs(data_view_id: str, layer_id: str) -> list[dict[str, str]]:
    return [
        {
            "type": "index-pattern",
            "id": data_view_id,
            "name": f"indexpattern-datasource-layer-{layer_id}",
        }
    ]


def _count_col(_col_id: str | None = None) -> dict[str, Any]:
    return {
        "label": "Count of records",
        "dataType": "number",
        "operationType": "count",
        "isBucketed": False,
        "scale": "ratio",
        "sourceField": "___records___",
        "params": {"emptyAsNull": True},
    }


def _date_col(_col_id: str | None = None, field: str = TIME) -> dict[str, Any]:
    return {
        "label": field,
        "dataType": "date",
        "operationType": "date_histogram",
        "sourceField": field,
        "isBucketed": True,
        "scale": "interval",
        "params": {"interval": "auto", "includeEmptyRows": True, "dropPartials": False},
    }


def _terms_col(field: str, size: int, metric_col: str) -> dict[str, Any]:
    return {
        "label": f"Top values of {field}",
        "dataType": "string",
        "operationType": "terms",
        "scale": "ordinal",
        "sourceField": field,
        "isBucketed": True,
        "params": {
            "size": size,
            "orderBy": {"type": "column", "columnId": metric_col},
            "orderDirection": "desc",
            "otherBucket": True,
            "missingBucket": False,
            "parentFormat": {"id": "terms"},
            "include": [],
            "exclude": [],
            "includeIsRegex": False,
            "excludeIsRegex": False,
        },
    }


def severity_color_mapping() -> dict[str, Any]:
    assignments = []
    for value, color in (
        ("error", "#BD271E"),
        ("warn", "#F5A700"),
        ("info", "#6092C0"),
    ):
        assignments.append(
            {
                "rules": [{"type": "raw", "value": value}],
                "color": {"type": "colorCode", "colorCode": color},
                "touched": False,
            }
        )
    return {
        "paletteId": "elastic_classic",
        "colorMode": {"type": "categorical"},
        "assignments": assignments,
        "specialAssignments": [
            {
                "rules": [{"type": "other"}],
                "color": {"type": "loop"},
                "touched": False,
            }
        ],
    }


def _form_based(layer_id: str, columns: dict[str, Any], order: list[str]) -> dict[str, Any]:
    return {
        "formBased": {
            "layers": {
                layer_id: {
                    "columns": columns,
                    "columnOrder": order,
                    "incompleteColumns": {},
                    "sampling": 1,
                }
            }
        },
        "indexpattern": {"layers": {}},
        "textBased": {"layers": {}},
    }


def lens_state(
    data_view_id: str,
    layer_id: str,
    visualization: dict[str, Any],
    visualization_type: str,
    columns: dict[str, Any],
    order: list[str],
    kql: str,
) -> dict[str, Any]:
    return {
        "title": "",
        "visualizationType": visualization_type,
        "type": "lens",
        "references": _layer_refs(data_view_id, layer_id),
        "state": {
            "visualization": visualization,
            "query": {"query": kql, "language": "kuery"},
            "filters": [],
            "datasourceStates": _form_based(layer_id, columns, order),
            "internalReferences": [],
            "adHocDataViews": {},
        },
    }


def xy_split(
    dash: str,
    panel: str,
    data_view_id: str,
    split_field: str,
    kql: str = "",
    series_type: str = "bar_stacked",
    size: int = 10,
) -> dict[str, Any]:
    layer_id = uid(dash, panel, "layer")
    x_col = uid(dash, panel, "x")
    split_col = uid(dash, panel, "split")
    y_col = uid(dash, panel, "y")
    columns = {
        x_col: _date_col(x_col),
        split_col: _terms_col(split_field, size, y_col),
        y_col: _count_col(y_col),
    }
    vis = {
        "legend": {"isVisible": True, "position": "right"},
        "valueLabels": "hide",
        "fittingFunction": "None",
        "axisTitlesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
        "tickLabelsVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
        "labelsOrientation": {"x": 0, "yLeft": 0, "yRight": 0},
        "gridlinesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
        "preferredSeriesType": series_type,
        "layers": [
            {
                "layerId": layer_id,
                "seriesType": series_type,
                "accessors": [y_col],
                "yConfig": [{"forAccessor": y_col}],
                "layerType": "data",
                "xAccessor": x_col,
                "splitAccessor": split_col,
            }
        ],
    }
    if split_field == "atlas_severity":
        vis["layers"][0]["colorMapping"] = severity_color_mapping()
    return lens_state(
        data_view_id, layer_id, vis, "lnsXY", columns, [x_col, split_col, y_col], kql
    )


def xy_count(
    dash: str,
    panel: str,
    data_view_id: str,
    kql: str = "",
    series_type: str = "line",
) -> dict[str, Any]:
    layer_id = uid(dash, panel, "layer")
    x_col = uid(dash, panel, "x")
    y_col = uid(dash, panel, "y")
    columns = {x_col: _date_col(x_col), y_col: _count_col(y_col)}
    vis = {
        "legend": {"isVisible": False, "position": "right"},
        "valueLabels": "hide",
        "fittingFunction": "None",
        "axisTitlesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
        "tickLabelsVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
        "labelsOrientation": {"x": 0, "yLeft": 0, "yRight": 0},
        "gridlinesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
        "preferredSeriesType": series_type,
        "layers": [
            {
                "layerId": layer_id,
                "seriesType": series_type,
                "accessors": [y_col],
                "yConfig": [{"forAccessor": y_col}],
                "layerType": "data",
                "xAccessor": x_col,
            }
        ],
    }
    return lens_state(data_view_id, layer_id, vis, "lnsXY", columns, [x_col, y_col], kql)


def pie_terms(
    dash: str,
    panel: str,
    data_view_id: str,
    field: str,
    kql: str = "",
    size: int = 10,
) -> dict[str, Any]:
    layer_id = uid(dash, panel, "layer")
    split_col = uid(dash, panel, "split")
    y_col = uid(dash, panel, "y")
    columns = {split_col: _terms_col(field, size, y_col), y_col: _count_col(y_col)}
    vis = {
        "layers": [
            {
                "layerId": layer_id,
                "layerType": "data",
                "primaryGroups": [split_col],
                "metrics": [y_col],
                "numberDisplay": "percent",
                "categoryDisplay": "default",
                "legendDisplay": "default",
                "nestedLegend": False,
            }
        ],
        "shape": "pie",
    }
    return lens_state(
        data_view_id, layer_id, vis, "lnsPie", columns, [split_col, y_col], kql
    )


def table_terms(
    dash: str,
    panel: str,
    data_view_id: str,
    fields: list[str],
    kql: str = "",
    sizes: list[int] | None = None,
    include_time: bool = False,
) -> dict[str, Any]:
    layer_id = uid(dash, panel, "layer")
    y_col = uid(dash, panel, "y")
    columns: dict[str, Any] = {}
    vis_cols: list[dict[str, Any]] = []
    order: list[str] = []
    fields = list(fields)
    sizes = list(sizes or [10] * len(fields))
    if include_time and "atlas_severity" not in fields:
        fields = ["atlas_severity"] + fields
        sizes = [5] + sizes
    if include_time:
        t_col = uid(dash, panel, "t")
        columns[t_col] = _date_col(t_col)
        vis_cols.append({"columnId": t_col, "isTransposed": False})
        order.append(t_col)
    for field, size in zip(fields, sizes):
        col = uid(dash, panel, field)
        columns[col] = _terms_col(field, size, y_col)
        vis_col: dict[str, Any] = {
            "columnId": col,
            "isTransposed": False,
            "isMetric": False,
        }
        if field == "atlas_severity":
            vis_col["colorMapping"] = severity_color_mapping()
        vis_cols.append(vis_col)
        order.append(col)
    columns[y_col] = _count_col(y_col)
    vis_cols.append({"columnId": y_col, "isTransposed": False})
    order.append(y_col)
    vis = {
        "layerId": layer_id,
        "layerType": "data",
        "columns": vis_cols,
        "sorting": {"columnId": y_col, "direction": "desc"},
    }
    return lens_state(
        data_view_id, layer_id, vis, "lnsDatatable", columns, order, kql
    )


def lens_panel(
    dash: str,
    panel: str,
    title: str,
    attributes: dict[str, Any],
    x: int,
    y: int,
    w: int,
    h: int,
) -> dict[str, Any]:
    panel_id = uid(dash, panel, "panel")
    data_view_id = attributes["references"][0]["id"]
    layer_name = attributes["references"][0]["name"]
    return {
        "type": "lens",
        "panelIndex": panel_id,
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": panel_id},
        "embeddableConfig": {
            "enhancements": {
                "dynamicActions": {
                    "events": [
                        {
                            "eventId": uid(dash, panel, "drilldown"),
                            "triggers": [
                                "FILTER_TRIGGER",
                                "VALUE_CLICK_TRIGGER",
                            ],
                            "action": {
                                "factoryId": "OPEN_IN_DISCOVER_DRILLDOWN",
                                "name": "Open in Discover",
                                "config": {"openInNewTab": True},
                            },
                        }
                    ]
                }
            },
            "syncColors": True,
            "syncCursor": True,
            "syncTooltips": True,
            "hidePanelTitles": False,
            "title": title,
            "filters": [],
            "query": {"query": "", "language": "kuery"},
            "attributes": attributes,
        },
        "_refs": [
            {
                "id": data_view_id,
                "name": f"{panel_id}:{layer_name}",
                "type": "index-pattern",
            }
        ],
    }


def options_control(
    dash: str, field: str, title: str, data_view_id: str, order: int
) -> tuple[str, dict[str, Any], dict[str, str]]:
    control_id = uid(dash, "control", data_view_id, field)
    body = {
        "type": "optionsListControl",
        "order": order,
        "grow": True,
        "width": "medium",
        "explicitInput": {
            "id": control_id,
            "title": title,
            "dataViewId": data_view_id,
            "fieldName": field,
            "selectedOptions": [],
            "existsSelected": False,
            "exclude": False,
            "enhancements": {"dynamicActions": {}},
        },
    }
    ref = {
        "name": f"controlGroup_{control_id}:index-pattern",
        "type": "index-pattern",
        "id": data_view_id,
    }
    return control_id, body, ref


def saved_search(
    search_id: str,
    title: str,
    data_view_id: str,
    columns: list[str],
    query: str = "",
    description: str = "",
) -> dict[str, Any]:
    return {
        "attributes": {
            "columns": columns,
            "description": description,
            "hits": 0,
            "hideChart": True,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": dumps(
                    {
                        "query": {"query": query, "language": "kuery"},
                        "filter": [],
                        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
                    }
                )
            },
            "sort": [[TIME, "desc"]],
            "title": title,
        },
        "coreMigrationVersion": CORE_MIGRATION,
        "id": search_id,
        "managed": False,
        "references": [
            {
                "id": data_view_id,
                "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                "type": "index-pattern",
            }
        ],
        "type": "search",
        "typeMigrationVersion": SEARCH_MIGRATION,
    }


def search_panel(
    dash: str,
    panel: str,
    title: str,
    search_id: str,
    x: int,
    y: int,
    w: int,
    h: int,
) -> dict[str, Any]:
    panel_id = uid(dash, panel, "panel")
    return {
        "type": "search",
        "panelIndex": panel_id,
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": panel_id},
        "embeddableConfig": {
            "enhancements": {"dynamicActions": {"events": []}},
            "hidePanelTitles": False,
            "title": title,
            "savedObjectId": search_id,
        },
        "_refs": [
            {
                "id": search_id,
                "name": f"{panel_id}:panelId",
                "type": "search",
            }
        ],
    }


def kube_controls(dash: str) -> tuple[str, list[dict[str, str]]]:
    panels: dict[str, Any] = {}
    refs: list[dict[str, str]] = []
    specs = [
        ("atlas_severity", "Severity", 0),
        ("kubernetes.namespace_name", "Namespace", 1),
        ("kubernetes.host", "Node", 2),
        ("kubernetes.container_name", "Container", 3),
    ]
    for field, title, order in specs:
        cid, body, ref = options_control(dash, field, title, K8S, order)
        panels[cid] = body
        refs.append(ref)
    return dumps(panels), refs


def host_controls(dash: str) -> tuple[str, list[dict[str, str]]]:
    panels: dict[str, Any] = {}
    refs: list[dict[str, str]] = []
    specs = [
        ("atlas_severity", "Severity", 0),
        ("_HOSTNAME", "Host", 1),
        ("SYSLOG_IDENTIFIER", "Identifier", 2),
        ("_SYSTEMD_UNIT", "Unit", 3),
    ]
    for field, title, order in specs:
        cid, body, ref = options_control(dash, field, title, HOST, order)
        panels[cid] = body
        refs.append(ref)
    return dumps(panels), refs


def mixed_controls(dash: str) -> tuple[str, list[dict[str, str]]]:
    panels: dict[str, Any] = {}
    refs: list[dict[str, str]] = []
    specs = [
        (K8S, "atlas_severity", "Severity", 0),
        (K8S, "kubernetes.namespace_name", "Namespace", 1),
        (K8S, "kubernetes.host", "Node", 2),
        (K8S, "kubernetes.container_name", "Container", 3),
        (HOST, "atlas_severity", "Host severity", 4),
        (HOST, "_HOSTNAME", "Host", 5),
    ]
    for dv, field, title, order in specs:
        cid, body, ref = options_control(dash, field, title, dv, order)
        panels[cid] = body
        refs.append(ref)
    return dumps(panels), refs


def cluster_controls(dash: str) -> tuple[str, list[dict[str, str]]]:
    panels: dict[str, Any] = {}
    refs: list[dict[str, str]] = []
    specs = [
        (K8S, "atlas_severity", "Severity", 0),
        (K8S, "kubernetes.namespace_name", "Namespace", 1),
        (K8S, "kubernetes.container_name", "Container", 2),
        (K8S, "kubernetes.pod_name", "Pod", 3),
        (K8S, "kubernetes.host", "Node", 4),
        (HOST, "atlas_severity", "Host severity", 5),
        (HOST, "_HOSTNAME", "Host", 6),
    ]
    for dv, field, title, order in specs:
        cid, body, ref = options_control(dash, field, title, dv, order)
        panels[cid] = body
        refs.append(ref)
    return dumps(panels), refs


def tag_object(tag_id: str, name: str, color: str, description: str = "") -> dict[str, Any]:
    return {
        "attributes": {
            "color": color,
            "description": description,
            "name": name,
        },
        "coreMigrationVersion": CORE_MIGRATION,
        "id": tag_id,
        "managed": False,
        "references": [],
        "type": "tag",
        "typeMigrationVersion": TAG_MIGRATION,
    }


def tag_refs(*tag_ids: str) -> list[dict[str, str]]:
    return [{"id": tid, "name": f"tag-ref-{tid}", "type": "tag"} for tid in tag_ids]


def dashboard(
    dash_id: str,
    title: str,
    description: str,
    panels: list[dict[str, Any]],
    controls_json: str,
    control_refs: list[dict[str, str]],
    landing: bool = False,
) -> dict[str, Any]:
    refs: list[dict[str, str]] = []
    clean_panels: list[dict[str, Any]] = []
    for panel in panels:
        refs.extend(panel.pop("_refs"))
        clean_panels.append(panel)
    refs.extend(control_refs)
    tags = [TAG_ATLAS, TAG_LOGS]
    if landing:
        tags.append(TAG_NOC)
    refs.extend(tag_refs(*tags))
    attributes: dict[str, Any] = {
        "controlGroupInput": {
            "chainingSystem": "HIERARCHICAL",
            "controlStyle": "oneLine",
            "ignoreParentSettingsJSON": dumps(
                {
                    "ignoreFilters": False,
                    "ignoreQuery": False,
                    "ignoreTimerange": False,
                    "ignoreValidations": False,
                }
            ),
            "panelsJSON": controls_json,
            "showApplySelections": False,
        },
        "description": description,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": dumps(
                {"filter": [], "query": {"language": "kuery", "query": ""}}
            )
        },
        "optionsJSON": dumps(
            {
                "useMargins": True,
                "syncColors": True,
                "syncCursor": True,
                "syncTooltips": True,
                "hidePanelTitles": False,
            }
        ),
        "panelsJSON": dumps(clean_panels),
        "timeFrom": "now-1h",
        "timeRestore": True,
        "timeTo": "now",
        "title": title,
        "version": 3,
    }
    if landing:
        attributes["refreshInterval"] = {"pause": False, "value": 60000}
    return {
        "attributes": attributes,
        "coreMigrationVersion": CORE_MIGRATION,
        "id": dash_id,
        "managed": False,
        "references": refs,
        "type": "dashboard",
        "typeMigrationVersion": DASHBOARD_MIGRATION,
    }


def index_pattern(pattern_id: str, title: str) -> dict[str, Any]:
    return {
        "attributes": {"title": title, "timeFieldName": TIME, "name": title},
        "coreMigrationVersion": CORE_MIGRATION,
        "id": pattern_id,
        "managed": False,
        "references": [],
        "type": "index-pattern",
        "typeMigrationVersion": "7.11.0",
    }


def tenant_kql() -> str:
    quoted = " or ".join(f'"{ns}"' for ns in SYSTEM_NAMESPACES)
    return (
        f"NOT kubernetes.namespace_name: ({quoted}) "
        "and kubernetes.namespace_name: *"
    )


def discover_description() -> str:
    return (
        "NOC noise and heartbeat, not CPU/Ceph metrics (use Grafana). "
        "ILM deletes logs after 7 days. Calico Audit webhook is grepped out. "
        "Click a namespace bar to open Discover. Landing: Last 1h, refresh 1m."
    )


def or_ns(names: list[str]) -> str:
    inner = " or ".join(names)
    return f"kubernetes.namespace_name: ({inner})"


def build_all() -> dict[str, list[dict[str, Any]]]:
    files: dict[str, list[dict[str, Any]]] = {}

    files["atlas-data-views.ndjson"] = [
        tag_object(TAG_ATLAS, "atlas", "#6092C0", "Atlas saved objects"),
        tag_object(TAG_LOGS, "logs", "#54B399", "Cluster logs"),
        tag_object(TAG_NOC, "noc", "#BD271E", "NOC landing: overview, cluster, pipeline"),
        index_pattern(K8S, "kube-logs-*"),
        index_pattern(HOST, "host-logs-*"),
    ]

    d = "atlas-logs-overview"
    cjson, crefs = mixed_controls(d)
    files[f"{d}.ndjson"] = [
        dashboard(
            d,
            "Atlas logs overview",
            discover_description(),
            [
                lens_panel(
                    d,
                    "kube-sev",
                    "Kube logs by atlas_severity",
                    xy_split(d, "kube-sev", K8S, "atlas_severity", "", "bar_stacked", 5),
                    0,
                    0,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "host-sev",
                    "Host logs by atlas_severity",
                    xy_split(d, "host-sev", HOST, "atlas_severity", "", "bar_stacked", 5),
                    24,
                    0,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "ns",
                    "By namespace",
                    xy_split(d, "ns", K8S, "kubernetes.namespace_name", ""),
                    0,
                    12,
                    16,
                    12,
                ),
                lens_panel(
                    d,
                    "node",
                    "By node",
                    xy_split(d, "node", K8S, "kubernetes.host", ""),
                    16,
                    12,
                    16,
                    12,
                ),
                lens_panel(
                    d,
                    "stream",
                    "Kube stream",
                    pie_terms(d, "stream", K8S, "stream", "", 5),
                    32,
                    12,
                    16,
                    12,
                ),
                lens_panel(
                    d,
                    "top-ns",
                    "Top noisy namespace / container",
                    table_terms(
                        d,
                        "top-ns",
                        K8S,
                        ["kubernetes.namespace_name", "kubernetes.container_name"],
                        "",
                        [10, 10],
                    ),
                    0,
                    24,
                    24,
                    14,
                ),
                lens_panel(
                    d,
                    "hb",
                    "Fluent Bit heartbeat by node (silent = gap)",
                    xy_split(
                        d,
                        "hb",
                        HOST,
                        "_HOSTNAME",
                        "atlas_heartbeat: true",
                        "line",
                        20,
                    ),
                    24,
                    24,
                    24,
                    14,
                ),
                lens_panel(
                    d,
                    "last-err",
                    "Recent kube logs",
                    table_terms(
                        d,
                        "last-err",
                        K8S,
                        ["kubernetes.namespace_name", "kubernetes.pod_name", "log.keyword"],
                        "",
                        [8, 8, 5],
                        include_time=True,
                    ),
                    0,
                    38,
                    48,
                    14,
                ),
            ],
            cjson,
            crefs,
            landing=True,
        )
    ]

    d = "atlas-logs-control-plane"
    cjson, crefs = mixed_controls(d)
    kube_cp = (
        "kubernetes.namespace_name: kube-system and kubernetes.container_name: "
        "(kube-apiserver or kube-controller-manager or kube-scheduler or etcd)"
    )
    host_cp = (
        "SYSLOG_IDENTIFIER: (kubelet or containerd or kube-apiserver or etcd or "
        '"kube-controller-manager" or "kube-scheduler")'
    )
    files[f"{d}.ndjson"] = [
        dashboard(
            d,
            "Atlas logs control plane",
            "API server, controller-manager, scheduler, etcd, kubelet, containerd. "
            "Not Grafana CPU. ILM 7 days. Click a series to open Discover.",
            [
                lens_panel(
                    d,
                    "apiserver",
                    "kube-apiserver by node",
                    xy_split(
                        d,
                        "apiserver",
                        K8S,
                        "kubernetes.host",
                        "kubernetes.container_name: kube-apiserver",
                    ),
                    0,
                    0,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "cp-cont",
                    "Control-plane containers",
                    xy_split(d, "cp-cont", K8S, "kubernetes.container_name", kube_cp),
                    24,
                    0,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "host-ident",
                    "Host kubelet / containerd / etcd",
                    xy_split(d, "host-ident", HOST, "SYSLOG_IDENTIFIER", host_cp),
                    0,
                    12,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "cp-table",
                    "Control-plane lines",
                    table_terms(
                        d,
                        "cp-table",
                        K8S,
                        [
                            "kubernetes.container_name",
                            "kubernetes.host",
                            "log.keyword",
                        ],
                        kube_cp,
                        [8, 8, 5],
                        include_time=True,
                    ),
                    24,
                    12,
                    24,
                    14,
                ),
            ],
            cjson,
            crefs,
        )
    ]

    d = "atlas-logs-edge"
    cjson, crefs = kube_controls(d)
    edge_kql = (
        "kubernetes.namespace_name: (envoy-gateway-system or istio-system) or "
        "kubernetes.container_name: (envoy or haproxy or envoy-gateway)"
    )
    edge_5xx = (
        f"({edge_kql}) and "
        "(log: *timeout* or log: *upstream* or log: *status=5* or log: * 5??*)"
    )
    files[f"{d}.ndjson"] = [
        dashboard(
            d,
            "Atlas logs edge",
            "Envoy Gateway / Istio / HAProxy log text. Request rate and 5xx metrics are Grafana/Kiali. "
            "ILM 7 days. Click a series to open Discover.",
            [
                lens_panel(
                    d,
                    "rate",
                    "Edge logs by severity",
                    xy_split(d, "rate", K8S, "atlas_severity", edge_kql, "bar_stacked", 5),
                    0,
                    0,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "gw",
                    "By gateway name",
                    xy_split(
                        d,
                        "gw",
                        K8S,
                        "kubernetes.labels.gateway_envoyproxy_io/owning-gateway-name",
                        edge_kql,
                    ),
                    24,
                    0,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "ns",
                    "By namespace",
                    xy_split(d, "ns", K8S, "kubernetes.namespace_name", edge_kql),
                    0,
                    12,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "five",
                    "5xx / timeout / upstream phrases",
                    table_terms(
                        d,
                        "five",
                        K8S,
                        ["kubernetes.container_name", "log.keyword"],
                        edge_5xx,
                        [8, 8],
                        include_time=True,
                    ),
                    24,
                    12,
                    24,
                    14,
                ),
            ],
            cjson,
            crefs,
        )
    ]

    d = "atlas-logs-calico"
    cjson, crefs = kube_controls(d)
    calico = "kubernetes.namespace_name: calico-system"
    files[f"{d}.ndjson"] = [
        dashboard(
            d,
            "Atlas logs Calico",
            "Felix / Typha / CNI container logs. Calico Audit webhook "
            "(audit-logging.api.projectcalico.org) is grepped out of the pipeline. "
            "ILM 7 days. Click a series to open Discover.",
            [
                lens_panel(
                    d,
                    "cont",
                    "Calico by container",
                    xy_split(d, "cont", K8S, "kubernetes.container_name", calico),
                    0,
                    0,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "node",
                    "Calico by node",
                    xy_split(d, "node", K8S, "kubernetes.host", calico),
                    24,
                    0,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "table",
                    "Calico lines",
                    table_terms(
                        d,
                        "table",
                        K8S,
                        ["kubernetes.container_name", "kubernetes.host", "log.keyword"],
                        calico,
                        [8, 8, 5],
                        include_time=True,
                    ),
                    0,
                    12,
                    48,
                    14,
                ),
            ],
            cjson,
            crefs,
        )
    ]

    d = "atlas-logs-storage"
    cjson, crefs = kube_controls(d)
    ceph = or_ns(["rook-ceph", "rook-ceph-cluster"])
    files[f"{d}.ndjson"] = [
        dashboard(
            d,
            "Atlas logs storage",
            "Ceph mgr/OSD/CSI. Ceph health and disk metrics are Grafana. "
            "ILM 7 days. Click a series to open Discover.",
            [
                lens_panel(
                    d,
                    "ceph-rate",
                    "Ceph by container",
                    xy_split(d, "ceph-rate", K8S, "kubernetes.container_name", ceph),
                    0,
                    0,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "ceph-slow",
                    "Ceph slow / HEALTH / CSI",
                    table_terms(
                        d,
                        "ceph-slow",
                        K8S,
                        ["kubernetes.container_name", "log.keyword"],
                        f'({ceph}) and (log: "slow request" or log: HEALTH_ERR or log: HEALTH_WARN or kubernetes.container_name: *csi*)',
                        [8, 8],
                    ),
                    24,
                    0,
                    24,
                    12,
                ),
            ],
            cjson,
            crefs,
        )
    ]

    d = "atlas-logs-security"
    cjson, crefs = kube_controls(d)
    sec = or_ns(
        [
            "falco",
            "kyverno",
            "policy-reporter",
            "vault",
            "cert-manager",
            "keycloak",
        ]
    )
    falco_json = "kubernetes.namespace_name: falco and log_processed.rule: *"
    files[f"{d}.ndjson"] = [
        dashboard(
            d,
            "Atlas logs security",
            "Falco, Kyverno, Policy Reporter, Vault, cert-manager, Keycloak. "
            "Not a SIEM: no Kubernetes Audit index. Falco pie is JSON rules only "
            "(log_processed.rule: *); Falco UI / non-JSON lines do not appear there. "
            "ILM 7 days. CPU and Ceph health are Grafana.",
            [
                lens_panel(
                    d,
                    "ns",
                    "Security namespaces by severity",
                    xy_split(d, "ns", K8S, "kubernetes.namespace_name", sec),
                    0,
                    0,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "falco-rule",
                    "Falco rules (log_processed.rule)",
                    xy_split(
                        d,
                        "falco-rule",
                        K8S,
                        "log_processed.rule",
                        falco_json,
                    ),
                    24,
                    0,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "falco-prio",
                    "Falco priority (log_processed.priority)",
                    pie_terms(
                        d,
                        "falco-prio",
                        K8S,
                        "log_processed.priority",
                        falco_json,
                        8,
                    ),
                    0,
                    12,
                    16,
                    12,
                ),
                lens_panel(
                    d,
                    "falco-log",
                    "Falco raw log.keyword",
                    table_terms(
                        d,
                        "falco-log",
                        K8S,
                        ["kubernetes.pod_name", "log.keyword"],
                        "kubernetes.namespace_name: falco",
                        [8, 8],
                        include_time=True,
                    ),
                    16,
                    12,
                    32,
                    12,
                ),
                lens_panel(
                    d,
                    "policy",
                    "Kyverno / Policy Reporter violate-fail",
                    table_terms(
                        d,
                        "policy",
                        K8S,
                        ["kubernetes.namespace_name", "log.keyword"],
                        "kubernetes.namespace_name: (kyverno or policy-reporter) and (log: *fail* or log: *violat*)",
                        [8, 8],
                    ),
                    0,
                    24,
                    16,
                    12,
                ),
                lens_panel(
                    d,
                    "keycloak",
                    "Keycloak login / error",
                    table_terms(
                        d,
                        "keycloak",
                        K8S,
                        ["log.keyword"],
                        "kubernetes.namespace_name: keycloak and (log: *login* or log: *brute*)",
                        [10],
                    ),
                    16,
                    24,
                    16,
                    12,
                ),
                lens_panel(
                    d,
                    "vault",
                    "Vault sealed / denied",
                    table_terms(
                        d,
                        "vault",
                        K8S,
                        ["log.keyword"],
                        "kubernetes.namespace_name: vault and (log: *sealed* or log: *permission denied*)",
                        [10],
                    ),
                    32,
                    24,
                    16,
                    12,
                ),
            ],
            cjson,
            crefs,
        )
    ]

    d = "atlas-logs-gitops"
    cjson, crefs = kube_controls(d)
    argocd = "kubernetes.namespace_name: argocd"
    files[f"{d}.ndjson"] = [
        dashboard(
            d,
            "Atlas logs GitOps",
            "Argo CD application-controller / repo-server / applicationset. "
            "Sync status metrics are Grafana. ILM 7 days. Click a series to open Discover.",
            [
                lens_panel(
                    d,
                    "cont",
                    "Argo CD by container",
                    xy_split(d, "cont", K8S, "kubernetes.container_name", argocd),
                    0,
                    0,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "err",
                    "Argo CD by severity",
                    xy_split(
                        d,
                        "err",
                        K8S,
                        "atlas_severity",
                        argocd,
                        "bar_stacked",
                        5,
                    ),
                    24,
                    0,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "table",
                    "Sync / refresh / repo phrases",
                    table_terms(
                        d,
                        "table",
                        K8S,
                        ["kubernetes.container_name", "log.keyword"],
                        f"{argocd} and (log: *sync* or log: *refresh* or log: *repo*)",
                        [8, 8],
                        include_time=True,
                    ),
                    0,
                    12,
                    48,
                    14,
                ),
            ],
            cjson,
            crefs,
        )
    ]

    d = "atlas-logs-nodes"
    cjson, crefs = host_controls(d)
    prio = "PRIORITY: (0 or 1 or 2 or 3)"
    text_err = f"not {prio}"
    kernel = (
        "SYSLOG_IDENTIFIER: kernel and "
        '(MESSAGE: "*oom*" or log: "*oom*" or '
        'MESSAGE: "*Out of memory*" or log: "*Out of memory*" or '
        'MESSAGE: "*I/O error*" or log: "*I/O error*" or '
        'MESSAGE: "*link down*" or log: "*link down*" or '
        'MESSAGE: "*Reset adapter*" or log: "*Reset adapter*")'
    )
    files[f"{d}.ndjson"] = [
        dashboard(
            d,
            "Atlas logs nodes",
            "Host journal and syslog on the same Host value (NODE_NAME). "
            "PRIORITY vs text-matched errors, kernel, units. ILM 7 days. "
            "Click a series to open Discover.",
            [
                lens_panel(
                    d,
                    "prio",
                    "PRIORITY <= 3",
                    xy_split(d, "prio", HOST, "_HOSTNAME", prio),
                    0,
                    0,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "text",
                    "PRIORITY > 3",
                    xy_split(d, "text", HOST, "_HOSTNAME", text_err),
                    24,
                    0,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "ident",
                    "By SYSLOG_IDENTIFIER",
                    xy_split(d, "ident", HOST, "SYSLOG_IDENTIFIER", ""),
                    0,
                    12,
                    16,
                    12,
                ),
                lens_panel(
                    d,
                    "unit",
                    "By _SYSTEMD_UNIT",
                    xy_split(d, "unit", HOST, "_SYSTEMD_UNIT", ""),
                    16,
                    12,
                    16,
                    12,
                ),
                lens_panel(
                    d,
                    "kernel",
                    "Kernel OOM / disk / NIC",
                    table_terms(
                        d,
                        "kernel",
                        HOST,
                        ["_HOSTNAME", "MESSAGE"],
                        kernel,
                        [8, 8],
                        include_time=True,
                    ),
                    32,
                    12,
                    16,
                    12,
                ),
                lens_panel(
                    d,
                    "hosts",
                    "All hosts (master vs worker is hostname prefix)",
                    table_terms(d, "hosts", HOST, ["_HOSTNAME", "PRIORITY"], "", [20, 8]),
                    0,
                    24,
                    48,
                    12,
                ),
            ],
            cjson,
            crefs,
        )
    ]

    d = "atlas-logs-pipeline"
    cjson, crefs = mixed_controls(d)
    files[f"{d}.ndjson"] = [
        dashboard(
            d,
            "Atlas logs pipeline",
            "Fluent Bit / ES ingest health: logging ns, heartbeats, timestamp gaps. "
            "Not CPU or Ceph health (Grafana). ILM 7 days. Landing: Last 1h, refresh 1m.",
            [
                lens_panel(
                    d,
                    "logging",
                    "logging namespace",
                    xy_split(
                        d,
                        "logging",
                        K8S,
                        "kubernetes.container_name",
                        "kubernetes.namespace_name: logging",
                    ),
                    0,
                    0,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "hb",
                    "Heartbeat documents / node",
                    xy_split(
                        d,
                        "hb",
                        HOST,
                        "_HOSTNAME",
                        "atlas_heartbeat: true",
                        "line",
                        20,
                    ),
                    24,
                    0,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "kube-gap",
                    "kube-logs volume (gaps = ingest holes)",
                    xy_count(d, "kube-gap", K8S, "", "area"),
                    0,
                    12,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "host-gap",
                    "host-logs volume",
                    xy_count(d, "host-gap", HOST, "", "area"),
                    24,
                    12,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "hb-table",
                    "Heartbeat hosts",
                    table_terms(
                        d,
                        "hb-table",
                        HOST,
                        ["_HOSTNAME"],
                        "atlas_heartbeat: true",
                        [50],
                    ),
                    0,
                    24,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "fb-err",
                    "Fluent Bit / ES in logging ns",
                    table_terms(
                        d,
                        "fb-err",
                        K8S,
                        ["kubernetes.pod_name", "log.keyword"],
                        "kubernetes.namespace_name: logging",
                        [8, 8],
                    ),
                    24,
                    24,
                    24,
                    12,
                ),
            ],
            cjson,
            crefs,
            landing=True,
        )
    ]

    d = "atlas-logs-tenant"
    cjson, crefs = kube_controls(d)
    tenant = tenant_kql()
    files[f"{d}.ndjson"] = [
        dashboard(
            d,
            "Atlas logs tenant",
            "Non-platform namespaces (catalog system-list excluded). "
            "Requires kubernetes.namespace_name. ILM 7 days. Click a series to open Discover.",
            [
                lens_panel(
                    d,
                    "app",
                    "By app.kubernetes.io/name",
                    xy_split(
                        d,
                        "app",
                        K8S,
                        "kubernetes.labels.app_kubernetes_io/name",
                        tenant,
                    ),
                    0,
                    0,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "cont",
                    "By container",
                    xy_split(
                        d,
                        "cont",
                        K8S,
                        "kubernetes.container_name",
                        tenant,
                    ),
                    24,
                    0,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "table",
                    "Repeated messages",
                    table_terms(
                        d,
                        "table",
                        K8S,
                        [
                            "kubernetes.namespace_name",
                            "kubernetes.container_name",
                            "log.keyword",
                        ],
                        tenant,
                        [10, 10, 8],
                        include_time=True,
                    ),
                    0,
                    12,
                    48,
                    16,
                ),
            ],
            cjson,
            crefs,
        )
    ]

    d = "atlas-logs-cluster"
    cjson, crefs = cluster_controls(d)
    kube_search_id = "atlas-logs-cluster-kube-search"
    host_search_id = "atlas-logs-cluster-host-search"
    files[f"{d}.ndjson"] = [
        saved_search(
            kube_search_id,
            "Atlas kube logs",
            K8S,
            KUBE_SEARCH_COLUMNS,
        ),
        saved_search(
            host_search_id,
            "Atlas host logs",
            HOST,
            HOST_SEARCH_COLUMNS,
        ),
        saved_search(
            "atlas-logs-kube-errors",
            "Atlas kube errors",
            K8S,
            KUBE_SEARCH_COLUMNS,
            query="atlas_severity: error",
        ),
        saved_search(
            "atlas-logs-kube-error-warn",
            "Atlas kube error+warn",
            K8S,
            KUBE_SEARCH_COLUMNS,
            query="atlas_severity: (error or warn)",
            description="Append and kubernetes.namespace_name: foo",
        ),
        saved_search(
            "atlas-logs-heartbeat",
            "Atlas Fluent Bit heartbeat",
            HOST,
            HOST_SEARCH_COLUMNS,
            query="atlas_heartbeat: true",
        ),
        saved_search(
            "atlas-logs-falco-rules",
            "Atlas Falco JSON rules",
            K8S,
            KUBE_SEARCH_COLUMNS,
            query="log_processed.rule: *",
        ),
        dashboard(
            d,
            "Atlas logs cluster",
            "All cluster logs (kube + host): working desk, not overview noise. "
            "Filter Severity / Namespace / Container / Pod / Node / Host. "
            "Open Discover searches for errors, heartbeat, Falco. "
            "Not CPU/Ceph metrics (Grafana). ILM 7 days. Landing: Last 1h, refresh 1m.",
            [
                lens_panel(
                    d,
                    "kube-sev",
                    "Kube volume by severity",
                    xy_split(d, "kube-sev", K8S, "atlas_severity", "", "bar_stacked", 5),
                    0,
                    0,
                    24,
                    12,
                ),
                lens_panel(
                    d,
                    "kube-ns",
                    "Kube volume by namespace",
                    xy_split(d, "kube-ns", K8S, "kubernetes.namespace_name", ""),
                    24,
                    0,
                    24,
                    12,
                ),
                search_panel(
                    d,
                    "kube-docs",
                    "Kube log documents",
                    kube_search_id,
                    0,
                    12,
                    48,
                    16,
                ),
                lens_panel(
                    d,
                    "host-sev",
                    "Host volume by severity",
                    xy_split(d, "host-sev", HOST, "atlas_severity", "", "bar_stacked", 5),
                    0,
                    28,
                    24,
                    10,
                ),
                search_panel(
                    d,
                    "host-docs",
                    "Host log documents",
                    host_search_id,
                    24,
                    28,
                    24,
                    10,
                ),
            ],
            cjson,
            crefs,
            landing=True,
        ),
    ]

    return files


def ndjson_text(objects: list[dict[str, Any]]) -> str:
    return "".join(dumps(obj) + "\n" for obj in objects)


def expected_files() -> dict[str, str]:
    return {name: ndjson_text(objs) for name, objs in build_all().items()}


def main() -> int:
    expected = expected_files()
    if "--check" in sys.argv:
        failed = False
        for name, content in expected.items():
            path = OUT_DIR / name
            if not path.is_file():
                print(f"missing {name}", file=sys.stderr)
                failed = True
                continue
            if path.read_text(encoding="utf-8") != content:
                print(f"stale {name}", file=sys.stderr)
                failed = True
        extras = sorted(
            p.name
            for p in OUT_DIR.glob("atlas-*.ndjson")
            if p.name not in expected
        )
        if extras:
            print("unexpected " + ", ".join(extras), file=sys.stderr)
            failed = True
        return 1 if failed else 0
    for name, content in expected.items():
        (OUT_DIR / name).write_text(content, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
