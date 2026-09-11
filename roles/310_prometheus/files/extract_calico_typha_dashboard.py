#!/usr/bin/env python3
"""Extract typha-dashboard.json from official projectcalico grafana-dashboards.yaml.

Does not vendor JSON in git. Apply-time UID rewrite maps Calico demo datasource
uids onto the kube-prometheus-stack Grafana uid (prometheus).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

TYPHA_KEY = "typha-dashboard.json"
UID_REPLACEMENTS = (
    ("calico-demo-prometheus", "prometheus"),
    ("P11C5FC3F3B681947", "prometheus"),
)


def extract(src: str) -> dict:
    i = src.find(TYPHA_KEY)
    if i < 0:
        raise SystemExit(f"missing {TYPHA_KEY} in Calico grafana-dashboards.yaml")
    j = src.find("{", i)
    if j < 0:
        raise SystemExit(f"no JSON object after {TYPHA_KEY}")
    obj, _ = json.JSONDecoder().raw_decode(src[j:])
    if not isinstance(obj, dict):
        raise SystemExit(f"{TYPHA_KEY} is not a JSON object")
    return obj


def rewrite_uids(obj: dict) -> dict:
    blob = json.dumps(obj, ensure_ascii=False)
    for old, new in UID_REPLACEMENTS:
        blob = blob.replace(old, new)
    rewritten = json.loads(blob)
    if not isinstance(rewritten, dict):
        raise SystemExit("UID rewrite did not yield a JSON object")
    return rewritten


def main(argv: list[str]) -> None:
    if len(argv) != 3:
        raise SystemExit(f"usage: {argv[0]} SRC.yaml DST.json")
    src_path, dst_path = Path(argv[1]), Path(argv[2])
    obj = rewrite_uids(extract(src_path.read_text(encoding="utf-8")))
    dst_path.write_text(
        json.dumps(obj, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main(sys.argv)
