#!/usr/bin/env python3
"""Fail-closed guard for the SDK surface. Run in CI on every change.

Fails when:
  - an allowlisted operation is missing from the served public spec (removed or renamed);
  - the public spec has an api_key operation that is not allowlisted (needs review first);
  - the SDK spec contains a denied path prefix, an admin tag, a denied parameter
    (X-Two-Factor-Code) or a schema whose name matches the deny pattern;
  - the spec states x-required-scope and it disagrees with the allowlist;
  - the spec carries an ErrorCode enum that differs from errors.yaml.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
METHODS = ("get", "put", "post", "delete", "patch")


def main() -> int:
    sys.path.insert(0, str(ROOT / "tools"))
    from build import fetch_public  # noqa: E402

    public = fetch_public()
    sdk = json.loads((ROOT / "spec" / "openapi.sdk.json").read_text())
    surface = yaml.safe_load((ROOT / "surface.yaml").read_text())
    codes = yaml.safe_load((ROOT / "errors.yaml").read_text())["codes"]
    deny = surface["deny"]
    problems: list[str] = []

    allowed = {(o["method"].lower(), o["path"]): o for o in surface["operations"]}
    public_ops = {(m, p): op for p, item in public["paths"].items() for m in METHODS if (op := item.get(m))}

    segments = [s.lower() for s in deny.get("path_segments", [])]

    def denied(path: str) -> bool:
        return any(path.startswith(p) for p in deny["path_prefixes"]) or any(
            seg in path.lower().split("/") for seg in segments)

    for key, entry in allowed.items():
        if key not in public_ops:
            problems.append(f"allowlisted {key[0].upper()} {key[1]} is not in the public spec")
        elif (spec_scope := public_ops[key].get("x-required-scope")) and spec_scope != entry["scope"]:
            problems.append(f"{key[0].upper()} {key[1]}: spec scope {spec_scope!r} != allowlist {entry['scope']!r}")
        if denied(key[1]):
            problems.append(f"allowlisted {key[1]} is denied")

    for key, op in public_ops.items():
        key_auth = any("api_key" in s for s in op.get("security") or [])
        if key_auth and key not in allowed and not denied(key[1]):
            problems.append(f"new api_key operation needs review: {key[0].upper()} {key[1]}")

    pattern = re.compile(deny["schema_name_pattern"])
    denied_params = {p.lower() for p in deny["parameters"]}
    for path, item in sdk["paths"].items():
        if denied(path):
            problems.append(f"SDK spec contains denied path {path}")
        for m in METHODS:
            op = item.get(m)
            if not op:
                continue
            if "admin" in (op.get("tags") or []):
                problems.append(f"SDK spec contains admin-tagged {m.upper()} {path}")
            for prm in op.get("parameters") or []:
                if (prm.get("name") or "").lower() in denied_params:
                    problems.append(f"SDK spec {m.upper()} {path} takes denied parameter {prm['name']}")
    for name in sdk["components"]["schemas"]:
        if pattern.search(name):
            problems.append(f"SDK spec contains denied schema {name}")

    note = re.compile(r"legacy|finding S\d+|ambiguity A\d+|docs/[\w./-]+\.md|\.rs\b|\bworker\b|§\d", re.IGNORECASE)

    def texts(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("description", "summary") and isinstance(v, str):
                    yield v
                else:
                    yield from texts(v)
        elif isinstance(node, list):
            for v in node:
                yield from texts(v)

    for t in texts(sdk):
        if m := note.search(t):
            problems.append(f"SDK spec text contains an implementation note ({m.group(0)!r}): {t[:80]!r}")

    info = sdk.get("info", {})
    if (info.get("license") or {}).get("name") != "MIT" or info.get("title") != "CEXY API":
        problems.append("SDK spec info must have license MIT and title 'CEXY API'")

    spec_codes = public.get("components", {}).get("schemas", {}).get("ErrorCode", {}).get("enum")
    if spec_codes and sorted(spec_codes) != sorted(codes):
        problems.append("errors.yaml differs from the ErrorCode enum in the public spec: regenerate it")

    if problems:
        print("surface check FAILED:", *problems, sep="\n  - ", file=sys.stderr)
        return 1
    print(f"surface check ok: {len(allowed)} allowlisted operations, {len(sdk['components']['schemas'])} schemas")
    return 0


if __name__ == "__main__":
    sys.exit(main())
