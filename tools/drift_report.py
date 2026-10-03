#!/usr/bin/env python3
"""Summarise how the served public spec and AsyncAPI document differ from what is committed.

    python tools/drift_report.py            # fetch fresh, rebuild in memory, print Markdown
Exit code: 0 = no drift, 3 = drift (Markdown on stdout), 1 = error.

Used by the weekly spec-drift workflow to open or update an issue; nothing is committed here.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import build  # noqa: E402

METHODS = build.METHODS


def ops(doc: dict) -> set[tuple[str, str]]:
    return {(m.upper(), p) for p, item in doc.get("paths", {}).items() for m in METHODS if m in item}


def main() -> int:
    public = build.fetch_public(force=True)
    surface = build.load_surface()
    new_sdk = json.loads(build.render(build.build(public, surface, build.load_error_codes())))
    old_sdk = json.loads(build.OUT.read_text())
    new_errors = build.render_errors(public)
    old_errors = build.ERRORS.read_text()

    public_key_ops = {(m.upper(), p) for p, item in public["paths"].items() for m in METHODS
                      if (op := item.get(m)) and any("api_key" in s for s in op.get("security") or [])}
    allowed = {(o["method"].upper(), o["path"]) for o in surface["operations"]}
    unlisted = sorted(public_key_ops - allowed)
    deny = surface.get("deny") or {}
    denied_segments = set(deny.get("path_segments") or [])
    denied_prefixes = tuple(deny.get("path_prefixes") or [])

    def denied(path: str) -> bool:
        return bool(set(path.strip("/").split("/")) & denied_segments) or any(
            path == pre or path.startswith(pre.rstrip("/") + "/") for pre in denied_prefixes)

    # New API-key operations that are neither allowlisted nor denied need a decision, even when
    # the SDK spec itself did not change (the allowlist hides them from it).
    undecided = [(m, p) for m, p in unlisted if not denied(p)]

    new_async = build.render_asyncapi(build.fetch_asyncapi(force=True))
    old_async = build.ASYNC_OUT.read_text()
    async_drift = new_async != old_async

    if new_sdk == old_sdk and (new_errors is None or new_errors == old_errors) and not undecided \
            and not async_drift:
        print("no drift")
        return 0

    lines = ["The served public spec (`https://api.cexy.io/api/v1/openapi.json`) or AsyncAPI document "
             "(`https://api.cexy.io/api/v1/asyncapi.json`) no longer matches the committed SDK spec. Run `python tools/build.py --fetch`, review, and open a PR (with the "
             "SDK sync PRs in the same round).", ""]
    added, removed = ops(new_sdk) - ops(old_sdk), ops(old_sdk) - ops(new_sdk)
    lines.append(f"- **SDK operations:** +{len(added)} / -{len(removed)}")
    lines += [f"  - added `{m} {p}`" for m, p in sorted(added)]
    lines += [f"  - removed `{m} {p}`" for m, p in sorted(removed)]
    old_s, new_s = old_sdk["components"]["schemas"], new_sdk["components"]["schemas"]
    changed = sorted(k for k in set(old_s) & set(new_s) if old_s[k] != new_s[k])
    lines.append(f"- **Schemas:** +{sorted(set(new_s) - set(old_s))} / -{sorted(set(old_s) - set(new_s))}; "
                 f"changed: {changed[:20]}{' …' if len(changed) > 20 else ''}")
    if new_errors is not None and new_errors != old_errors:
        o = set(yaml.safe_load(old_errors)["codes"])
        n = set(yaml.safe_load(new_errors)["codes"])
        lines.append(f"- **Error codes:** +{sorted(n - o)} / -{sorted(o - n)}")
    info_old, info_new = old_sdk.get("info", {}).get("version"), new_sdk.get("info", {}).get("version")
    if info_old != info_new:
        lines.append(f"- **info.version:** {info_old} → {info_new}")

    if async_drift:
        oa, na = yaml.safe_load(old_async), yaml.safe_load(new_async)
        for part, get in (("channels", lambda d: d.get("channels", {})),
                          ("messages", lambda d: d.get("components", {}).get("messages", {})),
                          ("WebSocket schemas", lambda d: d.get("components", {}).get("schemas", {}))):
            o, n = get(oa), get(na)
            ch = sorted(k for k in set(o) & set(n) if o[k] != n[k])
            lines.append(f"- **asyncapi.yaml {part}:** +{sorted(set(n) - set(o))} / -{sorted(set(o) - set(n))}; "
                         f"changed: {ch[:20]}{' …' if len(ch) > 20 else ''}")
        if oa.get("info", {}).get("description") != na.get("info", {}).get("description"):
            lines.append("- **asyncapi.yaml info.description** changed: check ws-client-rules.md")

    if undecided:
        lines.append(f"- **API-key operations neither allowlisted nor denied (decide: add to surface.yaml or "
                     f"deny):** " + ", ".join(f"`{m} {p}`" for m, p in undecided[:20]))

    check = subprocess.run([sys.executable, str(ROOT / "tools" / "check.py")], capture_output=True, text=True)
    lines += ["", f"`tools/check.py` against the committed SDK spec: exit {check.returncode}"]
    print("\n".join(lines))
    return 3


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - report any failure as an error exit
        print(f"drift report failed: {exc}", file=sys.stderr)
        sys.exit(1)
