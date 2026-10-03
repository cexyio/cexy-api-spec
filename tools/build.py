#!/usr/bin/env python3
"""Build the SDK spec: allowlist (surface.yaml) intersected with the served public spec.

    python tools/build.py            # writes spec/openapi.sdk.json (uses the cached public spec)
    python tools/build.py --fetch    # re-fetches the served public spec first
    python tools/build.py --check    # fails if a committed generated file is out of date

The result keeps only allowlisted operations and the schemas they reach, stamps each
operation with `x-required-scope` from the allowlist, adds the error envelope and the
ErrorCode enum from errors.yaml only if the served spec lacks them, writes errors.yaml from the
spec's ErrorCode, and sets
the production server URL. It also writes asyncapi.yaml from the served AsyncAPI document (the
WebSocket contract), with the same description cleaning.
"""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_URL = "https://api.cexy.io/api/v1/openapi.json"
# The raw public document is fetched, never committed: it carries text that is not meant for
# the SDK repos (the built spec strips it). The cache is git-ignored.
PUBLIC = ROOT / "spec" / ".cache" / "openapi.public.json"
ASYNC_URL = "https://api.cexy.io/api/v1/asyncapi.json"
ASYNC_PUBLIC = ROOT / "spec" / ".cache" / "asyncapi.public.json"
ASYNC_OUT = ROOT / "asyncapi.yaml"
OUT = ROOT / "spec" / "openapi.sdk.json"
METHODS = ("get", "put", "post", "delete", "patch")
SERVER = {"url": "https://api.cexy.io", "description": "CEXY.io production"}

ERROR_SCHEMAS = {
    "ErrorResponse": {
        "type": "object",
        "description": "The error envelope returned by every failing request.",
        "required": ["error"],
        "properties": {"error": {"$ref": "#/components/schemas/ErrorBody"}},
    },
    "ErrorBody": {
        "type": "object",
        "required": ["code", "message", "retryable"],
        "properties": {
            "code": {"$ref": "#/components/schemas/ErrorCode"},
            "message": {"type": "string", "description": "Human-readable; may change. Branch on `code`."},
            "details": {"type": "object", "additionalProperties": True},
            "fields": {"type": "object", "additionalProperties": {"type": "string"}},
            "request_id": {"type": "string", "nullable": True},
            "retryable": {"type": "boolean"},
        },
    },
}


def load_surface() -> dict[str, Any]:
    return yaml.safe_load((ROOT / "surface.yaml").read_text())


def load_error_codes() -> list[str]:
    return yaml.safe_load((ROOT / "errors.yaml").read_text())["codes"]


def refs(node: Any, found: set[str]) -> None:
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
            found.add(ref.rsplit("/", 1)[1])
        for v in node.values():
            refs(v, found)
    elif isinstance(node, list):
        for v in node:
            refs(v, found)


def build(public: dict[str, Any], surface: dict[str, Any], error_codes: list[str]) -> dict[str, Any]:
    allowed = {(o["method"].lower(), o["path"]): o for o in surface["operations"]}
    paths: dict[str, Any] = {}
    for path, item in public["paths"].items():
        for method in METHODS:
            op = item.get(method)
            if op is None or (method, path) not in allowed:
                continue
            entry = allowed[(method, path)]
            op = copy.deepcopy(op)
            op["x-required-scope"] = entry["scope"]
            if entry.get("side_effect"):
                op["x-side-effect"] = entry["side_effect"]
            if entry["auth"] == "api_key":
                # API keys only: sessions (Bearer) belong to the web app, not to SDK users. The
                # requirement is copied from the served spec (request signing: key id, timestamp,
                # nonce and signature), never hard-coded.
                key_reqs = [r for r in op.get("security", []) if "api_key" in r]
                if len(key_reqs) != 1:
                    raise SystemExit(f"{method.upper()} {path}: expected one api_key security requirement, got {key_reqs}")
                op["security"] = key_reqs
            else:
                op["security"] = []
            new_item = paths.setdefault(path, {k: v for k, v in item.items() if k not in METHODS})
            new_item[method] = op

    doc = {k: v for k, v in public.items() if k not in ("paths", "components", "servers")}
    doc["info"] = {**public.get("info", {}), "title": "CEXY API",
                   "license": {"name": "MIT", "url": "https://opensource.org/license/mit"}}
    doc["servers"] = [SERVER]
    doc["paths"] = paths
    all_schemas = dict(public.get("components", {}).get("schemas", {}))
    all_schemas.update({k: v for k, v in ERROR_SCHEMAS.items() if k not in all_schemas})
    if "ErrorCode" not in all_schemas:
        all_schemas["ErrorCode"] = {"type": "string", "enum": error_codes,
                                    "description": "PROVISIONAL (errors.yaml) until the served spec includes it."}

    needed: set[str] = {"ErrorResponse", "ErrorBody", "ErrorCode"}
    refs(paths, needed)
    frontier = list(needed)
    while frontier:
        name = frontier.pop()
        found: set[str] = set()
        refs(all_schemas.get(name, {}), found)
        for f in found - needed:
            needed.add(f)
            frontier.append(f)
    schemes = public.get("components", {}).get("securitySchemes", {})
    used_schemes = {name for item in paths.values() for m, op in item.items() if m in METHODS
                    for req in op.get("security", []) for name in req}
    doc["components"] = {
        "schemas": {k: all_schemas[k] for k in sorted(needed) if k in all_schemas},
        "securitySchemes": {k: v for k, v in schemes.items() if k in used_schemes},
    }
    return apply_overrides(sanitize(doc))


def _pointer_parts(pointer: str) -> list[str]:
    return [p.replace("~1", "/").replace("~0", "~") for p in pointer.lstrip("/").split("/")]


def apply_overrides(doc: dict[str, Any]) -> dict[str, Any]:
    """Apply description-overrides.yaml: confirmed corrections awaiting the backend's spec fix."""
    path = ROOT / "description-overrides.yaml"
    if not path.exists():
        return doc
    for o in yaml.safe_load(path.read_text()).get("overrides") or []:
        *parents, key = _pointer_parts(o["pointer"])
        node: Any = doc
        for p in parents:
            node = node.get(p) if isinstance(node, dict) else None
            if node is None:
                break
        if not isinstance(node, dict):
            print(f"note: override target {o['pointer']} not found (stale override?)", file=sys.stderr)
            continue
        if not str(node.get(key, "")).startswith(o["upstream_starts_with"]):
            print(f"note: upstream text at {o['pointer']} changed; review this override", file=sys.stderr)
        node[key] = o["text"]
    return doc


# Implementation notes that belong in the exchange's own docs, not in public SDKs.
INTERNAL_NOTE = re.compile(r"legacy|finding S\d+|ambiguity A\d+|docs/[\w./-]+\.md|\.rs\b|\bworker\b|§\d",
                           re.IGNORECASE)


def _clean_text(text: str) -> str:
    """Drop sentences that are implementation history rather than API behaviour."""
    paragraphs = []
    for para in text.split("\n\n"):
        if para.lstrip().startswith(("*", "-", "|", "`")):
            # A list: keep or drop whole items (an item runs until the next bullet line).
            items: list[list[str]] = []
            for ln in para.split("\n"):
                if ln.lstrip().startswith(("* ", "- ", "|")) or not items:
                    items.append([ln])
                else:
                    items[-1].append(ln)
            kept_items = ["\n".join(it) for it in items if not INTERNAL_NOTE.search(" ".join(it))]
            if kept_items:
                paragraphs.append("\n".join(kept_items))
            continue
        sentences = re.split(r"(?<=[.!?])\s+", para.replace("\n", " "))
        kept = [x for x in sentences if not INTERNAL_NOTE.search(x)]
        if kept:
            paragraphs.append(" ".join(kept))
    return "\n\n".join(paragraphs).strip()


def sanitize(node: Any) -> Any:
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k in ("description", "summary") and isinstance(v, str):
                cleaned = _clean_text(v)
                if cleaned:
                    out[k] = cleaned
            else:
                out[k] = sanitize(v)
        return out
    if isinstance(node, list):
        return [sanitize(v) for v in node]
    return node


def render(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2) + "\n"


def _fetch(url: str, cache: Path, force: bool) -> dict[str, Any]:
    """A served public document, from the git-ignored cache or fetched (public, unauthenticated)."""
    if force or not cache.exists():
        import urllib.request

        req = urllib.request.Request(url, headers={"User-Agent": "cexy-api-spec-build/1 (+https://cexy.io)",
                                                   "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (fixed https URL)
            body = resp.read()
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(body)
    return json.loads(cache.read_text())


def fetch_public(force: bool = False) -> dict[str, Any]:
    """The served public spec."""
    return _fetch(PUBLIC_URL, PUBLIC, force)


def fetch_asyncapi(force: bool = False) -> dict[str, Any]:
    """The served AsyncAPI document (the WebSocket contract)."""
    return _fetch(ASYNC_URL, ASYNC_PUBLIC, force)


ASYNC_HEADER = f"""\
# CEXY.io WebSocket API (AsyncAPI 3.0).
# GENERATED by tools/build.py from {ASYNC_URL}; do not edit.
# Client rules on top of this contract (snapshots, sequences, sign-outs): ws-client-rules.md.
"""


def render_asyncapi(doc: dict[str, Any]) -> str:
    doc = sanitize(doc)
    doc["info"] = {**doc.get("info", {}), "license": {"name": "MIT", "url": "https://opensource.org/license/mit"}}
    return ASYNC_HEADER + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=100)


ERRORS = ROOT / "errors.yaml"
ERRORS_HEADER = """\
# Error codes returned in error.code (REST) and in WebSocket error frames.
# GENERATED by tools/build.py from the ErrorCode schema of the served public spec; do not edit.
# Branch on the code, never on the message. SDKs must tolerate codes added later.
"""


def render_errors(public: dict[str, Any]) -> str | None:
    """errors.yaml from the spec's ErrorCode enum (None if the spec does not carry it)."""
    enum = public.get("components", {}).get("schemas", {}).get("ErrorCode", {}).get("enum")
    if not enum:
        return None
    return ERRORS_HEADER + "status: generated\ncodes:\n" + "".join(f"  - {c}\n" for c in enum)


def main() -> int:
    force = "--fetch" in sys.argv
    public = fetch_public(force=force)
    errors_text = render_errors(public)
    async_text = render_asyncapi(fetch_asyncapi(force=force))
    text = render(build(public, load_surface(), load_error_codes()))
    if "--check" in sys.argv:
        stale = []
        if not OUT.exists() or OUT.read_text() != text:
            stale.append("spec/openapi.sdk.json")
        if errors_text is not None and ERRORS.read_text() != errors_text:
            stale.append("errors.yaml")
        if not ASYNC_OUT.exists() or ASYNC_OUT.read_text() != async_text:
            stale.append("asyncapi.yaml")
        if stale:
            print(f"{', '.join(stale)} out of date: run python tools/build.py", file=sys.stderr)
            return 1
        print("spec/openapi.sdk.json, errors.yaml and asyncapi.yaml are up to date")
        return 0
    if errors_text is not None:
        ERRORS.write_text(errors_text)
    OUT.write_text(text)
    ASYNC_OUT.write_text(async_text)
    doc = json.loads(text)
    ops = sum(1 for item in doc["paths"].values() for m in METHODS if m in item)
    print(f"wrote {OUT.relative_to(ROOT)}: {ops} operations, {len(doc['components']['schemas'])} schemas")
    adoc = yaml.safe_load(async_text)
    print(f"wrote {ASYNC_OUT.relative_to(ROOT)}: {len(adoc.get('channels', {}))} channels, "
          f"{len(adoc.get('components', {}).get('messages', {}))} messages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
