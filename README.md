# cexy-api-spec

The public API contract that every CEXY.io SDK and the CEXY MCP server are built from.

| File | What it is |
|---|---|
| `surface.yaml` | **The allowlist**: every operation the SDKs expose, with its auth (`none` / `api_key`) and required key scope (`read` / `trade`), plus a hard deny list |
| `spec/openapi.sdk.json` | Generated from the public document served at `https://api.cexy.io/api/v1/openapi.json` (fetched at build time, not committed): allowlist ∩ public spec, with `x-required-scope`, the error envelope and the production server. SDKs generate their models from this file. |
| `errors.yaml` | Every `error.code` value, generated from the served spec's `ErrorCode` schema by `tools/build.py` (do not edit). |
| `asyncapi.yaml` | WebSocket API: connection rules, channels, frames. Derived from the public documentation, pending an official export. |
| `conformance/` | Shared test cases every SDK must pass: auth headers, redaction, error mapping, 429/409 retries, WebSocket frames |

## Using the spec

```bash
pip install pyyaml
python tools/build.py --fetch  # fetch the served public spec and regenerate spec/openapi.sdk.json
python tools/check.py          # surface guard (fails closed)
python tools/scan_internal.py  # no internal hostnames, IPs or paths (plus local patterns, see the script)
```

**Spec drift:** a weekly job (`.github/workflows/spec-drift.yml`, also runnable by hand) compares the served spec with the committed one, and on any difference opens or updates one issue labelled `spec-drift`. The issue summarises added or removed operations, changed schemas, new error codes, and API-key operations that are not on the allowlist. The update itself is a normal reviewed PR, with the SDK sync PRs in the same round. Dependabot proposes GitHub Actions updates weekly.

`tools/check.py` fails when:
- an allowlisted operation disappears from the public spec;
- the public spec gains an API-key operation that is not allowlisted (it must be reviewed first);
- anything denied appears in the SDK spec: an admin tag, `/auth`, `/futures` and similar prefixes, a two-factor parameter, or an admin/internal schema;
- the spec's `x-required-scope` disagrees with the allowlist;
- `errors.yaml` disagrees with the spec's `ErrorCode`.

## Authentication

Every private request is signed with the API key (`CEXY-HMAC-SHA256-v1`): it sends `X-API-Key: ak_…`,
`X-API-Timestamp`, `X-API-Nonce` and `X-API-Signature`. The secret itself is never sent; the API is
switching off the old `X-API-Secret` header and refuses it with `SIGNATURE_REQUIRED`. The SDKs sign
by default. The signing test vectors are in `conformance/signing/`; the live `/api/v1/openapi.json`
describes the scheme.
- Never put credentials in a URL.
- Keys have scopes `read` and/or `trade`, and can be limited to IP addresses (`allowed_ips`).
- **Keys can never withdraw or transfer funds.**

## Retry safety (confirmed by the exchange)

- **Orders:** `client_order_id` is unique per account. A repeat is refused before funds move; recover the order with `GET /api/v1/trading/orders/by-client-id/{id}`. `Idempotency-Key` is **not** honoured on order endpoints, so SDKs must not rely on it there.
- **Cancel:** retrying a cancel that already succeeded returns `INVALID_STATE` ("no longer open"). After a retry, treat that as done.
- **Cancel-all:** repeating it is harmless. `{}` or `{"symbol": null}` cancels **every** market, so SDKs require an explicit symbol or an explicit null. It is limited to 30 requests per minute per account.
- `Idempotency-Key` is honoured on pool join/exit.

## Rate limits

- Anonymous: 120 requests/min per IP.
- API key: 600/min per key (after the key-auth release).
- `X-RateLimit-Reset` is in seconds until the window resets.

## Versioning

- SDK major version = API major version: `/api/v1` is SDK 0.x now and 1.x once signing ships.
- Additive API changes produce SDK minor releases.
- Each SDK release notes the `openapi.sdk.json` version it was built from.

## License

MIT, see `LICENSE`. Report security issues as described in `SECURITY.md`.
