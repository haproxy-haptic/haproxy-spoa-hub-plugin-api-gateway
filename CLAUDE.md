# haproxy-spoa-hub-plugin-api-gateway — development context

Rust cdylib plugin for `haproxy-spoa-hub`, edition 2024.

## Hard constraints

- No request/response body modification. This plugin validates only.
- Keep the request path bounded and synchronous: schemas compile at init/reload;
  each request only checks body length, parses JSON, and validates in memory.
- No network or file resolution for JSON Schema references. The dependency is
  configured with `jsonschema` default features disabled.
- Validation defaults fail closed. Per-route fail-open is an explicit escape
  hatch for missing schema/config errors, not for invalid client payloads.

## Commands

```sh
make test
make lint
make fmt
make build
```
