# haproxy-spoa-hub-plugin-api-gateway

Low-latency API gateway validation plugin for
[haproxy-spoa-hub](https://github.com/haproxy-haptic/haproxy-spoa-hub).

Initial scope:

- validate buffered JSON request bodies against configured JSON Schemas;
- return HAProxy transaction variables under `txn.hub.api_gateway.*`;
- never modify request or response bodies.

Message `validate-request` accepts:

- `schema_id`: configured schema key;
- `body`: buffered request body;
- `content_type`: request `Content-Type` header;
- `max_body_bytes`: per-route body cap;
- `fail_open`: whether missing schema/config errors allow the request.

Verdict variables:

- `allowed` (`bool`);
- `outcome` (`allowed`, `invalid_json`, `schema_invalid`, `schema_not_found`,
  `body_too_large`, `unsupported_media_type`, `plugin_error`);
- `detail`;
- `schema_known`.

Build and test:

```sh
make test
make lint
make fmt
make build
```

The release artifact is `target/release/libapi_gateway_plugin.so`.
