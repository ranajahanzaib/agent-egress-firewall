# Security Policy Engine

The Go policy engine translates detection findings into deterministic enforcement decisions.

## 1. Actions

- **`allow`**: Forwards the original request without modification.
- **`redact`**: Replaces sensitive spans with unguessable tokens (`[AEGF:<CAT>:<HEX>]`) and saves originals in the encrypted local vault.
- **`block`**: Rejects request immediately with HTTP 403 Forbidden. The upstream destination is never contacted.

## 2. Rule Precedence

1. **`BLOCK`**: If _any_ detected entity triggers a `block` rule, the entire request is rejected immediately.
2. **`REDACT`**: If no entity triggers `block`, but one or more entities trigger `redact`, the sensitive values are redacted.
3. **`ALLOW`**: If no entity triggers `block` or `redact`, the request is forwarded as-is.

## 3. Destination-Scoped Exceptions

An exception allows specific categories to be permitted only for specified destinations:

```yaml
exceptions:
  - destination: "*.openai.com"
    allow:
      - API_KEY
```

Exceptions are narrow, explicit, and never apply to unlisted destinations.

## 4. Fail-Closed Guarantees

Under strict policies, failure behavior ensures that operational faults (e.g. inference timeout, malformed payload, crash) result in a fail-closed response:

```yaml
failure_behavior:
  inference_unavailable: block
  inference_timeout: block
  malformed_payload: block
  unsupported_content: block
  oversized_payload: block
```
