# Security Model & Guarantees

## 1. Request Safety & SSRF Defenses

1. **Anti-Open-Proxy:**
   The gateway only routes to destinations explicitly configured in `routes[].upstream`. Unregistered prefixes return HTTP 404/403.
2. **Hop-by-Hop Header Stripping:**
   Headers such as `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `TE`, and `Transfer-Encoding` are stripped before upstream forwarding.
3. **Request Body Bounding:**
   `max_body_size_bytes` is enforced with `io.LimitReader` to prevent unbounded memory allocation and denial of service.
4. **Decompression Bomb Protection:**
   Gzip decompression is bounded strictly by `max_body_size_bytes`. Decompressed streams exceeding the limit trigger an oversized payload error.

## 2. Response Streaming Passthrough

Upstream Server-Sent Events (SSE) and chunked HTTP responses are flushed immediately using Go's `http.Flusher` interface without full-response memory buffering. Client context cancellation propagates immediately to the upstream connection.
