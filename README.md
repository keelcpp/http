# keel-http (`keel::http`)

**keel-http** is a lightweight, zero-STL-header C++20 HTTP/HTTPS and WebSocket client library built on top of [**keel**](https://github.com/keelcpp/keel) and licensed under **0BSD**.

## Features

- **Featherweight Public Header (`keel/http.h`)**: Zero STL headers, verified by `test_guidelines_headers` under both MSVC and ClangCL, compiles cleanly under `-fno-exceptions -fno-rtti`.
- **Native OS Backends**:
  - **Windows**: Native `WinHTTP` (`winhttp.dll`) with TLS 1.2/1.3, HTTP/2, and `WinHttpWebSocket*`.
  - **Linux / macOS**: `libcurl` (`CURL::libcurl`) with connection pooling.
  - **WebAssembly (Emscripten)**: Browser `emscripten_fetch` and `emscripten_websocket`.
- **RFC 3986 URL & Query Utilities**: `parse_url`, `url_encode`, `url_decode`, `build_query_string`, `parse_query_string`, `resolve_url` (with dot-segment normalization), and fluent `UrlBuilder`.
- **RFC 9110 Redirect Engine**: Configurable `max_redirects`, relative `Location` resolution, 301/302/303 method rewriting (`POST` → `GET`), 307/308 method/body preservation, and automatic cross-origin `Authorization`/`Cookie` header stripping.
- **Retry & Backoff (`HttpRetryPolicy`)**: Configurable automatic retries on network errors, 5xx (500/502/503/504), and 429 with `Retry-After` support and jittered exponential backoff.
- **RFC 6265 Thread-Safe `CookieJar`**: Domain/path matching, `Secure`, `HttpOnly`, `Max-Age`, `Expires`, automatic redirect-hop updates, and deletion on expiry.
- **RFC 7578 `MultipartFormData` & Auth Helpers**: CSPRNG boundary generation, disposition-parameter sanitization, `post_multipart`, `post_form`, `make_bearer_auth_header`, and `make_basic_auth_header`.
- **Streaming Downloads**: Bounded-memory `execute_streaming(req, on_chunk)` with abort support and `download_to_file(url, dest_path)` (cleans up partial files on error).
- **Full HTTP Verbs & WebSocket Client**: `get`, `head`, `post`, `put`, `patch`, `del`, plus `WebSocketClient` and mockable `IHttpClient`/`IWebSocketClient` interfaces.

## Building & Testing

```bash
cmake -B build -DKEEL_HTTP_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
python tests/verify_integration.py
```

## License

Zero-Clause BSD ([0BSD](LICENSE)).
