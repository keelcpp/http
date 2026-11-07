# keel-http (`keel::http`)

**keel-http** is a lightweight, zero-STL-header C++20 HTTP/HTTPS and WebSocket client library built on top of [**keel**](https://github.com/keelcpp/keel) and licensed under **0BSD**.

## Features

- **Featherweight Public Header (`keel/http.h`)**: Transitively includes **only** `<cstddef>`, `<cstdint>`, and `<new>` (verified by `test_header_purity`), keeping compile times minimal.
- **Native OS Backends (Zero Heavy Dependencies on Windows & WebAssembly)**:
  - **Windows**: Native `WinHTTP` (`winhttp.dll`) with TLS 1.2/1.3, HTTP/2, and `WinHttpWebSocket*`.
  - **Linux / macOS**: `libcurl` (`CURL::libcurl`) with connection pooling.
  - **WebAssembly (Emscripten)**: Browser `emscripten_fetch` and `emscripten_websocket`.
- **First-Class `keel` Types**: Uses `keel::String`, `keel::StringRef`, `keel::InplaceString`, `keel::Array<u8>`, and `keel::SmallArray<HttpHeader, 8>` (zero heap allocations for typical header lists), while interoperating seamlessly with `std::string_view` and `std::span` at API boundaries.
- **RFC 3986 URL Parser**: Supports `http`, `https`, `ws`, and `wss` schemes, IPv4, IPv6 (`[::1]`), ports, and query strings.
- **Testable Interfaces**: Provides `IHttpClient` and `IWebSocketClient` interfaces for deterministic mocking in unit tests.

## Building & Running Tests

```bash
cmake -B build
cmake --build build
ctest --test-dir build -C Debug --output-on-failure
```

## License

Zero-Clause BSD ([0BSD](LICENSE)).
