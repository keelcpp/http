#pragma once

#include "keel/array.h"
#include "keel/small_array.h"
#include "keel/string.h"

namespace keel {

// ============================================================================
// 1. RFC 3986 URL Parser (http / https / ws / wss)
// ============================================================================

struct ParsedUrl {
    FixedString<16> scheme{};   // "http", "https", "ws", "wss" (lowercase)
    String host{};              // Domain, IPv4, or unbracketed IPv6
    u16 port = 0;               // Explicit or default port (80 or 443)
    String path_and_query{};    // Starts with '/', includes '?query' if present
    bool is_secure = false;     // true for "https" and "wss"
    bool is_websocket = false;  // true for "ws" and "wss"
    bool valid = false;
};

[[nodiscard]] ParsedUrl parse_url(StringRef url);

// ============================================================================
// 2. Cross-Platform HTTP / HTTPS Client (WinHTTP / libcurl / Emscripten Fetch)
// ============================================================================

enum class HttpMethod : u8 {
    Get = 0,
    Post,
    Put,
    Delete,
    Head,
    Patch
};

struct HttpHeader {
    String name{};
    String value{};
};

struct HttpRequest {
    String url{};
    HttpMethod method = HttpMethod::Get;
    SmallArray<HttpHeader, 8> headers{};
    Array<u8> body{};
    String user_agent{};
    u32 connect_timeout_ms = 2500;
    u32 read_timeout_ms = 5000;
    usize max_response_bytes = 16u * 1024u * 1024u; // 16 MB safety cap
    bool follow_redirects = true;
    bool verify_tls_peer = true;
};

struct HttpResponse {
    i32 status_code = 0;
    SmallArray<HttpHeader, 8> headers{};
    Array<u8> body{};
    String content_type{};
    String error_message{};
    f64 elapsed_ms = 0.0;

    [[nodiscard]] bool succeeded() const noexcept {
        return status_code >= 200 && status_code < 300 && error_message.empty();
    }

    [[nodiscard]] StringRef body_as_text() const noexcept {
        if (body.empty()) return {};
        return StringRef(reinterpret_cast<const char*>(body.data()), body.size());
    }

    [[nodiscard]] StringRef get_header(StringRef name) const noexcept;
};

class IHttpClient {
public:
    virtual ~IHttpClient() = default;
    [[nodiscard]] virtual HttpResponse execute(const HttpRequest& request) const = 0;
};

class HttpClient final : public IHttpClient {
public:
    explicit HttpClient(StringRef default_user_agent = "keel-http/0.1");
    ~HttpClient() override;

    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;
    HttpClient(HttpClient&& other) noexcept;
    HttpClient& operator=(HttpClient&& other) noexcept;

    // Thread-safe synchronous HTTP/HTTPS execution reusing the underlying OS session pool.
    [[nodiscard]] HttpResponse execute(const HttpRequest& request) const override;

    // Convenience helper for GET requests.
    [[nodiscard]] HttpResponse get(
        StringRef url,
        ArrayRef<HttpHeader> headers = {},
        u32 timeout_ms = 3000
    ) const;

    // Convenience helper for POST requests.
    [[nodiscard]] HttpResponse post(
        StringRef url,
        ArrayRef<u8> body,
        StringRef content_type = "application/octet-stream",
        ArrayRef<HttpHeader> headers = {},
        u32 timeout_ms = 5000
    ) const;

    // Returns active native backend identifier ("WinHTTP", "libcurl", "EmscriptenFetch", or "OfflineStub").
    [[nodiscard]] static StringRef backend_name() noexcept;

private:
    struct Impl;
    Impl* m_impl = nullptr;
};

// ============================================================================
// 3. Cross-Platform WebSocket Client (WinHTTP WS / libcurl WS / Emscripten WS)
// ============================================================================

enum class WebSocketState : u8 {
    Disconnected = 0,
    Connecting,
    Connected,
    Closing,
    Error
};

enum class WebSocketFrameType : u8 {
    Text = 0,
    Binary,
    Close
};

struct WebSocketMessage {
    WebSocketFrameType type = WebSocketFrameType::Text;
    Array<u8> data{};
    u16 close_status = 1000;

    [[nodiscard]] StringRef as_text() const noexcept {
        if (data.empty()) return {};
        return StringRef(reinterpret_cast<const char*>(data.data()), data.size());
    }
};

struct WebSocketConnectOptions {
    SmallArray<HttpHeader, 8> headers{};
    String user_agent{};
    u32 connect_timeout_ms = 5000;
    usize max_message_bytes = 16u * 1024u * 1024u;
    bool verify_tls_peer = true;
};

class IWebSocketClient {
public:
    virtual ~IWebSocketClient() = default;
    [[nodiscard]] virtual bool connect(StringRef url, const WebSocketConnectOptions& options = {}) = 0;
    [[nodiscard]] virtual bool send_text(StringRef text) = 0;
    [[nodiscard]] virtual bool send_binary(ArrayRef<u8> payload) = 0;
    [[nodiscard]] virtual bool receive(WebSocketMessage& out_message) = 0;
    virtual void close(u16 status_code = 1000, StringRef reason = "Normal closure") noexcept = 0;
    [[nodiscard]] virtual WebSocketState state() const noexcept = 0;
    [[nodiscard]] virtual String last_error() const = 0;
};

class WebSocketClient final : public IWebSocketClient {
public:
    WebSocketClient();
    ~WebSocketClient() override;

    WebSocketClient(const WebSocketClient&) = delete;
    WebSocketClient& operator=(const WebSocketClient&) = delete;
    WebSocketClient(WebSocketClient&& other) noexcept;
    WebSocketClient& operator=(WebSocketClient&& other) noexcept;

    [[nodiscard]] bool connect(StringRef url, const WebSocketConnectOptions& options = {}) override;
    [[nodiscard]] bool send_text(StringRef text) override;
    [[nodiscard]] bool send_binary(ArrayRef<u8> payload) override;
    [[nodiscard]] bool receive(WebSocketMessage& out_message) override;
    void close(u16 status_code = 1000, StringRef reason = "Normal closure") noexcept override;

    [[nodiscard]] WebSocketState state() const noexcept override;
    [[nodiscard]] String last_error() const override;

private:
    struct Impl;
    Impl* m_impl = nullptr;
};

namespace http {
using keel::ParsedUrl;
using keel::parse_url;
using keel::HttpMethod;
using keel::HttpHeader;
using keel::HttpRequest;
using keel::HttpResponse;
using keel::IHttpClient;
using keel::HttpClient;
using keel::WebSocketState;
using keel::WebSocketFrameType;
using keel::WebSocketMessage;
using keel::WebSocketConnectOptions;
using keel::IWebSocketClient;
using keel::WebSocketClient;
} // namespace http

} // namespace keel
