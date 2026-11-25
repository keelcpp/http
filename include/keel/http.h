#pragma once

#include "keel/array.h"
#include "keel/function_ref.h"
#include "keel/optional.h"
#include "keel/small_array.h"
#include "keel/string.h"

namespace keel {

// ============================================================================
// 1. RFC 3986 URL Parser, Percent-Encoding, Query Builder & Reference Resolver
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

// RFC 3986 percent-encoding (unreserved A-Za-z0-9-_.~ preserved).
// When space_as_plus is true, ' ' is encoded as '+' (application/x-www-form-urlencoded).
[[nodiscard]] String url_encode(StringRef input, bool space_as_plus = false, Allocator* alloc = nullptr);

// Strict percent-decoding. Returns kNullOpt on truncated or malformed %XX escape.
[[nodiscard]] Optional<String> url_decode(StringRef input, bool plus_as_space = false, Allocator* alloc = nullptr);

struct HttpQueryParam {
    String key{};
    String value{};
};

// Encodes key=value pairs separated by '&' using application/x-www-form-urlencoded rules.
[[nodiscard]] String build_query_string(ArrayRef<HttpQueryParam> params, Allocator* alloc = nullptr);

// Parses a query string (with or without leading '?') into decoded key/value pairs.
[[nodiscard]] Array<HttpQueryParam> parse_query_string(StringRef query, Allocator* alloc = nullptr);

// Resolves a relative or absolute RFC 3986 Location reference against a base URL.
// Returns an empty string if base_url is invalid or location cannot be resolved.
[[nodiscard]] String resolve_url(StringRef base_url, StringRef location, Allocator* alloc = nullptr);

class UrlBuilder {
public:
    explicit UrlBuilder(StringRef base_url);

    UrlBuilder& add_query(StringRef key, StringRef value);
    UrlBuilder& set_fragment(StringRef fragment);
    [[nodiscard]] String build(Allocator* alloc = nullptr) const;

private:
    String m_base{};
    Array<HttpQueryParam> m_params{};
    String m_fragment{};
};

// ============================================================================
// 2. HTTP Headers, Auth Helpers, Multipart Form Builder & RFC 6265 Cookie Jar
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

[[nodiscard]] HttpHeader make_bearer_auth_header(StringRef token);
[[nodiscard]] HttpHeader make_basic_auth_header(StringRef username, StringRef password);

// RFC 7578 multipart/form-data builder with OS-CSPRNG boundary generation.
class MultipartFormData {
public:
    MultipartFormData();
    explicit MultipartFormData(StringRef custom_boundary);

    MultipartFormData& add_field(StringRef name, StringRef value);
    MultipartFormData& add_file(
        StringRef name,
        StringRef filename,
        ArrayRef<u8> data,
        StringRef content_type = "application/octet-stream"
    );

    [[nodiscard]] StringRef boundary() const noexcept { return m_boundary.as_ref(); }

    // Serializes the multipart payload and its matching "multipart/form-data; boundary=..." Content-Type.
    void build(Array<u8>& out_body, String& out_content_type) const;

private:
    struct Part {
        String name{};
        String filename{};
        String content_type{};
        Array<u8> data{};
        bool is_file = false;
    };

    String m_boundary{};
    Array<Part> m_parts{};
};

struct HttpCookie {
    String name{};
    String value{};
    String domain{};
    String path{};
    i64 expires_unix_s = 0; // Seconds since Unix epoch (when has_expiry == true)
    bool has_expiry = false;
    bool secure = false;
    bool http_only = false;
    bool host_only = true;
};

// Thread-safe RFC 6265 cookie jar.
class CookieJar {
public:
    CookieJar();
    ~CookieJar();

    CookieJar(const CookieJar&) = delete;
    CookieJar& operator=(const CookieJar&) = delete;
    CookieJar(CookieJar&& other) noexcept;
    CookieJar& operator=(CookieJar&& other) noexcept;

    void set_cookie(const HttpCookie& cookie);
    void store_from_headers(StringRef request_url, ArrayRef<HttpHeader> response_headers);
    [[nodiscard]] String cookie_header_for(StringRef request_url, Allocator* alloc = nullptr) const;
    [[nodiscard]] usize size() const noexcept;
    void clear() noexcept;

private:
    struct Impl;
    Impl* m_impl = nullptr;
};

// ============================================================================
// 3. Cross-Platform HTTP / HTTPS Client (WinHTTP / libcurl / Emscripten Fetch)
// ============================================================================

struct HttpRetryPolicy {
    u32 max_retries = 0;               // 0 disables automatic retries
    u32 initial_delay_ms = 200;        // Base exponential backoff delay
    u32 max_delay_ms = 10000;          // Maximum sleep between retries (also caps Retry-After)
    bool retry_on_network_error = true;
    bool retry_on_5xx = true;          // 500, 502, 503, 504
    bool retry_on_429 = true;          // 429 Too Many Requests (honors Retry-After seconds)
    bool retry_non_idempotent = false; // When false, only retries GET/HEAD/PUT/DELETE
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
    u32 max_redirects = 10;
    HttpRetryPolicy retry{};
    CookieJar* cookie_jar = nullptr; // Optional per-request jar (overrides HttpClient default)
};

struct HttpResponse {
    i32 status_code = 0;
    SmallArray<HttpHeader, 8> headers{};
    Array<u8> body{};
    String content_type{};
    String error_message{};
    f64 elapsed_ms = 0.0;
    String final_url{};
    u32 redirect_count = 0;
    u32 attempts = 1;
    usize bytes_received = 0;

    [[nodiscard]] bool succeeded() const noexcept {
        return status_code >= 200 && status_code < 300 && error_message.empty();
    }

    [[nodiscard]] StringRef body_as_text() const noexcept {
        if (body.empty()) return {};
        return StringRef(reinterpret_cast<const char*>(body.data()), body.size());
    }

    [[nodiscard]] StringRef get_header(StringRef name) const noexcept;
    [[nodiscard]] SmallArray<StringRef, 4> get_headers(StringRef name) const;
};

class IHttpClient {
public:
    virtual ~IHttpClient() = default;
    [[nodiscard]] virtual HttpResponse execute(const HttpRequest& request) const = 0;
};

class HttpClient final : public IHttpClient {
public:
    explicit HttpClient(StringRef default_user_agent = "keel-http/0.2");
    ~HttpClient() override;

    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;
    HttpClient(HttpClient&& other) noexcept;
    HttpClient& operator=(HttpClient&& other) noexcept;

    // Optional default CookieJar used whenever HttpRequest::cookie_jar is nullptr (caller owns lifetime).
    void set_cookie_jar(CookieJar* jar) noexcept;
    [[nodiscard]] CookieJar* cookie_jar() const noexcept;

    // Thread-safe synchronous HTTP/HTTPS execution reusing the underlying OS session pool.
    // Supports RFC 9110 redirects (with cross-origin credential stripping), CookieJar updates,
    // and optional retry with exponential backoff + Retry-After.
    [[nodiscard]] HttpResponse execute(const HttpRequest& request) const override;

    // Streaming execution: delivers response body chunks to `on_chunk` without buffering
    // the full payload in HttpResponse::body. Returning false from `on_chunk` aborts cleanly.
    [[nodiscard]] HttpResponse execute_streaming(
        const HttpRequest& request,
        FunctionRef<bool(ArrayRef<u8>)> on_chunk
    ) const;

    // Streams an HTTP GET response directly to a file on disk (atomically via temp sibling or direct write).
    [[nodiscard]] HttpResponse download_to_file(
        StringRef url,
        StringRef dest_path,
        ArrayRef<HttpHeader> headers = {},
        u32 timeout_ms = 30000
    ) const;

    // Convenience HTTP verb helpers.
    [[nodiscard]] HttpResponse get(
        StringRef url,
        ArrayRef<HttpHeader> headers = {},
        u32 timeout_ms = 3000
    ) const;

    [[nodiscard]] HttpResponse head(
        StringRef url,
        ArrayRef<HttpHeader> headers = {},
        u32 timeout_ms = 3000
    ) const;

    [[nodiscard]] HttpResponse post(
        StringRef url,
        ArrayRef<u8> body,
        StringRef content_type = "application/octet-stream",
        ArrayRef<HttpHeader> headers = {},
        u32 timeout_ms = 5000
    ) const;

    [[nodiscard]] HttpResponse put(
        StringRef url,
        ArrayRef<u8> body,
        StringRef content_type = "application/octet-stream",
        ArrayRef<HttpHeader> headers = {},
        u32 timeout_ms = 5000
    ) const;

    [[nodiscard]] HttpResponse patch(
        StringRef url,
        ArrayRef<u8> body,
        StringRef content_type = "application/octet-stream",
        ArrayRef<HttpHeader> headers = {},
        u32 timeout_ms = 5000
    ) const;

    [[nodiscard]] HttpResponse del(
        StringRef url,
        ArrayRef<HttpHeader> headers = {},
        u32 timeout_ms = 5000
    ) const;

    [[nodiscard]] HttpResponse post_form(
        StringRef url,
        ArrayRef<HttpQueryParam> fields,
        ArrayRef<HttpHeader> headers = {},
        u32 timeout_ms = 5000
    ) const;

    [[nodiscard]] HttpResponse post_multipart(
        StringRef url,
        const MultipartFormData& form,
        ArrayRef<HttpHeader> headers = {},
        u32 timeout_ms = 10000
    ) const;

    // Returns active native backend identifier ("WinHTTP", "libcurl", "EmscriptenFetch", or "OfflineStub").
    [[nodiscard]] static StringRef backend_name() noexcept;

private:
    struct Impl;
    Impl* m_impl = nullptr;

    [[nodiscard]] HttpResponse execute_internal(
        const HttpRequest& request,
        FunctionRef<bool(ArrayRef<u8>)> on_chunk,
        bool streaming
    ) const;
};

// ============================================================================
// 4. Cross-Platform WebSocket Client (WinHTTP WS / libcurl WS / Emscripten WS)
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
using keel::url_encode;
using keel::url_decode;
using keel::HttpQueryParam;
using keel::build_query_string;
using keel::parse_query_string;
using keel::resolve_url;
using keel::UrlBuilder;
using keel::HttpMethod;
using keel::HttpHeader;
using keel::make_bearer_auth_header;
using keel::make_basic_auth_header;
using keel::MultipartFormData;
using keel::HttpCookie;
using keel::CookieJar;
using keel::HttpRetryPolicy;
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
