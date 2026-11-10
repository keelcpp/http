#include "keel/http.h"
#include "keel/format.h"
#include "keel/number.h"
#include "keel/ring.h"

#include <chrono>
#include <cstring>
#include <mutex>
#include <thread>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winhttp.h>
#elif defined(__EMSCRIPTEN__)
#include <emscripten/fetch.h>
#include <emscripten/websocket.h>
#elif defined(KEEL_HTTP_HAS_CURL)
#include <curl/curl.h>
#endif

namespace keel {

namespace {

[[nodiscard]] char ascii_to_lower(char c) noexcept {
    if (c >= 'A' && c <= 'Z') {
        return static_cast<char>(c - 'A' + 'a');
    }
    return c;
}

[[nodiscard]] bool equals_ignore_case(StringRef a, StringRef b) noexcept {
    if (a.size() != b.size()) return false;
    for (usize i = 0; i < a.size(); ++i) {
        if (ascii_to_lower(a[i]) != ascii_to_lower(b[i])) return false;
    }
    return true;
}

[[nodiscard]] StringRef trim_ascii(StringRef sv) noexcept {
    while (!sv.empty() && (sv[0] == ' ' || sv[0] == '\t' || sv[0] == '\r' || sv[0] == '\n')) {
        sv = sv.substr(1);
    }
    while (!sv.empty()) {
        const char back = sv[sv.size() - 1];
        if (back == ' ' || back == '\t' || back == '\r' || back == '\n') {
            sv = sv.substr(0, sv.size() - 1);
        } else {
            break;
        }
    }
    return sv;
}

// Guards against CRLF header injection in caller-supplied HTTP headers.
[[maybe_unused]] [[nodiscard]] bool is_safe_header_token(StringRef sv) noexcept {
    for (usize i = 0; i < sv.size(); ++i) {
        const char c = sv[i];
        if (c == '\r' || c == '\n' || c == '\0') {
            return false;
        }
    }
    return true;
}

[[maybe_unused]] [[nodiscard]] const char* http_method_to_cstr(HttpMethod method) noexcept {
    switch (method) {
        case HttpMethod::Get:    return "GET";
        case HttpMethod::Post:   return "POST";
        case HttpMethod::Put:    return "PUT";
        case HttpMethod::Delete: return "DELETE";
        case HttpMethod::Head:   return "HEAD";
        case HttpMethod::Patch:  return "PATCH";
    }
    return "GET";
}

#if defined(_WIN32)
class ScopedWinHttpHandle {
public:
    ScopedWinHttpHandle() noexcept = default;
    explicit ScopedWinHttpHandle(HINTERNET h) noexcept : m_handle(h) {}
    ~ScopedWinHttpHandle() noexcept { reset(); }

    ScopedWinHttpHandle(const ScopedWinHttpHandle&) = delete;
    ScopedWinHttpHandle& operator=(const ScopedWinHttpHandle&) = delete;

    ScopedWinHttpHandle(ScopedWinHttpHandle&& other) noexcept
        : m_handle(other.release()) {}

    ScopedWinHttpHandle& operator=(ScopedWinHttpHandle&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    void reset(HINTERNET new_handle = nullptr) noexcept {
        if (m_handle) {
            WinHttpCloseHandle(m_handle);
        }
        m_handle = new_handle;
    }

    [[nodiscard]] HINTERNET release() noexcept {
        HINTERNET tmp = m_handle;
        m_handle = nullptr;
        return tmp;
    }

    [[nodiscard]] HINTERNET get() const noexcept { return m_handle; }
    [[nodiscard]] explicit operator bool() const noexcept { return m_handle != nullptr; }

private:
    HINTERNET m_handle = nullptr;
};

[[nodiscard]] String format_winhttp_error(StringRef context, DWORD err_code) {
    char buf[192];
    const StringRef r = format_buf(buf, "%s (WinHTTP error=%u)", context, static_cast<u32>(err_code));
    return String::from(r);
}

// Null-terminated UTF-16 buffer for WinHTTP APIs.
struct WideBuffer {
    SmallArray<wchar_t, 256> chars{};

    WideBuffer() {
        chars.push_back(L'\0');
    }

    void append_utf8(StringRef utf8) {
        if (utf8.empty()) return;
        const int needed = MultiByteToWideChar(
            CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
        if (needed <= 0) return;
        if (!chars.empty() && chars.back() == L'\0') {
            chars.pop_back();
        }
        const usize old_len = chars.size();
        chars.resize(old_len + static_cast<usize>(needed) + 1, L'\0');
        MultiByteToWideChar(
            CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), chars.data() + old_len, needed);
        chars[old_len + static_cast<usize>(needed)] = L'\0';
    }

    void append_literal(const wchar_t* lit) {
        if (!lit || !*lit) return;
        if (!chars.empty() && chars.back() == L'\0') {
            chars.pop_back();
        }
        while (*lit) {
            chars.push_back(*lit++);
        }
        chars.push_back(L'\0');
    }

    [[nodiscard]] const wchar_t* c_str() const noexcept {
        return chars.empty() ? L"" : chars.data();
    }

    [[nodiscard]] usize length() const noexcept {
        return chars.size() > 0 ? (chars.size() - 1) : 0;
    }

    [[nodiscard]] bool empty() const noexcept {
        return length() == 0;
    }
};

[[nodiscard]] WideBuffer utf8_to_wide(StringRef utf8) {
    WideBuffer wb;
    wb.append_utf8(utf8);
    return wb;
}

[[nodiscard]] String wide_to_utf8(const wchar_t* wide, usize wide_len) {
    if (!wide || wide_len == 0) return String{};
    const int needed = WideCharToMultiByte(
        CP_UTF8, 0, wide, static_cast<int>(wide_len), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return String{};
    Array<char> tmp;
    tmp.resize(static_cast<usize>(needed));
    WideCharToMultiByte(
        CP_UTF8, 0, wide, static_cast<int>(wide_len), tmp.data(), needed, nullptr, nullptr);
    return String::from(StringRef(tmp.data(), tmp.size()));
}

[[nodiscard]] const wchar_t* http_method_to_wide_cstr(HttpMethod method) noexcept {
    switch (method) {
        case HttpMethod::Get:    return L"GET";
        case HttpMethod::Post:   return L"POST";
        case HttpMethod::Put:    return L"PUT";
        case HttpMethod::Delete: return L"DELETE";
        case HttpMethod::Head:   return L"HEAD";
        case HttpMethod::Patch:  return L"PATCH";
    }
    return L"GET";
}

void parse_winhttp_raw_headers(HINTERNET hRequest, SmallArray<HttpHeader, 8>& out_headers, String& out_content_type) {
    DWORD byte_size = 0;
    WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_RAW_HEADERS_CRLF,
        WINHTTP_HEADER_NAME_BY_INDEX,
        WINHTTP_NO_OUTPUT_BUFFER,
        &byte_size,
        WINHTTP_NO_HEADER_INDEX
    );
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || byte_size < sizeof(wchar_t)) {
        return;
    }

    Array<wchar_t> raw_buf;
    raw_buf.resize(byte_size / sizeof(wchar_t), L'\0');
    if (!WinHttpQueryHeaders(
            hRequest,
            WINHTTP_QUERY_RAW_HEADERS_CRLF,
            WINHTTP_HEADER_NAME_BY_INDEX,
            raw_buf.data(),
            &byte_size,
            WINHTTP_NO_HEADER_INDEX)) {
        return;
    }

    const usize actual_wchars = byte_size / sizeof(wchar_t);
    const String utf8_raw = wide_to_utf8(raw_buf.data(), actual_wchars);
    StringRef sv = utf8_raw.as_ref();
    bool first_line = true;
    while (!sv.empty()) {
        const usize eol = sv.find("\r\n");
        const StringRef line = (eol == StringRef::npos) ? sv : sv.substr(0, eol);
        if (eol == StringRef::npos) {
            sv = {};
        } else {
            sv = sv.substr(eol + 2);
        }

        if (first_line) {
            first_line = false;
            continue;
        }
        if (line.empty()) continue;

        const usize colon = line.find(':');
        if (colon == StringRef::npos || colon == 0) continue;

        const StringRef name_ref = trim_ascii(line.substr(0, colon));
        const StringRef val_ref = trim_ascii(line.substr(colon + 1));
        if (name_ref.empty()) continue;

        if (equals_ignore_case(name_ref, "content-type") && out_content_type.empty()) {
            out_content_type = String::from(val_ref);
        }
        HttpHeader hdr{};
        hdr.name = String::from(name_ref);
        hdr.value = String::from(val_ref);
        out_headers.push_back(keel::move(hdr));
    }
}
#endif

} // namespace

// ============================================================================
// 1. URL Parser Implementation
// ============================================================================

ParsedUrl parse_url(StringRef url) {
    ParsedUrl result{};
    url = trim_ascii(url);
    if (url.empty()) return result;

    const usize scheme_sep = url.find("://");
    if (scheme_sep == StringRef::npos || scheme_sep == 0 || scheme_sep >= 15) {
        return result;
    }

    char scheme_buf[16]{};
    for (usize i = 0; i < scheme_sep; ++i) {
        scheme_buf[i] = ascii_to_lower(url[i]);
    }
    result.scheme.set(StringRef(scheme_buf, scheme_sep));

    if (result.scheme == "http") {
        result.is_secure = false;
        result.is_websocket = false;
        result.port = 80;
    } else if (result.scheme == "https") {
        result.is_secure = true;
        result.is_websocket = false;
        result.port = 443;
    } else if (result.scheme == "ws") {
        result.is_secure = false;
        result.is_websocket = true;
        result.port = 80;
    } else if (result.scheme == "wss") {
        result.is_secure = true;
        result.is_websocket = true;
        result.port = 443;
    } else {
        return result;
    }

    StringRef remainder = url.substr(scheme_sep + 3);
    if (remainder.empty()) return result;

    usize path_pos = StringRef::npos;
    for (usize i = 0; i < remainder.size(); ++i) {
        const char c = remainder[i];
        if (c == '/' || c == '?' || c == '#') {
            path_pos = i;
            break;
        }
    }

    StringRef authority = (path_pos == StringRef::npos)
        ? remainder
        : remainder.substr(0, path_pos);

    StringRef path_part = (path_pos == StringRef::npos)
        ? StringRef{}
        : remainder.substr(path_pos);

    const usize hash_pos = path_part.find('#');
    if (hash_pos != StringRef::npos) {
        path_part = path_part.substr(0, hash_pos);
    }

    if (path_part.empty()) {
        result.path_and_query = String::from("/");
    } else if (path_part[0] == '?') {
        result.path_and_query = String::with_capacity(1 + path_part.size());
        result.path_and_query.push_back('/');
        result.path_and_query.append(path_part);
    } else {
        result.path_and_query = String::from(path_part);
    }

    const usize at_pos = authority.rfind('@');
    if (at_pos != StringRef::npos) {
        authority = authority.substr(at_pos + 1);
    }
    if (authority.empty()) return result;

    if (authority[0] == '[') {
        const usize close_bracket = authority.find(']');
        if (close_bracket == StringRef::npos) return result;
        result.host = String::from(authority.substr(1, close_bracket - 1));
        StringRef port_part = authority.substr(close_bracket + 1);
        if (!port_part.empty()) {
            if (port_part[0] != ':') return result;
            port_part = port_part.substr(1);
            const auto port_res = parse_u64(port_part);
            if (!port_res.is_ok() || port_res.value() == 0 || port_res.value() > 65535) {
                return result;
            }
            result.port = static_cast<u16>(port_res.value());
        }
    } else {
        const usize colon_pos = authority.rfind(':');
        if (colon_pos != StringRef::npos) {
            result.host = String::from(authority.substr(0, colon_pos));
            StringRef port_part = authority.substr(colon_pos + 1);
            const auto port_res = parse_u64(port_part);
            if (!port_res.is_ok() || port_res.value() == 0 || port_res.value() > 65535) {
                return result;
            }
            result.port = static_cast<u16>(port_res.value());
        } else {
            result.host = String::from(authority);
        }
    }

    if (result.host.empty()) return result;
    result.valid = true;
    return result;
}

StringRef HttpResponse::get_header(StringRef name) const noexcept {
    for (usize i = 0; i < headers.size(); ++i) {
        if (equals_ignore_case(headers[i].name.as_ref(), name)) {
            return headers[i].value.as_ref();
        }
    }
    return {};
}

// ============================================================================
// 2. HttpClient Implementation (with Persistent Connection Pooling)
// ============================================================================

struct HttpClient::Impl {
    String default_user_agent{};

#if defined(_WIN32)
    ScopedWinHttpHandle session{};

    explicit Impl(StringRef ua) : default_user_agent(String::from(ua.empty() ? StringRef("keel-http/0.1") : ua)) {
        const WideBuffer w_ua = utf8_to_wide(default_user_agent.as_ref());
        HINTERNET raw_session = nullptr;
#ifdef WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
        raw_session = WinHttpOpen(
            w_ua.empty() ? L"keel-http/0.1" : w_ua.c_str(),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );
#endif
        if (!raw_session) {
            raw_session = WinHttpOpen(
                w_ua.empty() ? L"keel-http/0.1" : w_ua.c_str(),
                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                WINHTTP_NO_PROXY_NAME,
                WINHTTP_NO_PROXY_BYPASS,
                0
            );
        }
        session.reset(raw_session);

        if (session) {
            DWORD secure_protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
#ifdef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
            secure_protocols |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
#endif
            WinHttpSetOption(session.get(), WINHTTP_OPTION_SECURE_PROTOCOLS, &secure_protocols, sizeof(secure_protocols));

#ifdef WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL
#ifdef WINHTTP_PROTOCOL_FLAG_HTTP2
            DWORD http2_flag = WINHTTP_PROTOCOL_FLAG_HTTP2;
            WinHttpSetOption(session.get(), WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &http2_flag, sizeof(http2_flag));
#endif
#endif
        }
    }

#elif defined(KEEL_HTTP_HAS_CURL)
    mutable std::mutex pool_mutex{};
    mutable SmallArray<CURL*, 16> handle_pool{};

    explicit Impl(StringRef ua) : default_user_agent(String::from(ua.empty() ? StringRef("keel-http/0.1") : ua)) {
        static std::once_flag s_curl_init_flag;
        std::call_once(s_curl_init_flag, []() {
            curl_global_init(CURL_GLOBAL_DEFAULT);
        });
    }

    ~Impl() {
        std::lock_guard<std::mutex> lk(pool_mutex);
        for (usize i = 0; i < handle_pool.size(); ++i) {
            if (handle_pool[i]) curl_easy_cleanup(handle_pool[i]);
        }
        handle_pool.clear();
    }

    [[nodiscard]] CURL* acquire_handle() const {
        {
            std::lock_guard<std::mutex> lk(pool_mutex);
            if (!handle_pool.empty()) {
                CURL* h = handle_pool.back();
                handle_pool.pop_back();
                curl_easy_reset(h);
                return h;
            }
        }
        return curl_easy_init();
    }

    void release_handle(CURL* h) const noexcept {
        if (!h) return;
        std::lock_guard<std::mutex> lk(pool_mutex);
        if (handle_pool.size() < 16) {
            handle_pool.push_back(h);
        } else {
            curl_easy_cleanup(h);
        }
    }
#else
    explicit Impl(StringRef ua) : default_user_agent(String::from(ua.empty() ? StringRef("keel-http/0.1") : ua)) {}
#endif
};

HttpClient::HttpClient(StringRef default_user_agent)
    : m_impl(new Impl(default_user_agent)) {}

HttpClient::~HttpClient() {
    delete m_impl;
}

HttpClient::HttpClient(HttpClient&& other) noexcept : m_impl(other.m_impl) {
    other.m_impl = nullptr;
}

HttpClient& HttpClient::operator=(HttpClient&& other) noexcept {
    if (this != &other) {
        delete m_impl;
        m_impl = other.m_impl;
        other.m_impl = nullptr;
    }
    return *this;
}

StringRef HttpClient::backend_name() noexcept {
#if defined(_WIN32)
    return "WinHTTP";
#elif defined(__EMSCRIPTEN__)
    return "EmscriptenFetch";
#elif defined(KEEL_HTTP_HAS_CURL)
    return "libcurl";
#else
    return "OfflineStub";
#endif
}

HttpResponse HttpClient::get(
    StringRef url,
    ArrayRef<HttpHeader> headers,
    u32 timeout_ms
) const {
    HttpRequest req{};
    req.url = String::from(url);
    req.method = HttpMethod::Get;
    for (usize i = 0; i < headers.size(); ++i) {
        req.headers.push_back(HttpHeader{
            .name = headers[i].name.clone(),
            .value = headers[i].value.clone()
        });
    }
    if (m_impl && !m_impl->default_user_agent.empty()) {
        req.user_agent = m_impl->default_user_agent.clone();
    }
    req.connect_timeout_ms = timeout_ms;
    req.read_timeout_ms = timeout_ms;
    return execute(req);
}

HttpResponse HttpClient::post(
    StringRef url,
    ArrayRef<u8> body,
    StringRef content_type,
    ArrayRef<HttpHeader> headers,
    u32 timeout_ms
) const {
    HttpRequest req{};
    req.url = String::from(url);
    req.method = HttpMethod::Post;
    req.body.append(body);
    for (usize i = 0; i < headers.size(); ++i) {
        req.headers.push_back(HttpHeader{
            .name = headers[i].name.clone(),
            .value = headers[i].value.clone()
        });
    }
    if (!content_type.empty()) {
        req.headers.push_back(HttpHeader{
            .name = String::from("Content-Type"),
            .value = String::from(content_type)
        });
    }
    if (m_impl && !m_impl->default_user_agent.empty()) {
        req.user_agent = m_impl->default_user_agent.clone();
    }
    req.connect_timeout_ms = timeout_ms;
    req.read_timeout_ms = timeout_ms;
    return execute(req);
}

HttpResponse HttpClient::execute(const HttpRequest& request) const {
    const auto t0 = std::chrono::steady_clock::now();
    HttpResponse response{};

    const ParsedUrl parsed = parse_url(request.url.as_ref());
    if (!parsed.valid || parsed.is_websocket) {
        response.error_message = String::from("Invalid HTTP/HTTPS URL");
        return response;
    }

#if defined(_WIN32)
    if (!m_impl || !m_impl->session) {
        response.error_message = String::from("WinHTTP session not initialized");
        return response;
    }

    const WideBuffer w_host = utf8_to_wide(parsed.host.as_ref());
    ScopedWinHttpHandle h_connect(WinHttpConnect(
        m_impl->session.get(),
        w_host.c_str(),
        static_cast<INTERNET_PORT>(parsed.port),
        0
    ));
    if (!h_connect) {
        response.error_message = format_winhttp_error("WinHttpConnect failed", GetLastError());
        return response;
    }

    const WideBuffer w_path = utf8_to_wide(parsed.path_and_query.as_ref());
    const DWORD request_flags = parsed.is_secure ? WINHTTP_FLAG_SECURE : 0;
    ScopedWinHttpHandle h_request(WinHttpOpenRequest(
        h_connect.get(),
        http_method_to_wide_cstr(request.method),
        w_path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        request_flags
    ));
    if (!h_request) {
        response.error_message = format_winhttp_error("WinHttpOpenRequest failed", GetLastError());
        return response;
    }

    const int conn_timeout = static_cast<int>(keel::max<u32>(100u, request.connect_timeout_ms));
    const int io_timeout = static_cast<int>(keel::max<u32>(100u, request.read_timeout_ms));
    WinHttpSetTimeouts(h_request.get(), conn_timeout, conn_timeout, io_timeout, io_timeout);

    if (!request.follow_redirects) {
        DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        WinHttpSetOption(h_request.get(), WINHTTP_OPTION_REDIRECT_POLICY, &redirect_policy, sizeof(redirect_policy));
    }

    if (parsed.is_secure && !request.verify_tls_peer) {
        DWORD sec_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(h_request.get(), WINHTTP_OPTION_SECURITY_FLAGS, &sec_flags, sizeof(sec_flags));
    }

    WideBuffer extra_headers;
    const StringRef effective_ua = request.user_agent.empty()
        ? m_impl->default_user_agent.as_ref()
        : request.user_agent.as_ref();
    if (!effective_ua.empty() && is_safe_header_token(effective_ua)) {
        extra_headers.append_literal(L"User-Agent: ");
        extra_headers.append_utf8(effective_ua);
        extra_headers.append_literal(L"\r\n");
    }
    for (usize i = 0; i < request.headers.size(); ++i) {
        const auto& hdr = request.headers[i];
        if (!hdr.name.empty() && is_safe_header_token(hdr.name.as_ref()) && is_safe_header_token(hdr.value.as_ref())) {
            extra_headers.append_utf8(hdr.name.as_ref());
            extra_headers.append_literal(L": ");
            extra_headers.append_utf8(hdr.value.as_ref());
            extra_headers.append_literal(L"\r\n");
        }
    }

    LPVOID body_ptr = request.body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<u8*>(request.body.data());
    const DWORD body_len = static_cast<DWORD>(request.body.size());

    if (!WinHttpSendRequest(
            h_request.get(),
            extra_headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : extra_headers.c_str(),
            extra_headers.empty() ? 0 : static_cast<DWORD>(extra_headers.length()),
            body_ptr,
            body_len,
            body_len,
            0)) {
        response.error_message = format_winhttp_error("WinHttpSendRequest failed", GetLastError());
        return response;
    }

    if (!WinHttpReceiveResponse(h_request.get(), nullptr)) {
        response.error_message = format_winhttp_error("WinHttpReceiveResponse failed", GetLastError());
        return response;
    }

    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    if (WinHttpQueryHeaders(
            h_request.get(),
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &status_code,
            &status_size,
            WINHTTP_NO_HEADER_INDEX)) {
        response.status_code = static_cast<i32>(status_code);
    }

    parse_winhttp_raw_headers(h_request.get(), response.headers, response.content_type);

    if (request.method != HttpMethod::Head) {
        DWORD dw_size = 0;
        while (WinHttpQueryDataAvailable(h_request.get(), &dw_size) && dw_size > 0) {
            const usize old_size = response.body.size();
            if (old_size + dw_size > request.max_response_bytes) {
                response.error_message = String::from("Response exceeded max_response_bytes limit");
                response.body.clear();
                break;
            }
            response.body.resize(old_size + dw_size);
            DWORD dw_downloaded = 0;
            if (!WinHttpReadData(h_request.get(), response.body.data() + old_size, dw_size, &dw_downloaded)) {
                response.error_message = format_winhttp_error("WinHttpReadData failed", GetLastError());
                response.body.clear();
                break;
            }
            response.body.resize(old_size + dw_downloaded);
        }
    }

#elif defined(__EMSCRIPTEN__)
    emscripten_fetch_attr_t attr;
    emscripten_fetch_attr_init(&attr);
    std::strncpy(attr.requestMethod, http_method_to_cstr(request.method), sizeof(attr.requestMethod) - 1);
    attr.attributes = EMSCRIPTEN_FETCH_LOAD_TO_MEMORY | EMSCRIPTEN_FETCH_SYNCHRONOUS;
    attr.timeoutMSecs = keel::max<u32>(request.connect_timeout_ms, request.read_timeout_ms);

    SmallArray<const char*, 18> header_kvs;
    for (usize i = 0; i < request.headers.size(); ++i) {
        const auto& h = request.headers[i];
        if (!h.name.empty() && is_safe_header_token(h.name.as_ref()) && is_safe_header_token(h.value.as_ref())) {
            header_kvs.push_back(h.name.c_str());
            header_kvs.push_back(h.value.c_str());
        }
    }
    header_kvs.push_back(nullptr);
    if (header_kvs.size() > 1) {
        attr.requestHeaders = header_kvs.data();
    }

    if (!request.body.empty()) {
        attr.requestData = reinterpret_cast<const char*>(request.body.data());
        attr.requestDataSize = request.body.size();
    }

    emscripten_fetch_t* fetch = emscripten_fetch(&attr, request.url.c_str());
    if (!fetch) {
        response.error_message = String::from("emscripten_fetch failed to initialize");
        return response;
    }

    response.status_code = static_cast<i32>(fetch->status);
    if (fetch->data && fetch->numBytes > 0) {
        if (fetch->numBytes <= request.max_response_bytes) {
            const auto* bytes = reinterpret_cast<const u8*>(fetch->data);
            response.body.append(ArrayRef<u8>(bytes, static_cast<usize>(fetch->numBytes)));
        } else {
            response.error_message = String::from("Response exceeded max_response_bytes limit");
        }
    }
    emscripten_fetch_close(fetch);

#elif defined(KEEL_HTTP_HAS_CURL)
    if (!m_impl) {
        response.error_message = String::from("HttpClient not initialized");
        return response;
    }

    CURL* curl = m_impl->acquire_handle();
    if (!curl) {
        response.error_message = String::from("curl_easy_init failed");
        return response;
    }

    struct WriteContext {
        Array<u8>* body = nullptr;
        usize max_bytes = 0;
        bool overflow = false;
    } write_ctx{&response.body, request.max_response_bytes, false};

    auto write_cb = +[](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
        auto* ctx = static_cast<WriteContext*>(userdata);
        const usize total = size * nmemb;
        if (!ctx || !ctx->body) return 0;
        if (ctx->body->size() + total > ctx->max_bytes) {
            ctx->overflow = true;
            return 0;
        }
        ctx->body->append(ArrayRef<u8>(reinterpret_cast<const u8*>(ptr), total));
        return total;
    };

    auto header_cb = +[](char* buffer, size_t size, size_t nitems, void* userdata) -> size_t {
        auto* resp = static_cast<HttpResponse*>(userdata);
        const usize total = size * nitems;
        if (!resp || total == 0) return total;
        StringRef line(buffer, total);
        line = trim_ascii(line);
        if (line.size() >= 5 && equals_ignore_case(line.substr(0, 5), "HTTP/")) {
            // Reset intermediate 3xx redirect headers when a new HTTP status line begins
            resp->headers.clear();
            resp->content_type.clear();
            return total;
        }
        const usize colon = line.find(':');
        if (colon != StringRef::npos && colon > 0) {
            const StringRef name_ref = trim_ascii(line.substr(0, colon));
            const StringRef val_ref = trim_ascii(line.substr(colon + 1));
            if (equals_ignore_case(name_ref, "content-type") && resp->content_type.empty()) {
                resp->content_type = String::from(val_ref);
            }
            HttpHeader hdr{};
            hdr.name = String::from(name_ref);
            hdr.value = String::from(val_ref);
            resp->headers.push_back(keel::move(hdr));
        }
        return total;
    };

    curl_easy_setopt(curl, CURLOPT_URL, request.url.c_str());
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(keel::max<u32>(100u, request.connect_timeout_ms)));
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(keel::max<u32>(100u, request.connect_timeout_ms + request.read_timeout_ms)));
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, request.follow_redirects ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, request.verify_tls_peer ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, request.verify_tls_peer ? 2L : 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_ctx);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response);

    const StringRef effective_ua = request.user_agent.empty()
        ? m_impl->default_user_agent.as_ref()
        : request.user_agent.as_ref();
    if (!effective_ua.empty() && is_safe_header_token(effective_ua)) {
        const String ua_str = String::from(effective_ua);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, ua_str.c_str());
    }

    if (request.method == HttpMethod::Head) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    } else if (request.method == HttpMethod::Post) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.body.empty() ? "" : reinterpret_cast<const char*>(request.body.data()));
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(request.body.size()));
    } else if (request.method != HttpMethod::Get) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, http_method_to_cstr(request.method));
        if (!request.body.empty()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, reinterpret_cast<const char*>(request.body.data()));
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(request.body.size()));
        }
    }

    struct curl_slist* header_list = nullptr;
    for (usize i = 0; i < request.headers.size(); ++i) {
        const auto& h = request.headers[i];
        if (!h.name.empty() && is_safe_header_token(h.name.as_ref()) && is_safe_header_token(h.value.as_ref())) {
            String combined = String::with_capacity(h.name.size() + 2 + h.value.size());
            combined.append(h.name.as_ref());
            combined.append(": ");
            combined.append(h.value.as_ref());
            header_list = curl_slist_append(header_list, combined.c_str());
        }
    }
    if (header_list) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
    }

    const CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        response.status_code = static_cast<i32>(http_code);
    } else if (write_ctx.overflow) {
        response.body.clear();
        response.error_message = String::from("Response exceeded max_response_bytes limit");
    } else {
        response.error_message = String::from(curl_easy_strerror(res));
    }

    if (header_list) {
        curl_slist_free_all(header_list);
    }
    m_impl->release_handle(curl);
#else
    response.error_message = String::from("No HTTP backend compiled for this platform");
#endif

    const auto t1 = std::chrono::steady_clock::now();
    response.elapsed_ms = std::chrono::duration<f64, std::milli>(t1 - t0).count();
    return response;
}

// ============================================================================
// 3. WebSocketClient Implementation
// ============================================================================

struct WebSocketClient::Impl {
    mutable std::mutex mutex{};
    WebSocketState state = WebSocketState::Disconnected;
    String last_error{};
    usize max_message_bytes = 16u * 1024u * 1024u;
    u32 read_timeout_ms = 5000;

#if defined(_WIN32)
    ScopedWinHttpHandle h_session{};
    ScopedWinHttpHandle h_connect{};
    ScopedWinHttpHandle h_websocket{};

    void cleanup_handles() noexcept {
        h_websocket.reset();
        h_connect.reset();
        h_session.reset();
    }
#elif defined(__EMSCRIPTEN__)
    EMSCRIPTEN_WEBSOCKET_T ws_handle = 0;
    Ring<WebSocketMessage> incoming_queue{};

    void cleanup_handles() noexcept {
        if (ws_handle > 0) {
            emscripten_websocket_delete(ws_handle);
            ws_handle = 0;
        }
    }

    ~Impl() {
        cleanup_handles();
    }
#elif defined(KEEL_HTTP_HAS_CURL)
    CURL* curl = nullptr;

    void cleanup_handles() noexcept {
        if (curl) {
            curl_easy_cleanup(curl);
            curl = nullptr;
        }
    }

    ~Impl() {
        cleanup_handles();
    }
#else
    void cleanup_handles() noexcept {}
#endif
};

WebSocketClient::WebSocketClient()
    : m_impl(new Impl()) {}

WebSocketClient::~WebSocketClient() {
    close();
    delete m_impl;
}

WebSocketClient::WebSocketClient(WebSocketClient&& other) noexcept : m_impl(other.m_impl) {
    other.m_impl = nullptr;
}

WebSocketClient& WebSocketClient::operator=(WebSocketClient&& other) noexcept {
    if (this != &other) {
        close();
        delete m_impl;
        m_impl = other.m_impl;
        other.m_impl = nullptr;
    }
    return *this;
}

WebSocketState WebSocketClient::state() const noexcept {
    if (!m_impl) return WebSocketState::Disconnected;
    std::lock_guard<std::mutex> lk(m_impl->mutex);
    return m_impl->state;
}

String WebSocketClient::last_error() const {
    if (!m_impl) return String{};
    std::lock_guard<std::mutex> lk(m_impl->mutex);
    return m_impl->last_error.clone();
}

bool WebSocketClient::connect(StringRef url, const WebSocketConnectOptions& options) {
    if (!m_impl) return false;
    close();

    const ParsedUrl parsed = parse_url(url);
    if (!parsed.valid || !parsed.is_websocket) {
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        m_impl->state = WebSocketState::Error;
        m_impl->last_error = String::from("Invalid WebSocket URL (expected ws:// or wss://)");
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        m_impl->state = WebSocketState::Connecting;
        m_impl->last_error.clear();
        m_impl->max_message_bytes = options.max_message_bytes;
    }

#if defined(_WIN32)
    const WideBuffer w_ua = utf8_to_wide(options.user_agent.empty() ? StringRef("keel-http/0.1") : options.user_agent.as_ref());
    ScopedWinHttpHandle h_session(WinHttpOpen(
        w_ua.c_str(),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    ));
    if (!h_session) {
        const DWORD err = ::GetLastError();
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        m_impl->state = WebSocketState::Error;
        m_impl->last_error = format_winhttp_error("WinHttpOpen failed for WebSocket", err);
        return false;
    }

    const int timeout_ms = static_cast<int>(keel::max<u32>(500u, options.connect_timeout_ms));
    WinHttpSetTimeouts(h_session.get(), timeout_ms, timeout_ms, timeout_ms, timeout_ms);

    const WideBuffer w_host = utf8_to_wide(parsed.host.as_ref());
    ScopedWinHttpHandle h_connect(WinHttpConnect(
        h_session.get(),
        w_host.c_str(),
        static_cast<INTERNET_PORT>(parsed.port),
        0
    ));
    if (!h_connect) {
        const DWORD err = ::GetLastError();
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        m_impl->state = WebSocketState::Error;
        m_impl->last_error = format_winhttp_error("WinHttpConnect failed for WebSocket", err);
        return false;
    }

    const WideBuffer w_path = utf8_to_wide(parsed.path_and_query.as_ref());
    ScopedWinHttpHandle h_request(WinHttpOpenRequest(
        h_connect.get(),
        L"GET",
        w_path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        parsed.is_secure ? WINHTTP_FLAG_SECURE : 0
    ));
    if (!h_request) {
        const DWORD err = ::GetLastError();
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        m_impl->state = WebSocketState::Error;
        m_impl->last_error = format_winhttp_error("WinHttpOpenRequest failed for WebSocket", err);
        return false;
    }

    if (parsed.is_secure && !options.verify_tls_peer) {
        DWORD sec_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(h_request.get(), WINHTTP_OPTION_SECURITY_FLAGS, &sec_flags, sizeof(sec_flags));
    }

    if (!WinHttpSetOption(h_request.get(), WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0)) {
        const DWORD err = ::GetLastError();
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        m_impl->state = WebSocketState::Error;
        m_impl->last_error = format_winhttp_error("WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET failed", err);
        return false;
    }

    WideBuffer extra_headers;
    for (usize i = 0; i < options.headers.size(); ++i) {
        const auto& hdr = options.headers[i];
        if (!hdr.name.empty() && is_safe_header_token(hdr.name.as_ref()) && is_safe_header_token(hdr.value.as_ref())) {
            extra_headers.append_utf8(hdr.name.as_ref());
            extra_headers.append_literal(L": ");
            extra_headers.append_utf8(hdr.value.as_ref());
            extra_headers.append_literal(L"\r\n");
        }
    }

    if (!WinHttpSendRequest(
            h_request.get(),
            extra_headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : extra_headers.c_str(),
            extra_headers.empty() ? 0 : static_cast<DWORD>(extra_headers.length()),
            WINHTTP_NO_REQUEST_DATA,
            0,
            0,
            0) ||
        !WinHttpReceiveResponse(h_request.get(), nullptr)) {
        const DWORD err = ::GetLastError();
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        m_impl->state = WebSocketState::Error;
        m_impl->last_error = format_winhttp_error("WebSocket HTTP upgrade handshake failed", err);
        return false;
    }

    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    if (WinHttpQueryHeaders(
            h_request.get(),
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &status_code,
            &status_size,
            WINHTTP_NO_HEADER_INDEX) &&
        status_code != 101) {
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        m_impl->state = WebSocketState::Error;
        char buf[128];
        const StringRef r = format_buf(buf, "WebSocket upgrade rejected by server (HTTP %u)", static_cast<u32>(status_code));
        m_impl->last_error = String::from(r);
        return false;
    }

    ScopedWinHttpHandle h_websocket(WinHttpWebSocketCompleteUpgrade(h_request.get(), 0));
    h_request.reset();

    if (!h_websocket) {
        const DWORD err = ::GetLastError();
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        m_impl->state = WebSocketState::Error;
        m_impl->last_error = format_winhttp_error("WinHttpWebSocketCompleteUpgrade failed", err);
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        m_impl->h_session = keel::move(h_session);
        m_impl->h_connect = keel::move(h_connect);
        m_impl->h_websocket = keel::move(h_websocket);
        m_impl->state = WebSocketState::Connected;
    }
    return true;

#elif defined(__EMSCRIPTEN__)
    if (!emscripten_websocket_is_supported()) {
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        m_impl->state = WebSocketState::Error;
        m_impl->last_error = String::from("Emscripten WebSockets not supported in this environment");
        return false;
    }

    const String url_str = String::from(url);
    EmscriptenWebSocketCreateAttributes ws_attr;
    emscripten_websocket_init_create_attributes(&ws_attr);
    ws_attr.url = url_str.c_str();
    ws_attr.createOnMainThread = EM_TRUE;

    EMSCRIPTEN_WEBSOCKET_T ws = emscripten_websocket_new(&ws_attr);
    if (ws <= 0) {
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        m_impl->state = WebSocketState::Error;
        m_impl->last_error = String::from("emscripten_websocket_new failed");
        return false;
    }

    emscripten_websocket_set_onopen_callback(ws, m_impl, +[](int, const EmscriptenWebSocketOpenEvent*, void* user_data) -> EM_BOOL {
        auto* self = static_cast<Impl*>(user_data);
        std::lock_guard<std::mutex> lk(self->mutex);
        self->state = WebSocketState::Connected;
        return EM_TRUE;
    });

    emscripten_websocket_set_onmessage_callback(ws, m_impl, +[](int, const EmscriptenWebSocketMessageEvent* ev, void* user_data) -> EM_BOOL {
        auto* self = static_cast<Impl*>(user_data);
        if (!ev) return EM_TRUE;
        std::lock_guard<std::mutex> lk(self->mutex);
        if (ev->numBytes <= self->max_message_bytes) {
            WebSocketMessage msg{};
            msg.type = ev->isText ? WebSocketFrameType::Text : WebSocketFrameType::Binary;
            const usize len = (ev->isText && ev->numBytes > 0 && ev->data[ev->numBytes - 1] == 0)
                ? static_cast<usize>(ev->numBytes - 1)
                : static_cast<usize>(ev->numBytes);
            msg.data.append(ArrayRef<u8>(ev->data, len));
            self->incoming_queue.push_back(keel::move(msg));
        }
        return EM_TRUE;
    });

    emscripten_websocket_set_onerror_callback(ws, m_impl, +[](int, const EmscriptenWebSocketErrorEvent*, void* user_data) -> EM_BOOL {
        auto* self = static_cast<Impl*>(user_data);
        std::lock_guard<std::mutex> lk(self->mutex);
        self->state = WebSocketState::Error;
        self->last_error = String::from("WebSocket error event");
        return EM_TRUE;
    });

    emscripten_websocket_set_onclose_callback(ws, m_impl, +[](int, const EmscriptenWebSocketCloseEvent* ev, void* user_data) -> EM_BOOL {
        auto* self = static_cast<Impl*>(user_data);
        std::lock_guard<std::mutex> lk(self->mutex);
        self->state = WebSocketState::Disconnected;
        WebSocketMessage close_msg{};
        close_msg.type = WebSocketFrameType::Close;
        close_msg.close_status = ev ? ev->code : 1000;
        self->incoming_queue.push_back(keel::move(close_msg));
        return EM_TRUE;
    });

    {
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        m_impl->ws_handle = ws;
    }
    return true;

#elif defined(KEEL_HTTP_HAS_CURL) && (LIBCURL_VERSION_NUM >= 0x075600)
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        m_impl->state = WebSocketState::Error;
        m_impl->last_error = String::from("curl_easy_init failed for WebSocket");
        return false;
    }

    const String url_str = String::from(url);
    curl_easy_setopt(curl, CURLOPT_URL, url_str.c_str());
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(keel::max<u32>(500u, options.connect_timeout_ms)));
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, options.verify_tls_peer ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, options.verify_tls_peer ? 2L : 0L);
    if (!options.user_agent.empty() && is_safe_header_token(options.user_agent.as_ref())) {
        curl_easy_setopt(curl, CURLOPT_USERAGENT, options.user_agent.c_str());
    }

    struct curl_slist* header_list = nullptr;
    for (usize i = 0; i < options.headers.size(); ++i) {
        const auto& h = options.headers[i];
        if (!h.name.empty() && is_safe_header_token(h.name.as_ref()) && is_safe_header_token(h.value.as_ref())) {
            String combined = String::with_capacity(h.name.size() + 2 + h.value.size());
            combined.append(h.name.as_ref());
            combined.append(": ");
            combined.append(h.value.as_ref());
            header_list = curl_slist_append(header_list, combined.c_str());
        }
    }
    if (header_list) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
    }

    const CURLcode res = curl_easy_perform(curl);
    if (header_list) {
        curl_slist_free_all(header_list);
    }
    if (res != CURLE_OK) {
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        m_impl->state = WebSocketState::Error;
        m_impl->last_error = String::from(curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        m_impl->curl = curl;
        m_impl->read_timeout_ms = keel::max<u32>(500u, options.connect_timeout_ms);
        m_impl->state = WebSocketState::Connected;
    }
    return true;
#else
    (void)options;
    std::lock_guard<std::mutex> lk(m_impl->mutex);
    m_impl->state = WebSocketState::Error;
    m_impl->last_error = String::from("WebSocket backend not available in this build");
    return false;
#endif
}

bool WebSocketClient::send_text(StringRef text) {
    if (!m_impl) return false;
#if defined(_WIN32)
    HINTERNET h_ws = nullptr;
    {
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        if (m_impl->state != WebSocketState::Connected || !m_impl->h_websocket) return false;
        h_ws = m_impl->h_websocket.get();
    }
    const DWORD err = WinHttpWebSocketSend(
        h_ws,
        WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
        const_cast<char*>(text.data()),
        static_cast<DWORD>(text.size())
    );
    return err == NO_ERROR;
#elif defined(__EMSCRIPTEN__)
    std::lock_guard<std::mutex> lk(m_impl->mutex);
    if (m_impl->state != WebSocketState::Connected || m_impl->ws_handle <= 0) return false;
    const String copy = String::from(text);
    return emscripten_websocket_send_utf8_text(m_impl->ws_handle, copy.c_str()) == EMSCRIPTEN_RESULT_SUCCESS;
#elif defined(KEEL_HTTP_HAS_CURL) && (LIBCURL_VERSION_NUM >= 0x075600)
    std::lock_guard<std::mutex> lk(m_impl->mutex);
    if (m_impl->state != WebSocketState::Connected || !m_impl->curl) return false;
    size_t sent = 0;
    return curl_ws_send(m_impl->curl, text.data(), text.size(), &sent, 0, CURLWS_TEXT) == CURLE_OK;
#else
    (void)text;
    return false;
#endif
}

bool WebSocketClient::send_binary(ArrayRef<u8> payload) {
    if (!m_impl) return false;
#if defined(_WIN32)
    HINTERNET h_ws = nullptr;
    {
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        if (m_impl->state != WebSocketState::Connected || !m_impl->h_websocket) return false;
        h_ws = m_impl->h_websocket.get();
    }
    const DWORD err = WinHttpWebSocketSend(
        h_ws,
        WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
        const_cast<u8*>(payload.data()),
        static_cast<DWORD>(payload.size())
    );
    return err == NO_ERROR;
#elif defined(__EMSCRIPTEN__)
    std::lock_guard<std::mutex> lk(m_impl->mutex);
    if (m_impl->state != WebSocketState::Connected || m_impl->ws_handle <= 0) return false;
    return emscripten_websocket_send_binary(
        m_impl->ws_handle,
        const_cast<u8*>(payload.data()),
        static_cast<uint32_t>(payload.size())
    ) == EMSCRIPTEN_RESULT_SUCCESS;
#elif defined(KEEL_HTTP_HAS_CURL) && (LIBCURL_VERSION_NUM >= 0x075600)
    std::lock_guard<std::mutex> lk(m_impl->mutex);
    if (m_impl->state != WebSocketState::Connected || !m_impl->curl) return false;
    size_t sent = 0;
    return curl_ws_send(m_impl->curl, payload.data(), payload.size(), &sent, 0, CURLWS_BINARY) == CURLE_OK;
#else
    (void)payload;
    return false;
#endif
}

bool WebSocketClient::receive(WebSocketMessage& out_message) {
    out_message = {};
    if (!m_impl) return false;

#if defined(_WIN32)
    HINTERNET h_ws = nullptr;
    usize max_bytes = 0;
    {
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        if (m_impl->state != WebSocketState::Connected || !m_impl->h_websocket) return false;
        h_ws = m_impl->h_websocket.get();
        max_bytes = m_impl->max_message_bytes;
    }

    u8 chunk[8192];
    for (;;) {
        DWORD bytes_read = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE buf_type = WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE;
        const DWORD err = WinHttpWebSocketReceive(h_ws, chunk, sizeof(chunk), &bytes_read, &buf_type);
        if (err != NO_ERROR) {
            std::lock_guard<std::mutex> lk(m_impl->mutex);
            m_impl->state = WebSocketState::Error;
            m_impl->last_error = format_winhttp_error("WinHttpWebSocketReceive failed", err);
            return false;
        }

        if (buf_type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
            USHORT status = 1000;
            DWORD reason_consumed = 0;
            char reason_buf[128]{};
            WinHttpWebSocketQueryCloseStatus(h_ws, &status, reason_buf, sizeof(reason_buf), &reason_consumed);
            out_message.type = WebSocketFrameType::Close;
            out_message.close_status = status;
            out_message.data.append(ArrayRef<u8>(reinterpret_cast<const u8*>(reason_buf), static_cast<usize>(reason_consumed)));
            std::lock_guard<std::mutex> lk(m_impl->mutex);
            m_impl->state = WebSocketState::Disconnected;
            return true;
        }

        if (out_message.data.size() + bytes_read > max_bytes) {
            std::lock_guard<std::mutex> lk(m_impl->mutex);
            m_impl->state = WebSocketState::Error;
            m_impl->last_error = String::from("WebSocket message exceeded max_message_bytes");
            return false;
        }

        out_message.data.append(ArrayRef<u8>(chunk, static_cast<usize>(bytes_read)));
        if (buf_type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) {
            out_message.type = WebSocketFrameType::Text;
            return true;
        }
        if (buf_type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE) {
            out_message.type = WebSocketFrameType::Binary;
            return true;
        }
    }

#elif defined(__EMSCRIPTEN__)
    std::lock_guard<std::mutex> lk(m_impl->mutex);
    if (m_impl->incoming_queue.empty()) return false;
    out_message = keel::move(m_impl->incoming_queue.front());
    m_impl->incoming_queue.pop_front();
    return true;

#elif defined(KEEL_HTTP_HAS_CURL) && (LIBCURL_VERSION_NUM >= 0x075600)
    const auto deadline = std::chrono::steady_clock::now() + [&]() {
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        return std::chrono::milliseconds(m_impl->read_timeout_ms);
    }();

    u8 chunk[8192];
    for (;;) {
        size_t rlen = 0;
        const struct curl_ws_frame* meta = nullptr;
        CURLcode res = CURLE_OK;
        usize max_bytes = 0;
        {
            std::lock_guard<std::mutex> lk(m_impl->mutex);
            if (m_impl->state != WebSocketState::Connected || !m_impl->curl) return false;
            max_bytes = m_impl->max_message_bytes;
            res = curl_ws_recv(m_impl->curl, chunk, sizeof(chunk), &rlen, &meta);
            if (res != CURLE_OK && res != CURLE_AGAIN) {
                m_impl->state = WebSocketState::Error;
                m_impl->last_error = String::from(curl_easy_strerror(res));
                return false;
            }
            if (res == CURLE_OK && !meta) {
                m_impl->state = WebSocketState::Error;
                m_impl->last_error = String::from("WebSocket frame metadata missing");
                return false;
            }
            if (res == CURLE_OK && (meta->flags & CURLWS_CLOSE)) {
                out_message.type = WebSocketFrameType::Close;
                m_impl->state = WebSocketState::Disconnected;
                return true;
            }
            if (res == CURLE_OK && out_message.data.size() + rlen > max_bytes) {
                m_impl->state = WebSocketState::Error;
                m_impl->last_error = String::from("WebSocket message exceeded max_message_bytes");
                return false;
            }
        }
        if (res == CURLE_AGAIN) {
            if (std::chrono::steady_clock::now() >= deadline) {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
            continue;
        }
        out_message.data.append(ArrayRef<u8>(chunk, rlen));
        if (meta->bytesleft == 0 && !(meta->flags & CURLWS_CONT)) {
            out_message.type = (meta->flags & CURLWS_TEXT) ? WebSocketFrameType::Text : WebSocketFrameType::Binary;
            return true;
        }
    }
#else
    return false;
#endif
}

void WebSocketClient::close(u16 status_code, StringRef reason) noexcept {
    if (!m_impl) return;
#if defined(_WIN32)
    HINTERNET h_ws = nullptr;
    {
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        if (m_impl->h_websocket && m_impl->state == WebSocketState::Connected) {
            h_ws = m_impl->h_websocket.get();
            m_impl->state = WebSocketState::Closing;
        }
    }
    if (h_ws) {
        WinHttpWebSocketClose(
            h_ws,
            status_code,
            reason.empty() ? nullptr : const_cast<char*>(reason.data()),
            static_cast<DWORD>(keel::min<usize>(reason.size(), 120u))
        );
    }
    {
        std::lock_guard<std::mutex> lk(m_impl->mutex);
        m_impl->cleanup_handles();
        m_impl->state = WebSocketState::Disconnected;
    }
#elif defined(__EMSCRIPTEN__)
    std::lock_guard<std::mutex> lk(m_impl->mutex);
    if (m_impl->ws_handle > 0) {
        const String reason_str = String::from(reason.substr(0, keel::min<usize>(reason.size(), 120u)));
        emscripten_websocket_close(m_impl->ws_handle, status_code, reason_str.c_str());
        m_impl->cleanup_handles();
    }
    m_impl->state = WebSocketState::Disconnected;
#elif defined(KEEL_HTTP_HAS_CURL) && (LIBCURL_VERSION_NUM >= 0x075600)
    std::lock_guard<std::mutex> lk(m_impl->mutex);
    if (m_impl->curl && m_impl->state == WebSocketState::Connected) {
        size_t sent = 0;
        curl_ws_send(m_impl->curl, "", 0, &sent, 0, CURLWS_CLOSE);
    }
    m_impl->cleanup_handles();
    m_impl->state = WebSocketState::Disconnected;
    (void)status_code;
    (void)reason;
#else
    (void)status_code;
    (void)reason;
    std::lock_guard<std::mutex> lk(m_impl->mutex);
    m_impl->state = WebSocketState::Disconnected;
#endif
}

} // namespace keel
