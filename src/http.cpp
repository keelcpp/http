#include "keel/http.h"
#include "keel/algo.h"
#include "keel/format.h"
#include "keel/fs.h"
#include "keel/io.h"
#include "keel/memory.h"
#include "keel/number.h"
#include "keel/os_random.h"
#include "keel/ring.h"
#include "keel/sync.h"
#include "keel/time.h"

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

constexpr char kHexUpper[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

constexpr char kHexLower[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

constexpr char kBase64Alphabet[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
};

[[nodiscard]] char ascii_to_lower(char c) noexcept {
    if (c >= 'A' && c <= 'Z') {
        return static_cast<char>(c - 'A' + 'a');
    }
    return c;
}

[[nodiscard]] String to_lower_ascii(StringRef s, Allocator* alloc = nullptr) {
    String out(alloc);
    out.reserve(s.size());
    for (usize i = 0; i < s.size(); ++i) {
        out.push_back(ascii_to_lower(s[i]));
    }
    return out;
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

[[nodiscard]] bool is_unreserved_uri_char(u8 c) noexcept {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
           c == '-' || c == '_' || c == '.' || c == '~';
}

[[nodiscard]] i32 hex_nibble(char c) noexcept {
    if (c >= '0' && c <= '9') return as<i32>(c - '0');
    if (c >= 'a' && c <= 'f') return 10 + as<i32>(c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + as<i32>(c - 'A');
    return -1;
}

// Guards against CRLF header injection in caller-supplied HTTP headers.
[[nodiscard]] bool is_safe_header_token(StringRef sv) noexcept {
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

[[nodiscard]] String base64_encode(ArrayRef<u8> data) {
    String out;
    out.reserve(((data.size() + 2u) / 3u) * 4u);
    usize i = 0;
    while (i + 3u <= data.size()) {
        const u32 triple = (as<u32>(data[i]) << 16) | (as<u32>(data[i + 1u]) << 8) | as<u32>(data[i + 2u]);
        out.push_back(kBase64Alphabet[(triple >> 18) & 0x3Fu]);
        out.push_back(kBase64Alphabet[(triple >> 12) & 0x3Fu]);
        out.push_back(kBase64Alphabet[(triple >> 6) & 0x3Fu]);
        out.push_back(kBase64Alphabet[triple & 0x3Fu]);
        i += 3u;
    }
    const usize rem = data.size() - i;
    if (rem == 1u) {
        const u32 v = as<u32>(data[i]) << 16;
        out.push_back(kBase64Alphabet[(v >> 18) & 0x3Fu]);
        out.push_back(kBase64Alphabet[(v >> 12) & 0x3Fu]);
        out.push_back('=');
        out.push_back('=');
    } else if (rem == 2u) {
        const u32 v = (as<u32>(data[i]) << 16) | (as<u32>(data[i + 1u]) << 8);
        out.push_back(kBase64Alphabet[(v >> 18) & 0x3Fu]);
        out.push_back(kBase64Alphabet[(v >> 12) & 0x3Fu]);
        out.push_back(kBase64Alphabet[(v >> 6) & 0x3Fu]);
        out.push_back('=');
    }
    return out;
}

[[nodiscard]] String sanitize_disposition_param(StringRef s) {
    String out;
    out.reserve(s.size());
    for (usize i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (c == '\r' || c == '\n' || c == '\0') continue;
        if (c == '"') {
            out.append("%22");
        } else {
            out.push_back(c);
        }
    }
    return out;
}

[[nodiscard]] String generate_multipart_boundary() {
    u8 rnd[16]{};
    if (os_random_bytes(MutArrayRef<u8>(rnd, sizeof(rnd))).is_err()) {
        // Monotonic fallback if OS CSPRNG is unavailable.
        const u64 t = monotonic_ns();
        for (usize i = 0; i < 8u; ++i) {
            rnd[i] = as<u8>((t >> (i * 8u)) & 0xFFu);
            rnd[i + 8u] = as<u8>(rnd[i] ^ 0xA5u);
        }
    }
    String out = String::with_capacity(50);
    out.append("----KeelFormBoundary");
    for (usize i = 0; i < sizeof(rnd); ++i) {
        out.push_back(kHexLower[(rnd[i] >> 4) & 0xFu]);
        out.push_back(kHexLower[rnd[i] & 0xFu]);
    }
    return out;
}

// RFC 3986 §5.2.4 dot-segment removal.
[[nodiscard]] String normalize_url_path(StringRef path, Allocator* alloc = nullptr) {
    Array<StringRef> segs;
    usize i = 0;
    const bool trailing_slash = !path.empty() && path.back() == '/';
    bool ended_with_dot = false;

    while (i < path.size()) {
        while (i < path.size() && path[i] == '/') ++i;
        if (i >= path.size()) break;
        const usize start = i;
        while (i < path.size() && path[i] != '/') ++i;
        const StringRef seg = path.substr(start, i - start);
        if (seg == ".") {
            ended_with_dot = (i >= path.size());
        } else if (seg == "..") {
            if (!segs.empty()) segs.pop_back();
            ended_with_dot = (i >= path.size());
        } else {
            segs.push_back(seg);
            ended_with_dot = false;
        }
    }

    String out(alloc);
    out.push_back('/');
    for (usize k = 0; k < segs.size(); ++k) {
        if (k > 0) out.push_back('/');
        out.append(segs[k]);
    }
    if (!segs.empty() && (trailing_slash || ended_with_dot)) {
        out.push_back('/');
    }
    return out;
}

[[nodiscard]] String format_origin(const ParsedUrl& u, Allocator* alloc = nullptr) {
    String out(alloc);
    out.reserve(u.scheme.size() + u.host.size() + 16);
    out.append(u.scheme.as_ref());
    out.append("://");
    const bool is_ipv6 = u.host.as_ref().contains(':');
    if (is_ipv6) out.push_back('[');
    out.append(u.host.as_ref());
    if (is_ipv6) out.push_back(']');
    const u16 default_port = u.is_secure ? 443u : 80u;
    if (u.port != default_port) {
        char pbuf[16];
        const usize n = format_u64(pbuf, sizeof(pbuf), as<u64>(u.port));
        out.push_back(':');
        out.append(StringRef(pbuf, n));
    }
    return out;
}

[[nodiscard]] bool same_origin(const ParsedUrl& a, const ParsedUrl& b) noexcept {
    return a.valid && b.valid &&
           a.scheme.as_ref() == b.scheme.as_ref() &&
           a.port == b.port &&
           equals_ignore_case(a.host.as_ref(), b.host.as_ref());
}

[[nodiscard]] bool is_redirect_status(i32 status) noexcept {
    return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
}

[[nodiscard]] bool is_idempotent_method(HttpMethod m) noexcept {
    return m == HttpMethod::Get || m == HttpMethod::Head || m == HttpMethod::Put || m == HttpMethod::Delete;
}

// Civil calendar date (UTC) -> Unix seconds (Howard Hinnant's exact algorithm).
[[nodiscard]] i64 civil_to_unix_s(i32 year, i32 month, i32 day, i32 hour, i32 minute, i32 second) noexcept {
    const i64 y = as<i64>(year) - (month <= 2 ? 1 : 0);
    const i64 era = (y >= 0 ? y : y - 399) / 400;
    const i64 yoe = y - era * 400;
    const i64 m = as<i64>(month);
    const i64 doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + as<i64>(day) - 1;
    const i64 doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const i64 days = era * 146097 + doe - 719468;
    return days * 86400LL + as<i64>(hour) * 3600LL + as<i64>(minute) * 60LL + as<i64>(second);
}

[[nodiscard]] i32 parse_http_month(StringRef mon) noexcept {
    static const char* kMonths[12] = {
        "jan", "feb", "mar", "apr", "may", "jun",
        "jul", "aug", "sep", "oct", "nov", "dec"
    };
    for (i32 i = 0; i < 12; ++i) {
        if (equals_ignore_case(mon, kMonths[i])) return i + 1;
    }
    return 0;
}

// Parses IMF-fixdate / RFC 1123 HTTP date: "Sun, 06 Nov 1994 08:49:37 GMT"
[[nodiscard]] Optional<i64> parse_http_date_unix_s(StringRef date_str) noexcept {
    date_str = trim_ascii(date_str);
    const usize comma = date_str.find(',');
    if (comma != StringRef::npos) {
        date_str = trim_ascii(date_str.substr(comma + 1));
    }
    // Expect: DD Mon YYYY HH:MM:SS GMT (space or '-' separated).
    SmallArray<StringRef, 8> parts;
    usize i = 0;
    while (i < date_str.size()) {
        while (i < date_str.size() && (date_str[i] == ' ' || date_str[i] == '-' || date_str[i] == '\t')) ++i;
        if (i >= date_str.size()) break;
        const usize start = i;
        while (i < date_str.size() && date_str[i] != ' ' && date_str[i] != '-' && date_str[i] != '\t') ++i;
        parts.push_back(date_str.substr(start, i - start));
        if (parts.size() >= 6) break;
    }
    if (parts.size() < 4) return kNullOpt;
    const auto day_r = parse_u64(parts[0]);
    const i32 mon = parse_http_month(parts[1]);
    const auto year_r = parse_u64(parts[2]);
    if (!day_r.is_ok() || mon == 0 || !year_r.is_ok()) return kNullOpt;
    i32 year = as<i32>(year_r.value());
    if (year < 70) year += 2000;
    else if (year < 100) year += 1900;
    const i32 day = as<i32>(day_r.value());
    if (day < 1 || day > 31) return kNullOpt;

    const StringRef hms = parts[3];
    const usize c1 = hms.find(':');
    if (c1 == StringRef::npos) return kNullOpt;
    const usize c2 = hms.find(':', c1 + 1);
    if (c2 == StringRef::npos) return kNullOpt;
    const auto h_r = parse_u64(hms.substr(0, c1));
    const auto m_r = parse_u64(hms.substr(c1 + 1, c2 - (c1 + 1)));
    const auto s_r = parse_u64(hms.substr(c2 + 1));
    if (!h_r.is_ok() || !m_r.is_ok() || !s_r.is_ok()) return kNullOpt;
    if (h_r.value() > 23 || m_r.value() > 59 || s_r.value() > 60) return kNullOpt;

    return civil_to_unix_s(
        year, mon, day,
        as<i32>(h_r.value()),
        as<i32>(m_r.value()),
        as<i32>(keel::min<u64>(s_r.value(), 59u))
    );
}

[[nodiscard]] bool is_ip_literal(StringRef host) noexcept {
    if (host.empty()) return false;
    // IPv6 literal (unbracketed in ParsedUrl::host) always contains ':'.
    if (host.contains(':')) return true;
    // IPv4 literal: 4 dot-separated decimal octets 0..255.
    usize dots = 0;
    usize seg_len = 0;
    u32 val = 0;
    for (usize i = 0; i < host.size(); ++i) {
        const char c = host[i];
        if (c == '.') {
            if (seg_len == 0 || val > 255u) return false;
            ++dots;
            seg_len = 0;
            val = 0;
        } else if (c >= '0' && c <= '9') {
            val = val * 10u + as<u32>(c - '0');
            ++seg_len;
            if (seg_len > 3u || val > 255u) return false;
        } else {
            return false;
        }
    }
    return dots == 3u && seg_len > 0 && val <= 255u;
}

[[nodiscard]] bool domain_matches(StringRef req_host_lower, StringRef cookie_domain_lower, bool host_only) noexcept {
    if (req_host_lower == cookie_domain_lower) return true;
    if (host_only) return false;
    // RFC 6265 §5.1.3: domain-suffix matching does not apply to IP address literals.
    if (is_ip_literal(req_host_lower)) return false;
    if (req_host_lower.size() <= cookie_domain_lower.size()) return false;
    if (!req_host_lower.ends_with(cookie_domain_lower)) return false;
    return req_host_lower[req_host_lower.size() - cookie_domain_lower.size() - 1] == '.';
}

[[nodiscard]] bool path_matches(StringRef req_path, StringRef cookie_path) noexcept {
    if (cookie_path.empty() || cookie_path == "/") return true;
    if (req_path == cookie_path) return true;
    if (!req_path.starts_with(cookie_path)) return false;
    if (cookie_path.back() == '/') return true;
    return req_path[cookie_path.size()] == '/';
}

[[nodiscard]] String default_cookie_path(StringRef path_and_query) {
    const usize qpos = path_and_query.find('?');
    const StringRef path = (qpos == StringRef::npos) ? path_and_query : path_and_query.substr(0, qpos);
    if (path.empty() || path[0] != '/') return String::from("/");
    const usize last_slash = path.rfind('/');
    if (last_slash == StringRef::npos || last_slash == 0) return String::from("/");
    return String::from(path.substr(0, last_slash));
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
        const i32 needed = MultiByteToWideChar(
            CP_UTF8, 0, utf8.data(), as<i32>(utf8.size()), nullptr, 0);
        if (needed <= 0) return;
        if (!chars.empty() && chars.back() == L'\0') {
            chars.pop_back();
        }
        const usize old_len = chars.size();
        chars.resize(old_len + as<usize>(needed) + 1, L'\0');
        MultiByteToWideChar(
            CP_UTF8, 0, utf8.data(), as<i32>(utf8.size()), chars.data() + old_len, needed);
        chars[old_len + as<usize>(needed)] = L'\0';
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
    const i32 needed = WideCharToMultiByte(
        CP_UTF8, 0, wide, as<i32>(wide_len), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return String{};
    Array<char> tmp;
    tmp.resize(as<usize>(needed));
    WideCharToMultiByte(
        CP_UTF8, 0, wide, as<i32>(wide_len), tmp.data(), needed, nullptr, nullptr);
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
// 1. URL Parser, Percent-Encoding, Query Builder & Reference Resolver
// ============================================================================

ParsedUrl parse_url(StringRef url) {
    ParsedUrl result{};
    url = trim_ascii(url);
    if (url.empty()) return result;

    // Reject ASCII control characters (including CR, LF, NUL, TAB) to prevent request-line/header injection.
    for (usize i = 0; i < url.size(); ++i) {
        const u8 b = as<u8>(url[i]);
        if (b < 0x20u || b == 0x7Fu) return result;
    }

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

String url_encode(StringRef input, bool space_as_plus, Allocator* alloc) {
    String out(alloc);
    out.reserve(input.size() + input.size() / 4u);
    for (usize i = 0; i < input.size(); ++i) {
        const u8 b = as<u8>(input[i]);
        if (is_unreserved_uri_char(b)) {
            out.push_back(input[i]);
        } else if (space_as_plus && b == ' ') {
            out.push_back('+');
        } else {
            out.push_back('%');
            out.push_back(kHexUpper[(b >> 4) & 0xFu]);
            out.push_back(kHexUpper[b & 0xFu]);
        }
    }
    return out;
}

Optional<String> url_decode(StringRef input, bool plus_as_space, Allocator* alloc) {
    String out(alloc);
    out.reserve(input.size());
    for (usize i = 0; i < input.size(); ++i) {
        const char c = input[i];
        if (c == '%') {
            if (i + 2u >= input.size()) return kNullOpt;
            const i32 hi = hex_nibble(input[i + 1u]);
            const i32 lo = hex_nibble(input[i + 2u]);
            if (hi < 0 || lo < 0) return kNullOpt;
            out.push_back(as<char>((hi << 4) | lo));
            i += 2u;
        } else if (plus_as_space && c == '+') {
            out.push_back(' ');
        } else {
            out.push_back(c);
        }
    }
    return out;
}

String build_query_string(ArrayRef<HttpQueryParam> params, Allocator* alloc) {
    String out(alloc);
    for (usize i = 0; i < params.size(); ++i) {
        if (i > 0) out.push_back('&');
        out.append(url_encode(params[i].key.as_ref(), true, alloc));
        out.push_back('=');
        out.append(url_encode(params[i].value.as_ref(), true, alloc));
    }
    return out;
}

Array<HttpQueryParam> parse_query_string(StringRef query, Allocator* alloc) {
    Array<HttpQueryParam> out(alloc);
    if (!query.empty() && query[0] == '?') {
        query = query.substr(1);
    }
    const usize hash = query.find('#');
    if (hash != StringRef::npos) {
        query = query.substr(0, hash);
    }
    usize pos = 0;
    while (pos < query.size()) {
        usize amp = query.find('&', pos);
        if (amp == StringRef::npos) amp = query.size();
        const StringRef pair = query.substr(pos, amp - pos);
        pos = (amp < query.size()) ? (amp + 1u) : query.size();
        if (pair.empty()) continue;

        const usize eq = pair.find('=');
        const StringRef raw_k = (eq == StringRef::npos) ? pair : pair.substr(0, eq);
        const StringRef raw_v = (eq == StringRef::npos) ? StringRef{} : pair.substr(eq + 1u);
        auto dec_k = url_decode(raw_k, true, alloc);
        auto dec_v = url_decode(raw_v, true, alloc);
        HttpQueryParam param{};
        param.key = dec_k ? keel::move(*dec_k) : String::from(raw_k, alloc);
        param.value = dec_v ? keel::move(*dec_v) : String::from(raw_v, alloc);
        out.push_back(keel::move(param));
    }
    return out;
}

String resolve_url(StringRef base_url, StringRef location, Allocator* alloc) {
    location = trim_ascii(location);
    const ParsedUrl base = parse_url(base_url);
    if (!base.valid) return String(alloc);
    if (location.empty()) return String::from(trim_ascii(base_url), alloc);

    // Absolute URL with scheme?
    const usize scheme_sep = location.find("://");
    if (scheme_sep != StringRef::npos && scheme_sep > 0 && scheme_sep < 15) {
        bool valid_scheme_chars = true;
        for (usize i = 0; i < scheme_sep; ++i) {
            const char c = location[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '+' || c == '-' || c == '.')) {
                valid_scheme_chars = false;
                break;
            }
        }
        if (valid_scheme_chars) {
            const ParsedUrl abs_parsed = parse_url(location);
            return abs_parsed.valid ? String::from(location, alloc) : String(alloc);
        }
    }

    // Scheme-relative URL: "//host/path"
    if (location.starts_with("//")) {
        String combined(alloc);
        combined.reserve(base.scheme.size() + 1u + location.size());
        combined.append(base.scheme.as_ref());
        combined.push_back(':');
        combined.append(location);
        const ParsedUrl p = parse_url(combined.as_ref());
        return p.valid ? keel::move(combined) : String(alloc);
    }

    const String origin = format_origin(base, alloc);
    const usize base_q = base.path_and_query.as_ref().find('?');
    const StringRef base_path = (base_q == StringRef::npos)
        ? base.path_and_query.as_ref()
        : base.path_and_query.as_ref().substr(0, base_q);

    // Fragment-only reference
    if (location[0] == '#') {
        String out(alloc);
        out.append(origin);
        out.append(base.path_and_query);
        out.append(location);
        return out;
    }

    // Query-only reference
    if (location[0] == '?') {
        String out(alloc);
        out.append(origin);
        out.append(base_path);
        out.append(location);
        return out;
    }

    // Separate location into path + optional ?query + optional #fragment.
    usize tail_pos = StringRef::npos;
    for (usize i = 0; i < location.size(); ++i) {
        if (location[i] == '?' || location[i] == '#') {
            tail_pos = i;
            break;
        }
    }
    const StringRef loc_path = (tail_pos == StringRef::npos) ? location : location.substr(0, tail_pos);
    const StringRef loc_tail = (tail_pos == StringRef::npos) ? StringRef{} : location.substr(tail_pos);

    String merged_path(alloc);
    if (!loc_path.empty() && loc_path[0] == '/') {
        merged_path = normalize_url_path(loc_path, alloc);
    } else {
        const usize last_slash = base_path.rfind('/');
        String raw_merged(alloc);
        if (last_slash == StringRef::npos) {
            raw_merged.push_back('/');
        } else {
            raw_merged.append(base_path.substr(0, last_slash + 1u));
        }
        raw_merged.append(loc_path);
        merged_path = normalize_url_path(raw_merged.as_ref(), alloc);
    }

    String out(alloc);
    out.reserve(origin.size() + merged_path.size() + loc_tail.size());
    out.append(origin);
    out.append(merged_path);
    out.append(loc_tail);
    return out;
}

UrlBuilder::UrlBuilder(StringRef base_url) {
    const usize hash = base_url.find('#');
    if (hash != StringRef::npos) {
        m_fragment = String::from(base_url.substr(hash + 1u));
        base_url = base_url.substr(0, hash);
    }
    const usize q = base_url.find('?');
    if (q != StringRef::npos) {
        m_base = String::from(base_url.substr(0, q));
        Array<HttpQueryParam> existing = parse_query_string(base_url.substr(q + 1u));
        for (usize i = 0; i < existing.size(); ++i) {
            m_params.push_back(keel::move(existing[i]));
        }
    } else {
        m_base = String::from(base_url);
    }
}

UrlBuilder& UrlBuilder::add_query(StringRef key, StringRef value) {
    HttpQueryParam p{};
    p.key = String::from(key);
    p.value = String::from(value);
    m_params.push_back(keel::move(p));
    return *this;
}

UrlBuilder& UrlBuilder::set_fragment(StringRef fragment) {
    m_fragment = String::from(fragment);
    return *this;
}

String UrlBuilder::build(Allocator* alloc) const {
    String out(alloc);
    out.append(m_base);
    if (!m_params.empty()) {
        out.push_back('?');
        out.append(build_query_string(ArrayRef<HttpQueryParam>(m_params), alloc));
    }
    if (!m_fragment.empty()) {
        out.push_back('#');
        out.append(m_fragment);
    }
    return out;
}

// ============================================================================
// 2. Auth Helpers, MultipartFormData & RFC 6265 CookieJar
// ============================================================================

HttpHeader make_bearer_auth_header(StringRef token) {
    HttpHeader h{};
    h.name = String::from("Authorization");
    h.value = String::with_capacity(7u + token.size());
    h.value.append("Bearer ");
    h.value.append(token);
    return h;
}

HttpHeader make_basic_auth_header(StringRef username, StringRef password) {
    String combined = String::with_capacity(username.size() + 1u + password.size());
    combined.append(username);
    combined.push_back(':');
    combined.append(password);
    const String encoded = base64_encode(
        ArrayRef<u8>(reinterpret_cast<const u8*>(combined.data()), combined.size())
    );
    HttpHeader h{};
    h.name = String::from("Authorization");
    h.value = String::with_capacity(6u + encoded.size());
    h.value.append("Basic ");
    h.value.append(encoded);
    return h;
}

MultipartFormData::MultipartFormData() : m_boundary(generate_multipart_boundary()) {}

MultipartFormData::MultipartFormData(StringRef custom_boundary)
    : m_boundary(custom_boundary.empty() ? generate_multipart_boundary() : String::from(custom_boundary)) {}

MultipartFormData& MultipartFormData::add_field(StringRef name, StringRef value) {
    Part part{};
    part.name = sanitize_disposition_param(name);
    part.is_file = false;
    part.data.append(ArrayRef<u8>(reinterpret_cast<const u8*>(value.data()), value.size()));
    m_parts.push_back(keel::move(part));
    return *this;
}

MultipartFormData& MultipartFormData::add_file(
    StringRef name,
    StringRef filename,
    ArrayRef<u8> data,
    StringRef content_type
) {
    Part part{};
    part.name = sanitize_disposition_param(name);
    part.filename = sanitize_disposition_param(filename);
    part.content_type = String::from(
        (content_type.empty() || !is_safe_header_token(content_type))
            ? StringRef("application/octet-stream")
            : content_type
    );
    part.data.append(data);
    part.is_file = true;
    m_parts.push_back(keel::move(part));
    return *this;
}

void MultipartFormData::build(Array<u8>& out_body, String& out_content_type) const {
    out_body.clear();
    out_content_type = String::with_capacity(30u + m_boundary.size());
    out_content_type.append("multipart/form-data; boundary=");
    out_content_type.append(m_boundary);

    auto append_str = [&out_body](StringRef s) {
        if (!s.empty()) {
            out_body.append(ArrayRef<u8>(reinterpret_cast<const u8*>(s.data()), s.size()));
        }
    };

    for (usize i = 0; i < m_parts.size(); ++i) {
        const Part& p = m_parts[i];
        append_str("--");
        append_str(m_boundary.as_ref());
        append_str("\r\nContent-Disposition: form-data; name=\"");
        append_str(p.name.as_ref());
        append_str("\"");
        if (p.is_file) {
            append_str("; filename=\"");
            append_str(p.filename.as_ref());
            append_str("\"\r\nContent-Type: ");
            append_str(p.content_type.as_ref());
        }
        append_str("\r\n\r\n");
        if (!p.data.empty()) {
            out_body.append(ArrayRef<u8>(p.data));
        }
        append_str("\r\n");
    }
    append_str("--");
    append_str(m_boundary.as_ref());
    append_str("--\r\n");
}

struct CookieJar::Impl {
    mutable Mutex mutex{};
    Array<HttpCookie> cookies{};
};

CookieJar::CookieJar() : m_impl(new Impl()) {}
CookieJar::~CookieJar() { delete m_impl; }
CookieJar::CookieJar(CookieJar&& other) noexcept : m_impl(other.m_impl) { other.m_impl = nullptr; }
CookieJar& CookieJar::operator=(CookieJar&& other) noexcept {
    if (this != &other) {
        delete m_impl;
        m_impl = other.m_impl;
        other.m_impl = nullptr;
    }
    return *this;
}

void CookieJar::set_cookie(const HttpCookie& cookie) {
    if (!m_impl || cookie.name.empty()) return;
    HttpCookie norm{};
    norm.name = cookie.name.clone();
    norm.value = cookie.value.clone();
    norm.domain = to_lower_ascii(cookie.domain.as_ref());
    norm.path = cookie.path.empty() ? String::from("/") : cookie.path.clone();
    norm.expires_unix_s = cookie.expires_unix_s;
    norm.has_expiry = cookie.has_expiry;
    norm.secure = cookie.secure;
    norm.http_only = cookie.http_only;
    norm.host_only = cookie.host_only;

    const i64 now = wall_clock_sec();
    const bool expired = norm.has_expiry && norm.expires_unix_s <= now;

    LockGuard<Mutex> lk(m_impl->mutex);
    for (usize i = 0; i < m_impl->cookies.size(); ++i) {
        const HttpCookie& cur = m_impl->cookies[i];
        if (cur.name == norm.name && cur.domain == norm.domain && cur.path == norm.path) {
            if (expired) {
                m_impl->cookies.erase(i);
            } else {
                m_impl->cookies[i] = keel::move(norm);
            }
            return;
        }
    }
    if (!expired) {
        m_impl->cookies.push_back(keel::move(norm));
    }
}

void CookieJar::store_from_headers(StringRef request_url, ArrayRef<HttpHeader> response_headers) {
    if (!m_impl) return;
    const ParsedUrl parsed = parse_url(request_url);
    if (!parsed.valid) return;

    const String req_host_lower = to_lower_ascii(parsed.host.as_ref());
    const String def_path = default_cookie_path(parsed.path_and_query.as_ref());
    const i64 now = wall_clock_sec();

    for (usize h = 0; h < response_headers.size(); ++h) {
        if (!equals_ignore_case(response_headers[h].name.as_ref(), "Set-Cookie")) continue;
        StringRef raw = response_headers[h].value.as_ref();

        usize semi = raw.find(';');
        const StringRef nv = trim_ascii(semi == StringRef::npos ? raw : raw.substr(0, semi));
        const usize eq = nv.find('=');
        if (eq == StringRef::npos || eq == 0) continue;

        HttpCookie c{};
        c.name = String::from(trim_ascii(nv.substr(0, eq)));
        c.value = String::from(trim_ascii(nv.substr(eq + 1u)));
        if (c.name.empty()) continue;
        c.domain = req_host_lower.clone();
        c.path = def_path.clone();
        c.host_only = true;

        bool saw_max_age = false;
        bool domain_rejected = false;

        while (semi != StringRef::npos) {
            raw = raw.substr(semi + 1u);
            semi = raw.find(';');
            const StringRef attr = trim_ascii(semi == StringRef::npos ? raw : raw.substr(0, semi));
            if (attr.empty()) continue;

            const usize aeq = attr.find('=');
            const StringRef aname = trim_ascii(aeq == StringRef::npos ? attr : attr.substr(0, aeq));
            const StringRef aval = (aeq == StringRef::npos) ? StringRef{} : trim_ascii(attr.substr(aeq + 1u));

            if (equals_ignore_case(aname, "Domain")) {
                StringRef dom = aval;
                if (!dom.empty() && dom[0] == '.') dom = dom.substr(1);
                if (!dom.empty()) {
                    const String dom_lower = to_lower_ascii(dom);
                    if (!domain_matches(req_host_lower.as_ref(), dom_lower.as_ref(), false)) {
                        domain_rejected = true;
                        break;
                    }
                    c.domain = dom_lower.clone();
                    c.host_only = false;
                }
            } else if (equals_ignore_case(aname, "Path")) {
                if (!aval.empty() && aval[0] == '/') {
                    c.path = String::from(aval);
                }
            } else if (equals_ignore_case(aname, "Max-Age")) {
                const auto parsed_ma = parse_i64(aval);
                if (parsed_ma.is_ok()) {
                    saw_max_age = true;
                    c.has_expiry = true;
                    c.expires_unix_s = (parsed_ma.value() <= 0) ? 0 : (now + parsed_ma.value());
                }
            } else if (equals_ignore_case(aname, "Expires") && !saw_max_age) {
                auto ts = parse_http_date_unix_s(aval);
                if (ts) {
                    c.has_expiry = true;
                    c.expires_unix_s = *ts;
                }
            } else if (equals_ignore_case(aname, "Secure")) {
                c.secure = true;
            } else if (equals_ignore_case(aname, "HttpOnly")) {
                c.http_only = true;
            }
        }

        if (!domain_rejected) {
            set_cookie(c);
        }
    }
}

String CookieJar::cookie_header_for(StringRef request_url, Allocator* alloc) const {
    if (!m_impl) return String(alloc);
    const ParsedUrl parsed = parse_url(request_url);
    if (!parsed.valid) return String(alloc);

    const String req_host_lower = to_lower_ascii(parsed.host.as_ref());
    const usize qpos = parsed.path_and_query.as_ref().find('?');
    const StringRef req_path = (qpos == StringRef::npos)
        ? parsed.path_and_query.as_ref()
        : parsed.path_and_query.as_ref().substr(0, qpos);
    const i64 now = wall_clock_sec();

    struct Matched {
        usize idx = 0;
        usize path_len = 0;
    };
    SmallArray<Matched, 8> matches;

    LockGuard<Mutex> lk(m_impl->mutex);
    for (usize i = 0; i < m_impl->cookies.size(); ++i) {
        const HttpCookie& c = m_impl->cookies[i];
        if (c.has_expiry && c.expires_unix_s <= now) continue;
        if (c.secure && !parsed.is_secure) continue;
        if (!domain_matches(req_host_lower.as_ref(), c.domain.as_ref(), c.host_only)) continue;
        if (!path_matches(req_path, c.path.as_ref())) continue;
        matches.push_back(Matched{i, c.path.size()});
    }

    // RFC 6265 §5.4: longer paths first.
    keel::sort(matches, [](const Matched& a, const Matched& b) {
        return a.path_len > b.path_len;
    });

    String out(alloc);
    for (usize k = 0; k < matches.size(); ++k) {
        if (k > 0) out.append("; ");
        const HttpCookie& c = m_impl->cookies[matches[k].idx];
        out.append(c.name);
        out.push_back('=');
        out.append(c.value);
    }
    return out;
}

usize CookieJar::size() const noexcept {
    if (!m_impl) return 0;
    LockGuard<Mutex> lk(m_impl->mutex);
    return m_impl->cookies.size();
}

void CookieJar::clear() noexcept {
    if (!m_impl) return;
    LockGuard<Mutex> lk(m_impl->mutex);
    m_impl->cookies.clear();
}

// ============================================================================
// 3. HttpResponse & HttpClient Implementation
// ============================================================================

StringRef HttpResponse::get_header(StringRef name) const noexcept {
    for (usize i = 0; i < headers.size(); ++i) {
        if (equals_ignore_case(headers[i].name.as_ref(), name)) {
            return headers[i].value.as_ref();
        }
    }
    return {};
}

SmallArray<StringRef, 4> HttpResponse::get_headers(StringRef name) const {
    SmallArray<StringRef, 4> out;
    for (usize i = 0; i < headers.size(); ++i) {
        if (equals_ignore_case(headers[i].name.as_ref(), name)) {
            out.push_back(headers[i].value.as_ref());
        }
    }
    return out;
}

struct HttpClient::Impl {
    String default_user_agent{};
    CookieJar* default_cookie_jar = nullptr;

#if defined(_WIN32)
    ScopedWinHttpHandle session{};

    explicit Impl(StringRef ua) : default_user_agent(String::from(ua.empty() ? StringRef("keel-http/0.2") : ua)) {
        const WideBuffer w_ua = utf8_to_wide(default_user_agent.as_ref());
        HINTERNET raw_session = nullptr;
#ifdef WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
        raw_session = WinHttpOpen(
            w_ua.empty() ? L"keel-http/0.2" : w_ua.c_str(),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );
#endif
        if (!raw_session) {
            raw_session = WinHttpOpen(
                w_ua.empty() ? L"keel-http/0.2" : w_ua.c_str(),
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
    mutable Mutex pool_mutex{};
    mutable SmallArray<CURL*, 16> handle_pool{};

    explicit Impl(StringRef ua) : default_user_agent(String::from(ua.empty() ? StringRef("keel-http/0.2") : ua)) {
        static OnceFlag s_curl_init_flag;
        call_once(s_curl_init_flag, []() {
            curl_global_init(CURL_GLOBAL_DEFAULT);
        });
    }

    ~Impl() {
        LockGuard<Mutex> lk(pool_mutex);
        for (usize i = 0; i < handle_pool.size(); ++i) {
            if (handle_pool[i]) curl_easy_cleanup(handle_pool[i]);
        }
        handle_pool.clear();
    }

    [[nodiscard]] CURL* acquire_handle() const {
        {
            LockGuard<Mutex> lk(pool_mutex);
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
        LockGuard<Mutex> lk(pool_mutex);
        if (handle_pool.size() < 16) {
            handle_pool.push_back(h);
        } else {
            curl_easy_cleanup(h);
        }
    }
#else
    explicit Impl(StringRef ua) : default_user_agent(String::from(ua.empty() ? StringRef("keel-http/0.2") : ua)) {}
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

void HttpClient::set_cookie_jar(CookieJar* jar) noexcept {
    if (m_impl) m_impl->default_cookie_jar = jar;
}

CookieJar* HttpClient::cookie_jar() const noexcept {
    return m_impl ? m_impl->default_cookie_jar : nullptr;
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

namespace {

HttpRequest make_verb_request(
    HttpMethod method,
    StringRef url,
    ArrayRef<u8> body,
    StringRef content_type,
    ArrayRef<HttpHeader> headers,
    StringRef default_ua,
    u32 timeout_ms
) {
    HttpRequest req{};
    req.url = String::from(url);
    req.method = method;
    if (!body.empty()) {
        req.body.append(body);
    }
    bool has_ct = false;
    for (usize i = 0; i < headers.size(); ++i) {
        if (equals_ignore_case(headers[i].name.as_ref(), "Content-Type")) {
            has_ct = true;
        }
        req.headers.push_back(HttpHeader{
            .name = headers[i].name.clone(),
            .value = headers[i].value.clone()
        });
    }
    if (!content_type.empty() && !has_ct) {
        req.headers.push_back(HttpHeader{
            .name = String::from("Content-Type"),
            .value = String::from(content_type)
        });
    }
    if (!default_ua.empty()) {
        req.user_agent = String::from(default_ua);
    }
    req.connect_timeout_ms = timeout_ms;
    req.read_timeout_ms = timeout_ms;
    return req;
}

struct HopResult {
    HttpResponse response{};
    bool network_error = false;
    bool aborted = false;
    bool overflow = false;
};

[[nodiscard]] bool should_retry_hop(
    const HttpRetryPolicy& policy,
    HttpMethod method,
    const HopResult& hop,
    u32 retries_done
) noexcept {
    if (retries_done >= policy.max_retries) return false;
    if (hop.aborted || hop.overflow) return false;
    if (!policy.retry_non_idempotent && !is_idempotent_method(method)) return false;
    if (hop.network_error) return policy.retry_on_network_error;
    const i32 s = hop.response.status_code;
    if (s == 429) return policy.retry_on_429;
    if (s == 500 || s == 502 || s == 503 || s == 504) return policy.retry_on_5xx;
    return false;
}

[[nodiscard]] u32 compute_retry_delay_ms(
    const HttpRetryPolicy& policy,
    const HttpResponse& resp,
    u32 retry_index
) noexcept {
    const u32 cap = keel::max<u32>(1u, policy.max_delay_ms);
    const StringRef ra = trim_ascii(resp.get_header("Retry-After"));
    if (!ra.empty()) {
        const auto secs = parse_u64(ra);
        if (secs.is_ok()) {
            const u64 ms = secs.value() * 1000ULL;
            return as<u32>(keel::min<u64>(ms, as<u64>(cap)));
        }
    }
    const u32 shift = keel::min<u32>(retry_index, 16u);
    u64 base = as<u64>(policy.initial_delay_ms) << shift;
    if (base > as<u64>(cap)) base = as<u64>(cap);
    const auto jitter_r = os_random_u32();
    const u64 jitter = (jitter_r.is_ok() && base >= 4ULL) ? (as<u64>(jitter_r.value()) % (base / 4ULL + 1ULL)) : 0ULL;
    return as<u32>(keel::min<u64>(base + jitter, as<u64>(cap)));
}

} // namespace

HttpResponse HttpClient::get(StringRef url, ArrayRef<HttpHeader> headers, u32 timeout_ms) const {
    const StringRef ua = m_impl ? m_impl->default_user_agent.as_ref() : StringRef{};
    return execute(make_verb_request(HttpMethod::Get, url, {}, {}, headers, ua, timeout_ms));
}

HttpResponse HttpClient::head(StringRef url, ArrayRef<HttpHeader> headers, u32 timeout_ms) const {
    const StringRef ua = m_impl ? m_impl->default_user_agent.as_ref() : StringRef{};
    return execute(make_verb_request(HttpMethod::Head, url, {}, {}, headers, ua, timeout_ms));
}

HttpResponse HttpClient::post(
    StringRef url,
    ArrayRef<u8> body,
    StringRef content_type,
    ArrayRef<HttpHeader> headers,
    u32 timeout_ms
) const {
    const StringRef ua = m_impl ? m_impl->default_user_agent.as_ref() : StringRef{};
    return execute(make_verb_request(HttpMethod::Post, url, body, content_type, headers, ua, timeout_ms));
}

HttpResponse HttpClient::put(
    StringRef url,
    ArrayRef<u8> body,
    StringRef content_type,
    ArrayRef<HttpHeader> headers,
    u32 timeout_ms
) const {
    const StringRef ua = m_impl ? m_impl->default_user_agent.as_ref() : StringRef{};
    return execute(make_verb_request(HttpMethod::Put, url, body, content_type, headers, ua, timeout_ms));
}

HttpResponse HttpClient::patch(
    StringRef url,
    ArrayRef<u8> body,
    StringRef content_type,
    ArrayRef<HttpHeader> headers,
    u32 timeout_ms
) const {
    const StringRef ua = m_impl ? m_impl->default_user_agent.as_ref() : StringRef{};
    return execute(make_verb_request(HttpMethod::Patch, url, body, content_type, headers, ua, timeout_ms));
}

HttpResponse HttpClient::del(StringRef url, ArrayRef<HttpHeader> headers, u32 timeout_ms) const {
    const StringRef ua = m_impl ? m_impl->default_user_agent.as_ref() : StringRef{};
    return execute(make_verb_request(HttpMethod::Delete, url, {}, {}, headers, ua, timeout_ms));
}

HttpResponse HttpClient::post_form(
    StringRef url,
    ArrayRef<HttpQueryParam> fields,
    ArrayRef<HttpHeader> headers,
    u32 timeout_ms
) const {
    const String encoded = build_query_string(fields);
    const ArrayRef<u8> body(reinterpret_cast<const u8*>(encoded.data()), encoded.size());
    return post(url, body, "application/x-www-form-urlencoded", headers, timeout_ms);
}

HttpResponse HttpClient::post_multipart(
    StringRef url,
    const MultipartFormData& form,
    ArrayRef<HttpHeader> headers,
    u32 timeout_ms
) const {
    Array<u8> body;
    String content_type;
    form.build(body, content_type);
    return post(url, ArrayRef<u8>(body), content_type.as_ref(), headers, timeout_ms);
}

HttpResponse HttpClient::download_to_file(
    StringRef url,
    StringRef dest_path,
    ArrayRef<HttpHeader> headers,
    u32 timeout_ms
) const {
    const StringRef ua = m_impl ? m_impl->default_user_agent.as_ref() : StringRef{};
    HttpRequest req = make_verb_request(HttpMethod::Get, url, {}, {}, headers, ua, timeout_ms);
    req.max_response_bytes = Limits<usize>::kMax;

    auto opened = File::open(dest_path, FileMode::Write);
    if (opened.is_err()) {
        HttpResponse resp{};
        resp.error_message = String::from("Failed to open destination file for writing");
        return resp;
    }
    File file = keel::move(opened.value());

    bool write_failed = false;
    HttpResponse resp = execute_streaming(req, [&](ArrayRef<u8> chunk) -> bool {
        file.write(chunk);
        if (file.sticky_error().is_err()) {
            write_failed = true;
            return false;
        }
        return true;
    });

    const Error close_err = file.close();
    if (write_failed || close_err.is_err()) {
        if (resp.error_message.empty()) {
            resp.error_message = String::from("Failed while writing downloaded data to disk");
        }
        (void)fs_remove(dest_path);
        return resp;
    }
    if (!resp.succeeded()) {
        (void)fs_remove(dest_path);
    }
    return resp;
}

HttpResponse HttpClient::execute(const HttpRequest& request) const {
    auto noop_chunk = [](ArrayRef<u8>) -> bool { return true; };
    return execute_internal(request, noop_chunk, false);
}

HttpResponse HttpClient::execute_streaming(
    const HttpRequest& request,
    FunctionRef<bool(ArrayRef<u8>)> on_chunk
) const {
    return execute_internal(request, on_chunk, true);
}

HttpResponse HttpClient::execute_internal(
    const HttpRequest& request,
    FunctionRef<bool(ArrayRef<u8>)> on_chunk,
    bool streaming
) const {
    const u64 t0_ns = monotonic_ns();

    const ParsedUrl initial_parsed = parse_url(request.url.as_ref());
    if (!initial_parsed.valid || initial_parsed.is_websocket) {
        HttpResponse invalid{};
        invalid.error_message = String::from("Invalid HTTP/HTTPS URL");
        return invalid;
    }

    CookieJar* active_jar = request.cookie_jar ? request.cookie_jar : (m_impl ? m_impl->default_cookie_jar : nullptr);

    auto run_single_hop = [&](
        const ParsedUrl& parsed,
        StringRef url_str,
        HttpMethod method,
        const SmallArray<HttpHeader, 8>& headers,
        ArrayRef<u8> body,
        bool allow_stream_body,
        bool suppress_body_on_redirect_or_retry,
        u32 retries_done,
        u32 redirects_done
    ) -> HopResult {
        HopResult hop{};
        HttpResponse& response = hop.response;
        response.final_url = String::from(url_str);

        auto will_skip_body = [&](i32 status, const SmallArray<HttpHeader, 8>& resp_hdrs) -> bool {
            if (!suppress_body_on_redirect_or_retry) return false;
            if (request.follow_redirects && is_redirect_status(status) && redirects_done < request.max_redirects) {
                for (usize i = 0; i < resp_hdrs.size(); ++i) {
                    if (equals_ignore_case(resp_hdrs[i].name.as_ref(), "Location") && !resp_hdrs[i].value.empty()) {
                        return true;
                    }
                }
            }
            if (retries_done < request.retry.max_retries &&
                (request.retry.retry_non_idempotent || is_idempotent_method(method))) {
                if (status == 429 && request.retry.retry_on_429) return true;
                if ((status == 500 || status == 502 || status == 503 || status == 504) && request.retry.retry_on_5xx) {
                    return true;
                }
            }
            return false;
        };

#if defined(_WIN32)
        if (!m_impl || !m_impl->session) {
            response.error_message = String::from("WinHTTP session not initialized");
            return hop;
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
            hop.network_error = true;
            return hop;
        }

        const WideBuffer w_path = utf8_to_wide(parsed.path_and_query.as_ref());
        const DWORD request_flags = parsed.is_secure ? WINHTTP_FLAG_SECURE : 0;
        ScopedWinHttpHandle h_request(WinHttpOpenRequest(
            h_connect.get(),
            http_method_to_wide_cstr(method),
            w_path.c_str(),
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            request_flags
        ));
        if (!h_request) {
            response.error_message = format_winhttp_error("WinHttpOpenRequest failed", GetLastError());
            hop.network_error = true;
            return hop;
        }

        // WinHTTP silently treats receive timeouts below 500 ms as infinite (0 ms) on Windows,
        // and overriding WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT after WinHttpSetTimeouts
        // suppresses the request receive timeout on Windows 11. Use WinHttpSetTimeouts alone.
        const u32 max_t = as<u32>(Limits<i32>::kMax);
        const i32 conn_timeout = as<i32>(keel::min<u32>(keel::max<u32>(500u, request.connect_timeout_ms), max_t));
        const i32 io_timeout = as<i32>(keel::min<u32>(keel::max<u32>(500u, request.read_timeout_ms), max_t));
        WinHttpSetTimeouts(h_request.get(), conn_timeout, conn_timeout, io_timeout, io_timeout);

        // Redirects and cookies are managed explicitly across hops for consistent RFC behavior.
        DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        WinHttpSetOption(h_request.get(), WINHTTP_OPTION_REDIRECT_POLICY, &redirect_policy, sizeof(redirect_policy));
        DWORD disable_cookies = WINHTTP_DISABLE_COOKIES;
        WinHttpSetOption(h_request.get(), WINHTTP_OPTION_DISABLE_FEATURE, &disable_cookies, sizeof(disable_cookies));

        if (parsed.is_secure && !request.verify_tls_peer) {
            DWORD sec_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                              SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                              SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                              SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
            WinHttpSetOption(h_request.get(), WINHTTP_OPTION_SECURITY_FLAGS, &sec_flags, sizeof(sec_flags));
        }

        WideBuffer extra_headers;
        bool caller_has_ua = false;
        for (usize i = 0; i < headers.size(); ++i) {
            if (equals_ignore_case(headers[i].name.as_ref(), "User-Agent")) {
                caller_has_ua = true;
                break;
            }
        }
        if (!caller_has_ua) {
            const StringRef effective_ua = request.user_agent.empty()
                ? m_impl->default_user_agent.as_ref()
                : request.user_agent.as_ref();
            if (!effective_ua.empty() && is_safe_header_token(effective_ua)) {
                extra_headers.append_literal(L"User-Agent: ");
                extra_headers.append_utf8(effective_ua);
                extra_headers.append_literal(L"\r\n");
            }
        }
        for (usize i = 0; i < headers.size(); ++i) {
            const auto& hdr = headers[i];
            if (!hdr.name.empty() && is_safe_header_token(hdr.name.as_ref()) && is_safe_header_token(hdr.value.as_ref())) {
                extra_headers.append_utf8(hdr.name.as_ref());
                extra_headers.append_literal(L": ");
                extra_headers.append_utf8(hdr.value.as_ref());
                extra_headers.append_literal(L"\r\n");
            }
        }

        LPVOID body_ptr = body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<u8*>(body.data());
        const DWORD body_len = static_cast<DWORD>(body.size());

        if (!WinHttpSendRequest(
                h_request.get(),
                extra_headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : extra_headers.c_str(),
                extra_headers.empty() ? 0 : static_cast<DWORD>(extra_headers.length()),
                body_ptr,
                body_len,
                body_len,
                0)) {
            response.error_message = format_winhttp_error("WinHttpSendRequest failed", GetLastError());
            hop.network_error = true;
            return hop;
        }

        if (!WinHttpReceiveResponse(h_request.get(), nullptr)) {
            response.error_message = format_winhttp_error("WinHttpReceiveResponse failed", GetLastError());
            hop.network_error = true;
            return hop;
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

        if (method != HttpMethod::Head && !will_skip_body(response.status_code, response.headers)) {
            u8 stack_buf[16384];
            for (;;) {
                DWORD dw_size = 0;
                if (!WinHttpQueryDataAvailable(h_request.get(), &dw_size)) {
                    response.error_message = format_winhttp_error("WinHttpQueryDataAvailable failed", GetLastError());
                    response.body.clear();
                    hop.network_error = true;
                    break;
                }
                if (dw_size == 0) break;

                DWORD remaining = dw_size;
                bool stop = false;
                while (remaining > 0) {
                    const DWORD to_read = remaining < sizeof(stack_buf) ? remaining : static_cast<DWORD>(sizeof(stack_buf));
                    DWORD dw_downloaded = 0;
                    if (!WinHttpReadData(h_request.get(), stack_buf, to_read, &dw_downloaded)) {
                        response.error_message = format_winhttp_error("WinHttpReadData failed", GetLastError());
                        response.body.clear();
                        hop.network_error = true;
                        stop = true;
                        break;
                    }
                    if (dw_downloaded == 0) {
                        stop = true;
                        break;
                    }
                    if (dw_downloaded > request.max_response_bytes ||
                        response.bytes_received > request.max_response_bytes - static_cast<usize>(dw_downloaded)) {
                        response.error_message = String::from("Response exceeded max_response_bytes limit");
                        response.body.clear();
                        hop.overflow = true;
                        stop = true;
                        break;
                    }
                    response.bytes_received += static_cast<usize>(dw_downloaded);
                    if (allow_stream_body) {
                        if (!on_chunk(ArrayRef<u8>(stack_buf, static_cast<usize>(dw_downloaded)))) {
                            response.error_message = String::from("Aborted by response chunk callback");
                            hop.aborted = true;
                            stop = true;
                            break;
                        }
                    } else {
                        response.body.append(ArrayRef<u8>(stack_buf, static_cast<usize>(dw_downloaded)));
                    }
                    remaining -= dw_downloaded;
                }
                if (stop) break;
            }
        }

#elif defined(__EMSCRIPTEN__)
        (void)parsed;
        (void)will_skip_body;
        emscripten_fetch_attr_t attr;
        emscripten_fetch_attr_init(&attr);
        const StringRef m_str = http_method_to_cstr(method);
        const usize m_len = keel::min<usize>(m_str.size(), sizeof(attr.requestMethod) - 1u);
        mem_copy(attr.requestMethod, m_str.data(), m_len);
        attr.requestMethod[m_len] = '\0';
        attr.attributes = EMSCRIPTEN_FETCH_LOAD_TO_MEMORY | EMSCRIPTEN_FETCH_SYNCHRONOUS;
        attr.timeoutMSecs = keel::max<u32>(request.connect_timeout_ms, request.read_timeout_ms);

        SmallArray<const char*, 18> header_kvs;
        for (usize i = 0; i < headers.size(); ++i) {
            const auto& h = headers[i];
            if (!h.name.empty() && is_safe_header_token(h.name.as_ref()) && is_safe_header_token(h.value.as_ref())) {
                header_kvs.push_back(h.name.c_str());
                header_kvs.push_back(h.value.c_str());
            }
        }
        header_kvs.push_back(nullptr);
        if (header_kvs.size() > 1) {
            attr.requestHeaders = header_kvs.data();
        }

        if (!body.empty()) {
            attr.requestData = reinterpret_cast<const char*>(body.data());
            attr.requestDataSize = body.size();
        }

        const String url_copy = String::from(url_str);
        emscripten_fetch_t* fetch = emscripten_fetch(&attr, url_copy.c_str());
        if (!fetch) {
            response.error_message = String::from("emscripten_fetch failed to initialize");
            hop.network_error = true;
            return hop;
        }

        response.status_code = static_cast<i32>(fetch->status);
        if (fetch->data && fetch->numBytes > 0) {
            const usize nbytes = static_cast<usize>(fetch->numBytes);
            if (nbytes <= request.max_response_bytes) {
                response.bytes_received = nbytes;
                const auto* bytes = reinterpret_cast<const u8*>(fetch->data);
                if (allow_stream_body) {
                    if (!on_chunk(ArrayRef<u8>(bytes, nbytes))) {
                        response.error_message = String::from("Aborted by response chunk callback");
                        hop.aborted = true;
                    }
                } else {
                    response.body.append(ArrayRef<u8>(bytes, nbytes));
                }
            } else {
                response.error_message = String::from("Response exceeded max_response_bytes limit");
                hop.overflow = true;
            }
        }
        emscripten_fetch_close(fetch);

#elif defined(KEEL_HTTP_HAS_CURL)
        (void)parsed;
        if (!m_impl) {
            response.error_message = String::from("HttpClient not initialized");
            return hop;
        }

        CURL* curl = m_impl->acquire_handle();
        if (!curl) {
            response.error_message = String::from("curl_easy_init failed");
            hop.network_error = true;
            return hop;
        }

        struct WriteContext {
            HttpResponse* resp = nullptr;
            FunctionRef<bool(ArrayRef<u8>)>* cb = nullptr;
            usize max_bytes = 0;
            bool allow_stream = false;
            bool skip_body = false;
            bool decided_skip = false;
            bool overflow = false;
            bool aborted = false;
            CURL* curl_handle = nullptr;
            bool follow_redirects = false;
            u32 redirects_done = 0;
            u32 max_redirects = 0;
            u32 retries_done = 0;
            HttpRetryPolicy retry{};
            HttpMethod method = HttpMethod::Get;
        } write_ctx{};
        write_ctx.resp = &response;
        write_ctx.cb = &on_chunk;
        write_ctx.max_bytes = request.max_response_bytes;
        write_ctx.allow_stream = allow_stream_body;
        write_ctx.curl_handle = curl;
        write_ctx.follow_redirects = request.follow_redirects && suppress_body_on_redirect_or_retry;
        write_ctx.redirects_done = redirects_done;
        write_ctx.max_redirects = request.max_redirects;
        write_ctx.retries_done = retries_done;
        write_ctx.retry = request.retry;
        write_ctx.method = method;

        auto write_cb = +[](char* ptr, usize size, usize nmemb, void* userdata) -> usize {
            auto* ctx = static_cast<WriteContext*>(userdata);
            const usize total = size * nmemb;
            if (!ctx || !ctx->resp) return 0;
            if (!ctx->decided_skip) {
                ctx->decided_skip = true;
                long code = 0; // keel-lint: ignore
                curl_easy_getinfo(ctx->curl_handle, CURLINFO_RESPONSE_CODE, &code);
                const i32 status = static_cast<i32>(code);
                if (ctx->follow_redirects && is_redirect_status(status) && ctx->redirects_done < ctx->max_redirects) {
                    if (!ctx->resp->get_header("Location").empty()) {
                        ctx->skip_body = true;
                    }
                }
                if (!ctx->skip_body && ctx->retries_done < ctx->retry.max_retries &&
                    (ctx->retry.retry_non_idempotent || is_idempotent_method(ctx->method))) {
                    if ((status == 429 && ctx->retry.retry_on_429) ||
                        ((status == 500 || status == 502 || status == 503 || status == 504) && ctx->retry.retry_on_5xx)) {
                        ctx->skip_body = true;
                    }
                }
            }
            if (ctx->skip_body) return total;
            if (total > ctx->max_bytes || ctx->resp->bytes_received > ctx->max_bytes - total) {
                ctx->overflow = true;
                return 0;
            }
            ctx->resp->bytes_received += total;
            const ArrayRef<u8> chunk(reinterpret_cast<const u8*>(ptr), total);
            if (ctx->allow_stream) {
                if (!(*ctx->cb)(chunk)) {
                    ctx->aborted = true;
                    return 0;
                }
            } else {
                ctx->resp->body.append(chunk);
            }
            return total;
        };

        auto header_cb = +[](char* buffer, usize size, usize nitems, void* userdata) -> usize {
            auto* resp = static_cast<HttpResponse*>(userdata);
            const usize total = size * nitems;
            if (!resp || total == 0) return total;
            StringRef line(buffer, total);
            line = trim_ascii(line);
            if (line.size() >= 5 && equals_ignore_case(line.substr(0, 5), "HTTP/")) {
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

        const String url_copy = String::from(url_str);
        curl_easy_setopt(curl, CURLOPT_URL, url_copy.c_str());
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
        const u64 conn_ms = keel::max<u64>(100ULL, as<u64>(request.connect_timeout_ms));
        const u64 total_ms = keel::min<u64>(
            as<u64>(Limits<i32>::kMax),
            keel::max<u64>(100ULL, as<u64>(request.connect_timeout_ms) + as<u64>(request.read_timeout_ms))
        );
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(keel::min<u64>(conn_ms, as<u64>(Limits<i32>::kMax)))); // keel-lint: ignore
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(total_ms)); // keel-lint: ignore
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, request.verify_tls_peer ? 1L : 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, request.verify_tls_peer ? 2L : 0L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_ctx);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response);

        const StringRef effective_ua = request.user_agent.empty()
            ? m_impl->default_user_agent.as_ref()
            : request.user_agent.as_ref();
        String ua_str;
        if (!effective_ua.empty() && is_safe_header_token(effective_ua)) {
            ua_str = String::from(effective_ua);
            curl_easy_setopt(curl, CURLOPT_USERAGENT, ua_str.c_str());
        }

        if (method == HttpMethod::Head) {
            curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        } else if (method == HttpMethod::Post) {
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.empty() ? "" : reinterpret_cast<const char*>(body.data()));
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size())); // keel-lint: ignore
        } else if (method != HttpMethod::Get) {
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, http_method_to_cstr(method));
            if (!body.empty()) {
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, reinterpret_cast<const char*>(body.data()));
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size())); // keel-lint: ignore
            }
        }

        struct curl_slist* header_list = nullptr;
        for (usize i = 0; i < headers.size(); ++i) {
            const auto& h = headers[i];
            if (!h.name.empty() && is_safe_header_token(h.name.as_ref()) && is_safe_header_token(h.value.as_ref())) {
                String combined = String::with_capacity(h.name.size() + 2u + h.value.size());
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
            long http_code = 0; // keel-lint: ignore
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            response.status_code = static_cast<i32>(http_code);
        } else if (write_ctx.overflow) {
            response.body.clear();
            response.error_message = String::from("Response exceeded max_response_bytes limit");
            hop.overflow = true;
        } else if (write_ctx.aborted) {
            response.error_message = String::from("Aborted by response chunk callback");
            hop.aborted = true;
        } else {
            response.error_message = String::from(curl_easy_strerror(res));
            hop.network_error = true;
        }

        if (header_list) {
            curl_slist_free_all(header_list);
        }
        m_impl->release_handle(curl);
        (void)will_skip_body;
#else
        (void)parsed;
        (void)method;
        (void)headers;
        (void)body;
        (void)allow_stream_body;
        (void)will_skip_body;
        response.error_message = String::from("No HTTP backend compiled for this platform");
#endif
        return hop;
    };

    HttpResponse final_response{};
    u32 attempts = 0;

    for (u32 retry_idx = 0; ; ++retry_idx) {
        ++attempts;

        String cur_url = request.url.clone();
        ParsedUrl cur_parsed = parse_url(cur_url.as_ref());
        HttpMethod cur_method = request.method;
        SmallArray<HttpHeader, 8> cur_headers;
        for (usize i = 0; i < request.headers.size(); ++i) {
            cur_headers.push_back(HttpHeader{
                .name = request.headers[i].name.clone(),
                .value = request.headers[i].value.clone()
            });
        }
        Array<u8> cur_body;
        cur_body.append(ArrayRef<u8>(request.body));

        u32 redirects = 0;
        HopResult hop{};

        for (;;) {
            // Attach CookieJar header unless caller already provided explicit Cookie header.
            SmallArray<HttpHeader, 8> hop_headers;
            bool has_cookie_hdr = false;
            for (usize i = 0; i < cur_headers.size(); ++i) {
                if (equals_ignore_case(cur_headers[i].name.as_ref(), "Cookie")) {
                    has_cookie_hdr = true;
                }
                hop_headers.push_back(HttpHeader{
                    .name = cur_headers[i].name.clone(),
                    .value = cur_headers[i].value.clone()
                });
            }
            if (active_jar && !has_cookie_hdr) {
                String cookie_val = active_jar->cookie_header_for(cur_url.as_ref());
                if (!cookie_val.empty()) {
                    hop_headers.push_back(HttpHeader{
                        .name = String::from("Cookie"),
                        .value = keel::move(cookie_val)
                    });
                }
            }

            hop = run_single_hop(
                cur_parsed,
                cur_url.as_ref(),
                cur_method,
                hop_headers,
                ArrayRef<u8>(cur_body),
                streaming,
                true,
                retry_idx,
                redirects
            );

            if (active_jar && !hop.response.headers.empty()) {
                active_jar->store_from_headers(cur_url.as_ref(), ArrayRef<HttpHeader>(hop.response.headers));
            }

            if (request.follow_redirects && hop.response.error_message.empty() &&
                is_redirect_status(hop.response.status_code)) {
                const StringRef location = trim_ascii(hop.response.get_header("Location"));
                if (!location.empty()) {
                    if (redirects >= request.max_redirects) {
                        hop.response.error_message = String::from("Too many redirects");
                        break;
                    }
                    String next_url = resolve_url(cur_url.as_ref(), location);
                    ParsedUrl next_parsed = parse_url(next_url.as_ref());
                    if (!next_parsed.valid || next_parsed.is_websocket) {
                        hop.response.error_message = String::from("Invalid redirect Location URL");
                        break;
                    }

                    // Cross-origin redirect: strip sensitive credentials.
                    if (!same_origin(cur_parsed, next_parsed)) {
                        SmallArray<HttpHeader, 8> filtered;
                        for (usize i = 0; i < cur_headers.size(); ++i) {
                            const StringRef n = cur_headers[i].name.as_ref();
                            if (equals_ignore_case(n, "Authorization") ||
                                equals_ignore_case(n, "Proxy-Authorization") ||
                                equals_ignore_case(n, "Cookie")) {
                                continue;
                            }
                            filtered.push_back(keel::move(cur_headers[i]));
                        }
                        cur_headers = keel::move(filtered);
                    }

                    // RFC 9110 method rewriting on 301/302/303.
                    const i32 st = hop.response.status_code;
                    const bool downgrade_to_get =
                        (st == 303 && cur_method != HttpMethod::Get && cur_method != HttpMethod::Head) ||
                        ((st == 301 || st == 302) && cur_method == HttpMethod::Post);
                    if (downgrade_to_get) {
                        cur_method = HttpMethod::Get;
                        cur_body.clear();
                        SmallArray<HttpHeader, 8> filtered;
                        for (usize i = 0; i < cur_headers.size(); ++i) {
                            const StringRef n = cur_headers[i].name.as_ref();
                            if (equals_ignore_case(n, "Content-Type") ||
                                equals_ignore_case(n, "Content-Length")) {
                                continue;
                            }
                            filtered.push_back(keel::move(cur_headers[i]));
                        }
                        cur_headers = keel::move(filtered);
                    }

                    cur_url = keel::move(next_url);
                    cur_parsed = keel::move(next_parsed);
                    ++redirects;
                    continue;
                }
            }
            break;
        }

        hop.response.redirect_count = redirects;
        hop.response.attempts = attempts;

        if (should_retry_hop(request.retry, request.method, hop, retry_idx)) {
            const u32 delay_ms = compute_retry_delay_ms(request.retry, hop.response, retry_idx);
            if (delay_ms > 0u) {
                sleep_ms(as<u64>(delay_ms));
            }
            continue;
        }

        final_response = keel::move(hop.response);
        break;
    }

    const u64 t1_ns = monotonic_ns();
    final_response.elapsed_ms = as<f64>(t1_ns - t0_ns) * 1e-6;
    return final_response;
}

// ============================================================================
// 4. WebSocketClient Implementation
// ============================================================================

struct WebSocketClient::Impl {
    mutable Mutex mutex{};
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
    LockGuard<Mutex> lk(m_impl->mutex);
    return m_impl->state;
}

String WebSocketClient::last_error() const {
    if (!m_impl) return String{};
    LockGuard<Mutex> lk(m_impl->mutex);
    return m_impl->last_error.clone();
}

bool WebSocketClient::connect(StringRef url, const WebSocketConnectOptions& options) {
    if (!m_impl) return false;
    close();

    const ParsedUrl parsed = parse_url(url);
    if (!parsed.valid || !parsed.is_websocket) {
        LockGuard<Mutex> lk(m_impl->mutex);
        m_impl->state = WebSocketState::Error;
        m_impl->last_error = String::from("Invalid WebSocket URL (expected ws:// or wss://)");
        return false;
    }

    {
        LockGuard<Mutex> lk(m_impl->mutex);
        m_impl->state = WebSocketState::Connecting;
        m_impl->last_error.clear();
        m_impl->max_message_bytes = options.max_message_bytes;
    }

#if defined(_WIN32)
    const WideBuffer w_ua = utf8_to_wide(options.user_agent.empty() ? StringRef("keel-http/0.2") : options.user_agent.as_ref());
    ScopedWinHttpHandle h_session(WinHttpOpen(
        w_ua.c_str(),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    ));
    if (!h_session) {
        const DWORD err = ::GetLastError();
        LockGuard<Mutex> lk(m_impl->mutex);
        m_impl->state = WebSocketState::Error;
        m_impl->last_error = format_winhttp_error("WinHttpOpen failed for WebSocket", err);
        return false;
    }

    const i32 timeout_ms = as<i32>(keel::max<u32>(500u, options.connect_timeout_ms));
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
        LockGuard<Mutex> lk(m_impl->mutex);
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
        LockGuard<Mutex> lk(m_impl->mutex);
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
        LockGuard<Mutex> lk(m_impl->mutex);
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
        LockGuard<Mutex> lk(m_impl->mutex);
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
        LockGuard<Mutex> lk(m_impl->mutex);
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
        LockGuard<Mutex> lk(m_impl->mutex);
        m_impl->state = WebSocketState::Error;
        m_impl->last_error = format_winhttp_error("WinHttpWebSocketCompleteUpgrade failed", err);
        return false;
    }

    {
        LockGuard<Mutex> lk(m_impl->mutex);
        m_impl->h_session = keel::move(h_session);
        m_impl->h_connect = keel::move(h_connect);
        m_impl->h_websocket = keel::move(h_websocket);
        m_impl->state = WebSocketState::Connected;
    }
    return true;

#elif defined(__EMSCRIPTEN__)
    if (!emscripten_websocket_is_supported()) {
        LockGuard<Mutex> lk(m_impl->mutex);
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
        LockGuard<Mutex> lk(m_impl->mutex);
        m_impl->state = WebSocketState::Error;
        m_impl->last_error = String::from("emscripten_websocket_new failed");
        return false;
    }

    emscripten_websocket_set_onopen_callback(ws, m_impl, +[](int, const EmscriptenWebSocketOpenEvent*, void* user_data) -> EM_BOOL { // keel-lint: ignore
        auto* self = static_cast<Impl*>(user_data);
        LockGuard<Mutex> lk(self->mutex);
        self->state = WebSocketState::Connected;
        return EM_TRUE;
    });

    emscripten_websocket_set_onmessage_callback(ws, m_impl, +[](int, const EmscriptenWebSocketMessageEvent* ev, void* user_data) -> EM_BOOL { // keel-lint: ignore
        auto* self = static_cast<Impl*>(user_data);
        if (!ev) return EM_TRUE;
        LockGuard<Mutex> lk(self->mutex);
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

    emscripten_websocket_set_onerror_callback(ws, m_impl, +[](int, const EmscriptenWebSocketErrorEvent*, void* user_data) -> EM_BOOL { // keel-lint: ignore
        auto* self = static_cast<Impl*>(user_data);
        LockGuard<Mutex> lk(self->mutex);
        self->state = WebSocketState::Error;
        self->last_error = String::from("WebSocket error event");
        return EM_TRUE;
    });

    emscripten_websocket_set_onclose_callback(ws, m_impl, +[](int, const EmscriptenWebSocketCloseEvent* ev, void* user_data) -> EM_BOOL { // keel-lint: ignore
        auto* self = static_cast<Impl*>(user_data);
        LockGuard<Mutex> lk(self->mutex);
        self->state = WebSocketState::Disconnected;
        WebSocketMessage close_msg{};
        close_msg.type = WebSocketFrameType::Close;
        close_msg.close_status = ev ? ev->code : 1000;
        self->incoming_queue.push_back(keel::move(close_msg));
        return EM_TRUE;
    });

    {
        LockGuard<Mutex> lk(m_impl->mutex);
        m_impl->ws_handle = ws;
    }
    return true;

#elif defined(KEEL_HTTP_HAS_CURL) && (LIBCURL_VERSION_NUM >= 0x075600)
    CURL* curl = curl_easy_init();
    if (!curl) {
        LockGuard<Mutex> lk(m_impl->mutex);
        m_impl->state = WebSocketState::Error;
        m_impl->last_error = String::from("curl_easy_init failed for WebSocket");
        return false;
    }

    const String url_str = String::from(url);
    curl_easy_setopt(curl, CURLOPT_URL, url_str.c_str());
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(keel::max<u32>(500u, options.connect_timeout_ms))); // keel-lint: ignore
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
        LockGuard<Mutex> lk(m_impl->mutex);
        m_impl->state = WebSocketState::Error;
        m_impl->last_error = String::from(curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return false;
    }

    {
        LockGuard<Mutex> lk(m_impl->mutex);
        m_impl->curl = curl;
        m_impl->read_timeout_ms = keel::max<u32>(500u, options.connect_timeout_ms);
        m_impl->state = WebSocketState::Connected;
    }
    return true;
#else
    (void)options;
    LockGuard<Mutex> lk(m_impl->mutex);
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
        LockGuard<Mutex> lk(m_impl->mutex);
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
    LockGuard<Mutex> lk(m_impl->mutex);
    if (m_impl->state != WebSocketState::Connected || m_impl->ws_handle <= 0) return false;
    const String copy = String::from(text);
    return emscripten_websocket_send_utf8_text(m_impl->ws_handle, copy.c_str()) == EMSCRIPTEN_RESULT_SUCCESS;
#elif defined(KEEL_HTTP_HAS_CURL) && (LIBCURL_VERSION_NUM >= 0x075600)
    LockGuard<Mutex> lk(m_impl->mutex);
    if (m_impl->state != WebSocketState::Connected || !m_impl->curl) return false;
    usize sent = 0;
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
        LockGuard<Mutex> lk(m_impl->mutex);
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
    LockGuard<Mutex> lk(m_impl->mutex);
    if (m_impl->state != WebSocketState::Connected || m_impl->ws_handle <= 0) return false;
    return emscripten_websocket_send_binary(
        m_impl->ws_handle,
        const_cast<u8*>(payload.data()),
        as<u32>(payload.size())
    ) == EMSCRIPTEN_RESULT_SUCCESS;
#elif defined(KEEL_HTTP_HAS_CURL) && (LIBCURL_VERSION_NUM >= 0x075600)
    LockGuard<Mutex> lk(m_impl->mutex);
    if (m_impl->state != WebSocketState::Connected || !m_impl->curl) return false;
    usize sent = 0;
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
        LockGuard<Mutex> lk(m_impl->mutex);
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
            LockGuard<Mutex> lk(m_impl->mutex);
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
            LockGuard<Mutex> lk(m_impl->mutex);
            m_impl->state = WebSocketState::Disconnected;
            return true;
        }

        if (out_message.data.size() + bytes_read > max_bytes) {
            LockGuard<Mutex> lk(m_impl->mutex);
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
    LockGuard<Mutex> lk(m_impl->mutex);
    if (m_impl->incoming_queue.empty()) return false;
    out_message = keel::move(m_impl->incoming_queue.front());
    m_impl->incoming_queue.pop_front();
    return true;

#elif defined(KEEL_HTTP_HAS_CURL) && (LIBCURL_VERSION_NUM >= 0x075600)
    const u64 deadline_ns = monotonic_ns() + [&]() -> u64 {
        LockGuard<Mutex> lk(m_impl->mutex);
        return as<u64>(m_impl->read_timeout_ms) * 1000000ULL;
    }();

    u8 chunk[8192];
    for (;;) {
        usize rlen = 0;
        const struct curl_ws_frame* meta = nullptr;
        CURLcode res = CURLE_OK;
        usize max_bytes = 0;
        {
            LockGuard<Mutex> lk(m_impl->mutex);
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
            if (monotonic_ns() >= deadline_ns) {
                return false;
            }
            sleep_ms(2u);
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
        LockGuard<Mutex> lk(m_impl->mutex);
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
        LockGuard<Mutex> lk(m_impl->mutex);
        m_impl->cleanup_handles();
        m_impl->state = WebSocketState::Disconnected;
    }
#elif defined(__EMSCRIPTEN__)
    LockGuard<Mutex> lk(m_impl->mutex);
    if (m_impl->ws_handle > 0) {
        const String reason_str = String::from(reason.substr(0, keel::min<usize>(reason.size(), 120u)));
        emscripten_websocket_close(m_impl->ws_handle, status_code, reason_str.c_str());
        m_impl->cleanup_handles();
    }
    m_impl->state = WebSocketState::Disconnected;
#elif defined(KEEL_HTTP_HAS_CURL) && (LIBCURL_VERSION_NUM >= 0x075600)
    LockGuard<Mutex> lk(m_impl->mutex);
    if (m_impl->curl && m_impl->state == WebSocketState::Connected) {
        usize sent = 0;
        curl_ws_send(m_impl->curl, "", 0, &sent, 0, CURLWS_CLOSE);
    }
    m_impl->cleanup_handles();
    m_impl->state = WebSocketState::Disconnected;
    (void)status_code;
    (void)reason;
#else
    (void)status_code;
    (void)reason;
    LockGuard<Mutex> lk(m_impl->mutex);
    m_impl->state = WebSocketState::Disconnected;
#endif
}

} // namespace keel
