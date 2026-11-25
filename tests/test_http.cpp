#include "keel/http.h"
#include "keel/format.h"
#include "keel/fs.h"
#include "keel/time.h"

namespace {

keel::i32 g_failures = 0;

void check_impl(bool cond, const char* expr, const char* file, keel::i32 line) {
    if (!cond) {
        keel::eprintln("[FAIL] {}:{}: {}", file, line, expr);
        ++g_failures;
    }
}

#define CHECK(expr) check_impl((expr), #expr, __FILE__, __LINE__)

class MockHttpClient final : public keel::IHttpClient {
public:
    keel::HttpResponse execute(const keel::HttpRequest& request) const override {
        keel::HttpResponse resp{};
        if (request.url == "https://api.example.com/echo") {
            resp.status_code = 200;
            resp.content_type = keel::String::from("text/plain");
            resp.headers.push_back(keel::HttpHeader{
                .name = keel::String::from("X-Server"),
                .value = keel::String::from("keel-mock")
            });
            resp.headers.push_back(keel::HttpHeader{
                .name = keel::String::from("Set-Cookie"),
                .value = keel::String::from("a=1")
            });
            resp.headers.push_back(keel::HttpHeader{
                .name = keel::String::from("Set-Cookie"),
                .value = keel::String::from("b=2")
            });
            resp.body.append(request.body);
            resp.bytes_received = request.body.size();
        } else {
            resp.status_code = 404;
            resp.error_message = keel::String::from("Not found");
        }
        return resp;
    }
};

void test_url_parser_and_encoding() {
    {
        const auto u = keel::parse_url("https://tile.openstreetmap.org/14/9532/5841.png");
        CHECK(u.valid);
        CHECK(u.scheme == "https");
        CHECK(u.is_secure);
        CHECK(!u.is_websocket);
        CHECK(u.host == "tile.openstreetmap.org");
        CHECK(u.port == 443);
        CHECK(u.path_and_query == "/14/9532/5841.png");
    }
    {
        const auto u = keel::parse_url("  HTTP://Example.COM:8080?foo=1&bar=2#section ");
        CHECK(u.valid);
        CHECK(u.scheme == "http");
        CHECK(!u.is_secure);
        CHECK(!u.is_websocket);
        CHECK(u.host == "Example.COM");
        CHECK(u.port == 8080);
        CHECK(u.path_and_query == "/?foo=1&bar=2");
    }
    {
        const auto u = keel::parse_url("wss://user:pass@ais.stream.local:8443/live?v=2#frag");
        CHECK(u.valid);
        CHECK(u.scheme == "wss");
        CHECK(u.is_secure);
        CHECK(u.is_websocket);
        CHECK(u.host == "ais.stream.local");
        CHECK(u.port == 8443);
        CHECK(u.path_and_query == "/live?v=2");
    }
    {
        const auto u = keel::parse_url("ws://[::1]:9001/socket");
        CHECK(u.valid);
        CHECK(u.scheme == "ws");
        CHECK(!u.is_secure);
        CHECK(u.is_websocket);
        CHECK(u.host == "::1");
        CHECK(u.port == 9001);
        CHECK(u.path_and_query == "/socket");
    }
    {
        CHECK(!keel::parse_url("").valid);
        CHECK(!keel::parse_url("ftp://example.com/file").valid);
        CHECK(!keel::parse_url("http://example.com:0/").valid);
        CHECK(!keel::parse_url("http://example.com:70000/").valid);
        CHECK(!keel::parse_url("http://[::1/bad").valid);
        // Reject embedded control characters (CRLF/NUL/TAB injection defense).
        CHECK(!keel::parse_url("http://example.com/a\r\nX-Evil: 1").valid);
        CHECK(!keel::parse_url("http://example.com/a\nb").valid);
        CHECK(!keel::parse_url(keel::StringRef("http://example.com/a\0b", 22)).valid);
    }

    // Percent-encoding & decoding.
    CHECK(keel::url_encode("hello world/a?b=c&d=1~_-.") == "hello%20world%2Fa%3Fb%3Dc%26d%3D1~_-.");
    CHECK(keel::url_encode("a b+c", true) == "a+b%2Bc");
    CHECK(keel::url_decode("hello%20world%2Fa").value() == "hello world/a");
    CHECK(keel::url_decode("a+b%2Bc", true).value() == "a b+c");
    CHECK(!keel::url_decode("bad%2").has_value());
    CHECK(!keel::url_decode("bad%ZZ").has_value());

    // Query builder & parser.
    keel::UrlBuilder ub("https://api.example.com/v1/search?lang=en");
    ub.add_query("q", "c++ & http").add_query("page", "2").set_fragment("top");
    const keel::String built = ub.build();
    CHECK(built == "https://api.example.com/v1/search?lang=en&q=c%2B%2B+%26+http&page=2#top");

    const auto parsed_q = keel::parse_query_string("?lang=en&q=c%2B%2B+%26+http&empty=");
    CHECK(parsed_q.size() == 3);
    CHECK(parsed_q[0].key == "lang" && parsed_q[0].value == "en");
    CHECK(parsed_q[1].key == "q" && parsed_q[1].value == "c++ & http");
    CHECK(parsed_q[2].key == "empty" && parsed_q[2].value == "");

    // RFC 3986 relative URL resolution.
    const keel::StringRef base = "https://example.com:8443/a/b/c/d?old=1";
    CHECK(keel::resolve_url(base, "http://other.test/x") == "http://other.test/x");
    CHECK(keel::resolve_url(base, "//cdn.example.com/img.png") == "https://cdn.example.com/img.png");
    CHECK(keel::resolve_url(base, "/root/file") == "https://example.com:8443/root/file");
    CHECK(keel::resolve_url(base, "e") == "https://example.com:8443/a/b/c/e");
    CHECK(keel::resolve_url(base, "../g") == "https://example.com:8443/a/b/g");
    CHECK(keel::resolve_url(base, "../../x/y") == "https://example.com:8443/a/x/y");
    CHECK(keel::resolve_url(base, "?new=2") == "https://example.com:8443/a/b/c/d?new=2");
    CHECK(keel::resolve_url(base, "#frag") == "https://example.com:8443/a/b/c/d?old=1#frag");
    CHECK(keel::resolve_url("http://[::1]:8080/dir/page", "../next") == "http://[::1]:8080/next");
}

void test_auth_and_multipart() {
    const auto bearer = keel::make_bearer_auth_header("tok_12345");
    CHECK(bearer.name == "Authorization");
    CHECK(bearer.value == "Bearer tok_12345");

    // RFC 7617 example: "Aladdin:open sesame" -> "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
    const auto basic = keel::make_basic_auth_header("Aladdin", "open sesame");
    CHECK(basic.name == "Authorization");
    CHECK(basic.value == "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");

    keel::MultipartFormData form("TestBound123");
    form.add_field("user", "alice");
    const keel::u8 bin[] = {0x00, 0x01, 0xFF, 0x42};
    form.add_file("upload", "a\"b\r\n.bin", keel::ArrayRef<keel::u8>(bin), "application/octet-stream");

    keel::Array<keel::u8> body;
    keel::String ct;
    form.build(body, ct);
    CHECK(ct == "multipart/form-data; boundary=TestBound123");
    const keel::StringRef body_sv(reinterpret_cast<const char*>(body.data()), body.size());
    CHECK(body_sv.contains("--TestBound123\r\n"));
    CHECK(body_sv.contains("name=\"user\"\r\n\r\nalice\r\n"));
    CHECK(body_sv.contains("filename=\"a%22b.bin\""));
    CHECK(body_sv.contains("--TestBound123--\r\n"));

    // Auto-generated CSPRNG boundary is non-empty and unique.
    keel::MultipartFormData f1;
    keel::MultipartFormData f2;
    CHECK(!f1.boundary().empty());
    CHECK(f1.boundary() != f2.boundary());
}

void test_cookie_jar() {
    keel::CookieJar jar;
    keel::SmallArray<keel::HttpHeader, 8> hdrs;
    hdrs.push_back(keel::HttpHeader{
        .name = keel::String::from("Set-Cookie"),
        .value = keel::String::from("sid=xyz; Path=/; HttpOnly")
    });
    hdrs.push_back(keel::HttpHeader{
        .name = keel::String::from("Set-Cookie"),
        .value = keel::String::from("admin=yes; Path=/api/admin; Secure")
    });
    hdrs.push_back(keel::HttpHeader{
        .name = keel::String::from("Set-Cookie"),
        .value = keel::String::from("shared=1; Domain=example.com; Path=/")
    });
    // Security: evil domain must be rejected for sub.example.com!
    hdrs.push_back(keel::HttpHeader{
        .name = keel::String::from("Set-Cookie"),
        .value = keel::String::from("hijack=1; Domain=other.com; Path=/")
    });
    // Expired in past must not be stored!
    hdrs.push_back(keel::HttpHeader{
        .name = keel::String::from("Set-Cookie"),
        .value = keel::String::from("old=1; Expires=Sun, 06 Nov 1994 08:49:37 GMT")
    });

    jar.store_from_headers("https://sub.example.com/api/login", keel::ArrayRef<keel::HttpHeader>(hdrs));
    CHECK(jar.size() == 3);

    // HTTP (non-secure) must NOT send Secure cookie `admin`.
    const keel::String http_cookies = jar.cookie_header_for("http://sub.example.com/api/admin/panel");
    CHECK(http_cookies.as_ref().contains("sid=xyz"));
    CHECK(http_cookies.as_ref().contains("shared=1"));
    CHECK(!http_cookies.as_ref().contains("admin=yes"));

    // HTTPS on /api/admin/panel gets all three, longest path (`admin`) first!
    const keel::String https_cookies = jar.cookie_header_for("https://sub.example.com/api/admin/panel");
    CHECK(https_cookies.as_ref().starts_with("admin=yes; "));
    CHECK(https_cookies.as_ref().contains("sid=xyz"));
    CHECK(https_cookies.as_ref().contains("shared=1"));

    // Another subdomain gets Domain=example.com cookie, NOT host-only `sid`.
    const keel::String other_sub = jar.cookie_header_for("https://other.example.com/");
    CHECK(other_sub == "shared=1");

    // Max-Age=0 deletes cookie (and takes precedence over future Expires per RFC 6265 §5.3).
    keel::SmallArray<keel::HttpHeader, 4> del_hdrs;
    del_hdrs.push_back(keel::HttpHeader{
        .name = keel::String::from("Set-Cookie"),
        .value = keel::String::from("sid=; Path=/; Expires=Wed, 21 Oct 2099 07:28:00 GMT; Max-Age=0")
    });
    jar.store_from_headers("https://sub.example.com/api/logout", keel::ArrayRef<keel::HttpHeader>(del_hdrs));
    CHECK(jar.size() == 2);
    CHECK(!jar.cookie_header_for("https://sub.example.com/").as_ref().contains("sid="));

    // Future Expires stores cookie; path boundary /api must NOT match /apiv2.
    keel::SmallArray<keel::HttpHeader, 4> edge_hdrs;
    edge_hdrs.push_back(keel::HttpHeader{
        .name = keel::String::from("Set-Cookie"),
        .value = keel::String::from("fut=ok; Path=/api; Expires=Wed, 21 Oct 2099 07:28:00 GMT")
    });
    jar.store_from_headers("https://sub.example.com/api/v1", keel::ArrayRef<keel::HttpHeader>(edge_hdrs));
    CHECK(jar.cookie_header_for("https://sub.example.com/api").as_ref().contains("fut=ok"));
    CHECK(jar.cookie_header_for("https://sub.example.com/api/items").as_ref().contains("fut=ok"));
    CHECK(!jar.cookie_header_for("https://sub.example.com/apiv2").as_ref().contains("fut=ok"));

    // RFC 6265 §5.1.3: IP literal must reject domain-suffix cookie attributes.
    keel::CookieJar ip_jar;
    keel::SmallArray<keel::HttpHeader, 2> ip_hdrs;
    ip_hdrs.push_back(keel::HttpHeader{
        .name = keel::String::from("Set-Cookie"),
        .value = keel::String::from("bad=1; Domain=0.0.1; Path=/")
    });
    ip_jar.store_from_headers("http://127.0.0.1:8080/", keel::ArrayRef<keel::HttpHeader>(ip_hdrs));
    CHECK(ip_jar.size() == 0);
}

void test_http_types_and_mock() {
    MockHttpClient mock;
    keel::HttpRequest req{};
    req.url = keel::String::from("https://api.example.com/echo");
    req.method = keel::HttpMethod::Post;
    const keel::StringRef payload = "hello keel::http";
    req.body.append(keel::ArrayRef<keel::u8>(reinterpret_cast<const keel::u8*>(payload.data()), payload.size()));

    const keel::HttpResponse resp = mock.execute(req);
    CHECK(resp.succeeded());
    CHECK(resp.status_code == 200);
    CHECK(resp.body_as_text() == "hello keel::http");
    CHECK(resp.get_header("x-server") == "keel-mock");
    CHECK(resp.get_header("X-SERVER") == "keel-mock");
    CHECK(resp.get_header("missing").empty());
    const auto cookies = resp.get_headers("set-cookie");
    CHECK(cookies.size() == 2 && cookies[0] == "a=1" && cookies[1] == "b=2");
}

void test_clients_lifecycle() {
    keel::HttpClient http("keel-test/0.2");
    CHECK(!keel::HttpClient::backend_name().empty());

    // Invalid URLs fail immediately without network I/O
    const auto bad_resp = http.get("ws://not-an-http-url.local/stream");
    CHECK(!bad_resp.succeeded());
    CHECK(!bad_resp.error_message.empty());

    keel::WebSocketClient ws;
    CHECK(ws.state() == keel::WebSocketState::Disconnected);
    CHECK(!ws.connect("https://not-a-websocket-url.local"));
    CHECK(ws.state() == keel::WebSocketState::Error);
    CHECK(!ws.last_error().empty());
    ws.close();
    CHECK(ws.state() == keel::WebSocketState::Disconnected);
}

// ============================================================================
// Live Loopback Integration Suite (driven by tests/verify_integration.py)
// ============================================================================
keel::i32 run_integration_suite(
    keel::StringRef base_url,
    keel::StringRef ws_url,
    keel::StringRef closed_url,
    keel::StringRef temp_dir
) {
    keel::HttpClient client("keel-integration/0.2");

    auto url_of = [&base_url](keel::StringRef path) -> keel::String {
        keel::String u = keel::String::from(base_url);
        u.append(path);
        return u;
    };

    // 1. GET with UrlBuilder, custom headers, Bearer & Basic auth.
    {
        keel::UrlBuilder ub(url_of("/echo"));
        ub.add_query("msg", "hello world").add_query("k", "a&b=c");
        keel::SmallArray<keel::HttpHeader, 4> hdrs;
        hdrs.push_back(keel::HttpHeader{keel::String::from("X-Custom"), keel::String::from("KeelValue")});
        hdrs.push_back(keel::make_bearer_auth_header("secret_tok"));
        const auto resp = client.get(ub.build(), keel::ArrayRef<keel::HttpHeader>(hdrs), 5000);
        CHECK(resp.succeeded());
        CHECK(resp.status_code == 200);
        CHECK(resp.body_as_text().contains("METHOD=GET"));
        CHECK(resp.body_as_text().contains("QUERY_msg=hello world"));
        CHECK(resp.body_as_text().contains("QUERY_k=a&b=c"));
        CHECK(resp.body_as_text().contains("HDR_x-custom=KeelValue"));
        CHECK(resp.body_as_text().contains("HDR_authorization=Bearer secret_tok"));
        CHECK(resp.body_as_text().contains("HDR_user-agent=keel-integration/0.2"));
    }

    // 2. HEAD, PUT, PATCH, DELETE, POST form.
    {
        const auto h = client.head(url_of("/head"), {}, 5000);
        CHECK(h.succeeded());
        CHECK(h.status_code == 200);
        CHECK(h.body.empty());
        CHECK(h.get_header("X-Head-Ok") == "yes");

        const keel::StringRef put_data = "put-payload-123";
        const auto pu = client.put(
            url_of("/echo"),
            keel::ArrayRef<keel::u8>(reinterpret_cast<const keel::u8*>(put_data.data()), put_data.size()),
            "text/plain", {}, 5000
        );
        CHECK(pu.succeeded());
        CHECK(pu.body_as_text().contains("METHOD=PUT"));
        CHECK(pu.body_as_text().contains("BODY=put-payload-123"));

        const keel::StringRef patch_data = "patch-payload";
        const auto pa = client.patch(
            url_of("/echo"),
            keel::ArrayRef<keel::u8>(reinterpret_cast<const keel::u8*>(patch_data.data()), patch_data.size()),
            "text/plain", {}, 5000
        );
        CHECK(pa.succeeded());
        CHECK(pa.body_as_text().contains("METHOD=PATCH"));
        CHECK(pa.body_as_text().contains("BODY=patch-payload"));

        const auto dl = client.del(url_of("/echo"), {}, 5000);
        CHECK(dl.succeeded());
        CHECK(dl.body_as_text().contains("METHOD=DELETE"));

        keel::SmallArray<keel::HttpQueryParam, 4> fields;
        fields.push_back(keel::HttpQueryParam{keel::String::from("name"), keel::String::from("Ada Lovelace")});
        fields.push_back(keel::HttpQueryParam{keel::String::from("lang"), keel::String::from("C++20")});
        const auto pf = client.post_form(url_of("/form"), keel::ArrayRef<keel::HttpQueryParam>(fields), {}, 5000);
        CHECK(pf.succeeded());
        CHECK(pf.body_as_text().contains("FIELD_name=Ada Lovelace"));
        CHECK(pf.body_as_text().contains("FIELD_lang=C++20"));
    }

    // 3. Multipart upload (fields + binary file with NUL bytes).
    {
        keel::MultipartFormData form;
        form.add_field("title", "hello multipart");
        keel::Array<keel::u8> bin;
        bin.reserve(256);
        for (keel::u32 i = 0; i < 256u; ++i) bin.push_back(keel::as<keel::u8>(i));
        form.add_file("blob", "all_bytes.bin", keel::ArrayRef<keel::u8>(bin), "application/octet-stream");
        const auto mp = client.post_multipart(url_of("/multipart"), form, {}, 5000);
        CHECK(mp.succeeded());
        CHECK(mp.body_as_text().contains("FIELD_title=hello multipart"));
        CHECK(mp.body_as_text().contains("FILE_blob=all_bytes.bin:256:OK"));
    }

    // 4. Redirects: relative 302, POST->GET 302, POST->POST 307, loop limit, disabled, cross-origin strip!
    {
        const auto rel = client.get(url_of("/redirect/sub/rel"), {}, 5000);
        CHECK(rel.succeeded());
        CHECK(rel.redirect_count == 1);
        CHECK(rel.final_url.as_ref().ends_with("/redirect/target"));
        CHECK(rel.body_as_text() == "redirect-target-ok");

        // 302 on POST must downgrade to GET and drop body.
        const keel::StringRef pbody = "secret-post-body";
        const auto r302 = client.post(
            url_of("/redirect/302-post"),
            keel::ArrayRef<keel::u8>(reinterpret_cast<const keel::u8*>(pbody.data()), pbody.size()),
            "text/plain", {}, 5000
        );
        CHECK(r302.succeeded());
        CHECK(r302.redirect_count == 1);
        CHECK(r302.body_as_text().contains("METHOD=GET"));
        CHECK(!r302.body_as_text().contains("secret-post-body"));

        // 307 on POST must preserve POST and body.
        const auto r307 = client.post(
            url_of("/redirect/307-post"),
            keel::ArrayRef<keel::u8>(reinterpret_cast<const keel::u8*>(pbody.data()), pbody.size()),
            "text/plain", {}, 5000
        );
        CHECK(r307.succeeded());
        CHECK(r307.redirect_count == 1);
        CHECK(r307.body_as_text().contains("METHOD=POST"));
        CHECK(r307.body_as_text().contains("BODY=secret-post-body"));

        // 303 on PUT must downgrade to GET and drop body.
        const auto r303 = client.put(
            url_of("/redirect/303-put"),
            keel::ArrayRef<keel::u8>(reinterpret_cast<const keel::u8*>(pbody.data()), pbody.size()),
            "text/plain", {}, 5000
        );
        CHECK(r303.succeeded());
        CHECK(r303.redirect_count == 1);
        CHECK(r303.body_as_text().contains("METHOD=GET"));
        CHECK(!r303.body_as_text().contains("secret-post-body"));

        // 308 on POST must preserve POST and body.
        const auto r308 = client.post(
            url_of("/redirect/308-post"),
            keel::ArrayRef<keel::u8>(reinterpret_cast<const keel::u8*>(pbody.data()), pbody.size()),
            "text/plain", {}, 5000
        );
        CHECK(r308.succeeded());
        CHECK(r308.redirect_count == 1);
        CHECK(r308.body_as_text().contains("METHOD=POST"));
        CHECK(r308.body_as_text().contains("BODY=secret-post-body"));

        // Redirect loop exceeds max_redirects.
        keel::HttpRequest loop_req{};
        loop_req.url = url_of("/redirect/loop");
        loop_req.max_redirects = 3;
        const auto loop_r = client.execute(loop_req);
        CHECK(!loop_r.succeeded());
        CHECK(loop_r.redirect_count == 3);
        CHECK(loop_r.error_message == "Too many redirects");

        // Disabled redirects return 302 directly.
        keel::HttpRequest no_redir{};
        no_redir.url = url_of("/redirect/sub/rel");
        no_redir.follow_redirects = false;
        const auto nr = client.execute(no_redir);
        CHECK(nr.status_code == 302);
        CHECK(nr.redirect_count == 0);
        CHECK(nr.get_header("Location") == "../target");

        // Cross-origin redirect must strip Authorization and Cookie headers!
        keel::SmallArray<keel::HttpHeader, 4> auth_hdrs;
        auth_hdrs.push_back(keel::make_bearer_auth_header("top_secret"));
        auth_hdrs.push_back(keel::HttpHeader{keel::String::from("Cookie"), keel::String::from("sess=keep_private")});
        auth_hdrs.push_back(keel::HttpHeader{keel::String::from("X-Public"), keel::String::from("safe")});
        const auto xorig = client.get(url_of("/redirect/cross-origin"), keel::ArrayRef<keel::HttpHeader>(auth_hdrs), 5000);
        CHECK(xorig.succeeded());
        CHECK(xorig.redirect_count == 1);
        CHECK(!xorig.body_as_text().contains("top_secret"));
        CHECK(!xorig.body_as_text().contains("keep_private"));
        CHECK(xorig.body_as_text().contains("HDR_x-public=safe"));
    }

    // 5. CookieJar across redirect + persistence + Max-Age=0 deletion.
    {
        keel::CookieJar jar;
        client.set_cookie_jar(&jar);
        const auto login = client.get(url_of("/cookie/login"), {}, 5000);
        CHECK(login.succeeded());
        CHECK(login.redirect_count == 1);
        CHECK(login.body_as_text().contains("COOKIE_sid=keel_session_42"));
        CHECK(jar.size() == 1);

        const auto profile = client.get(url_of("/cookie/profile"), {}, 5000);
        CHECK(profile.succeeded());
        CHECK(profile.body_as_text().contains("COOKIE_sid=keel_session_42"));

        const auto logout = client.get(url_of("/cookie/logout"), {}, 5000);
        CHECK(logout.succeeded());
        CHECK(jar.size() == 0);

        const auto after = client.get(url_of("/cookie/profile"), {}, 5000);
        CHECK(after.succeeded());
        CHECK(!after.body_as_text().contains("keel_session_42"));

        // Cross-host CookieJar isolation: host-only cookie on 127.0.0.1 must NOT be sent to localhost!
        const auto login2 = client.get(url_of("/cookie/login"), {}, 5000);
        CHECK(login2.succeeded() && jar.size() == 1);
        const auto xhost = client.get(url_of("/redirect/cross-host"), {}, 5000);
        CHECK(xhost.succeeded());
        CHECK(xhost.redirect_count == 1);
        CHECK(!xhost.body_as_text().contains("keel_session_42"));
        client.set_cookie_jar(nullptr);
    }

    // 6. Retry policy (503 x2 -> 200, 429 Retry-After -> 200, POST non-idempotent guard,
    //    network-error retry, streaming+redirect & streaming+retry body suppression).
    {
        keel::HttpRequest req503{};
        req503.url = url_of("/retry/flaky503");
        req503.retry.max_retries = 3;
        req503.retry.initial_delay_ms = 20;
        req503.retry.max_delay_ms = 200;
        const auto r503 = client.execute(req503);
        CHECK(r503.succeeded());
        CHECK(r503.status_code == 200);
        CHECK(r503.attempts == 3);
        CHECK(r503.body_as_text() == "recovered-503");

        keel::HttpRequest req429{};
        req429.url = url_of("/retry/rate429");
        req429.retry.max_retries = 2;
        req429.retry.initial_delay_ms = 20;
        const auto r429 = client.execute(req429);
        CHECK(r429.succeeded());
        CHECK(r429.attempts == 2);
        CHECK(r429.body_as_text() == "recovered-429");

        // POST is NOT retried when retry_non_idempotent == false (default), IS retried when true.
        keel::HttpRequest post_no_retry{};
        post_no_retry.url = url_of("/retry/post503");
        post_no_retry.method = keel::HttpMethod::Post;
        post_no_retry.retry.max_retries = 2;
        post_no_retry.retry.initial_delay_ms = 10;
        const auto pnr = client.execute(post_no_retry);
        CHECK(pnr.status_code == 503);
        CHECK(pnr.attempts == 1);

        keel::HttpRequest post_yes_retry = keel::move(post_no_retry);
        post_yes_retry.retry.retry_non_idempotent = true;
        const auto pyr = client.execute(post_yes_retry);
        CHECK(pyr.succeeded());
        CHECK(pyr.attempts == 2);
        CHECK(pyr.body_as_text() == "post-recovered");

        // Network-error retry against closed loopback port.
        keel::HttpRequest net_req{};
        net_req.url = keel::String::from(closed_url);
        net_req.connect_timeout_ms = 500;
        net_req.read_timeout_ms = 500;
        net_req.retry.max_retries = 2;
        net_req.retry.initial_delay_ms = 10;
        net_req.retry.max_delay_ms = 50;
        const auto net_r = client.execute(net_req);
        CHECK(!net_r.succeeded());
        CHECK(net_r.attempts == 3);

        // execute_streaming must NOT emit intermediate 302 redirect body into on_chunk!
        keel::HttpRequest sr_redir{};
        sr_redir.url = url_of("/redirect/sub/rel");
        keel::String stream_redir_text;
        const auto sr_r = client.execute_streaming(sr_redir, [&](keel::ArrayRef<keel::u8> c) -> bool {
            stream_redir_text.append(keel::StringRef(reinterpret_cast<const char*>(c.data()), c.size()));
            return true;
        });
        CHECK(sr_r.succeeded());
        CHECK(sr_r.redirect_count == 1);
        CHECK(stream_redir_text == "redirect-target-ok");

        // execute_streaming must NOT emit 503 error bodies on retries into on_chunk!
        keel::HttpRequest sr_retry{};
        sr_retry.url = url_of("/retry/stream503");
        sr_retry.retry.max_retries = 3;
        sr_retry.retry.initial_delay_ms = 15;
        keel::String stream_retry_text;
        const auto sr_t = client.execute_streaming(sr_retry, [&](keel::ArrayRef<keel::u8> c) -> bool {
            stream_retry_text.append(keel::StringRef(reinterpret_cast<const char*>(c.data()), c.size()));
            return true;
        });
        CHECK(sr_t.succeeded());
        CHECK(sr_t.attempts == 3);
        CHECK(stream_retry_text == "stream-recovered");
    }

    // 7. Streaming download, early abort, max_response_bytes cap, download_to_file.
    {
        keel::HttpRequest sreq{};
        sreq.url = url_of("/stream/large");
        keel::Array<keel::u8> collected;
        keel::usize chunk_calls = 0;
        const auto sr = client.execute_streaming(sreq, [&](keel::ArrayRef<keel::u8> chunk) -> bool {
            ++chunk_calls;
            collected.append(chunk);
            return true;
        });
        CHECK(sr.succeeded());
        CHECK(sr.body.empty()); // streaming must not duplicate into response.body
        CHECK(sr.bytes_received == 256u * 1024u);
        CHECK(collected.size() == 256u * 1024u);
        CHECK(chunk_calls >= 1u);
        bool pattern_ok = true;
        for (keel::usize i = 0; i < collected.size(); ++i) {
            if (collected[i] != keel::as<keel::u8>((i * 31u + 7u) & 0xFFu)) {
                pattern_ok = false;
                break;
            }
        }
        CHECK(pattern_ok);

        // Early abort via chunk callback.
        keel::usize seen = 0;
        const auto ab = client.execute_streaming(sreq, [&](keel::ArrayRef<keel::u8> chunk) -> bool {
            seen += chunk.size();
            return false; // abort immediately after first chunk
        });
        CHECK(!ab.succeeded());
        CHECK(seen > 0 && seen < 256u * 1024u);
        CHECK(ab.error_message.as_ref().contains("Aborted"));

        // max_response_bytes overflow guard.
        keel::HttpRequest cap_req{};
        cap_req.url = url_of("/stream/large");
        cap_req.max_response_bytes = 1024;
        const auto cap_r = client.execute(cap_req);
        CHECK(!cap_r.succeeded());
        CHECK(cap_r.body.empty());
        CHECK(cap_r.error_message.as_ref().contains("max_response_bytes"));

        // download_to_file success + 404 cleanup.
        const keel::String dst = keel::path_join(temp_dir, "downloaded.bin");
        const auto dl_ok = client.download_to_file(url_of("/stream/large"), dst.as_ref(), {}, 10000);
        CHECK(dl_ok.succeeded());
        CHECK(dl_ok.bytes_received == 256u * 1024u);
        auto disk = keel::fs_read_file(dst.as_ref());
        CHECK(disk.is_ok() && disk.value().size() == 256u * 1024u);
        if (disk.is_ok()) {
            CHECK(disk.value().size() == collected.size());
            bool eq = true;
            for (keel::usize i = 0; i < collected.size(); ++i) {
                if (disk.value()[i] != collected[i]) { eq = false; break; }
            }
            CHECK(eq);
        }
        (void)keel::fs_remove(dst.as_ref());

        const keel::String dst404 = keel::path_join(temp_dir, "should_not_exist.bin");
        const auto dl_404 = client.download_to_file(url_of("/not-found"), dst404.as_ref(), {}, 5000);
        CHECK(!dl_404.succeeded());
        CHECK(dl_404.status_code == 404);
        CHECK(!keel::fs_exists(dst404.as_ref()));
    }

    // 8. Timeout test (also verifies sub-500ms WinHTTP infinite-timeout clamp).
    {
        keel::HttpRequest treq{};
        treq.url = url_of("/slow");
        treq.connect_timeout_ms = 500;
        treq.read_timeout_ms = 150;
        const auto tr = client.execute(treq);
        CHECK(!tr.succeeded());
        CHECK(!tr.error_message.empty());
    }

    // 9. Live RFC 6455 WebSocket handshake, text echo, binary echo (>125 bytes), and close.
    {
        keel::WebSocketClient ws;
        keel::WebSocketConnectOptions opts{};
        opts.connect_timeout_ms = 5000;
        CHECK(ws.connect(ws_url, opts));
        CHECK(ws.state() == keel::WebSocketState::Connected);

        CHECK(ws.send_text("hello websocket keel"));
        keel::WebSocketMessage msg{};
        CHECK(ws.receive(msg));
        CHECK(msg.type == keel::WebSocketFrameType::Text);
        CHECK(msg.as_text() == "hello websocket keel");

        // Binary message of 512 bytes (exercises 16-bit extended RFC 6455 payload length + NULs).
        keel::Array<keel::u8> bin;
        bin.reserve(512);
        for (keel::u32 i = 0; i < 512u; ++i) {
            bin.push_back(keel::as<keel::u8>((i * 73u + 19u) & 0xFFu));
        }
        CHECK(ws.send_binary(keel::ArrayRef<keel::u8>(bin)));
        keel::WebSocketMessage bmsg{};
        CHECK(ws.receive(bmsg));
        CHECK(bmsg.type == keel::WebSocketFrameType::Binary);
        CHECK(bmsg.data.size() == bin.size());
        bool bin_ok = (bmsg.data.size() == bin.size());
        for (keel::usize i = 0; bin_ok && i < bin.size(); ++i) {
            if (bmsg.data[i] != bin[i]) bin_ok = false;
        }
        CHECK(bin_ok);

        ws.close(1000, "done");
        CHECK(ws.state() == keel::WebSocketState::Disconnected);
    }

    if (g_failures == 0) {
        keel::println("All keel_http integration tests passed.");
        return 0;
    }
    keel::eprintln("{} integration test(s) failed.", g_failures);
    return 1;
}

} // namespace

int main(int argc, char** argv) {
    if (argc == 6 && keel::StringRef(argv[1]) == "--integration") {
        return run_integration_suite(
            keel::StringRef(argv[2]),
            keel::StringRef(argv[3]),
            keel::StringRef(argv[4]),
            keel::StringRef(argv[5])
        );
    }
    if (argc == 4 && keel::StringRef(argv[1]) == "--resolve-url") {
        keel::println("{}", keel::resolve_url(keel::StringRef(argv[2]), keel::StringRef(argv[3])));
        return 0;
    }

    test_url_parser_and_encoding();
    test_auth_and_multipart();
    test_cookie_jar();
    test_http_types_and_mock();
    test_clients_lifecycle();

    if (g_failures == 0) {
        keel::println("All keel_http tests passed.");
        return 0;
    }
    keel::eprintln("{} test(s) failed.", g_failures);
    return 1;
}
