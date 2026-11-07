#include "keel/http.h"
#include "keel/format.h"

#include <cstdlib>

namespace {

int g_failures = 0;

void check_impl(bool cond, const char* expr, const char* file, int line) {
    if (!cond) {
        keel::eprintln("[FAIL] %s:%d: %s", file, line, expr);
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
            resp.body.append(request.body);
        } else {
            resp.status_code = 404;
            resp.error_message = keel::String::from("Not found");
        }
        return resp;
    }
};

void test_url_parser() {
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
    }
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
}

void test_clients_lifecycle() {
    keel::HttpClient http("keel-test/0.1");
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

} // namespace

int main() {
    test_url_parser();
    test_http_types_and_mock();
    test_clients_lifecycle();

    if (g_failures == 0) {
        keel::println("All keel_http tests passed.");
        return EXIT_SUCCESS;
    }
    keel::eprintln("%d test(s) failed.", g_failures);
    return EXIT_FAILURE;
}
