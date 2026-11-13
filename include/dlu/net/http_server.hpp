#pragma once
#include <string>
#include <map>
#include <functional>
#include <cstdint>

namespace dlu::net {

struct HttpRequest {
    std::string method;
    std::string path;                       // decoded path (no query)
    std::string query;                      // raw query string
    std::map<std::string, std::string> headers;
    std::string body;
    std::string query_get(const std::string& key) const;
};

struct HttpResponse {
    int status = 200;
    std::string content_type = "application/json";
    std::string body;
    std::map<std::string, std::string> extra_headers;
    static HttpResponse json(const std::string& j, int status = 200);
    static HttpResponse text(const std::string& t, int status = 200);
};

using Handler = std::function<HttpResponse(const HttpRequest&)>;

// Minimal, dependency-free HTTP/1.1 server (POSIX sockets). Thread-per-connection
// with a cap. Serves static files from a web root and dispatches registered API
// routes. Suitable for free single-binary hosting (serves PWA + core API).
class HttpServer {
public:
    HttpServer(std::string host, uint16_t port);
    void set_static_root(const std::string& dir) { static_root_ = dir; }
    void route(const std::string& method, const std::string& path, Handler h);
    // Blocks. Returns non-zero on fatal bind/listen error.
    int run();
    void set_max_body(size_t bytes) { max_body_ = bytes; }

private:
    std::string host_;
    uint16_t port_;
    std::string static_root_;
    size_t max_body_ = 64u * 1024 * 1024;
    std::map<std::string, Handler> routes_; // key "METHOD path"
    void handle_conn(int fd);
    bool serve_static(const HttpRequest& req, HttpResponse& res);
};

} // namespace dlu::net
