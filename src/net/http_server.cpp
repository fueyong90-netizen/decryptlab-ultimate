#include "dlu/net/http_server.hpp"
#include "dlu/core/fileio.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <csignal>
#include <thread>
#include <atomic>
#include <sstream>
#include <algorithm>

namespace dlu::net {

static std::atomic<int> g_active{0};
static const int kMaxConns = 64;

std::string HttpRequest::query_get(const std::string& key) const {
    std::stringstream ss(query);
    std::string kv;
    while (std::getline(ss, kv, '&')) {
        auto eq = kv.find('=');
        std::string k = eq == std::string::npos ? kv : kv.substr(0, eq);
        if (k == key) {
            std::string v = eq == std::string::npos ? "" : kv.substr(eq + 1);
            // minimal url-decode
            std::string out;
            for (size_t i = 0; i < v.size(); ++i) {
                if (v[i] == '%' && i + 2 < v.size()) { out.push_back((char)std::stoi(v.substr(i+1,2),nullptr,16)); i+=2; }
                else if (v[i] == '+') out.push_back(' ');
                else out.push_back(v[i]);
            }
            return out;
        }
    }
    return "";
}

HttpResponse HttpResponse::json(const std::string& j, int status) {
    return {status, "application/json; charset=utf-8", j, {}};
}
HttpResponse HttpResponse::text(const std::string& t, int status) {
    return {status, "text/plain; charset=utf-8", t, {}};
}

HttpServer::HttpServer(std::string host, uint16_t port) : host_(std::move(host)), port_(port) {}

void HttpServer::route(const std::string& method, const std::string& path, Handler h) {
    routes_[method + " " + path] = std::move(h);
}

static std::string mime_for(const std::string& path) {
    auto dot = path.find_last_of('.');
    std::string e = dot == std::string::npos ? "" : path.substr(dot + 1);
    if (e == "html") return "text/html; charset=utf-8";
    if (e == "js")   return "application/javascript; charset=utf-8";
    if (e == "css")  return "text/css; charset=utf-8";
    if (e == "json" || e == "webmanifest") return "application/manifest+json; charset=utf-8";
    if (e == "svg")  return "image/svg+xml";
    if (e == "png")  return "image/png";
    if (e == "ico")  return "image/x-icon";
    return "application/octet-stream";
}

bool HttpServer::serve_static(const HttpRequest& req, HttpResponse& res) {
    if (static_root_.empty()) return false;
    std::string rel = req.path == "/" ? "/index.html" : req.path;
    // Path-traversal guard.
    if (rel.find("..") != std::string::npos) { res.status = 400; res.body = "bad path"; return true; }
    std::string full = static_root_ + rel;
    if (!core::file_exists(full)) return false;
    auto data = core::read_all(full, 32u * 1024 * 1024);
    if (!data) return false;
    res.status = 200;
    res.content_type = mime_for(full);
    res.body.assign((const char*)data.value.data(), data.value.size());
    return true;
}

static std::string status_text(int c) {
    switch (c) {
        case 200: return "OK"; case 400: return "Bad Request";
        case 404: return "Not Found"; case 405: return "Method Not Allowed";
        case 413: return "Payload Too Large"; case 500: return "Internal Server Error";
        default: return "OK";
    }
}

void HttpServer::handle_conn(int fd) {
    struct Guard { ~Guard(){ --g_active; } } guard;
    std::string buf;
    char tmp[8192];
    ssize_t n;
    size_t header_end = std::string::npos;
    // Read until headers complete.
    while ((n = recv(fd, tmp, sizeof(tmp), 0)) > 0) {
        buf.append(tmp, n);
        header_end = buf.find("\r\n\r\n");
        if (header_end != std::string::npos) break;
        if (buf.size() > 65536) break;
    }
    if (header_end == std::string::npos) { close(fd); return; }

    HttpRequest req;
    {
        std::istringstream hs(buf.substr(0, header_end));
        std::string line;
        std::getline(hs, line);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::istringstream rl(line);
        std::string target;
        rl >> req.method >> target;
        auto q = target.find('?');
        req.path = q == std::string::npos ? target : target.substr(0, q);
        req.query = q == std::string::npos ? "" : target.substr(q + 1);
        while (std::getline(hs, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            auto c = line.find(':');
            if (c == std::string::npos) continue;
            std::string k = line.substr(0, c), v = line.substr(c + 1);
            std::transform(k.begin(), k.end(), k.begin(), ::tolower);
            size_t s = v.find_first_not_of(" \t");
            req.headers[k] = s == std::string::npos ? "" : v.substr(s);
        }
    }

    size_t content_len = 0;
    auto it = req.headers.find("content-length");
    if (it != req.headers.end()) content_len = (size_t)std::stoull(it->second);

    HttpResponse res;
    if (content_len > max_body_) {
        res.status = 413; res.content_type = "text/plain"; res.body = "payload too large";
    } else {
        std::string body = buf.substr(header_end + 4);
        while (body.size() < content_len && (n = recv(fd, tmp, sizeof(tmp), 0)) > 0)
            body.append(tmp, n);
        req.body = std::move(body);

        // CORS preflight.
        if (req.method == "OPTIONS") {
            res.status = 200; res.body = "";
        } else {
            auto rit = routes_.find(req.method + " " + req.path);
            if (rit != routes_.end()) {
                res = rit->second(req);
            } else if (req.method == "GET" && serve_static(req, res)) {
                // served
            } else {
                res.status = 404; res.content_type = "application/json";
                res.body = "{\"error\":\"not found\"}";
            }
        }
    }

    std::ostringstream out;
    out << "HTTP/1.1 " << res.status << " " << status_text(res.status) << "\r\n";
    out << "Content-Type: " << res.content_type << "\r\n";
    out << "Content-Length: " << res.body.size() << "\r\n";
    out << "Access-Control-Allow-Origin: *\r\n";
    out << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
    out << "Access-Control-Allow-Headers: Content-Type\r\n";
    for (auto& h : res.extra_headers) out << h.first << ": " << h.second << "\r\n";
    out << "Connection: close\r\n\r\n";
    out << res.body;
    std::string s = out.str();
    size_t sent = 0;
    while (sent < s.size()) {
        ssize_t w = send(fd, s.data() + sent, s.size() - sent, MSG_NOSIGNAL);
        if (w <= 0) break;
        sent += (size_t)w;
    }
    close(fd);
}

int HttpServer::run() {
    signal(SIGPIPE, SIG_IGN);
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) return 1;
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    addr.sin_addr.s_addr = (host_ == "0.0.0.0" || host_.empty()) ? INADDR_ANY : inet_addr(host_.c_str());
    if (bind(srv, (sockaddr*)&addr, sizeof(addr)) < 0) { close(srv); return 2; }
    if (listen(srv, 64) < 0) { close(srv); return 3; }

    while (true) {
        int fd = accept(srv, nullptr, nullptr);
        if (fd < 0) continue;
        if (g_active.load() >= kMaxConns) {
            const char* busy = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            send(fd, busy, strlen(busy), MSG_NOSIGNAL);
            close(fd);
            continue;
        }
        ++g_active;
        std::thread(&HttpServer::handle_conn, this, fd).detach();
    }
    close(srv);
    return 0;
}

} // namespace dlu::net
