#include <string>
#include <string_view>
#include <vector>
#include <filesystem>
#include <fmt/format.h>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/json/value.hpp>
#include <boost/json/parse.hpp>
#include <http_async.h>
#include <http_mime.h>

using boost::asio::detached;
using boost::asio::deferred;
using boost::asio::ip::tcp;
using boost::asio::make_strand;
using tcp_acceptor  = boost::asio::basic_socket_acceptor<tcp, boost::asio::io_context::executor_type>;
using tcp_socket    = boost::asio::basic_stream_socket<tcp,   boost::asio::strand<boost::asio::io_context::executor_type>>;
// using tls_socket    = boost::asio::ssl::stream<tcp_socket>;
template<class T> using awaitable           = boost::asio::awaitable<T, boost::asio::io_context::executor_type>;
template<class T> using awaitable_strand    = boost::asio::awaitable<T, boost::asio::strand<boost::asio::io_context::executor_type>>;
namespace fs = std::filesystem;

struct handler_return
{
    bool success{false};
    std::string response;
};

using handler       = std::function<handler_return(const boost::json::value& jv)>;
using handlers_t    = std::vector<std::pair<std::string_view, handler>>;

void http_unauthorized (const http::request& req, http::response& resp, std::string msg)
{
    printf("[HTTP] Authorization request\n");
    resp.status = http::status_type::unauthorized;
    resp.add_header(http::field::www_authenticate,    "Basic realm=\"Access to the staging site\"");
    resp.add_header(http::field::cache_control,       "no-store");
    resp.content_str = std::move(msg);
}

void http_bad_request (const http::request& req, http::response& resp, std::string why)
{
    resp.status         = http::status_type::bad_request;
    resp.content_str    = std::move(why);
}

void http_not_found (const http::request& req, http::response& resp)
{
    resp.status         = http::status_type::not_found;
    resp.content_str    = fmt::format("The resource {} was not found", req.uri);
}

void http_server_error (const http::request& req, http::response& resp, std::string what)
{
    resp.status         = http::status_type::internal_server_error;
    resp.content_str    = fmt::format("An error occured: `{}`", what); 
}

void http_file_data (const http::request& req, http::response& resp, std::string_view path, std::ifstream file)
{
    resp.status = http::status_type::ok;
    resp.add_header(http::field::content_type,    http::get_mime_type(path));
    resp.add_header(http::field::cache_control,   "no-cache, no-store, must-revalidate, private, max-age=0");
    resp.add_header(http::field::pragma,          "no-cache");
    resp.add_header(http::field::expires,         "0");
    resp.content_file = std::move(file);
}

void http_json_data (const http::request& req, http::response& resp, handler_return data)
{
    resp.status = data.success ? http::status_type::ok : http::status_type::internal_server_error;
    resp.add_header(http::field::content_type, data.success ? "application/json" : "text/plain");
    resp.content_str = std::move(data.response);
}

// auto handle_authorization (const request& req, std::string_view username_exp, std::string_view passwd_exp)
// {       
//     log::trace("HTTP", "Handling authorization response");
    
//     auto field = req.find(field::authorization);
//     if (field == req.headers.end())
//         return std::make_pair(false, "Missing Authorization field");
    
//     std::string_view  login_base64  = lskip(field->values, "Basic ");
//     const std::string login         = from_base64(login_base64);

//     const auto [user, passwd] = split_once(login, ":");

//     if (user.compare(username_exp) != 0 || passwd.compare(passwd_exp) != 0)
//         return std::make_pair(false, "Authentication username-password don't match expected");

//     log::trace("HTTP", "Handling authorization response... Success");
//     return std::make_pair(true, "Authenticated!");
// }

void handle_request (
    std::string_view        doc_root, 
    std::string_view        username,
    std::string_view        password,
    const handlers_t&       handlers,
    const http::request&    req, 
    http::response&         resp
)
{
    // print_http_request(req);

    // Make sure we can handle the method
    if( req.method != "GET"  &&
        req.method != "POST" &&
        req.method != "PUT")  
        return http_bad_request(req, resp, "Unknown HTTP-method");

    // Check the HTTP request is authorized
    // auto auth_res = handle_authorization(req, username, password);
    // if (!auth_res.first)
    //     return http_unauthorized(req, resp, auth_res.second);
        
    // Check handlers
    for (const auto& [key, hdl] : handlers)
    {
        if (key == req.uri)
        {
            try {
                boost::json::value req_jv;
                if (!req.content.empty())
                    req_jv = boost::json::parse(req.content);
                auto ret = std::invoke(hdl, req_jv);
                return http_json_data(req, resp, ret);
            } catch (const std::exception& e) {
                return http_bad_request(req, resp, fmt::format("Error parsing request body as JSON : `{}`", e.what()));
            }
            break;
        }   
    }

    // Request path must be absolute and not contain "..".
    if( req.uri.empty() ||
        req.uri[0] != '/' ||
        req.uri.find("..") != std::string_view::npos)
        return http_bad_request(req, resp, "Illegal request-target");

    // Build the path to the requested file
    const fs::path      uri  = req.uri == "/" ? "index.html" : req.uri;
    const std::string   path = fs::path(doc_root) / (uri.has_root_directory() ? uri.relative_path() : uri);

    // Attempt to open the file
    std::ifstream file(path);

    // Handle the case where the file doesn't exist
    if(!file.is_open())
        return http_not_found(req, resp);

    // Respond to GET request
    return http_file_data(req, resp, path, std::move(file));
}

awaitable_strand<void> websocket_session (
    tcp_socket sock
)
{
    
}

awaitable_strand<void> http_session (
    tcp_socket          sock, 
    std::string_view    doc_root,
    std::string_view    username,
    std::string_view    password,
    const handlers_t&   handlers
)
{
    try
    {
        http::request   req;
        http::response  resp;
        std::string     buf;
        
        for (;;)
        {
            // Read request
            size_t res = co_await http::async_http_read(sock, req, buf, deferred);

            // Manage websocket
            if (req.is_websocket_req())
            {
                // std::make_shared<websocket_session>(std::move(sock), websockets)->run(std::move(req));
                break;
            }

            // Handle request
            resp.clear();
            handle_request(doc_root, username, password, handlers, req, resp);

            // Write response
            const bool keep_alive = req.keep_alive();
            resp.prepare(keep_alive, req.http_version_major, req.http_version_minor);
            res = co_await async_http_write(sock, resp, deferred);

            // Shutdown if necessary
            if(!keep_alive)
            {
                // co_await sock.async_shutdown(deferred);
                sock.lowest_layer().shutdown(tcp_socket::shutdown_both);
                break;
            }
        }
    }
    catch(const std::exception& e)
    {
        printf("[session] %s\n", e.what());
    }
}

awaitable<void> listen (
    boost::asio::io_context&    ioc, 
    uint16_t                    port, 
    std::string_view            doc_root,
    std::string_view            username,
    std::string_view            password,
    const handlers_t&           handlers
)
{
    tcp_acceptor acceptor(ioc, {tcp::v4(), port});
    for (;;)
    {
        tcp_socket sock = co_await acceptor.async_accept(make_strand(ioc), deferred);
        co_spawn(sock.get_executor(), http_session(std::move(sock), doc_root, username, password, handlers), detached);
    }
}

int main()
{
    try
    {
        boost::asio::io_context ioc{1};
        boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&](auto, auto){ ioc.stop(); });

        uint16_t    port        = 8000;
        std::string doc_root    = "./web";
        std::string username    = "Tommy";
        std::string password    = "Aldridge";

        handlers_t handlers = {
            {"/status", [&](const boost::json::value& jv) -> handler_return {
                handler_return ret;
                ret.success = true;
                ret.response = "ok from here";
                return ret;
            }}
        };

        co_spawn(ioc, listen(ioc, port, doc_root, username, password, handlers), detached);

        ioc.run();
    }
    catch (const std::exception& e)
    {
        printf("Exception: %s\n", e.what());
    }
}