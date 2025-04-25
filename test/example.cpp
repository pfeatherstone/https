#include <string>
#include <string_view>
#include <vector>
#include <fstream>
#include <filesystem>
#include <fmt/format.h>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/signal_set.hpp>
#include <http_async.h>
#include <http_base64.h>

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// Typedefs
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

using boost::asio::detached;
using boost::asio::deferred;
using boost::asio::ip::tcp;
using boost::asio::make_strand;
using tcp_acceptor      = boost::asio::basic_socket_acceptor<tcp, boost::asio::io_context::executor_type>;
using tcp_socket        = boost::asio::basic_stream_socket<tcp,   boost::asio::strand<boost::asio::io_context::executor_type>>;
// using tls_socket    = boost::asio::ssl::stream<tcp_socket>;
using awaitable         = boost::asio::awaitable<void, boost::asio::io_context::executor_type>;
using awaitable_strand  = boost::asio::awaitable<void, boost::asio::strand<boost::asio::io_context::executor_type>>;
namespace fs = std::filesystem;

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// Example Data
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

std::string read_next(std::ifstream& fin, const size_t ncharacters)
{
    if (fin.eof())
    {
        fin.clear();
        fin.seekg(0);
    }

    std::string msg(ncharacters, '\0');
    fin.read(&msg[0], msg.size());
    msg.resize(fin.gcount());
    return msg;   
}

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// Example API
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

struct websocket
{
    virtual void send(const char* data, std::size_t ndata, bool is_text) = 0;
};

using http_handler_t    = std::function<void(const http::request& req, http::response& reply)>;
using http_handlers_t   = std::vector<std::pair<std::string_view, http_handler_t>>;
using ws_onopen_t       = std::function<void(std::shared_ptr<websocket> sock)>;
using ws_onclose_t      = std::function<void(std::shared_ptr<websocket> sock)>;
using ws_ondata_t       = std::function<void(std::shared_ptr<websocket> sock, const char* data, std::size_t ndata, bool is_text)>;
using ws_handlers_t     = struct{ws_onopen_t on_open; ws_onclose_t on_close; ws_ondata_t on_data;};

struct api_options
{
    uint16_t            port{};
    std::string_view    docroot;
    std::string_view    username;
    std::string_view    password;
    http_handlers_t     http_handlers;
    ws_handlers_t       ws_handlers;
};

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// Helpers
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

    constexpr std::string_view lskip(std::string_view str, std::string_view chrs)
    {
        auto pos = str.find(chrs);

        if (pos != std::string_view::npos)
            str = str.substr(pos + chrs.size());

        return str;
    }

    constexpr auto split_once(std::string_view str, std::string_view chrs)
    {
        auto pos = str.find(chrs);

        std::string_view first = str.substr(0, pos);
        std::string_view second = str.substr(pos+chrs.size());

        return std::make_pair(first, second);
    }

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// HTTP handling
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

void http_unauthorized (const http::request& req, http::response& resp, std::string msg)
{
    resp.status = http::status_type::unauthorized;
    resp.add_header(http::field::www_authenticate,    "Basic realm=\"Access to the staging site\"");
    resp.add_header(http::field::cache_control,       "no-store");
    resp.content_str = std::move(msg);
}

void http_bad_request (const http::request& req, http::response& resp, std::string_view why)
{
    resp.status         = http::status_type::bad_request;
    resp.content_str    = why;
}

void http_not_found (const http::request& req, http::response& resp)
{
    resp.status         = http::status_type::not_found;
    resp.content_str    = fmt::format("The resource {} was not found", req.uri);
}

void http_server_error (const http::request& req, http::response& resp, std::string what)
{
    resp.status         = http::status_type::internal_server_error;
    resp.content_str    = fmt::format("An error occured: {}", what); 
}

void http_file_data (const http::request& req, http::response& resp, std::string_view path, http::file_ptr file)
{
    resp.status = http::status_type::ok;
    resp.add_header(http::field::content_type,    http::get_mime_type(path));
    resp.add_header(http::field::cache_control,   "no-cache, no-store, must-revalidate, private, max-age=0");
    resp.add_header(http::field::pragma,          "no-cache");
    resp.add_header(http::field::expires,         "0");
    resp.content_file = std::move(file);
}

auto handle_authorization (const http::request& req, std::string_view username_exp, std::string_view passwd_exp)
{       
    auto field = req.find(http::field::authorization);
    if (field == end(req.headers))
        return std::make_pair(false, "Missing Authorization field");
    
    std::string_view  login_base64  = lskip(field->value, "Basic ");
    const std::string login         = http::from_base64(login_base64);

    const auto [user, passwd] = split_once(login, ":");

    if (user.compare(username_exp) != 0 || passwd.compare(passwd_exp) != 0)
        return std::make_pair(false, "Authentication username-password don't match expected");

    return std::make_pair(true, "Authenticated!");
}

void handle_request (
    std::string_view        doc_root, 
    std::string_view        username_exp,
    std::string_view        password_exp,
    const http_handlers_t&  handlers,
    const http::request&    req, 
    http::response&         resp
)
{
    // Make sure we can handle the method
    if( req.method != "GET"  &&
        req.method != "POST" &&
        req.method != "PUT")  
        return http_bad_request(req, resp, "Unknown HTTP-method");

    // Check the HTTP request is authorized
    auto auth_res = handle_authorization(req, username_exp, password_exp);
    if (!auth_res.first)
        return http_unauthorized(req, resp, auth_res.second);
        
    // Check handlers - catch exceptions in case json parsing or something else fails, in which case, send a "bad" response
    try
    {
        for (const auto& [key, hdl] : handlers)
            if (key == req.uri)
                return std::invoke(hdl, req, resp);
    }
    catch(const std::exception& e)
    {
        return http_bad_request(req, resp, e.what());
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
    http::file_ptr file(fopen(path.c_str(), "r"));

    // Handle the case where the file doesn't exist
    if(!file || ferror(file.get()) || feof(file.get()))
        return http_not_found(req, resp);

    // Respond to GET request
    return http_file_data(req, resp, path, std::move(file));
}

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// WS session
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

struct websocket_impl : websocket, std::enable_shared_from_this<websocket_impl>
{
    struct txbuf {std::vector<char> data; http::websocket_opcode code;};

    tcp_socket          sock;
    std::vector<txbuf>  buf_write_queue;

    websocket_impl(tcp_socket sock_) : sock{std::move(sock_)} {}

    void send(const char* data, std::size_t ndata, bool is_text);
    void enqueue(txbuf buf);
};

void websocket_impl::send(const char* data, std::size_t ndata, bool is_text)
{
    txbuf buf;
    buf.code = is_text ? http::WS_OPCODE_DATA_TEXT : http::WS_OPCODE_DATA_BINARY;
    buf.data.assign(data, data + ndata);

    boost::asio::dispatch(
        sock.get_executor(),
        std::bind_front(&websocket_impl::enqueue, shared_from_this(), std::move(buf)));
}

awaitable_strand websocket_write_loop(std::shared_ptr<websocket_impl> ws);

void websocket_impl::enqueue(txbuf buf)
{
    // Add to queue
    buf_write_queue.push_back(std::move(buf));

    // Check if we're already writing
    if (buf_write_queue.size() > 1)
        return;

    // We are not currently writing, restart write loop
    co_spawn(sock.get_executor(), websocket_write_loop(shared_from_this()), detached);
}

awaitable_strand websocket_write_loop(std::shared_ptr<websocket_impl> ws)
{
    try 
    {
        while (!ws->buf_write_queue.empty())
        {
            auto buf = std::move(ws->buf_write_queue.front());
            ws->buf_write_queue.erase(begin(ws->buf_write_queue));
            co_await http::async_ws_write(ws->sock, buf.data, buf.code, false, deferred);
        }
    }
    catch(const std::exception& e)
    {
        ws->sock.lowest_layer().close(); // notifies read to stop
        fprintf(stderr, "[WS session] %s\n", e.what());
    }
}

awaitable_strand websocket_session (
    tcp_socket              sock,
    http::request           req,
    const ws_handlers_t&    handlers
)
{
    // Move into shared state
    auto state = std::make_shared<websocket_impl>(std::move(sock));
    std::vector<char> buf;

    try 
    {
        // Handshake
        size_t ret = co_await http::async_ws_accept(state->sock, req, deferred);
        handlers.on_open(state);

        for(;;)
        {
            // Read
            http::websocket_opcode opcode = co_await http::async_ws_read(state->sock, buf, deferred);

            if (opcode == http::WS_OPCODE_CONTINUATION)
                break; // This shouldn't happen
            else if (opcode == http::WS_OPCODE_CLOSE)
                break; // Legit need to close
            else if (opcode == http::WS_OPCODE_PONG)
                continue; // Nothing to do
            else if (opcode == http::WS_OPCODE_PING)
                state->enqueue({buf, http::WS_OPCODE_PONG});
            else if (opcode == http::WS_OPCODE_DATA_TEXT)
                handlers.on_data(state, buf.data(), buf.size(), true);
            else if (opcode == http::WS_OPCODE_DATA_BINARY)
                handlers.on_data(state, buf.data(), buf.size(), false);
        }
    }
    catch(const std::exception& e)
    {
        fprintf(stderr, "[WS session] %s\n", e.what());
    }

    sock.lowest_layer().close();
    handlers.on_close(state);
}

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// HTTP session
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

awaitable_strand http_session (
    tcp_socket          sock, 
    const api_options&  options
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
                co_spawn(sock.get_executor(), websocket_session(std::move(sock), std::move(req), options.ws_handlers), detached);
                break;
            }

            // Reset response, set http version and keep alive status of response
            resp.clear();
            resp.http_version_major = req.http_version_major;
            resp.http_version_minor = req.http_version_minor;
            resp.keep_alive(req.keep_alive());
            
            // Handle request and set response
            handle_request(options.docroot, options.username, options.password, options.http_handlers, req, resp);

            // Write response
            const bool keep_alive = req.keep_alive();
            res = co_await async_http_write(sock, resp, buf, deferred);

            // Shutdown if necessary
            if(!keep_alive)
            {
                // co_await sock.async_shutdown(deferred);
                sock.lowest_layer().shutdown(tcp_socket::shutdown_both);
                break;
            }
        }
    }
    catch(const boost::system::system_error& e)
    {
        if (e.code() != boost::asio::error::eof)
            fprintf(stderr, "[HTTP session] %s\n", e.what());
    }
}

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// Listener
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

awaitable listen (
    boost::asio::io_context&    ioc, 
    const api_options&          options
)
{
    tcp_acceptor acceptor(ioc, {tcp::v4(), options.port});
    for (;;)
    {
        tcp_socket sock = co_await acceptor.async_accept(make_strand(ioc), deferred);
        co_spawn(sock.get_executor(), http_session(std::move(sock), options), detached);
    }
}

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// Example webserver
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

int main()
{
    try
    {
        std::ifstream fin("./test/pride_and_prejudice.txt");

        boost::asio::io_context ioc{1};
        boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&](auto, auto){ ioc.stop(); });

        api_options options = {
            .port       = 8000,
            .docroot    = "./test/web",
            .username   = "Tommy",
            .password   = "Aldridge",

            .http_handlers = {
                {"/darcy", [&](const http::request& req, http::response& reply)
                {
                    reply.status = http::status_type::ok;
                    reply.content_str = read_next(fin, 2000);
                    reply.add_header(http::field::content_type, "text/plain");
                }}
            },

            .ws_handlers = {
                .on_open  = [](auto ws) {printf("Websocket connection open\n");},
                .on_close = [](auto ws) {printf("Websocket closed\n");},
                .on_data  = [](auto ws, const char* data, size_t ndata, bool is_text) {
                    printf("Websocket received %zu bytes. Echoing back\n", ndata);
                    ws->send(data, ndata, is_text);
                }
            }
        };

        co_spawn(ioc, listen(ioc, options), detached);

        ioc.run();
    }
    catch (const std::exception& e)
    {
        printf("Exception: %s\n", e.what());
    }

    printf("Done\n");
}