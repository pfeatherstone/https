#include <string>
#include <string_view>
#include <vector>
#include <fstream>
#include <filesystem>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/signal_set.hpp>
#include <http_async.h>
#include "CLI11.hpp"

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// Typedefs
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

using boost::asio::detached;
using boost::asio::ip::tcp;
using boost::asio::make_strand;
using tcp_acceptor      = boost::asio::basic_socket_acceptor<tcp, boost::asio::io_context::executor_type>;
using tcp_socket        = boost::asio::basic_stream_socket<tcp,   boost::asio::strand<boost::asio::io_context::executor_type>>;
using tls_socket        = boost::asio::ssl::stream<tcp_socket>;
using awaitable         = boost::asio::awaitable<void, boost::asio::io_context::executor_type>;
using awaitable_strand  = boost::asio::awaitable<void, boost::asio::strand<boost::asio::io_context::executor_type>>;
namespace fs = std::filesystem;

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
    uint16_t        port{};
    std::string     docroot;
    std::string     username;
    std::string     password;
    std::string     cert_file;
    std::string     key_file;
    std::string     key_password;
    bool            use_tls;
    http_handlers_t http_handlers;
    ws_handlers_t   ws_handlers;
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
    resp.status      = http::status_type::bad_request;
    resp.content_str = why;
}

void http_not_found (const http::request& req, http::response& resp)
{
    resp.status      = http::status_type::not_found;
    resp.content_str = "The resourse " + req.uri + " was not found";
}

void http_server_error (const http::request& req, http::response& resp, std::string what)
{
    resp.status      = http::status_type::internal_server_error;
    resp.content_str = "An error occured: " + what;
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
    const std::string login         = http::base64_decode(login_base64);

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
    if( req.verb != http::GET  &&
        req.verb != http::POST &&
        req.verb != http::PUT)  
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

template<class Socket>
struct websocket_impl : websocket, std::enable_shared_from_this<websocket_impl<Socket>>
{
    struct txbuf {std::vector<char> data; bool is_text;};

    Socket                  sock;
    std::shared_ptr<void>   ctx;
    std::vector<txbuf>      buf_write_queue;

    websocket_impl(Socket sock_, std::shared_ptr<void> ctx_) : sock{std::move(sock_)}, ctx{ctx_} {}

    void send(const char* data, std::size_t ndata, bool is_text);
    void enqueue(txbuf buf);
};

template<class Socket>
void websocket_impl<Socket>::send(const char* data, std::size_t ndata, bool is_text)
{
    txbuf buf;
    buf.is_text = is_text;
    buf.data.assign(data, data + ndata);

    boost::asio::dispatch(
        sock.get_executor(),
        std::bind_front(&websocket_impl::enqueue, this->shared_from_this(), std::move(buf)));
}

template<class Socket>
awaitable_strand websocket_write_loop(std::shared_ptr<websocket_impl<Socket>> ws);

template<class Socket>
void websocket_impl<Socket>::enqueue(txbuf buf)
{
    // Add to queue
    buf_write_queue.push_back(std::move(buf));

    // Check if we're already writing
    if (buf_write_queue.size() > 1)
        return;

    // We are not currently writing, restart write loop
    co_spawn(sock.get_executor(), websocket_write_loop(this->shared_from_this()), detached);
}

template<class Socket>
awaitable_strand websocket_write_loop(std::shared_ptr<websocket_impl<Socket>> ws)
{
    try 
    {
        while (!ws->buf_write_queue.empty())
        {
            auto buf = std::move(ws->buf_write_queue.front());
            ws->buf_write_queue.erase(begin(ws->buf_write_queue));
            co_await http::async_ws_write(ws->sock, buf.data, buf.is_text, true);
        }
    }
    catch(const std::exception& e)
    {
        ws->sock.lowest_layer().close(); // notifies read to stop
        fprintf(stderr, "[WS session] write loop : %s\n", e.what());
    }
}

template<class Socket>
awaitable_strand websocket_session (
    Socket                  sock,
    http::request           req,
    const ws_handlers_t&    handlers,
    std::shared_ptr<void>   ctx
)
{
    // Move into shared state
    auto state = std::make_shared<websocket_impl<Socket>>(std::move(sock), ctx);
    std::vector<char> buf;

    try 
    {
        // Handshake
        size_t ret = co_await http::async_ws_accept(state->sock, req);
        handlers.on_open(state);

        for(;;)
        {
            // Read
            const bool is_text = co_await http::async_ws_read(state->sock, buf, true);
            handlers.on_data(state, buf.data(), buf.size(), is_text);
        }
    }
    catch(const std::exception& e)
    {
        fprintf(stderr, "[WS session] read loop : %s\n", e.what());
    }

    sock.lowest_layer().close();
    handlers.on_close(state);
}

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// HTTP session
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

template<class Socket>
awaitable_strand http_session (
    Socket                  sock, 
    const api_options&      options,
    std::shared_ptr<void>   ctx
)
{
    try
    {
        http::request   req;
        http::response  resp;
        std::string     buf;

        // Complete TLS handshake if SSL
        if constexpr(std::is_same_v<Socket, tls_socket>)
            co_await sock.async_handshake(boost::asio::ssl::stream_base::server);
        
        for (;;)
        {
            // Read request
            size_t res = co_await http::async_http_read(sock, req, buf);

            // Manage websocket
            if (req.is_websocket_req())
            {
                co_spawn(sock.get_executor(), websocket_session(std::move(sock), std::move(req), options.ws_handlers, ctx), detached);
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
            res = co_await async_http_write(sock, resp, buf);

            // Shutdown if necessary
            if(!keep_alive)
            {
                if constexpr(std::is_same_v<Socket, tls_socket>)
                    co_await sock.async_shutdown();
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
    std::shared_ptr<boost::asio::ssl::context> ssl{nullptr};

    if (options.use_tls)
    {
        ssl = std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::tlsv13_server);
        ssl->set_options(
            boost::asio::ssl::context::default_workarounds | 
            boost::asio::ssl::context::no_sslv2 | 
            boost::asio::ssl::context::single_dh_use |
            boost::asio::ssl::context::verify_peer
        );
        ssl->set_password_callback([=](std::size_t, boost::asio::ssl::context_base::password_purpose) {return options.key_password;});
        ssl->use_certificate_chain_file(options.cert_file);
        ssl->use_private_key_file(options.key_file, boost::asio::ssl::context::pem);
    }

    tcp_acceptor acceptor(ioc, {tcp::v4(), options.port});

    for (;;)
    {
        tcp_socket sock = co_await acceptor.async_accept(make_strand(ioc));

        if (options.use_tls)
        {
            tls_socket tls_sock{std::move(sock), *ssl};
            co_spawn(sock.get_executor(), http_session(std::move(tls_sock), options, ssl), detached);
        }
        else
        {
            co_spawn(sock.get_executor(), http_session(std::move(sock), options, nullptr), detached);
        }
    }
}

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// Example webserver
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
    bool     use_tls{false};
    CLI::App app{"HTTP and Websocket server"};
    try {
        app.add_flag("--use_tls", use_tls, "Use TLS");
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {return app.exit(e);}

    try
    {
        std::ifstream fin0("./test/data/pride_and_prejudice.txt");
        std::ifstream fin1("./test/data/pride_and_prejudice.txt");

        boost::asio::io_context ioc{1};
        boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&](auto, auto){ ioc.stop(); });

        api_options options = {
            .port           = 8000,
            .docroot        = "./test/web",
            .username       = "Tommy",
            .password       = "Aldridge",
            .cert_file      = "./test/data/cert.pem",
            .key_file       = "./test/data/key.pem",
            .key_password   = "hello there",
            .use_tls        = use_tls,

            .http_handlers = {
                {"/darcy", [&](const http::request& req, http::response& reply)
                {
                    reply.status = http::status_type::ok;
                    reply.content_str = read_next(fin0, 2000);
                    reply.add_header(http::field::content_type, "text/plain");
                }}
            },

            .ws_handlers = {
                .on_open  = [](auto ws) {printf("Websocket connection open\n");},
                .on_close = [](auto ws) {printf("Websocket closed\n");},
                .on_data  = [&](auto ws, const char* data, size_t ndata, bool is_text) {
                    printf("Websocket received `%.*s`\n", (int)ndata, data);
                    auto msg = read_next(fin1, 2000);
                    ws->send(msg.data(), msg.size(), true);
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
