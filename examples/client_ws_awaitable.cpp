#include <chrono>
#include <boost/asio/cancel_after.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/version.hpp>
#include <http_async.h>
#include "extra/CLI11.hpp"

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// Typedefs
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

using boost::asio::detached;
using boost::asio::ip::tcp;
using boost::asio::make_strand;
using tcp_socket        = boost::asio::basic_stream_socket<tcp, boost::asio::strand<boost::asio::io_context::executor_type>>;
using tls_socket        = boost::asio::ssl::stream<tcp_socket>;
using awaitable_strand  = boost::asio::awaitable<void, boost::asio::strand<boost::asio::io_context::executor_type>>;
using namespace std::chrono_literals;

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// WS session
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

awaitable_strand ws_session(std::string host, uint16_t port, std::string msg)
{
    try
    {
        // Connect
        tcp_socket          sock(co_await boost::asio::this_coro::executor);
        tcp::resolver       resolver(sock.get_executor());
        std::vector<char>   buf(begin(msg), end(msg));
        size_t              ret{};

        // Async IO
        co_await boost::asio::async_connect(sock, co_await resolver.async_resolve(host, std::to_string(port)), boost::asio::cancel_after(5s));
        co_await http::async_ws_handshake(sock, host, "/ws");
        ret = co_await http::async_ws_write(sock, buf, true, false);
        ret = co_await http::async_ws_read(sock, buf, false);
        co_await http::async_ws_close(sock, http::ws_going_away, false);

        // Print echo
        printf("Server echoed back\n\"%.*s\"\n", (int)buf.size(), buf.data());
    }
    catch(const boost::system::system_error& e)
    {
        if (e.code() != boost::asio::error::eof)
            fprintf(stderr, "[HTTP session] %s\n", e.what());
    }
}

awaitable_strand ws_ssl_session(std::string host, uint16_t port, std::string msg)
{
    try
    {
        // SSL
        boost::asio::ssl::context ssl(boost::asio::ssl::context::tlsv12_client);
        ssl.set_verify_callback([](bool preverified, boost::asio::ssl::verify_context& ctx) {return true;});
        ssl.set_verify_mode(boost::asio::ssl::verify_peer);

        // Connect
        tls_socket          sock(tcp_socket(co_await boost::asio::this_coro::executor), ssl);
        tcp::resolver       resolver(sock.get_executor());
        std::vector<char>   buf(begin(msg), end(msg));
        size_t              ret{};

        // Async IO
        co_await boost::asio::async_connect(sock.next_layer(), co_await resolver.async_resolve(host, std::to_string(port)), boost::asio::cancel_after(5s));
        co_await sock.async_handshake(boost::asio::ssl::stream_base::client);
        co_await http::async_ws_handshake(sock, host, "/ws");
        ret = co_await http::async_ws_write(sock, buf, true, false);
        ret = co_await http::async_ws_read(sock, buf, false);
        co_await http::async_ws_close(sock, http::ws_going_away, false);
        co_await sock.async_shutdown();

        // Print echo
        printf("Server echoed back\n\"%.*s\"\n", (int)buf.size(), buf.data());
    }
    catch(const boost::system::system_error& e)
    {
        if (e.code() != boost::asio::error::eof)
            fprintf(stderr, "[HTTP session] %s\n", e.what());
    }
}

int main(int argc, char* argv[])
{
    std::string host;
    uint16_t    port;
    std::string msg;
    bool        use_tls;
    CLI::App app{"WebSocket echo client"};
    try{
        app.add_option("--host", host, "Host or IP address of WebSocket server")->required();
        app.add_option("--port", port, "Port of WebSocket server")->required();
        app.add_option("--msg",  msg,  "Message to be echoed back by server")->required();
        app.add_flag("--tls", use_tls, "Use transport over TLS");
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {return app.exit(e);}
    
    boost::asio::io_context ioc{1};

    try
    {
        if (use_tls)
            co_spawn(make_strand(ioc), ws_ssl_session(host, port, msg), detached);
        else
            co_spawn(make_strand(ioc), ws_session(host, port, msg), detached);
        ioc.run();
    }
    catch (const std::exception& e)
    {
        printf("Exception: %s\n", e.what());
    }
}