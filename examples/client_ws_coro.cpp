#include <chrono>
#include <boost/compat/bind_front.hpp>
#include <boost/asio/cancel_after.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/version.hpp>
#include <http_async.h>
#include "extra/CLI11.hpp"

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// Typedefs
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

using boost::compat::bind_front;
using boost::asio::detached;
using boost::asio::ip::tcp;
using boost::asio::make_strand;
using tcp_socket            = boost::asio::basic_stream_socket<tcp, boost::asio::strand<boost::asio::io_context::executor_type>>;
using tls_socket            = boost::asio::ssl::stream<tcp_socket>;
using yield_context_strand  = boost::asio::basic_yield_context<boost::asio::strand<boost::asio::io_context::executor_type>>;
using namespace std::chrono_literals;

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// WS session
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

void ws_session(std::string host, uint16_t port, std::string msg, yield_context_strand yield)
{
    try
    {
        // Connect
        tcp_socket          sock(yield.get_executor());
        tcp::resolver       resolver(sock.get_executor());
        std::vector<char>   buf(begin(msg), end(msg));
        size_t              ret{};

        // Async IO
        boost::asio::async_connect(sock, resolver.async_resolve(host, std::to_string(port), yield), boost::asio::cancel_after(5s, yield));
        http::async_ws_handshake(sock, host, "/ws", yield);
        ret = http::async_ws_write(sock, buf, true, false, yield);
        ret = http::async_ws_read(sock, buf, false, yield);
        http::async_ws_close(sock, http::ws_going_away, false, yield);

        // Print echo
        printf("Server echoed back\n\"%.*s\"\n", (int)buf.size(), buf.data());
    }
    catch(const boost::system::system_error& e)
    {
        if (e.code() != boost::asio::error::eof)
            fprintf(stderr, "[HTTP session] %s\n", e.what());
    }
}

void ws_ssl_session(std::string host, uint16_t port, std::string msg, yield_context_strand yield)
{
    try
    {
        // SSL
        boost::asio::ssl::context ssl(boost::asio::ssl::context::tlsv12_client);
        ssl.set_verify_callback([](bool preverified, boost::asio::ssl::verify_context& ctx) {return true;});
        ssl.set_verify_mode(boost::asio::ssl::verify_peer);

        // Connect
        tls_socket          sock(tcp_socket(yield.get_executor()), ssl);
        tcp::resolver       resolver(sock.get_executor());
        std::vector<char>   buf(begin(msg), end(msg));
        size_t              ret{};

        // Async IO
        boost::asio::async_connect(sock.next_layer(), resolver.async_resolve(host, std::to_string(port), yield), boost::asio::cancel_after(5s, yield));
        sock.async_handshake(boost::asio::ssl::stream_base::client, yield);
        http::async_ws_handshake(sock, host, "/ws", yield);
        ret = http::async_ws_write(sock, buf, true, false, yield);
        ret = http::async_ws_read(sock, buf, false, yield);
        http::async_ws_close(sock, http::ws_going_away, false, yield);
        sock.async_shutdown(yield);

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
            boost::asio::spawn(make_strand(ioc), bind_front(ws_ssl_session, host, port, msg), detached);
        else
            boost::asio::spawn(make_strand(ioc), bind_front(ws_session, host, port, msg), detached);
        ioc.run();
    }
    catch (const std::exception& e)
    {
        printf("Exception: %s\n", e.what());
    }
}