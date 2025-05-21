#include <boost/asio/co_spawn.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <http_async.h>

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// Typedefs
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

using boost::asio::detached;
using boost::asio::ip::tcp;
using boost::asio::make_strand;
using tcp_socket        = boost::asio::basic_stream_socket<tcp,   boost::asio::strand<boost::asio::io_context::executor_type>>;
using tls_socket        = boost::asio::ssl::stream<tcp_socket>;
using awaitable         = boost::asio::awaitable<void, boost::asio::io_context::executor_type>;
using awaitable_strand  = boost::asio::awaitable<void, boost::asio::strand<boost::asio::io_context::executor_type>>;

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// HTTP session
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// HTTP session
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

awaitable_strand http_session(std::string_view host)
{
    try
    {
        // Connect
        tcp_socket      sock(co_await boost::asio::this_coro::executor);
        tcp::resolver   resolver(sock.get_executor());
        co_await boost::asio::async_connect(sock, co_await resolver.async_resolve(host, "80"));
        printf("Connected\n");

        http::request   req;
        http::response  resp;
        std::string     buf;
        size_t          ret{};

        // Write request
        req.method = "GET";
        req.uri    = "/get";
        req.http_version_major = req.http_version_minor = 1;
        req.add_header(http::host, host);
        // req.add_header(http::accept, "*/*");
        ret = co_await http::async_http_write(sock, req, buf);
        printf("Request sent\n");

        // Receive response
        ret = co_await http::async_http_read(sock, resp, buf);
        printf("Response received\n");
    }
    catch(const boost::system::system_error& e)
    {
        if (e.code() != boost::asio::error::eof)
            fprintf(stderr, "[HTTP session] %s\n", e.what());
    }
}

int main(int argc, char* argv[])
{
    boost::asio::io_context ioc{1};

    try
    {
        co_spawn(make_strand(ioc), http_session("postman-echo.com"), detached);
        ioc.run();
    }
    catch (const std::exception& e)
    {
        printf("Exception: %s\n", e.what());
    }

    printf("Done\n");
}