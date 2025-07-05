#include <chrono>
#include <boost/asio/cancel_after.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/version.hpp>
#include <http_async.h>
#include "extra/yyjson.h"

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// Typedefs
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

using boost::asio::deferred;
using boost::asio::detached;
using boost::asio::ip::tcp;
using boost::asio::make_strand;
using tcp_socket        = boost::asio::basic_stream_socket<tcp, boost::asio::strand<boost::asio::io_context::executor_type>>;
using http_socket       = http::stream<tcp_socket>;
using awaitable         = boost::asio::awaitable<void, boost::asio::io_context::executor_type>;
using awaitable_strand  = boost::asio::awaitable<void, boost::asio::strand<boost::asio::io_context::executor_type>>;
using namespace std::chrono_literals;

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// HTTP session
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

void print_header(const http::response& resp)
{
    printf("Status : %u - %s\n", resp.status, status_label(resp.status).data());
    printf("Headers:\n");
    for (size_t i{0} ; i < resp.headers.size() ; ++i)
    {
        const auto [k,v] = resp.headers[i];
        printf("\t%s : %.*s\n", field_label(k).data(), (int)v.size(), v.data());
    }
}

void print_json_body(const http::response& resp)
{
    printf("Body:\n");
    yyjson_doc *doc = yyjson_read(resp.content_str.c_str(), resp.content_str.size(), 0);
    if (doc)
        yyjson_write_fp(stdout, doc, YYJSON_WRITE_PRETTY, nullptr, nullptr);
    yyjson_doc_free(doc);
    printf("\n");
}

awaitable_strand http_session(std::string_view host)
{
    try
    {
        // Connect
        http_socket     sock(tcp_socket{co_await boost::asio::this_coro::executor}, false);
        tcp::resolver   resolver(sock.get_executor());
        http::request   req;
        http::response  resp;
        size_t          ret{};

        // Prepare request
        req.verb   = http::METHOD_GET;
        req.uri    = "/get";
        req.headers.add(http::host, host); // mandatory in HTTP/1.1 in request messages
        req.headers.add(http::user_agent, "Boost::asio " + std::to_string(BOOST_ASIO_VERSION)); // optional header

        // Async IO
        co_await boost::asio::async_connect(sock.next_layer(), co_await resolver.async_resolve(host, "80"), boost::asio::cancel_after(5s, deferred));
        ret = co_await http::async_http_write(sock, req);
        ret = co_await http::async_http_read(sock,  resp);

        // Print response
        print_header(resp);
        if (auto it = resp.headers.find(http::content_type); it && it->find("application/json") != size_t(-1))
            print_json_body(resp);   
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
}