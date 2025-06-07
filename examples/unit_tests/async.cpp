#include <string_view>
#include <vector>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/basic_resolver.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/connect.hpp>
#include <http_async.h>
#include "doctest.h"

using boost::asio::ip::tcp;
using boost::asio::ip::make_address_v4;
using tcp_acceptor  = boost::asio::basic_socket_acceptor<tcp, boost::asio::io_context::executor_type>;
using tcp_socket    = boost::asio::basic_stream_socket<tcp,   boost::asio::io_context::executor_type>;
using tcp_resolver  = boost::asio::ip::basic_resolver<tcp,    boost::asio::io_context::executor_type>; 
using tcp_endpoint  = boost::asio::ip::tcp::endpoint;

TEST_SUITE("[ASYNC]")
{
    TEST_CASE("HTTP GET")
    {
        boost::asio::io_context ioc{1};
        tcp_acceptor acceptor(ioc, {tcp::v4(), 6666});
        tcp_socket   peer(ioc);
        tcp_socket   client(ioc);
        tcp_resolver resolver(ioc);
        bool         exception_thrown{false};

        http::request   req_client, req_peer;
        http::response  resp_client, resp_peer;
        std::string     buf_client;
        std::string     buf_peer;

        req_client.verb   = http::GET;
        req_client.uri    = "/data?name=bane&code=Peace+is+a+lie.+There+is+only+Passion.";
        req_client.add_header(http::host, "hello there!");
        req_client.add_header(http::user_agent, "Boost::asio " + std::to_string(BOOST_ASIO_VERSION)); // optional header

        resp_peer.status = http::ok;
        resp_peer.content_str = "There is only passion";
        
        try
        {
            acceptor.async_accept(peer, [&](boost::system::error_code ec) {
                REQUIRE(!bool(ec));
                http::async_http_read(peer, req_peer, buf_peer, [&](boost::system::error_code ec, size_t){
                    REQUIRE(!bool(ec));
                    http::async_http_write(peer, resp_peer, buf_peer, [&](boost::system::error_code ec, size_t){
                        REQUIRE(!bool(ec));
                    });
                });
            });

            resolver.async_resolve("localhost", "6666", [&](boost::system::error_code ec, const auto& endpoints) {
                REQUIRE(!bool(ec));
                boost::asio::async_connect(client, endpoints, [&](boost::system::error_code ec, auto endpoint) {
                    REQUIRE(!bool(ec));
                    http::async_http_write(client, req_client, buf_client, [&](boost::system::error_code ec, size_t) {
                        REQUIRE(!bool(ec));
                        http::async_http_read(client, resp_client, buf_client, [&](boost::system::error_code ec, size_t) {
                            REQUIRE(!bool(ec));
                        });
                    });
                });
            });

            ioc.run();
        }
        catch(const std::exception& e)
        {
            exception_thrown = true;
        }

        REQUIRE(!exception_thrown);
        REQUIRE(req_peer.verb == http::GET);
        REQUIRE(req_peer.uri == "/data");
        REQUIRE(req_peer.params.size() == 2);
        REQUIRE(req_peer.params[0].key == "name");
        REQUIRE(req_peer.params[0].val == "bane");
        REQUIRE(req_peer.params[1].key == "code");
        REQUIRE(req_peer.params[1].val == "Peace is a lie. There is only Passion.");
        REQUIRE(req_peer.headers.size() == req_client.headers.size());
        for (size_t i = 0 ; i < req_peer.headers.size() ; ++i)
        {
            REQUIRE(req_peer.headers[i].key   == req_client.headers[i].key);
            REQUIRE(req_peer.headers[i].value == req_client.headers[i].value);
        }

        REQUIRE(resp_client.status == http::ok);
        REQUIRE(resp_client.content_str == "There is only passion");
        REQUIRE(resp_peer.headers.size() == resp_client.headers.size());
        for (size_t i = 0 ; i < resp_client.headers.size() ; ++i)
        {
            REQUIRE(resp_peer.headers[i].key   == resp_client.headers[i].key);
            REQUIRE(resp_peer.headers[i].value == resp_client.headers[i].value);
        }
    }
}