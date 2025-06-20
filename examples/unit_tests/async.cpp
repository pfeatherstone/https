#include <string_view>
#include <vector>
#include <random>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/basic_resolver.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/spawn.hpp>
#include <http_async.h>
#include "doctest.h"

using boost::asio::as_tuple;
using boost::asio::deferred;
using boost::asio::detached;
using boost::asio::ip::tcp;
using boost::asio::ip::make_address_v4;
using tcp_acceptor  = boost::asio::basic_socket_acceptor<tcp, boost::asio::io_context::executor_type>;
using tcp_socket    = boost::asio::basic_stream_socket<tcp,   boost::asio::io_context::executor_type>;
using tcp_resolver  = boost::asio::ip::basic_resolver<tcp,    boost::asio::io_context::executor_type>; 
using tcp_endpoint  = boost::asio::ip::tcp::endpoint;
using http_socket   = http::stream<tcp_socket>;
using awaitable     = boost::asio::awaitable<void, boost::asio::io_context::executor_type>;
using yield_context = boost::asio::basic_yield_context<boost::asio::io_context::executor_type>;

TEST_SUITE("[ASYNC]")
{
    TEST_CASE("HTTP GET")
    {
        boost::asio::io_context ioc{1};
        tcp_acceptor acceptor(ioc, {tcp::v4(), 6666});
        http_socket  peer(tcp_socket{ioc}, true);
        http_socket  client(tcp_socket{ioc}, false);
        tcp_resolver resolver(ioc);
        bool         exception_thrown{false};

        http::request   req_client, req_peer;
        http::response  resp_client, resp_peer;

        req_client.verb   = http::METHOD_GET;
        req_client.uri    = "/data?name=bane&code=Peace+is+a+lie.+There+is+only+Passion.";
        req_client.add_header(http::host, "hello there!");
        req_client.add_header(http::user_agent, "Boost::asio " + std::to_string(BOOST_ASIO_VERSION)); // optional header

        resp_peer.status = http::ok;
        resp_peer.content_str = "There is only passion";
        
        SUBCASE("async")
        {
            try
            {
                acceptor.async_accept(peer.lowest_layer(), [&](boost::system::error_code ec) {
                    REQUIRE(!bool(ec));
                    http::async_http_read(peer, req_peer, [&](boost::system::error_code ec, size_t){
                        REQUIRE(!bool(ec));
                        http::async_http_write(peer, resp_peer, [&](boost::system::error_code ec, size_t){
                            REQUIRE(!bool(ec));
                        });
                    });
                });

                resolver.async_resolve("localhost", "6666", [&](boost::system::error_code ec, const auto& endpoints) {
                    REQUIRE(!bool(ec));
                    boost::asio::async_connect(client.lowest_layer(), endpoints, [&](boost::system::error_code ec, auto endpoint) {
                        REQUIRE(!bool(ec));
                        http::async_http_write(client, req_client, [&](boost::system::error_code ec, size_t) {
                            REQUIRE(!bool(ec));
                            http::async_http_read(client, resp_client, [&](boost::system::error_code ec, size_t) {
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
        }

        SUBCASE("awaitable")
        {
            try
            {
                const auto run_server = [&]() -> awaitable
                {
                    co_await acceptor.async_accept(peer.lowest_layer());
                    co_await http::async_http_read(peer, req_peer);
                    co_await http::async_http_write(peer, resp_peer);
                };

                const auto run_client = [&]() -> awaitable
                {
                    co_await boost::asio::async_connect(client.lowest_layer(), co_await resolver.async_resolve("localhost", "6666"));
                    co_await http::async_http_write(client, req_client);
                    co_await http::async_http_read(client, resp_client);
                };

                co_spawn(ioc, run_server(), detached);
                co_spawn(ioc, run_client(), detached);
                ioc.run();
            }
            catch(const std::exception& e)
            {
                exception_thrown = true;
            }
        }

        SUBCASE("coro")
        {
            try
            {
                const auto run_server = [&](yield_context yield)
                {
                    acceptor.async_accept(peer.lowest_layer(), yield);
                    http::async_http_read(peer, req_peer, yield);
                    http::async_http_write(peer, resp_peer, yield);
                };

                const auto run_client = [&](yield_context yield)
                {
                    boost::asio::async_connect(client.lowest_layer(), resolver.async_resolve("localhost", "6666", yield), yield);
                    http::async_http_write(client, req_client, yield);
                    http::async_http_read(client, resp_client, yield);
                };

                boost::asio::spawn(ioc, run_server, detached);
                boost::asio::spawn(ioc, run_client, detached);
                ioc.run();
            }
            catch(const std::exception& e)
            {
                exception_thrown = true;
            }
        }

        REQUIRE(!exception_thrown);
        REQUIRE(req_peer.verb == http::METHOD_GET);
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

    TEST_CASE("WEBSOCKET")
    {
        boost::asio::io_context ioc{1};
        tcp_acceptor acceptor(ioc, {tcp::v4(), 6667});
        http_socket  peer(tcp_socket(ioc), true);
        http_socket  client(tcp_socket(ioc), false);
        tcp_resolver resolver(ioc);
        bool         exception_thrown{false};

        http::request     req;
        std::vector<char> data;
        std::string       text;
        std::vector<char> data_peer;
        std::vector<char> data_client;
        std::string       text_peer;
        std::string       text_client;

        std::mt19937 eng(std::random_device{}());
        std::uniform_int_distribution<unsigned int> d{0, 255};
        data.resize(1024);
        std::generate(begin(data), end(data), [&]{return static_cast<char>(d(eng));});
        text  = "Peace is a lie. There is only passion.";
        text += "Through passion, I gain strength.";
        text += "Through strength, I gain power.";
        text += "Through power, I gain victory.";

        SUBCASE("async - client sends")
        {
            try 
            {
                acceptor.async_accept(peer.lowest_layer(), [&](boost::system::error_code ec) {
                    REQUIRE(!bool(ec));
                    http::async_http_read(peer, req, [&](boost::system::error_code ec, size_t){
                        REQUIRE(!bool(ec));
                        REQUIRE(req.is_websocket_req());
                        http::async_ws_accept(peer, req, [&](boost::system::error_code ec, std::size_t) {
                            REQUIRE(!bool(ec));
                            http::async_ws_read(peer, data_peer, [&](boost::system::error_code ec, bool is_text) {
                                REQUIRE(!bool(ec));
                                REQUIRE(!is_text);
                                REQUIRE(data_peer == data);
                                http::async_ws_read(peer, text_peer, [&](boost::system::error_code ec, bool is_text) {
                                    REQUIRE(!bool(ec));
                                    REQUIRE(is_text);
                                    REQUIRE(text_peer == text);
                                    http::async_ws_read(peer, data_peer, [&](boost::system::error_code ec, bool is_text) {
                                        REQUIRE(ec == http::ws_going_away);
                                    });
                                });
                            });
                        });
                    });
                });

                resolver.async_resolve("localhost", "6667", [&](boost::system::error_code ec, const auto& endpoints) {
                    REQUIRE(!bool(ec));
                    boost::asio::async_connect(client.lowest_layer(), endpoints, [&](boost::system::error_code ec, auto endpoint) {
                        REQUIRE(!bool(ec));
                        http::async_ws_handshake(client, "localhost", "/ws", [&](boost::system::error_code ec) {
                            REQUIRE(!bool(ec));
                            http::async_ws_write(client, boost::asio::buffer(data), false, [&](boost::system::error_code ec, std::size_t) {
                                REQUIRE(!bool(ec));
                                http::async_ws_write(client, boost::asio::buffer(text), true, [&](boost::system::error_code ec, std::size_t) {
                                    REQUIRE(!bool(ec));
                                    http::async_ws_close(client, http::ws_going_away, [&](boost::system::error_code ec) {
                                        REQUIRE(!bool(ec));
                                    });
                                });
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
        }

        SUBCASE("awaitable - client sends")
        {
            try 
            {
                const auto run_server = [&]() -> awaitable
                {
                    bool is_text{};
                    co_await acceptor.async_accept(peer.lowest_layer());
                    co_await http::async_http_read(peer, req);
                    REQUIRE(req.is_websocket_req());
                    co_await http::async_ws_accept(peer, req);
                    is_text = co_await http::async_ws_read(peer, data_peer);
                    REQUIRE(!is_text);
                    REQUIRE(data_peer == data);
                    is_text = co_await http::async_ws_read(peer, text_peer);
                    REQUIRE(is_text);
                    REQUIRE(text_peer == text);
                    auto [ec, is_text2] = co_await http::async_ws_read(peer, data_peer, as_tuple(deferred));
                    REQUIRE(ec == http::ws_going_away);
                };

                const auto run_client = [&]() -> awaitable
                {
                    co_await boost::asio::async_connect(client.lowest_layer(), co_await resolver.async_resolve("localhost", "6667"));
                    co_await http::async_ws_handshake(client, "localhost", "/ws");
                    co_await http::async_ws_write(client, boost::asio::buffer(data), false);
                    co_await http::async_ws_write(client, boost::asio::buffer(text), true);
                    co_await http::async_ws_close(client, http::ws_going_away);
                };

                co_spawn(ioc, run_server(), detached);
                co_spawn(ioc, run_client(), detached);
                ioc.run();
            }
            catch(const std::exception& e)
            {
                exception_thrown = true;
            }
        }

        SUBCASE("coro - client sends")
        {
            try 
            {
                const auto run_server = [&](yield_context yield)
                {
                    bool is_text{};
                    acceptor.async_accept(peer.lowest_layer(), yield);
                    http::async_http_read(peer, req, yield);
                    REQUIRE(req.is_websocket_req());
                    http::async_ws_accept(peer, req, yield);
                    is_text = http::async_ws_read(peer, data_peer, yield);
                    REQUIRE(!is_text);
                    REQUIRE(data_peer == data);
                    is_text = http::async_ws_read(peer, text_peer, yield);
                    REQUIRE(is_text);
                    REQUIRE(text_peer == text);
                    boost::system::error_code ec{};
                    is_text = http::async_ws_read(peer, data_peer, yield[ec]);
                    REQUIRE(ec == http::ws_going_away);
                };

                const auto run_client = [&](yield_context yield)
                {
                    constexpr bool is_server{false};
                    boost::asio::async_connect(client.lowest_layer(), resolver.async_resolve("localhost", "6667", yield), yield);
                    http::async_ws_handshake(client, "localhost", "/ws", yield);
                    http::async_ws_write(client, boost::asio::buffer(data), false, yield);
                    http::async_ws_write(client, boost::asio::buffer(text), true, yield);
                    http::async_ws_close(client, http::ws_going_away, yield);
                };

                boost::asio::spawn(ioc, run_server, detached);
                boost::asio::spawn(ioc, run_client, detached);
                ioc.run();
            }
            catch(const std::exception& e)
            {
                exception_thrown = true;
            }
        }

        SUBCASE("async - server sends")
        {
            try 
            {
                acceptor.async_accept(peer.lowest_layer(), [&](boost::system::error_code ec) {
                    REQUIRE(!bool(ec));
                    http::async_http_read(peer, req, [&](boost::system::error_code ec, size_t) {
                        REQUIRE(!bool(ec));
                        REQUIRE(req.is_websocket_req());
                        http::async_ws_accept(peer, req, [&](boost::system::error_code ec, std::size_t) {
                            REQUIRE(!bool(ec));
                            http::async_ws_write(peer, boost::asio::buffer(data), false, [&](boost::system::error_code ec, std::size_t nwritten) {
                                REQUIRE(!bool(ec));
                                http::async_ws_write(peer, boost::asio::buffer(text), true, [&](boost::system::error_code ec, std::size_t) {
                                    REQUIRE(!bool(ec));
                                    http::async_ws_close(peer, http::ws_going_away, [&](boost::system::error_code ec) {
                                        REQUIRE(!bool(ec));
                                    });
                                });
                            });
                        });
                    });
                });

                resolver.async_resolve("localhost", "6667", [&](boost::system::error_code ec, const auto& endpoints) {
                    REQUIRE(!bool(ec));
                    boost::asio::async_connect(client.lowest_layer(), endpoints, [&](boost::system::error_code ec, auto endpoint) {
                        REQUIRE(!bool(ec));
                        http::async_ws_handshake(client, "localhost", "/ws", [&](boost::system::error_code ec) {
                            REQUIRE(!bool(ec));
                            http::async_ws_read(client, data_client, [&](boost::system::error_code ec, bool is_text) {
                                REQUIRE(!bool(ec));
                                REQUIRE(!is_text);
                                REQUIRE(data_client == data);
                                http::async_ws_read(client, text_client, [&](boost::system::error_code ec, bool is_text) {
                                    REQUIRE(!bool(ec));
                                    REQUIRE(is_text);
                                    REQUIRE(text_client == text);
                                    http::async_ws_read(client, data_client, [&](boost::system::error_code ec, bool is_text) {
                                        REQUIRE(ec == http::ws_going_away);
                                    });
                                });
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
        }

        SUBCASE("awaitable - server sends")
        {
            try 
            {
                const auto run_server = [&]() -> awaitable
                {
                    co_await acceptor.async_accept(peer.lowest_layer());
                    co_await http::async_http_read(peer, req);
                    REQUIRE(req.is_websocket_req());
                    co_await http::async_ws_accept(peer, req);
                    co_await http::async_ws_write(peer, boost::asio::buffer(data), false);
                    co_await http::async_ws_write(peer, boost::asio::buffer(text), true);
                    co_await http::async_ws_close(peer, http::ws_going_away);
                };

                const auto run_client = [&]() -> awaitable
                {
                    bool is_text{};
                    co_await boost::asio::async_connect(client.lowest_layer(), co_await resolver.async_resolve("localhost", "6667"));
                    co_await http::async_ws_handshake(client, "localhost", "/ws");
                    is_text = co_await http::async_ws_read(client, data_client);
                    REQUIRE(!is_text);
                    REQUIRE(data_client == data);
                    is_text = co_await http::async_ws_read(client, text_client);
                    REQUIRE(is_text);
                    REQUIRE(text_client == text);
                    auto [ec, is_text2] = co_await http::async_ws_read(client, data_client, as_tuple(deferred));
                    REQUIRE(ec == http::ws_going_away);
                };

                co_spawn(ioc, run_server(), detached);
                co_spawn(ioc, run_client(), detached);
                ioc.run();
            }
            catch(const std::exception& e)
            {
                exception_thrown = true;
            }
        }

        SUBCASE("coro - server sends")
        {
            try 
            {
                const auto run_server = [&](yield_context yield)
                {
                    acceptor.async_accept(peer.lowest_layer(), yield);
                    http::async_http_read(peer, req, yield);
                    REQUIRE(req.is_websocket_req());
                    http::async_ws_accept(peer, req, yield);
                    http::async_ws_write(peer, boost::asio::buffer(data), false, yield);
                    http::async_ws_write(peer, boost::asio::buffer(text), true, yield);
                    http::async_ws_close(peer, http::ws_going_away, yield);
                };

                const auto run_client = [&](yield_context yield)
                {
                    bool is_text{};
                    boost::asio::async_connect(client.lowest_layer(), resolver.async_resolve("localhost", "6667", yield), yield);
                    http::async_ws_handshake(client, "localhost", "/ws", yield);
                    is_text = http::async_ws_read(client, data_client, yield);
                    REQUIRE(!is_text);
                    REQUIRE(data_client == data);
                    is_text = http::async_ws_read(client, text_client, yield);
                    REQUIRE(is_text);
                    REQUIRE(text_client == text);
                    boost::system::error_code ec{};
                    is_text = http::async_ws_read(client, data_client, yield[ec]);
                    REQUIRE(ec == http::ws_going_away);
                };

                boost::asio::spawn(ioc, run_server, detached);
                boost::asio::spawn(ioc, run_client, detached);
                ioc.run();
            }
            catch(const std::exception& e)
            {
                exception_thrown = true;
            }
        }

        REQUIRE(!exception_thrown);
    }
}