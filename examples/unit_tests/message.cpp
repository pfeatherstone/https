#include <ostream>
#include <string_view>
#include <vector>
#include <http.h>
#include "doctest.h"

struct url_parsing_test_data
{
    std::string_view url;
    std::string_view target_expected;
    std::vector<std::pair<std::string_view, std::string_view>> query_params_expected;
};

static const url_parsing_test_data test_data[] = {
    {
        "/search?q=hello+world&lang=en",
        "/search",
        {{"q", "hello world"}, {"lang", "en"}}
    },
    {
        "/api/data?weird=%26%25%3F&empty=&plus=1%2B1%3D2",
        "/api/data",
        {{"weird", "&%?"}, {"empty", ""}, {"plus", "1+1=2"}}
    },
    {
        "/docs/space+test?file=name%20with%20spaces.txt&x=1",
        "/docs/space+test",
        {{"file", "name with spaces.txt"}, {"x", "1"}}
    },
    {
        "/multi?key=value1&key=value2&key=value3",
        "/multi",
        {{"key", "value1"}, {"key", "value2"}, {"key", "value3"}}
    },
    {
        "/equals?x=1%3D2%3D3",
        "/equals",
        {{"x", "1=2=3"}}
    },
    {
        "/onlypath",
        "/onlypath",
        {}
    },
    {
        "/weird?%3Fkey=%3Fvalue&key2=%26%3D",
        "/weird",
        {{"?key", "?value"}, {"key2", "&="}}
    },
    {
        "/complex+path/with%2Fslashes?q=%2Fthis%2Fis%2Fa%2Ftest",
        "/complex+path/with%2Fslashes",
        {{"q", "/this/is/a/test"}}
    },
    {
        "/emptykey?=novalue&foo=bar",
        "/emptykey",
        {{"", "novalue"}, {"foo", "bar"}}
    },
    {
        "/plus+in+path?plus=1+2",
        "/plus+in+path",
        {{"plus", "1 2"}}
    }
};

TEST_SUITE("[MESSAGE]")
{
    TEST_CASE("enums")
    {
        REQUIRE(http::verb_enum(http::verb_label(http::METHOD_UNKNOWN)) == http::METHOD_UNKNOWN);
        REQUIRE(http::verb_enum(http::verb_label(http::METHOD_GET))     == http::METHOD_GET);
        REQUIRE(http::verb_enum(http::verb_label(http::METHOD_HEAD))    == http::METHOD_HEAD);
        REQUIRE(http::verb_enum(http::verb_label(http::METHOD_POST))    == http::METHOD_POST);
        REQUIRE(http::verb_enum(http::verb_label(http::METHOD_PUT))     == http::METHOD_PUT);
        REQUIRE(http::verb_enum(http::verb_label(http::METHOD_DELETE))  == http::METHOD_DELETE);
        REQUIRE(http::verb_enum(http::verb_label(http::METHOD_CONNECT)) == http::METHOD_CONNECT);
        REQUIRE(http::verb_enum(http::verb_label(http::METHOD_OPTIONS)) == http::METHOD_OPTIONS);
        REQUIRE(http::verb_enum(http::verb_label(http::METHOD_TRACE))   == http::METHOD_TRACE);
        REQUIRE(http::verb_enum(http::verb_label(http::METHOD_PATCH))   == http::METHOD_PATCH);

        for (unsigned int f = http::unknown_field ; f <= http::xref ; ++f)
            REQUIRE(http::field_enum(http::field_label((http::field)f)) == f);
    }

    TEST_CASE("url parsing")
    {
        for (auto data : test_data)
        {
            std::error_code                 ec{};
            std::string                     target;
            std::vector<http::query_param>  params;
            http::parse_url(data.url, target, params, ec);
            REQUIRE(!bool(ec));
            REQUIRE(target == data.target_expected);
            REQUIRE(params.size() == data.query_params_expected.size());
            for (size_t i = 0 ; i < params.size() ; ++i)
            {
                REQUIRE(params[i].key == data.query_params_expected[i].first);
                REQUIRE(params[i].val == data.query_params_expected[i].second);
            }
        }
    }

    TEST_CASE("parse bad requests")
    {
        {
            std::string bad_req = "SHUV / HTTP/1.1\r\n";
            bad_req            += "Host: developer.mozilla.org\r\n";
            bad_req            += "User-Agent: curl/8.6.0\r\n";
            bad_req            += "Content-Type: application/json\r\n";
            bad_req            += "Content-Length: 32\r\n";
            bad_req            += "\r\n";
            bad_req            += "{\"name\": \"Obi\", \"creed\": \"Jedi\"}";

            http::request req;
            std::error_code ec{};
            bool finished = http::parser<http::request>{}.parse(req, bad_req, ec);
            REQUIRE(ec == http::http_read_bad_method);
        }
        
        {
            std::string bad_req = "POST / HTTP/2.1\r\n";
            bad_req            += "Host: developer.mozilla.org\r\n";
            bad_req            += "User-Agent: curl/8.6.0\r\n";
            bad_req            += "Content-Type: application/json\r\n";
            bad_req            += "Content-Length: 32\r\n";
            bad_req            += "\r\n";
            bad_req            += "{\"name\": \"Obi\", \"creed\": \"Jedi\"}";

            http::request req;
            std::error_code ec{};
            bool finished = http::parser<http::request>{}.parse(req, bad_req, ec);
            REQUIRE(ec == http::http_read_unsupported_http_version);
        }

        {
            std::string bad_req = "POST / HTTP/11\r\n";
            bad_req            += "Host: developer.mozilla.org\r\n";
            bad_req            += "User-Agent: curl/8.6.0\r\n";
            bad_req            += "Content-Type: application/json\r\n";
            bad_req            += "Content-Length: 32\r\n";
            bad_req            += "\r\n";
            bad_req            += "{\"name\": \"Obi\", \"creed\": \"Jedi\"}";

            http::request req;
            std::error_code ec{};
            bool finished = http::parser<http::request>{}.parse(req, bad_req, ec);
            REQUIRE(ec == http::http_read_unsupported_http_version);
        }

        {
            std::string bad_req = "POST / PROTOCOL/1.1\r\n";
            bad_req            += "Host: developer.mozilla.org\r\n";
            bad_req            += "User-Agent: curl/8.6.0\r\n";
            bad_req            += "Content-Type: application/json\r\n";
            bad_req            += "Content-Length: 32\r\n";
            bad_req            += "\r\n";
            bad_req            += "{\"name\": \"Obi\", \"creed\": \"Jedi\"}";

            http::request req;
            std::error_code ec{};
            bool finished = http::parser<http::request>{}.parse(req, bad_req, ec);
            REQUIRE(ec == http::http_read_unsupported_http_version);
        }

        {
            std::string bad_req = "POST / HTTP/1.1\r\n";
            bad_req            += "Host - developer.mozilla.org\r\n";
            bad_req            += "User-Agent: curl/8.6.0\r\n";
            bad_req            += "Content-Type: application/json\r\n";
            bad_req            += "Content-Length: 32\r\n";
            bad_req            += "\r\n";
            bad_req            += "{\"name\": \"Obi\", \"creed\": \"Jedi\"}";

            http::request req;
            std::error_code ec{};
            bool finished = http::parser<http::request>{}.parse(req, bad_req, ec);
            REQUIRE(ec == http::http_read_header_kv_delimiter_not_found);
        }

        {
            std::string bad_req = "POST / HTTP/1.1\r\n";
            bad_req            += "Host : developer.mozilla.org\r\n";
            bad_req            += "User-Agent: curl/8.6.0\r\n";
            bad_req            += "Content-Type: application/json\r\n";
            bad_req            += "Content-Length: 32\r\n";
            bad_req            += "Sith-Code: 66\r\n";
            bad_req            += "\r\n";
            bad_req            += "{\"name\": \"Obi\", \"creed\": \"Jedi\"}";

            http::request req;
            std::error_code ec{};
            bool finished = http::parser<http::request>{}.parse(req, bad_req, ec);
            REQUIRE(ec == http::http_read_header_unsupported_field); // (It should be "Host:" not "Host :")
        }

        {
            std::string bad_req = "POST / HTTP/1.1\r\n";
            bad_req            += "Host: developer.mozilla.org\r\n";
            bad_req            += "User-Agent: curl/8.6.0\r\n";
            bad_req            += "Content-Type: application/json\r\n";
            bad_req            += "Content-Length: 64\r\n";
            bad_req            += "\r\n";
            bad_req            += "{\"name\": \"Obi\", \"creed\": \"Jedi\"}";

            http::request req;
            std::error_code ec{};
            bool finished = http::parser<http::request>{}.parse(req, bad_req, ec);
            REQUIRE(!bool(ec));
            REQUIRE(!finished); // Incorrect Content-Length
            REQUIRE(bad_req.empty());
        }

        {
            std::string bad_req = "POST / HTTP/1.1\r\n";
            bad_req            += "Host: developer.mozilla.org\r\n";
            bad_req            += "User-Agent: curl/8.6.0\r\n";
            bad_req            += "Content-Type: application/json\r\n";
            bad_req            += "Content-Length: 32\r\n";
            bad_req            += "{\"name\": \"Obi\", \"creed\": \"Jedi\"}";

            http::request req;
            std::error_code ec{};
            bool finished = http::parser<http::request>{}.parse(req, bad_req, ec);
            REQUIRE(!bool(ec));
            REQUIRE(!finished); // Waiting for \r\n to test header
        }


        {
            std::string bad_req = "POST / HTTP/1.1\r\n";
            bad_req            += "Host: developer.mozilla.org\r\n";
            bad_req            += "User-Agent: curl/8.6.0\r\n";
            bad_req            += "Content-Type: application/json\r\n";
            bad_req            += "Content-Length: 32\r\n";
            bad_req            += "\r\n";
            bad_req            += "{\"name\": \"Obi\", \"creed\": \"Jedi\"}";

            http::request req;
            std::error_code ec{};
            bool finished = http::parser<http::request>{}.parse(req, bad_req, ec);
            REQUIRE(!bool(ec));
            REQUIRE(finished); // Done
            REQUIRE(bad_req.empty());
        }
    }

    TEST_CASE("parse bad response")
    {
        {
            std::string bad_reply    = "HTTP/2.1 200 ok\r\n";
            bad_reply               += "Server: Apache\r\n";
            bad_reply               += "Content-Type: text\r\n";
            bad_reply               += "Content-Length: 11\r\n";
            bad_reply               += "\r\n";
            bad_reply               += "hello there";

            http::response reply;
            std::error_code ec{};
            bool finished = http::parser<http::response>{}.parse(reply, bad_reply, ec);
            REQUIRE(ec == http::http_read_unsupported_http_version);
        }

        {
            std::string bad_reply    = "HTTP/11 200 ok\r\n";
            bad_reply               += "Server: Apache\r\n";
            bad_reply               += "Content-Type: text\r\n";
            bad_reply               += "Content-Length: 11\r\n";
            bad_reply               += "\r\n";
            bad_reply               += "hello there";

            http::response reply;
            std::error_code ec{};
            bool finished = http::parser<http::response>{}.parse(reply, bad_reply, ec);
            REQUIRE(ec == http::http_read_unsupported_http_version);
        }

        {
            std::string bad_reply    = "HTT/1.1 200 ok\r\n";
            bad_reply               += "Server: Apache\r\n";
            bad_reply               += "Content-Type: text\r\n";
            bad_reply               += "Content-Length: 11\r\n";
            bad_reply               += "\r\n";
            bad_reply               += "hello there";

            http::response reply;
            std::error_code ec{};
            bool finished = http::parser<http::response>{}.parse(reply, bad_reply, ec);
            REQUIRE(ec == http::http_read_unsupported_http_version);
        }

        {
            std::string bad_reply    = "HTTP/1.1 99 teapot\r\n";
            bad_reply               += "Server: Apache\r\n";
            bad_reply               += "Content-Type: text\r\n";
            bad_reply               += "Content-Length: 11\r\n";
            bad_reply               += "\r\n";
            bad_reply               += "hello there";

            http::response reply;
            std::error_code ec{};
            bool finished = http::parser<http::response>{}.parse(reply, bad_reply, ec);
            REQUIRE(ec == http::http_read_bad_status);
        }

        {
            std::string bad_reply    = "HTTP/1.1 200 ok\r\n";
            bad_reply               += "Server: Apache\r\n";
            bad_reply               += "Content-Type- text\r\n";
            bad_reply               += "Content-Length: 11\r\n";
            bad_reply               += "\r\n";
            bad_reply               += "hello there";

            http::response reply;
            std::error_code ec{};
            bool finished = http::parser<http::response>{}.parse(reply, bad_reply, ec);
            REQUIRE(ec == http::http_read_header_kv_delimiter_not_found);
        }

        {
            std::string bad_reply    = "HTTP/1.1 200 ok\r\n";
            bad_reply               += "Server: Apache\r\n";
            bad_reply               += "Content-Type : text\r\n";
            bad_reply               += "Content-Length: 11\r\n";
            bad_reply               += "\r\n";
            bad_reply               += "hello there";

            http::response reply;
            std::error_code ec{};
            bool finished = http::parser<http::response>{}.parse(reply, bad_reply, ec);
            REQUIRE(ec == http::http_read_header_unsupported_field);
        }

        {
            std::string bad_reply    = "HTTP/1.1 200 ok\r\n";
            bad_reply               += "Server: Apache\r\n";
            bad_reply               += "Content-Flavour: text\r\n";
            bad_reply               += "Content-Length: 11\r\n";
            bad_reply               += "\r\n";
            bad_reply               += "hello there";

            http::response reply;
            std::error_code ec{};
            bool finished = http::parser<http::response>{}.parse(reply, bad_reply, ec);
            REQUIRE(ec == http::http_read_header_unsupported_field);
        }

        {
            std::string bad_reply    = "HTTP/1.1 200 ok\r\n";
            bad_reply               += "Server: Apache\r\n";
            bad_reply               += "Content-Type: text\r\n";
            bad_reply               += "Content-Length: 32\r\n";
            bad_reply               += "\r\n";
            bad_reply               += "hello there";

            http::response reply;
            std::error_code ec{};
            bool finished = http::parser<http::response>{}.parse(reply, bad_reply, ec);
            REQUIRE(!bool(ec));
            REQUIRE(!finished); // Wrong content length. Waiting for rest of payload
            REQUIRE(bad_reply.empty());
        }

        {
            std::string good_reply    = "HTTP/1.1 200 ok\r\n";
            good_reply               += "Server: Apache\r\n";
            good_reply               += "Content-Type: text\r\n";
            good_reply               += "Content-Length: 11\r\n";
            good_reply               += "\r\n";
            good_reply               += "hello there";

            http::response reply;
            std::error_code ec{};
            bool finished = http::parser<http::response>{}.parse(reply, good_reply, ec);
            REQUIRE(!bool(ec));
            REQUIRE(finished); // Good
            REQUIRE(good_reply.empty());
        }
    }

    TEST_CASE("serialise bad requests")
    {
        http::request req;

        SUBCASE("empty")
        {
        }

        SUBCASE("missing uri")
        {
            req.verb = http::METHOD_GET;
        }

        SUBCASE("missing host")
        {
            req.verb = http::METHOD_GET;
            req.uri  = "/index";
        }

        std::error_code ec{};
        std::string buf;
        http::serialize_header(req, buf, ec);
        REQUIRE(bool(ec));
    }

    TEST_CASE("serialise bad response")
    {
        http::response resp;
        SUBCASE("empty"){}
        std::error_code ec{};
        std::string buf;
        http::serialize_header(resp, buf, ec);
        REQUIRE(bool(ec));
    }

    TEST_CASE("serialize & parse good request")
    {
        http::request req0;
        req0.verb = http::METHOD_GET;
        req0.uri  = "/path/to/resource/with+spaces";
        req0.headers.add(http::host,                     "www.example.com:8080");
        req0.headers.add(http::user_agent,               "CustomTestAgent/7.4.2 (compatible; FancyBot/1.0; +https://example.com/bot)");
        req0.headers.add(http::accept,                   "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        req0.headers.add(http::accept_language,          "en-US,en;q=0.5"); 
        req0.headers.add(http::accept_encoding,          "gzip, deflate, br");
        req0.headers.add(http::connection,               "keep-alive, Upgrade");
        req0.headers.add(http::upgrade,                  "websocket");
        req0.headers.add(http::sec_websocket_key,        "x3JJHMbDL1EzLkh9GBhXDw==");
        req0.headers.add(http::sec_websocket_version,    "13");
        req0.headers.add(http::cache_control,            "no-cache, no-store, must-revalidate");
        req0.headers.add(http::pragma,                   "no-cache");
        req0.headers.add(http::content_type,             "application/json; charset=\"utf-8\"");
        req0.content = "{\"message\": \"This is a test body with some content.\"}";
        req0.params.push_back({"q",     "search term"});
        req0.params.push_back({"empty", ""});
        req0.params.push_back({"weird", "&%?"});
        REQUIRE(req0.keep_alive());
        REQUIRE(req0.is_websocket_req());

        // Serialize
        std::error_code ec{};
        std::string buf;
        http::serialize_header(req0, buf, ec);
        buf.append(req0.content);
        REQUIRE(!bool(ec));

        http::request req1;
        
        SUBCASE("parse entire message")
        {
            const bool finished = http::parser<http::request>{}.parse(req1, buf, ec);
            REQUIRE(!bool(ec));
            REQUIRE(finished);
        }

        SUBCASE("parse block by block")
        {
            http::parser<http::request> parser;

            size_t blocksize{};

            SUBCASE("blocksize == 1")    { blocksize = 1;}
            SUBCASE("blocksize == 10")   { blocksize = 10;}
            SUBCASE("blocksize == 99")   { blocksize = 99;}
            SUBCASE("blocksize == 128")  { blocksize = 128;}
            SUBCASE("blocksize == 1024") { blocksize = 1024;}

            size_t nblocks = (buf.size() + blocksize - 1) / blocksize;
            std::string  block;

            for (size_t i = 0 ; i < nblocks ; ++i)
            {
                const size_t len = std::min(blocksize, buf.size());
                block.append(&buf[0], len);
                buf.erase(begin(buf), begin(buf) + len);
                const bool finished = parser.parse(req1, block, ec);
                REQUIRE(!bool(ec));
                REQUIRE(finished == (i == (nblocks-1)));
            }
            REQUIRE(block.empty());
        }
        
        REQUIRE(buf.empty());
        REQUIRE(req0.verb == req1.verb);
        REQUIRE(req0.version == req1.version);
        REQUIRE(req0.uri == req1.uri);
        REQUIRE(req0.params.size() == req1.params.size());
        for (size_t i = 0 ; i < req0.params.size() ; ++i)
        {
            REQUIRE(req0.params[i].key == req1.params[i].key);
            REQUIRE(req0.params[i].val == req1.params[i].val);
        }
        REQUIRE(req0.headers.size() == req1.headers.size());
        for (size_t i = 0 ; i < req0.headers.size() ; ++i)
        {
            const auto [key0, val0] = req0.headers[i];
            const auto [key1, val1] = req1.headers[i];
            REQUIRE(key0 == key1);
            REQUIRE(val0 == val1);
        }
        REQUIRE(req0.content == req1.content);
    }

    TEST_CASE("serialize & parse good response")
    {
        http::response resp0;
        resp0.status = http::ok;
        resp0.headers.add(http::date,            "Sat, 07 Jun 2025 11:34:29 GMT");
        resp0.headers.add(http::content_type,    "application/json");
        resp0.headers.add(http::set_cookie,      "sails.sid=s%3AzNjVxqbbKjdhW62QxWPrO9_s7iw6gFfj.YkpdH7mCTkx%2FC%2BgLXyBzXETRD7gKyFu%2BKWMS43uKq4Y; Path=/; HttpOnly");

        // Serialize
        std::error_code ec{};
        std::string buf;
        http::serialize_header(resp0, buf, ec);
        buf.append(resp0.content_str);
        REQUIRE(!bool(ec));

        // Parse
        http::response resp1;
        
        SUBCASE("parse entire message")
        {
            const bool finished = http::parser<http::response>{}.parse(resp1, buf, ec);
            REQUIRE(!bool(ec));
            REQUIRE(finished);
        }

        SUBCASE("parse block by block")
        {
            http::parser<http::response> parser;

            size_t blocksize{};

            SUBCASE("blocksize == 1")    { blocksize = 1;}
            SUBCASE("blocksize == 10")   { blocksize = 10;}
            SUBCASE("blocksize == 99")   { blocksize = 99;}
            SUBCASE("blocksize == 128")  { blocksize = 128;}
            SUBCASE("blocksize == 1024") { blocksize = 1024;}

            size_t nblocks = (buf.size() + blocksize - 1) / blocksize;
            std::string  block;

            for (size_t i = 0 ; i < nblocks ; ++i)
            {
                const size_t len = std::min(blocksize, buf.size());
                block.append(&buf[0], len);
                buf.erase(begin(buf), begin(buf) + len);
                const bool finished = parser.parse(resp1, block, ec);
                REQUIRE_MESSAGE(!bool(ec), ec.message());
                REQUIRE(finished == (i == (nblocks-1)));
            }
            REQUIRE(block.empty());
        }
        
        REQUIRE(buf.empty());
        REQUIRE(resp0.status == resp1.status);
        REQUIRE(resp0.version == resp1.version);
        REQUIRE(resp0.headers.size() == resp1.headers.size());
        for (size_t i = 0 ; i < resp0.headers.size() ; ++i)
        {
            const auto [key0, val0] = resp0.headers[i];
            const auto [key1, val1] = resp1.headers[i];
            REQUIRE(key0 == key1);
            REQUIRE(val0 == val1);
        }
        REQUIRE(resp0.content_str == resp1.content_str);
    }
}