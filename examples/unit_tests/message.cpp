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

    TEST_CASE("serialise & parse bad requests")
    {
        http::request req;

        SUBCASE("empty")
        {
        }

        SUBCASE("missing uri")
        {
            req.verb = http::GET;
        }

        SUBCASE("missing http version")
        {
            req.verb = http::GET;
            req.uri  = "/index";
        }

        SUBCASE("missing host")
        {
            req.verb = http::GET;
            req.uri  = "/index";
            req.http_version_minor = 1;
        }

        SUBCASE("bad http version")
        {
            req.verb = http::GET;
            req.uri  = "/index";
            req.http_version_minor = 100;
            req.add_header(http::host, "www.example.com");
        }

        std::error_code ec{};
        std::string buf;
        http::serialize_header(req, buf, ec);
        REQUIRE(bool(ec));
    }

    TEST_CASE("serialize & parse good request")
    {
        http::request req0;
        req0.verb = http::GET;
        req0.uri  = "/path/to/resource/with+spaces";
        req0.http_version_minor = 1;
        req0.add_header(http::host,                     "www.example.com:8080");
        req0.add_header(http::user_agent,               "CustomTestAgent/7.4.2 (compatible; FancyBot/1.0; +https://example.com/bot)");
        req0.add_header(http::accept,                   "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        req0.add_header(http::accept_language,          "en-US,en;q=0.5"); 
        req0.add_header(http::accept_encoding,          "gzip, deflate, br");
        req0.add_header(http::connection,               "keep-alive, Upgrade");
        req0.add_header(http::upgrade,                  "websocket");
        req0.add_header(http::sec_websocket_key,        "x3JJHMbDL1EzLkh9GBhXDw==");
        req0.add_header(http::sec_websocket_version,    "13");
        req0.add_header(http::cache_control,            "no-cache, no-store, must-revalidate");
        req0.add_header(http::pragma,                   "no-cache");
        req0.add_header(http::content_type,             "application/json; charset=\"utf-8\"");
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
        REQUIRE(req0.http_version_minor == req1.http_version_minor);
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
            REQUIRE(req0.headers[i].key == req1.headers[i].key);
            REQUIRE(req0.headers[i].value == req1.headers[i].value);
        }
        REQUIRE(req0.content == req1.content);
    }
}