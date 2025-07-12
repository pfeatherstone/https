#include <cstdint>
#include <cstddef>
#include <http.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::string     buf(reinterpret_cast<const char*>(data), size);
    http::request   req{};
    std::error_code ec{};
    http::parser_request parser;
    parser.parse(req, buf, ec);
    bool is_keep_alive    = req.keep_alive();
    bool is_websocket_req = req.is_websocket_req();
    buf.clear();
    ec = {};
    http::serialize_header(req, buf, ec);
    req.clear();
    return 0;
}