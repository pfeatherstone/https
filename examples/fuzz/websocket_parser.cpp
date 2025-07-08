#include <cstdint>
#include <cstddef>
#include <http.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::string buf(reinterpret_cast<const char*>(data), size);

    http::request   req{};
    std::error_code ec{};
    http::parser<http::request> parser;
    parser.parse(req, buf, ec);
    bool is_websocket_req = req.is_websocket_req();

    std::vector<char> msg;
    http::websocket_parser ws_parser;
    ws_parser.parse(msg, buf, ec);
    const auto opcode       = ws_parser.get_opcode();
    const auto is_server    = ws_parser.is_server();
    return 0;
}