#include <system_error>
#include "http_error.h"

namespace http
{
    struct http_error_category : std::error_category
    {
        const char* name() const noexcept override 
        {
            return "http_error_category";
        }

        std::string message(int ev) const override
        {
            switch(static_cast<error>(ev))
            {
            case http_read_header_fail:     return "Error while parsing HTTP request headers";
            case http_read_body_fail:       return "Error while reading HTTP body";
            case ws_accept_missing_seq_key: return "Missing seq-websocket-key in HTTP websocket upgrade request message";
            case ws_invalid_opcode:         return "Received invalid opcode";
            case ws_closed:                 return "Websocket received closed opcode";
            default:                        return "Unrecognised error";
            }
        }
    };

    const http_error_category http_error_category_singleton;

    std::error_code make_error_code(error ec)
    {
        return {static_cast<int>(ec), http_error_category_singleton};
    }
}