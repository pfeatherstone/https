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
            switch(static_cast<http_error>(ev))
            {
            case HTTP_READ_HEADER_FAIL:     return "Error while parsing HTTP request headers";
            case HTTP_READ_BODY_FAIL:       return "Error while reading HTTP body";
            case WS_ACCEPT_MISSING_SEQ_KEY: return "Missing seq-websocket-key in HTTP websocket upgrade request message";
            default:                        return "Unrecognised error";
            }
        }
    };

    const http_error_category http_error_category_singleton;

    std::error_code make_error_code(http_error ec)
    {
        return {static_cast<int>(ec), http_error_category_singleton};
    }
}