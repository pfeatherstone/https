#include <filesystem>
#include "http_mime.h"

namespace fs = std::filesystem;

namespace http
{
    struct mime_details
    {
        std::string_view extension;
        std::string_view mime_type;
    };

    constexpr mime_details MIME_TYPES[] = {
        {".htm",    "text/html"},
        {".html",   "text/html"},
        {".php",    "text/html"},
        {".css",    "text/css"},
        {".txt",    "text/plain"},
        {".js",     "application/javascript"},
        {".json",   "application/json"},
        {".xml",    "application/xml"},
        {".swf",    "application/x-shockwave-flash"},
        {".woff2",  "font/woff2"},
        {".png",    "image/png"},
        {".jpe",    "image/jpeg"},
        {".jpeg",   "image/jpeg"},
        {".jpg",    "image/jpeg"},
        {".gif",    "image/gif"},
        {".bmp",    "image/bmp"},
        {".ico",    "image/vnd.microsoft.icon"},
        {".tiff",   "image/tiff"},
        {".tif",    "image/tiff"},
        {".svg",    "image/svg+xml"},
        {".svgz",   "image/svg+xml"},
        {".flv",    "video/x-flv"},
    };

    std::string_view get_mime_type(std::string_view path)
    {
        const std::string ext2 = fs::path(path).extension();
        for (const auto& [ext1, mime] : MIME_TYPES)
            if (ext1 == ext2)
                return mime;
        return "application/text";
    }
}