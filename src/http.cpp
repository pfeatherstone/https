#include <cassert>
#include <cstring>
#include <cstdarg>
#include <cctype>
#include <algorithm>
#include <filesystem>
#include <boost/asio/version.hpp>
#include "http.h"

namespace fs = std::filesystem;

namespace http
{

//----------------------------------------------------------------------------------------------------------------

    std::string format(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));

    std::string format(const char* fmt, ...)
    {
        va_list args0, args1;
        va_start(args0, fmt);
        va_copy(args1, args0);
        const int ret = vsnprintf(nullptr, 0, fmt, args0);
        std::string str(ret+1, '\0');
        vsnprintf(&str[0], ret+1, fmt, args1);
        str.resize(ret);
        va_end(args0);
        va_end(args1);
        return str;
    }

//----------------------------------------------------------------------------------------------------------------

    constexpr std::string_view VERBS[] = {
        "UNKNOWN",
        "GET",
        "HEAD",
        "POST",
        "PUT",
        "DELETE",
        "CONNECT",
        "OPTIONS",
        "TRACE",
        "PATCH"
    };

    std::string_view verb_label(verb_type v)
    {
        return VERBS[v];
    }

    verb_type verb_enum(std::string_view str)
    {
        for (unsigned int i = 0 ; i < std::size(VERBS) ; ++i)
            if (VERBS[i] == str)
                return (verb_type)i;
        return UNKNOWN_VERB;
    }

//----------------------------------------------------------------------------------------------------------------

    constexpr std::string_view FIELDS[] = {
        "<unknown-field>",
        "a-im",
        "accept",
        "accept-additions",
        "accept-charset",
        "accept-datetime",
        "accept-encoding",
        "accept-features",
        "accept-language",
        "accept-patch",
        "accept-post",
        "accept-ranges",
        "access-control",
        "access-control-allow-credentials",
        "access-control-allow-headers",
        "access-control-allow-methods",
        "access-control-allow-origin",
        "access-control-expose-headers",
        "access-control-max-age",
        "access-control-request-headers",
        "access-control-request-method",
        "age",
        "allow",
        "alpn",
        "also-control",
        "alt-svc",
        "alt-used",
        "alternate-recipient",
        "alternates",
        "apparently-to",
        "apply-to-redirect-ref",
        "approved",
        "archive",
        "archived-at",
        "article-names",
        "article-updates",
        "authentication-control",
        "authentication-info",
        "authentication-results",
        "authorization",
        "auto-submitted",
        "autoforwarded",
        "autosubmitted",
        "base",
        "bcc",
        "body",
        "c-ext",
        "c-man",
        "c-opt",
        "c-pep",
        "c-pep-info",
        "cache-control",
        "caldav-timezones",
        "cancel-key",
        "cancel-lock",
        "cc",
        "close",
        "comments",
        "compliance",
        "connection",
        "content-alternative",
        "content-base",
        "content-description",
        "content-disposition",
        "content-duration",
        "content-encoding",
        "content-features",
        "content-id",
        "content-identifier",
        "content-language",
        "content-length",
        "content-location",
        "content-md5",
        "content-range",
        "content-return",
        "content-script-type",
        "content-style-type",
        "content-transfer-encoding",
        "content-type",
        "content-version",
        "control",
        "conversion",
        "conversion-with-loss",
        "cookie",
        "cookie2",
        "cost",
        "dasl",
        "date",
        "date-received",
        "dav",
        "default-style",
        "deferred-delivery",
        "delivery-date",
        "delta-base",
        "depth",
        "derived-from",
        "destination",
        "differential-id",
        "digest",
        "discarded-x400-ipms-extensions",
        "discarded-x400-mts-extensions",
        "disclose-recipients",
        "disposition-notification-options",
        "disposition-notification-to",
        "distribution",
        "dkim-signature",
        "dl-expansion-history",
        "downgraded-bcc",
        "downgraded-cc",
        "downgraded-disposition-notification-to",
        "downgraded-final-recipient",
        "downgraded-from",
        "downgraded-in-reply-to",
        "downgraded-mail-from",
        "downgraded-message-id",
        "downgraded-original-recipient",
        "downgraded-rcpt-to",
        "downgraded-references",
        "downgraded-reply-to",
        "downgraded-resent-bcc",
        "downgraded-resent-cc",
        "downgraded-resent-from",
        "downgraded-resent-reply-to",
        "downgraded-resent-sender",
        "downgraded-resent-to",
        "downgraded-return-path",
        "downgraded-sender",
        "downgraded-to",
        "ediint-features",
        "eesst-version",
        "encoding",
        "encrypted",
        "errors-to",
        "etag",
        "expect",
        "expires",
        "expiry-date",
        "ext",
        "followup-to",
        "forwarded",
        "from",
        "generate-delivery-report",
        "getprofile",
        "hobareg",
        "host",
        "http2-settings",
        "if",
        "if-match",
        "if-modified-since",
        "if-none-match",
        "if-range",
        "if-schedule-tag-match",
        "if-unmodified-since",
        "im",
        "importance",
        "in-reply-to",
        "incomplete-copy",
        "injection-date",
        "injection-info",
        "jabber-id",
        "keep-alive",
        "keywords",
        "label",
        "language",
        "last-modified",
        "latest-delivery-time",
        "lines",
        "link",
        "list-archive",
        "list-help",
        "list-id",
        "list-owner",
        "list-post",
        "list-subscribe",
        "list-unsubscribe",
        "list-unsubscribe-post",
        "location",
        "lock-token",
        "man",
        "max-forwards",
        "memento-datetime",
        "message-context",
        "message-id",
        "message-type",
        "meter",
        "method-check",
        "method-check-expires",
        "mime-version",
        "mmhs-acp127-message-identifier",
        "mmhs-authorizing-users",
        "mmhs-codress-message-indicator",
        "mmhs-copy-precedence",
        "mmhs-exempted-address",
        "mmhs-extended-authorisation-info",
        "mmhs-handling-instructions",
        "mmhs-message-instructions",
        "mmhs-message-type",
        "mmhs-originator-plad",
        "mmhs-originator-reference",
        "mmhs-other-recipients-indicator-cc",
        "mmhs-other-recipients-indicator-to",
        "mmhs-primary-precedence",
        "mmhs-subject-indicator-codes",
        "mt-priority",
        "negotiate",
        "newsgroups",
        "nntp-posting-date",
        "nntp-posting-host",
        "non-compliance",
        "obsoletes",
        "opt",
        "optional",
        "optional-www-authenticate",
        "ordering-type",
        "organization",
        "origin",
        "original-encoded-information-types",
        "original-from",
        "original-message-id",
        "original-recipient",
        "original-sender",
        "original-subject",
        "originator-return-address",
        "overwrite",
        "p3p",
        "path",
        "pep",
        "pep-info",
        "pics-label",
        "position",
        "posting-version",
        "pragma",
        "prefer",
        "preference-applied",
        "prevent-nondelivery-report",
        "priority",
        "privicon",
        "profileobject",
        "protocol",
        "protocol-info",
        "protocol-query",
        "protocol-request",
        "proxy-authenticate",
        "proxy-authentication-info",
        "proxy-authorization",
        "proxy-connection",
        "proxy-features",
        "proxy-instruction",
        "public",
        "public-key-pins",
        "public-key-pins-report-only",
        "range",
        "received",
        "received-spf",
        "redirect-ref",
        "references",
        "referer",
        "referer-root",
        "relay-version",
        "reply-by",
        "reply-to",
        "require-recipient-valid-since",
        "resent-bcc",
        "resent-cc",
        "resent-date",
        "resent-from",
        "resent-message-id",
        "resent-reply-to",
        "resent-sender",
        "resent-to",
        "resolution-hint",
        "resolver-location",
        "retry-after",
        "return-path",
        "safe",
        "schedule-reply",
        "schedule-tag",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "sec-websocket-accept",
        "sec-websocket-extensions",
        "sec-websocket-key",
        "sec-websocket-protocol",
        "sec-websocket-version",
        "security-scheme",
        "see-also",
        "sender",
        "sensitivity",
        "server",
        "set-cookie",
        "set-cookie2",
        "setprofile",
        "sio-label",
        "sio-label-history",
        "slug",
        "soapaction",
        "solicitation",
        "status-uri",
        "strict-transport-security",
        "subject",
        "subok",
        "subst",
        "summary",
        "supersedes",
        "surrogate-capability",
        "surrogate-control",
        "tcn",
        "te",
        "timeout",
        "title",
        "to",
        "topic",
        "trailer",
        "transfer-encoding",
        "ttl",
        "ua-color",
        "ua-media",
        "ua-pixels",
        "ua-resolution",
        "ua-windowpixels",
        "upgrade",
        "upgrade-insecure-requests",
        "urgency",
        "uri",
        "user-agent",
        "variant-vary",
        "vary",
        "vbr-info",
        "version",
        "via",
        "want-digest",
        "warning",
        "www-authenticate",
        "x-archived-at",
        "x-device-accept",
        "x-device-accept-charset",
        "x-device-accept-encoding",
        "x-device-accept-language",
        "x-device-user-agent",
        "x-frame-options",
        "x-mittente",
        "x-pgp-sig",
        "x-ricevuta",
        "x-riferimento-message-id",
        "x-tiporicevuta",
        "x-trasporto",
        "x-verificasicurezza",
        "x400-content-identifier",
        "x400-content-return",
        "x400-content-type",
        "x400-mts-identifier",
        "x400-originator",
        "x400-received",
        "x400-recipients",
        "x400-trace",
        "xref"
    };

    static_assert(std::size(FIELDS) == 361, "bad mapping");

//----------------------------------------------------------------------------------------------------------------

    std::string to_lower(std::string_view s)
    {
        std::string out(s.length(), '\0');
        std::transform(s.begin(), s.end(), out.begin(), [](unsigned char c) { return std::tolower(c); });
        return out;
    }

    std::string_view field_label(field f)
    {
        return FIELDS[f];
    }

    field field_enum(std::string_view f)
    {
        for (unsigned int i = 0 ; i < std::size(FIELDS) ; ++i)
            if (FIELDS[i] == to_lower(f))
                return (field)i;
        return unknown_field;
    }

//----------------------------------------------------------------------------------------------------------------

    std::string_view status_label(const status_type v)
    {
        switch(v)
        {
        // 1xx
        case status_type::continue_:                             return "Continue";
        case status_type::switching_protocols:                   return "Switching Protocols";
        case status_type::processing:                            return "Processing";
        case status_type::early_hints:                           return "Early Hints";

        // 2xx
        case status_type::ok:                                    return "OK";
        case status_type::created:                               return "Created";
        case status_type::accepted:                              return "Accepted";
        case status_type::non_authoritative_information:         return "Non-Authoritative Information";
        case status_type::no_content:                            return "No Content";
        case status_type::reset_content:                         return "Reset Content";
        case status_type::partial_content:                       return "Partial Content";
        case status_type::multi_status:                          return "Multi-Status";
        case status_type::already_reported:                      return "Already Reported";
        case status_type::im_used:                               return "IM Used";

        // 3xx
        case status_type::multiple_choices:                      return "Multiple Choices";
        case status_type::moved_permanently:                     return "Moved Permanently";
        case status_type::found:                                 return "Found";
        case status_type::see_other:                             return "See Other";
        case status_type::not_modified:                          return "Not Modified";
        case status_type::use_proxy:                             return "Use Proxy";
        case status_type::temporary_redirect:                    return "Temporary Redirect";
        case status_type::permanent_redirect:                    return "Permanent Redirect";

        // 4xx
        case status_type::bad_request:                           return "Bad Request";
        case status_type::unauthorized:                          return "Unauthorized";
        case status_type::payment_required:                      return "Payment Required";
        case status_type::forbidden:                             return "Forbidden";
        case status_type::not_found:                             return "Not Found";
        case status_type::method_not_allowed:                    return "Method Not Allowed";
        case status_type::not_acceptable:                        return "Not Acceptable";
        case status_type::proxy_authentication_required:         return "Proxy Authentication Required";
        case status_type::request_timeout:                       return "Request Timeout";
        case status_type::conflict:                              return "Conflict";
        case status_type::gone:                                  return "Gone";
        case status_type::length_required:                       return "Length Required";
        case status_type::precondition_failed:                   return "Precondition Failed";
        case status_type::payload_too_large:                     return "Payload Too Large";
        case status_type::uri_too_long:                          return "URI Too Long";
        case status_type::unsupported_media_type:                return "Unsupported Media Type";
        case status_type::range_not_satisfiable:                 return "Range Not Satisfiable";
        case status_type::expectation_failed:                    return "Expectation Failed";
        case status_type::i_am_a_teapot:                         return "I'm a teapot";
        case status_type::misdirected_request:                   return "Misdirected Request";
        case status_type::unprocessable_entity:                  return "Unprocessable Entity";
        case status_type::locked:                                return "Locked";
        case status_type::failed_dependency:                     return "Failed Dependency";
        case status_type::too_early:                             return "Too Early";
        case status_type::upgrade_required:                      return "Upgrade Required";
        case status_type::precondition_required:                 return "Precondition Required";
        case status_type::too_many_requests:                     return "Too Many Requests";
        case status_type::request_header_fields_too_large:       return "Request Header Fields Too Large";
        case status_type::unavailable_for_legal_reasons:         return "Unavailable For Legal Reasons";
        // 5xx
        case status_type::internal_server_error:                 return "Internal Server Error";
        case status_type::not_implemented:                       return "Not Implemented";
        case status_type::bad_gateway:                           return "Bad Gateway";
        case status_type::service_unavailable:                   return "Service Unavailable";
        case status_type::gateway_timeout:                       return "Gateway Timeout";
        case status_type::http_version_not_supported:            return "HTTP Version Not Supported";
        case status_type::variant_also_negotiates:               return "Variant Also Negotiates";
        case status_type::insufficient_storage:                  return "Insufficient Storage";
        case status_type::loop_detected:                         return "Loop Detected";
        case status_type::not_extended:                          return "Not Extended";
        case status_type::network_authentication_required:       return "Network Authentication Required";
        default: break;
        }
        return "<unknown-status>";
    }

//----------------------------------------------------------------------------------------------------------------

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

//----------------------------------------------------------------------------------------------------------------

    static constexpr uint32_t rotl(uint32_t x, size_t s)
    {
        return (x << s) | (x >> (32 - s));
    }

    static constexpr void process_sha1_block(uint32_t (&hash)[5], const uint8_t (&block)[64])
    {
        // Initialise buffer
        uint32_t w[80] = {};

        for (size_t i = 0 ; i < 16 ; ++i)
        {
            w[i]  = (block[i*4 + 0] << 24);
            w[i] |= (block[i*4 + 1] << 16);
            w[i] |= (block[i*4 + 2] << 8);
            w[i] |= (block[i*4 + 3]);
        }

        for (size_t i = 16; i < 80; ++i)
            w[i] = rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        
        // Initialize
        uint32_t a = hash[0];
        uint32_t b = hash[1];
        uint32_t c = hash[2];
        uint32_t d = hash[3];
        uint32_t e = hash[4];
        size_t   i{0};

        const auto fin = [&](const size_t i, const uint32_t k, const uint32_t f)
        {
            const unsigned temp = rotl(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = temp;
        };

        for (; i < 20; ++i) 
            fin(i, 0x5A827999, (b & c) | (~b & d));

        for (; i < 40; ++i) 
            fin(i, 0x6ED9EBA1, b ^ c ^ d);
        
        for (; i < 60; ++i)
            fin(i, 0x8F1BBCDC, (b & c) | (b & d) | (c & d));
        
        for (; i < 80; ++i)
            fin(i, 0xCA62C1D6, b ^ c ^ d);

        // update hash
        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
    }

    sha1& sha1::push(size_t ndata, const uint8_t* data)
    {
        for (size_t i = 0 ; i < ndata ; ++i)
        {
            block[off++] = data[i];
            ++total;

            if (off == std::size(block))
            {
                process_sha1_block(hash, block);
                off = 0;
            }
        }

        return *this;
    }

    sha1::digest sha1::finish()
    {
        // number of bits
        const uint64_t ml = total*8;

        // Add 0x80
        block[off++] = 0x80;
        if (off == std::size(block))
        {
            process_sha1_block(hash, block);
            off = 0;
        }

        // Add remaining 0 bits
        if (off > 56)
        {
            for (size_t i = off ; i < 64 ; ++i)
                block[off++] = 0;
            process_sha1_block(hash, block);
            off = 0;
        }

        for (size_t i = off ; i < 56 ; ++i)
            block[off++] = 0;
        
        // Add message length
        for (int i = 7 ; i >= 0 ; --i)
            block[off++] = static_cast<uint8_t>((ml >> i*8) & 0xFF);
        assert(off == std::size(block));
        process_sha1_block(hash, block);

        // Get final hash
        digest h = {};
        for (size_t i = 0 ; i < 5 ; ++i)
        {
            h[i*4+0] = static_cast<uint8_t>((hash[i] >> 24) & 0xFF);
            h[i*4+1] = static_cast<uint8_t>((hash[i] >> 16) & 0xFF);
            h[i*4+2] = static_cast<uint8_t>((hash[i] >> 8)  & 0xFF);
            h[i*4+3] = static_cast<uint8_t>(hash[i]         & 0xFF);
        }
        return h;
    }

//----------------------------------------------------------------------------------------------------------------

    constexpr std::array<uint8_t, 64> base64_encode_table = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
    };

    constexpr std::array<uint8_t, 256> base64_decoded_table = [] {
        std::array<uint8_t, 256> table{};
        for (size_t i = 0 ; i < base64_encode_table.size() ; ++i)
            table[base64_encode_table[i]] = i;
        return table;
    }();

    std::string base64_encode(const size_t ndata, const uint8_t* data)
    {
        std::string ret;
        ret.reserve((ndata+2) / 3 * 4);
        uint8_t word{0};
        uint8_t off{6};

        for (size_t i = 0 ; i < ndata ; ++i)
        {
            const uint8_t byte = data[i];

            for (int j = 7 ; j >= 0 ; --j)
            {
                const uint8_t bit = (byte >> j) & 0x1;

                word |= (bit << --off);

                if (off == 0)
                {
                    assert(word < 64);
                    ret.push_back(base64_encode_table[word]);
                    off  = 6;
                    word = 0;
                }
            }
        }

        assert(off == 6 || off == 2 || off == 4);

        if (off < 6)
        {
            const size_t npadding = off / 2;
            ret.push_back(base64_encode_table[word]);
            for (size_t i = 0 ; i < npadding ; ++i)
                ret.push_back('=');
        }
        
        return ret;
    }

    std::vector<uint8_t> base64_decode(std::string_view data)
    {
        std::vector<uint8_t> ret;
        ret.reserve(data.size() / 4 * 3);
        uint8_t word{0};
        uint8_t off{8};

        for (size_t i = 0 ; i < data.size() ; ++i)
        {
            if (data[i] == '=')
                continue;

            const uint8_t sixtet = base64_decoded_table[data[i]];

            for (int j = 5 ; j >= 0 ; --j)
            {
                const uint8_t bit = (sixtet >> j) & 0x1;

                word |= (bit << --off);

                if (off == 0)
                {
                    ret.push_back(word);
                    off  = 8;
                    word = 0;
                }
            }
        }

        return ret;
    }

//----------------------------------------------------------------------------------------------------------------

    static char from_hex(char ch) {return std::isdigit(ch) ? ch - '0' : std::tolower(ch) - 'a' + 10;}
    static char to_hex(char code) {constexpr char hex[] = "0123456789abcdef";  return hex[code & 15];}

    static std::string url_encode(std::string_view str)
    {
        std::string ret(str.size()*3+1, '\0');
        char* buf = &ret[0];

        for (auto c : str)
        {
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
                *buf++ = c;
            else if (c == ' ')
                *buf++ = '+';
            else
                *buf++ = '%', *buf++ = to_hex(c >> 4), *buf++ = to_hex(c & 15);
        }

        ret.resize(strlen(ret.data()));
        return ret;
    }

    static std::string url_decode(std::string_view str)
    {
        std::string ret(str.size() + 1, '\0');
        char* buf = &ret[0];

        for (size_t i = 0 ; i < str.size() ; ++i)
        {
            if (str[i] == '%' && str.size() > (i+2))
            {
                *buf++ = from_hex(str[i+1]) << 4 | from_hex(str[i+2]);
                i += 2;
            }
            else if (str[i] == '+')
                *buf++ = ' ';
            else
                *buf++ = str[i];
        }
        
        ret.resize(strlen(ret.data()));
        return ret;
    }

//----------------------------------------------------------------------------------------------------------------

    void parse_url(std::string_view url, std::string& target, std::vector<query_param>& params, std::error_code& ec)
    {
        // Find target
        auto end = url.find_first_of('?');
        target   = url.substr(0, end);
        auto pos = end + 1;
        if (end == std::string::npos || pos >= url.size())
            return;

        const auto extract_kv = [&](std::string_view query)
        {
            const auto key_end = query.find_first_of('=');

            if (key_end == std::string::npos || key_end+1 > query.size())
            {
                ec = make_error_code(http_read_bad_query_string);
            }
            else 
            {
                const std::string_view key = query.substr(0, key_end);
                const std::string_view val = query.substr(key_end+1);
                params.push_back({url_decode(key), url_decode(val)});
                pos = end + 1;
            }
        };

        // Find params
        while ((end = url.find_first_of('&', pos)) != std::string::npos && !ec)
        {
            extract_kv(url.substr(pos, end-pos));
            pos = end + 1;
        }

        if (!ec)
            extract_kv(url.substr(pos));  
    }

//----------------------------------------------------------------------------------------------------------------

    bool header::contains_value(std::string_view v) const
    {
        return value.find(v) != std::string_view::npos;
    }

//----------------------------------------------------------------------------------------------------------------
    
    constexpr auto find_field = [] (auto&& headers, const field f)
    {
        return std::find_if(begin(headers), end(headers), [=](const auto& hdr) {return hdr.key == f;});
    };

    constexpr auto remove_field = [] (auto& headers, const field f)
    {
        headers.erase(std::remove_if(begin(headers), end(headers), [=](const auto& hdr) {return hdr.key == f;}), end(headers));
    };

    constexpr auto contains = [] (auto&& headers, const field f)
    {
        return find_field(headers, f) != end(headers);
    };

    constexpr auto is_websocket_message = [](const auto& headers)
    {
        auto conn_field     = find_field(headers, field::connection);
        auto upgrade_field  = find_field(headers, field::upgrade);

        return conn_field    != end(headers) && 
               upgrade_field != end(headers) &&
               (conn_field->contains_value("Upgrade")      || conn_field->contains_value("upgrade")) &&
               (upgrade_field->contains_value("Websocket") || upgrade_field->contains_value("websocket"));
    };

//----------------------------------------------------------------------------------------------------------------

    void request::clear()
    {
        uri.clear();
        headers.clear();
        content.clear();
        http_version_minor = -1;
        verb = UNKNOWN_VERB;
    }

    void request::add_header(field f, std::string_view value)
    {
        headers.push_back({f, std::string(value)});
    }

    auto request::find(field f) const -> std::vector<header>::const_iterator
    {
        return find_field(headers, f);
    }

    bool request::keep_alive() const
    {
        auto it = find(field::connection);

        if (it != end(headers))
        {
            if (it->contains_value("keep-alive") || it->contains_value("Keep-Alive"))
                return true;

            else if (it->contains_value("Close") || it->contains_value("close"))
                return false;
        }

        // HTTP 1.1 - default is to keep open otherwise default is to close
        return http_version_minor == 1;
    }

    bool request::is_websocket_req() const
    {
        return is_websocket_message(headers);
    }

//----------------------------------------------------------------------------------------------------------------

    void response::clear()
    {
        status              = unknown;
        http_version_minor  = -1;
        headers.clear();
        content_str.clear();
        content_file.reset();
    }   
    
    void response::add_header(field f, std::string_view value)
    {
        headers.push_back({f, std::string(value)});
    }

    auto response::find(field f) const -> std::vector<header>::const_iterator
    {
        return find_field(headers, f);
    }

    void response::keep_alive(bool keep_alive_)
    {
        add_header(field::connection, keep_alive_ ? "keep-alive" : "close");
    }

    bool response::is_websocket_response() const
    {
        return is_websocket_message(headers);
    }

//----------------------------------------------------------------------------------------------------------------

    template<class Message>
    parser<Message>::parser()
    {
        reset();   
    }

    template<class Message>
    void parser<Message>::reset()
    {
        if constexpr (std::is_same_v<Message, request>)
            state = method;
        else
            state = http_version;
        body_read = 0;
    }

    template<class Message>
    bool parser<Message>::parse(Message& msg, std::string& buf, std::error_code& ec)
    {
        using namespace details;

        while (!buf.empty() && !ec && state != done)
        {
            // Check buffer size
            if (buf.size() > max_header_size)
                ec = make_error_code(http_read_header_line_too_big);

            // Start line method (Request only)
            else if (state == method)
            {
                constexpr std::size_t max_method_size{16};

                // Sufficient data
                if (buf.size() >= max_method_size)
                {
                    std::string_view method_str(&buf[0], max_method_size);
                    const auto      end     = method_str.find(" ");
                    const verb_type method  = verb_enum(method_str.substr(0, end));
                    
                    // Found
                    if (method != UNKNOWN_VERB)
                    {
                        if constexpr (std::is_same_v<Message, request>)
                            msg.verb = method;
                        
                        state = uri;
                        buf.erase(begin(buf), begin(buf) + end + 1);
                    }

                    // Not found
                    else
                        ec = make_error_code(http_read_bad_method);
                }
                
                // Insufficient
                else
                    break;                
            }

            // URI (Request only)
            else if (state == uri)
            {
                const auto end = buf.find(" ");

                // Found
                if (end != std::string_view::npos)
                {
                    if constexpr (std::is_same_v<Message, request>)
                        parse_url(buf.substr(0, end), msg.uri, msg.params, ec);
                    
                    state = http_version;
                    buf.erase(begin(buf), begin(buf) + end + 1);
                }

                // Not found
                else
                    break;
            }

            // HTTP version
            else if (state == http_version)
            {
                constexpr std::size_t http_size{8};

                // Sufficient data
                if (buf.size() > 10)
                {
                    buf[http_size] = '\0';
                    int major{-1};
                    int minor{-1};
                    const int ret = sscanf(&buf[0], "HTTP/%i.%i", &major, &minor);

                    // Found 
                    if (ret == 2 && major == 1 && (minor == 0 || minor == 1))
                    {
                        if constexpr (std::is_same_v<Message, request>)
                        {
                            state = header_line;
                            buf.erase(begin(buf), begin(buf) + http_size + 2);
                        }
                            
                        else
                        {
                            state = status_code;
                            buf.erase(begin(buf), begin(buf) + http_size + 1);
                        }
                            
                        msg.http_version_minor = minor;
                    }

                    // Not found
                    else
                        ec = make_error_code(http_read_unsupported_http_version);
                }

                // Insufficient
                else
                    break;
            }

            // Status code (response only)
            else if (state == status_code)
            {
                const auto end = buf.find(" ");

                // Sufficient
                if (end != std::string::npos)
                {
                    buf[end] = '\0';
                    int status{-1};
                    const int ret = sscanf(&buf[0], "%i", &status);

                    // Found
                    if (ret == 1 && status >= (int)status_type::continue_ && status <= 1000)
                    {
                        if constexpr (std::is_same_v<Message, response>)
                            msg.status = (status_type)status;
                        state = status_msg;
                        buf.erase(begin(buf), begin(buf) + end + 1);
                    }
                    
                    // Not found
                    else
                        ec = make_error_code(http_read_bad_status);
                }

                // Insufficient
                else
                    break;
            }

            // Status label
            else if (state == status_msg)
            {
                const auto end = buf.find("\r\n");

                // Found
                if (end != std::string::npos)
                {
                    state = header_line;
                    buf.erase(begin(buf), begin(buf) + end + 2);
                }

                // Not Found
                else
                    ec = make_error_code(http_read_bad_status);
            }

            // Header line
            else if (state == header_line)
            {
                // Find EOL
                char* end = strstr(&buf[0], "\r\n");

                // Not found
                if (end == nullptr)
                    break;
                    
                // Found
                else
                {
                    *end = '\0';

                    // Header line
                    if (std::distance(&buf[0], end) > 0)
                    {
                        char* kend = strstr(&buf[0], ": ");

                        if (kend == nullptr)
                            ec = make_error_code(http_read_header_kv_delimiter_not_found);
                        
                        else
                        {
                            auto field = field_enum(std::string_view(&buf[0], std::distance(&buf[0], kend)));
                            auto value = std::string_view(kend+2, std::distance(kend+2, end));

                            if (field == unknown_field)
                                ec = make_error_code(http_read_header_unsupported_field);
                            else
                                msg.add_header(field, value);
                        }
                    }

                    // End of header - found \r\n\r\n
                    else
                    {
                        const auto it               = msg.find(field::content_length);
                        const size_t content_size   = it != msg.headers.end() ? std::stoul(it->value) : 0;

                        // Read body
                        if (content_size > 0)
                        {
                            state = body;
                            get_content(msg).resize(content_size);
                        }

                        // Empty body
                        else
                            state = done;
                    }

                    buf.erase(begin(buf), begin(buf) + std::distance(&buf[0], end + 2));
                }
            }

            // Body
            else if (state == body)
            {
                const size_t remaining = get_content(msg).size() - body_read;
                const size_t available = std::min(remaining, buf.size());
                std::copy(begin(buf), begin(buf) + available, begin(get_content(msg)) + body_read);
                buf.erase(begin(buf), begin(buf) + available);
                body_read += available;
                    
                if (get_content(msg).size() == body_read)
                    state = done;
            }
        }

        return state == done;
    }

    template class parser<request>;
    template class parser<response>;

//----------------------------------------------------------------------------------------------------------------

    const auto handle_empty = [](auto& msg)
    {
        remove_field(msg.headers, field::content_type);
        remove_field(msg.headers, field::content_length);
    };

    const auto handle_content = [](auto& msg, const std::string& content)
    {
        // Add default Content type if empty
        if (!contains(msg.headers, field::content_type))
            msg.add_header(field::content_type, "text/plain");
        
        // Set Content length
        auto it = find_field(msg.headers, field::content_length);
        if (it == end(msg.headers))
            msg.add_header(field::content_length, std::to_string(content.size()));
        else
            it->value = std::to_string(content.size());     
    };

    const auto handle_file = [](auto& msg)
    {
        // Content type - assume it's already set
        if (!contains(msg.headers, field::content_type))
            fprintf(stderr, "Content-Type is not set for file\n");

        // Content length
        fseek(msg.content_file.get(), 0, SEEK_END);
        const size_t file_size = ftell(msg.content_file.get());
        fseek(msg.content_file.get(), 0, SEEK_SET);

        auto it = find_field(msg.headers, field::content_length);
        if (it == end(msg.headers))
            msg.add_header(field::content_length, std::to_string(file_size));
        else
            it->value = std::to_string(file_size);
    };

    const auto serialize_header_final = [](auto& msg, std::string_view start_line, std::string& buf)
    {
        buf.append(start_line);

        for (const auto& [k, v] : msg.headers)
        {
            buf.append(field_label(k));
            buf.append(": ");
            buf.append(v);
            buf.append("\r\n");
        }
        buf.append("\r\n");
    };

    void serialize_header(request& req, std::string& buf, std::error_code& ec)
    {
        // Check request
        if (req.verb == UNKNOWN_VERB)
        {
            ec = make_error_code(http::http_write_request_bad_verb);
            return;
        }

        if (req.uri.empty())
        {
            ec = make_error_code(http::http_write_request_missing_uri);
            return;
        }

        if (!(req.http_version_minor == 0 || req.http_version_minor == 1))
        {
            ec = make_error_code(http::http_write_unsupported_http_version);
            return;
        }

        // HTTP requests require "host" field
        if (!contains(req.headers, field::host))
        {
            ec = make_error_code(http::http_write_request_missing_host);
            return;
        }

        // Serialize URL
        std::string uri_encoded = req.uri;

        if (!req.params.empty())
        {
            uri_encoded += '?';

            for (size_t i = 0 ; i < req.params.size() ; ++i)
            {
                const std::string key_encoded = url_encode(req.params[i].key);
                const std::string val_encoded = url_encode(req.params[i].val);
                uri_encoded += key_encoded + '=' + val_encoded;
                if (i < (req.params.size() - 1))
                    uri_encoded += '&';
            }
        }

        // Set request line
        const std::string status_str = format("%s %s HTTP/1.%i\r\n", verb_label(req.verb).data(), uri_encoded.c_str(), req.http_version_minor);

        // Add default connection string if empty
        if (!contains(req.headers, field::connection))
            req.add_header(field::connection, "close");

        // Handle empty body
        if (req.content.empty())
            handle_empty(req);

        // Handle string body
        else if (!req.content.empty())
            handle_content(req, req.content);

        // Serialize
        serialize_header_final(req, status_str, buf);
    }

    void serialize_header(response& resp, std::string& buf, std::error_code& ec)
    {
        // Set status string
        char status_str[64] = {0};
        snprintf(status_str, sizeof(status_str), "HTTP/1.%i %i %s\r\n", resp.http_version_minor, resp.status, status_label(resp.status).data());

        // Add default server string if empty
        if (!contains(resp.headers, field::server))
            resp.add_header(field::server, "Boost::asio " + std::to_string(BOOST_ASIO_VERSION));

        // Add default connection string if empty
        if (!contains(resp.headers, field::connection))
            resp.add_header(field::connection, "close");

        // Handle empty body
        if (resp.content_str.empty() && resp.content_file == nullptr)
            handle_empty(resp);

        // Handle string body
        else if (!resp.content_str.empty())
            handle_content(resp, resp.content_str);

        // Handle file body
        else if (resp.content_file)
            handle_file(resp);

        // Serialize
        serialize_header_final(resp, status_str, buf);
    }

//----------------------------------------------------------------------------------------------------------------

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
            case http_read_header_line_too_big:             return "HTTP header line is too big";
            case http_read_bad_method:                      return "HTTP request method bad";
            case http_read_unsupported_http_version:        return "HTTP version either bad or unsupported";
            case http_read_bad_status:                      return "HTTP status code bad";
            case http_read_bad_query_string:                return "Bad query string formatting";
            case http_read_header_kv_delimiter_not_found:   return "Missing delimiter in HTTP header line";
            case http_read_header_unsupported_field:        return "HTTP header field unsupported";
            case http_write_unsupported_http_version:       return "HTTP message contains bad or unsupported http minor version";
            case http_write_request_bad_verb:               return "HTTP request contains bad verb";
            case http_write_request_missing_uri:            return "HTTP request missing URI";
            case http_write_request_missing_host:           return "HTTP request missing 'host' filed";
            case ws_handshake_bad_status:                   return "Status code not 101 (Switching Protocol) in websocket upgrade response";
            case ws_handshake_bad_headers:                  return "Missing connection: upgrade or upgrade: websocket in HTTP headers";
            case ws_handshake_missing_seq_accept:           return "Missing seq-websocket-accept in HTTP websocket switching response message";
            case ws_handshake_bad_sec_accept:               return "Bad sec-websocket-accept in HTTP websocket switching response message";
            case ws_accept_missing_seq_key:                 return "Missing seq-websocket-key in HTTP websocket upgrade request message";
            case ws_invalid_opcode:                         return "Received invalid opcode";
            case ws_closing_handshake_non_matching_opcode:  return "Did not receive a CLOSE frame in closing handshake";
            case ws_closing_handshake_non_matching_reason:  return "The CLOSE frame does not have matching status code (reason) as the endpoint who sent the original";
            default:                                        return "Unrecognised error";
            }
        }
    };

    const http_error_category http_error_category_singleton;

    std::error_code make_error_code(error ec)
    {
        return {static_cast<int>(ec), http_error_category_singleton};
    }

//----------------------------------------------------------------------------------------------------------------

    struct ws_code_category : std::error_category
    {
        const char* name() const noexcept override 
        {
            return "ws_code_category";
        }

        std::string message(int ev) const override
        {
            switch(static_cast<ws_code>(ev))
            {
            case ws_normal_closure:                 return "Closed opcode (normal closure)";
            case ws_going_away:                     return "Closed opcode (going away)";
            case ws_protocol_error:                 return "Closed opcode (protocol error)";
            case ws_unsupported_data:               return "Closed opcode (unsupported data)";
            case ws_no_code_received:               return "WS error (no code received)";
            case ws_connection_closed_abnormally:   return "WS error (connection closed abnormally)";
            case ws_invalid_payload_data:           return "Closed opcode (invalid payload data)";
            case ws_policy_violated:                return "Closed opcode (policy violated)";
            case ws_message_too_big:                return "Closed opcode (message too big)";
            case ws_unsupported_extension:          return "Closed opcode (unsupported extensions)";
            case ws_internal_server_error:          return "Closed opcode (internal server error)";
            case ws_tls_handshake_failure:          return "WS error (TLS handshake failure)";
            default:                                return "Unrecognised error";
            }
        }
    };

    const ws_code_category ws_code_category_singleton;

    std::error_code make_error_code(ws_code ec)
    {
        return {static_cast<int>(ec), ws_code_category_singleton};
    }

//----------------------------------------------------------------------------------------------------------------

}
