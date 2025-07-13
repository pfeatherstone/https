#include <cassert>
#include <cstring>
#include <cctype>
#include <charconv>
#include <algorithm>
#include <filesystem>
#include <boost/asio/version.hpp>
#include "http.h"

namespace fs = std::filesystem;

namespace http
{
    
//----------------------------------------------------------------------------------------------------------------

    constexpr uint16_t byte_swap16(uint16_t v)
    {
        return static_cast<uint16_t>(((v & 0x00FF) << 8) | ((v & 0xFF00) >> 8));
    }

    constexpr uint64_t byte_swap64(uint64_t v)
    {
        return static_cast<uint64_t>(((v & 0x00000000000000FFULL) << 56) |
                                    ((v & 0x000000000000FF00ULL) << 40) |
                                    ((v & 0x0000000000FF0000ULL) << 24) |
                                    ((v & 0x00000000FF000000ULL) << 8)  |
                                    ((v & 0x000000FF00000000ULL) >> 8)  |
                                    ((v & 0x0000FF0000000000ULL) >> 24) |
                                    ((v & 0x00FF000000000000ULL) >> 40) |
                                    ((v & 0xFF00000000000000ULL) >> 56));
    }

    static_assert(byte_swap16(0x1234)               == 0x3412,              "bad swap");
    static_assert(byte_swap64(0x123456789abcdef1)   == 0xf1debc9a78563412,  "bad swap");

//----------------------------------------------------------------------------------------------------------------

    inline bool is_little_endian() 
    {
        constexpr uint32_t v{0x01020304};
        const auto*        ptr{reinterpret_cast<const unsigned char*>(&v)};
        return ptr[0] == 0x04;
    }

//----------------------------------------------------------------------------------------------------------------

    inline uint16_t host_to_b16(uint16_t v)
    {
        return is_little_endian() ? byte_swap16(v) : v;
    }

    inline uint64_t host_to_b64(uint64_t v)
    {
        return is_little_endian() ? byte_swap64(v) : v;
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
        return METHOD_UNKNOWN;
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

    std::string_view field_label(field f)
    {
        return FIELDS[f];
    }

    field field_enum(std::string_view f)
    {
        for (unsigned int i = 0 ; i < std::size(FIELDS) ; ++i)
            if (FIELDS[i] == f)
                return (field)i;
        return unknown_field;
    }

//----------------------------------------------------------------------------------------------------------------

    constexpr std::pair<status_type, std::string_view> STATUS_LABELS[] = {
        // 1xx
        {status_type::continue_,                       "Continue"},
        {status_type::switching_protocols,             "Switching Protocols"},
        {status_type::processing,                      "Processing"},
        {status_type::early_hints,                     "Early Hints"},

        // 2xx
        {status_type::ok,                              "OK"},
        {status_type::created,                         "Created"},
        {status_type::accepted,                        "Accepted"},
        {status_type::non_authoritative_information,   "Non-Authoritative Information"},
        {status_type::no_content,                      "No Content"},
        {status_type::reset_content,                   "Reset Content"},
        {status_type::partial_content,                 "Partial Content"},
        {status_type::multi_status,                    "Multi-Status"},
        {status_type::already_reported,                "Already Reported"},
        {status_type::im_used,                         "IM Used"},

        // 3xx
        {status_type::multiple_choices,                "Multiple Choices"},
        {status_type::moved_permanently,               "Moved Permanently"},
        {status_type::found,                           "Found"},
        {status_type::see_other,                       "See Other"},
        {status_type::not_modified,                    "Not Modified"},
        {status_type::use_proxy,                       "Use Proxy"},
        {status_type::temporary_redirect,              "Temporary Redirect"},
        {status_type::permanent_redirect,              "Permanent Redirect"},

        // 4xx
        {status_type::bad_request,                     "Bad Request"},
        {status_type::unauthorized,                    "Unauthorized"},
        {status_type::payment_required,                "Payment Required"},
        {status_type::forbidden,                       "Forbidden"},
        {status_type::not_found,                       "Not Found"},
        {status_type::method_not_allowed,              "Method Not Allowed"},
        {status_type::not_acceptable,                  "Not Acceptable"},
        {status_type::proxy_authentication_required,   "Proxy Authentication Required"},
        {status_type::request_timeout,                 "Request Timeout"},
        {status_type::conflict,                        "Conflict"},
        {status_type::gone,                            "Gone"},
        {status_type::length_required,                 "Length Required"},
        {status_type::precondition_failed,             "Precondition Failed"},
        {status_type::payload_too_large,               "Payload Too Large"},
        {status_type::uri_too_long,                    "URI Too Long"},
        {status_type::unsupported_media_type,          "Unsupported Media Type"},
        {status_type::range_not_satisfiable,           "Range Not Satisfiable"},
        {status_type::expectation_failed,              "Expectation Failed"},
        {status_type::i_am_a_teapot,                   "I'm a teapot"},
        {status_type::misdirected_request,             "Misdirected Request"},
        {status_type::unprocessable_entity,            "Unprocessable Entity"},
        {status_type::locked,                          "Locked"},
        {status_type::failed_dependency,               "Failed Dependency"},
        {status_type::too_early,                       "Too Early"},
        {status_type::upgrade_required,                "Upgrade Required"},
        {status_type::precondition_required,           "Precondition Required"},
        {status_type::too_many_requests,               "Too Many Requests"},
        {status_type::request_header_fields_too_large, "Request Header Fields Too Large"},
        {status_type::unavailable_for_legal_reasons,   "Unavailable For Legal Reasons"},

        // 5xx
        {status_type::internal_server_error,           "Internal Server Error"},
        {status_type::not_implemented,                 "Not Implemented"},
        {status_type::bad_gateway,                     "Bad Gateway"},
        {status_type::service_unavailable,             "Service Unavailable"},
        {status_type::gateway_timeout,                 "Gateway Timeout"},
        {status_type::http_version_not_supported,      "HTTP Version Not Supported"},
        {status_type::variant_also_negotiates,         "Variant Also Negotiates"},
        {status_type::insufficient_storage,            "Insufficient Storage"},
        {status_type::loop_detected,                   "Loop Detected"},
        {status_type::not_extended,                    "Not Extended"},
        {status_type::network_authentication_required, "Network Authentication Required"},
    };

    std::string_view status_label(const status_type s)
    {
        for (auto [k,l] : STATUS_LABELS)
            if (k == s)
                return l;
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
        const std::string ext2 = fs::path(path).extension().string();
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

    constexpr uint8_t top6(const uint8_t a) {return a >> 2;}
    constexpr uint8_t bot6(const uint8_t a) {return a & 0x3f;}
    constexpr uint8_t top4(const uint8_t a) {return a >> 4;}
    constexpr uint8_t bot4(const uint8_t a) {return a & 0x0f;}
    constexpr uint8_t top2(const uint8_t a) {return a >> 6;}
    constexpr uint8_t bot2(const uint8_t a) {return a & 0x03;}

    std::string base64_encode(const size_t ndata, const uint8_t* data)
    {
        std::string ret;
        ret.resize((ndata+2) / 3 * 4);
        char* out{&ret[0]};

        for (size_t i = 0 ; i < ndata ; i += 3)
        {
            if (i+2 < ndata)
            {
                *out++ = base64_encode_table[top6(data[i+0])];
                *out++ = base64_encode_table[(bot2(data[i+0]) << 4) | top4(data[i+1])];
                *out++ = base64_encode_table[(bot4(data[i+1]) << 2) | top2(data[i+2])];
                *out++ = base64_encode_table[bot6(data[i+2])];
            }
            else if (i+1 < ndata)
            {
                *out++ = base64_encode_table[top6(data[i+0])];
                *out++ = base64_encode_table[(bot2(data[i+0]) << 4) | top4(data[i+1])];
                *out++ = base64_encode_table[bot4(data[i+1]) << 2];
                *out++ = '=';
            }
            else
            {
                *out++ = base64_encode_table[top6(data[i+0])];
                *out++ = base64_encode_table[bot2(data[i+0]) << 4];
                *out++ = '=';
                *out++ = '=';
            }
        }

        return ret;
    }

    std::vector<uint8_t> base64_decode(std::string_view data)
    {
        std::vector<uint8_t> ret;
        ret.resize((data.size() + 3)/ 4 * 3);
        uint8_t* out{&ret[0]};

        for (size_t i = 0 ; i < data.size() ; i += 4)
        {
            const uint8_t a0 = base64_decoded_table[data[i+0]];
            const uint8_t a1 = base64_decoded_table[data[i+1]];

            *out++ = (a0 << 2) | (a1 >> 4);

            if ((i+2) < data.size() && data[i+2] != '=')
            {
                const uint8_t a2 = base64_decoded_table[data[i+2]];

                *out++ = ((a1 & 0xf) << 4) | ((a2 & 0x3c) >> 2);

                if ((i+3) < data.size() && data[i+3] != '=')
                {
                    const uint8_t a3 = base64_decoded_table[data[i+3]];

                    *out++ = (a2 & 0x03) << 6 | a3;
                }
            }
        }

        ret.resize(std::distance(&ret[0], out));
        return ret;
    }

//----------------------------------------------------------------------------------------------------------------

    void dynamic_buffer::clear()
    {
        clear_(ptr_);
    }

    size_t dynamic_buffer::size() const
    {
        return size_(ptr_);
    }

    void dynamic_buffer::resize(size_t n)
    {
        resize_(ptr_, n);
    }

    void dynamic_buffer::append(const char* data, size_t ndata)
    {
        append_(ptr_, data, ndata);
    }

    void* dynamic_buffer::data()
    {
        return data_(ptr_);
    }

    boost::asio::const_buffer dynamic_buffer::buffer()
    {
        return boost::asio::const_buffer(data(), size());
    }

//----------------------------------------------------------------------------------------------------------------

    int find_header_private(const std::vector<field>& fields, field f)
    {
        for (size_t i = 0 ; i < fields.size() ; ++i)
            if (fields[i] == f)
                return i;
        return -1;
    }

    void headers_container::clear()
    {
        buf.clear();
        fields.clear();
        offsets.clear();
    }

    size_t headers_container::size() const
    {
        return fields.size();
    }

    std::optional<std::string_view> headers_container::find(field f) const
    {
        const auto index = find_header_private(fields, f);
        if (index == -1) return std::nullopt;
        const auto off = offsets[index];
        const auto end = (index+1) < fields.size() ? offsets[index+1] : buf.size();
        return std::string_view(&buf[off], end-off);
    }

    void headers_container::add(field f, std::string_view value)
    {
        const size_t off = buf.size();
        buf.insert(end(buf), begin(value), end(value));
        fields.push_back(f);
        offsets.push_back(off);
    }

    void headers_container::remove(field f)
    {
        const auto index = find_header_private(fields, f);
        if (index == -1) return;
        const auto off = offsets[index];
        const auto end = (index+1) < fields.size() ? offsets[index+1] : buf.size();
        const auto len = end-off;
        for (size_t i = index+1 ; i < offsets.size() ; ++i)
            offsets[i] -= len;
        offsets.erase(begin(offsets) + index);
        fields.erase(begin(fields) + index);
        buf.erase(begin(buf) + off, begin(buf) + end);
    }

    void headers_container::modify(field f, std::string_view value)
    {
        const auto index = find_header_private(fields, f);
        if (index == -1) return add(f, value);
        const auto off = offsets[index];
        const auto end = (index+1) < fields.size() ? offsets[index+1] : buf.size();
        const auto len = end-off;
        buf.erase(begin(buf) + off, begin(buf) + end);
        buf.insert(begin(buf) + off, begin(value), std::end(value));
        const auto len2 = value.size();
        for (size_t i = index+1 ; i < offsets.size() ; ++i)
            offsets[i] = (offsets[i] + len2) - len;
    }

    auto headers_container::operator[](const size_t i) const -> std::pair<field, std::string_view>
    {
        assert(i < size());
        const auto off = offsets[i];
        const auto end = (i+1) < fields.size() ? offsets[i+1] : buf.size();
        return std::make_pair(fields[i], std::string_view(&buf[off], end-off));
    }

//----------------------------------------------------------------------------------------------------------------
    
    auto contains(std::string_view str, std::string_view value)
    {
        return str.find(value) != std::string_view::npos;
    }

    auto is_websocket_message(const headers_container& h)
    {
        auto conn_field     = h.find(field::connection);
        auto upgrade_field  = h.find(field::upgrade);

        return conn_field.has_value()       && 
               upgrade_field.has_value()    &&
               (contains(*conn_field, "Upgrade")      || contains(*conn_field, "upgrade")) &&
               (contains(*upgrade_field, "Websocket") || contains(*upgrade_field, "websocket"));
    };

//----------------------------------------------------------------------------------------------------------------

    void request::clear()
    {
        verb = METHOD_UNKNOWN;
        version = {};
        uri.clear();
        params.clear();
        headers.clear();
        content.clear();
    }

    bool request::keep_alive() const
    {
        auto conn = headers.find(field::connection);

        if (conn)
        {
            if (contains(*conn, "keep-alive") || contains(*conn, "Keep-Alive"))
                return true;

            else if (contains(*conn, "Close") || contains(*conn, "close"))
                return false;
        }

        // HTTP 1.1 - default is to keep open otherwise default is to close
        return version == HTTP_1_1;
    }

    bool request::is_websocket_req() const
    {
        return is_websocket_message(headers);
    }

//----------------------------------------------------------------------------------------------------------------

    void response::clear()
    {
        status  = unknown;
        version = {};
        headers.clear();
        content_str.clear();
        content_file.reset();
    }   
    
    void response::keep_alive(bool keep_alive_)
    {
        headers.add(field::connection, keep_alive_ ? "keep-alive" : "close");
    }

    bool response::is_websocket_response() const
    {
        return is_websocket_message(headers);
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

    constexpr char fast_ascii_tolower(const char c) 
    {
        // The following is a tad faster than std::tolower(c)
        return (c >= 'A' && c <= 'Z') ? (c | 0x20) : c;
    }

//----------------------------------------------------------------------------------------------------------------

    constexpr size_t max_header_size = 8192;

    enum parsing_result
    {
        parse_incomplete,
        parse_ok
    };

//----------------------------------------------------------------------------------------------------------------

    const auto parse_method = [](request& req, std::string& buf, std::error_code& ec, auto cont)
    {
        constexpr std::size_t max_method_size{16};

        parsing_result res{parse_incomplete};

        // Sufficient data
        if (buf.size() >= max_method_size)
        {
            std::string_view method_str(&buf[0], max_method_size);
            const auto      end     = method_str.find(' ');
            const verb_type method  = verb_enum(method_str.substr(0, end));
            
            // Valid
            if (method != METHOD_UNKNOWN)
            {
                req.verb = method;
                buf.erase(begin(buf), begin(buf) + end + 1);
                cont();
                res = parse_ok;
            }

            // Not valid
            else
                ec = make_error_code(http_read_bad_method);
        }
        
        return res;    
    };

//----------------------------------------------------------------------------------------------------------------

    const auto parse_uri = [](request& req, std::string& buf, std::error_code& ec, auto cont)
    {
        parsing_result res{parse_incomplete};

        auto* end = strchr(&buf[0], ' ');

        if (end != nullptr)
        {
            const size_t len = std::distance(&buf[0], end);
            parse_url(std::string_view(&buf[0],len), req.uri, req.params, ec);
            buf.erase(begin(buf), begin(buf) + len + 1);
            cont();
            res = parse_ok;
        }

        return res;
    };

//----------------------------------------------------------------------------------------------------------------

    const auto parse_version = [](auto& msg, std::string& buf, std::error_code& ec, auto cont)
    {
        using Message = std::remove_cv_t<std::remove_reference_t<decltype(msg)>>;
        constexpr std::size_t http_size{8};
        constexpr std::size_t tail_size = std::is_same_v<Message, request> ? 2 : 1;

        parsing_result res{parse_incomplete};

        // Sufficient data
        if (buf.size() > 10)
        {
            buf[http_size] = '\0';
            int major{-1};
            int minor{-1};
            const int ret = sscanf(&buf[0], "HTTP/%i.%i", &major, &minor);

            // Valid 
            if (ret == 2 && major == 1 && (minor == 0 || minor == 1))
            { 
                msg.version = (http_version)minor;
                buf.erase(begin(buf), begin(buf) + http_size + tail_size);
                cont();
                res = parse_ok;
            }

            // Not valid
            else
                ec = make_error_code(http_read_unsupported_http_version);
        }

        return res;
    };

//----------------------------------------------------------------------------------------------------------------

    const auto parse_status_code = [](response& msg, std::string& buf, std::error_code& ec, auto cont)
    {
        parsing_result res{parse_incomplete};

        auto* end = strchr(&buf[0], ' ');

        // Sufficient
        if (end != nullptr)
        {
            const size_t len = std::distance(&buf[0], end);
            *end = '\0';
            int status{-1};
            const int ret = sscanf(&buf[0], "%i", &status);

            // Valid
            if (ret == 1 && status >= (int)status_type::continue_ && status <= 1000)
            {
                msg.status = (status_type)status;
                buf.erase(begin(buf), begin(buf) + len + 1);
                cont();
                res = parse_ok;
            }
            
            // Not valid
            else
                ec = make_error_code(http_read_bad_status);
        }

        return res;
    };

//----------------------------------------------------------------------------------------------------------------

    const auto parse_status_msg = [](response& msg, std::string& buf, std::error_code& ec, auto cont)
    {
        parsing_result res{parse_incomplete};

        auto* end = strstr(&buf[0], "\r\n");

        // Sufficient
        if (end != nullptr)
        {
            buf.erase(begin(buf), begin(buf) + std::distance(&buf[0], end) + 2);
            cont();
            res = parse_ok;
        }

        return res;
    };

//----------------------------------------------------------------------------------------------------------------

    const auto parse_header = [](auto& msg, std::string& buf, std::error_code& ec, auto cont)
    {
        using details::get_content;

        parsing_result res{parse_incomplete};

        auto* end = strstr(&buf[0], "\r\n");

        // Sufficient
        if (end != nullptr)
        {
            *end = '\0';
            const size_t line_length = std::distance(&buf[0], end);

            // Found header
            if (line_length > 0)
            {
                auto* kend = strstr(&buf[0], ": ");

                if (kend == nullptr)
                    ec = make_error_code(http_read_header_kv_delimiter_not_found);

                else
                {
                    for (auto* ptr = &buf[0] ; ptr != kend ; ++ptr)
                        *ptr = fast_ascii_tolower(*ptr);

                    auto field = field_enum(std::string_view(&buf[0], std::distance(&buf[0], kend)));
                    auto value = std::string_view(kend+2, std::distance(kend+2, end));

                    if (field == unknown_field)
                        ec = make_error_code(http_read_header_unsupported_field);

                    else
                        msg.headers.add(field, value);
                        res = parse_ok;
                }
            }

            // End of header - found \r\n\r\n
            else
            {
                const auto it = msg.headers.find(field::content_length);
                size_t content_size{0};
                if (it) std::from_chars(it->data(), it->data() + it->size(), content_size);
                get_content(msg).resize(content_size);
                cont();
                res = parse_ok;
            }

            buf.erase(begin(buf), begin(buf) + line_length + 2);
        }

        return res;
    };

//----------------------------------------------------------------------------------------------------------------

    const auto parse_body = [](auto& msg, std::string& buf, size_t& body_read, std::error_code& ec, auto cont)
    {
        using details::get_content;

        const size_t remaining = get_content(msg).size() - body_read;
        const size_t available = std::min(remaining, buf.size());
        std::copy(begin(buf), begin(buf) + available, begin(get_content(msg)) + body_read);
        buf.erase(begin(buf), begin(buf) + available);
        body_read += available;
            
        if (get_content(msg).size() == body_read)
            cont();

        return parse_ok;
    };

//----------------------------------------------------------------------------------------------------------------

    bool parser_request::parse(request& req, std::string& buf, std::error_code& ec)
    {
        using namespace details;

        while (!buf.empty() && !ec && state != done)
        {
            // Check buffer size
            if (buf.size() > max_header_size)
                ec = make_error_code(http_read_header_line_too_big);

            else
            {
                parsing_result res{parse_incomplete};

                switch(state)
                {
                case parser_request::method:        res = parse_method(req, buf, ec,  [&]{state = parser_request::uri;});           break;
                case parser_request::uri:           res = parse_uri(req, buf, ec,     [&]{state = parser_request::version;});       break;
                case parser_request::version:       res = parse_version(req, buf, ec, [&]{state = parser_request::header_line;});   break;
                case parser_request::header_line:   res = parse_header(req, buf, ec,  [&]{state = !req.content.empty() ? parser_request::body : parser_request::done;}); break;
                case parser_request::body:          res = parse_body(req, buf, body_read, ec, [&]{state = parser_request::done;});  break;
                case parser_request::done: break;
                }  
                
                if (res == parse_incomplete)
                    break;
            }
        }

        return state == done;
    }

    bool parser_response::parse(response& resp, std::string& buf, std::error_code& ec)
    {
        using namespace details;

        while (!buf.empty() && !ec && state != done)
        {
            // Check buffer size
            if (buf.size() > max_header_size)
                ec = make_error_code(http_read_header_line_too_big);

            else
            {
                parsing_result res{parse_incomplete};

                switch(state)
                {
                case parser_response::version:      res = parse_version(resp, buf, ec,      [&]{state = parser_response::status_code;});    break;
                case parser_response::status_code:  res = parse_status_code(resp, buf, ec,  [&]{state = parser_response::status_msg;});     break;
                case parser_response::status_msg:   res = parse_status_msg(resp, buf, ec,   [&]{state = parser_response::header_line;});    break;
                case parser_response::header_line:  res = parse_header(resp, buf, ec,       [&]{state = !resp.content_str.empty() ? parser_response::body : parser_response::done;}); break;
                case parser_response::body:         res = parse_body(resp, buf, body_read, ec, [&]{state = parser_response::done;});        break;
                case parser_response::done: break;
                }  
                
                if (res == parse_incomplete)
                    break;
            }
        }

        return state == done;
    }

//----------------------------------------------------------------------------------------------------------------

    const auto handle_empty = [](auto& msg)
    {
        msg.headers.remove(field::content_type);
        msg.headers.remove(field::content_length);
    };

    const auto handle_content = [](auto& msg, const std::string& content)
    {
        // Add default Content type if empty
        if (!msg.headers.find(field::content_type))
            msg.headers.add(field::content_type, "text/plain");
        
        // Set Content length
        msg.headers.modify(field::content_length, std::to_string(content.size()));
    };

    const auto handle_file = [](auto& msg)
    {
        // Content type - assume it's already set
        if (!msg.headers.find(field::content_type))
            fprintf(stderr, "Content-Type is not set for file\n");

        // Content length
        fseek(msg.content_file.get(), 0, SEEK_END);
        const size_t file_size = ftell(msg.content_file.get());
        fseek(msg.content_file.get(), 0, SEEK_SET);
        msg.headers.modify(field::content_length, std::to_string(file_size));
    };

    const auto serialize_header_final = [](auto& msg, std::string_view start_line, std::string& buf)
    {
        buf.append(start_line);

        for (size_t i = 0 ; i < msg.headers.size() ; ++i)
        {
            const auto[k,v] = msg.headers[i];
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
        if (req.verb == METHOD_UNKNOWN)
        {
            ec = make_error_code(http::http_write_request_bad_verb);
            return;
        }

        if (req.uri.empty())
        {
            ec = make_error_code(http::http_write_request_missing_uri);
            return;
        }

        // HTTP requests require "host" field
        if (!req.headers.find(field::host))
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
        std::string_view verb = verb_label(req.verb);
        std::string      status_str(verb.size() + uri_encoded.size() + 32, '\0');
        const int status_len = snprintf(&status_str[0], status_str.size(), "%s %s HTTP/1.%i\r\n", verb.data(), uri_encoded.c_str(), (int)req.version);
        status_str.resize(status_len);

        // Add default connection string if empty
        if (!req.headers.find(field::connection))
            req.headers.add(field::connection, "close");

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
        if (resp.status == unknown)
        {
            ec = make_error_code(http_write_response_missing_status);
            return;
        }

        // Set status string
        char status_str[64] = {0};
        snprintf(status_str, sizeof(status_str), "HTTP/1.%i %i %s\r\n", (int)resp.version, resp.status, status_label(resp.status).data());

        // Add default server string if empty
        if (!resp.headers.find(field::server))
            resp.headers.add(field::server, "Boost::asio " + std::to_string(BOOST_ASIO_VERSION));

        // Add default connection string if empty
        if (!resp.headers.find(field::connection))
            resp.headers.add(field::connection, "close");

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

    struct websocket_frame
    {
        unsigned char opcode : 4;
        unsigned char rsv3   : 1;
        unsigned char rsv2   : 1;
        unsigned char rsv1   : 1;
        unsigned char fin    : 1;
        unsigned char paylen : 7;
        unsigned char masked : 1;
    };

    static_assert(sizeof(websocket_frame) == 2, "bad");

//----------------------------------------------------------------------------------------------------------------

    bool websocket_parser::parse(dynamic_buffer msg, std::string& buf, std::error_code& ec)
    {
        while (!buf.empty() && !ec && state != done)
        {
            if (state == header_frame)
            {
                // Sufficient data
                if (buf.size() >= sizeof(websocket_frame))
                {
                    // Read header
                    websocket_frame hdr{};
                    memcpy(&hdr, &buf[0], sizeof(websocket_frame));
                    buf.erase(begin(buf), begin(buf) + sizeof(websocket_frame));

                    const bool opcode_valid = 
                        hdr.opcode == (unsigned char)WS_OPCODE_CONTINUATION || 
                        hdr.opcode == (unsigned char)WS_OPCODE_DATA_TEXT    || 
                        hdr.opcode == (unsigned char)WS_OPCODE_DATA_BINARY  ||
                        hdr.opcode == (unsigned char)WS_OPCODE_CLOSE        ||
                        hdr.opcode == (unsigned char)WS_OPCODE_PING         ||
                        hdr.opcode == (unsigned char)WS_OPCODE_PONG;

                    if (!opcode_valid)
                    {
                        ec = http::ws_read_bad_opcode;
                        break;
                    }

                    const bool rsv_valid = 
                        hdr.rsv1 == 0 && 
                        hdr.rsv2 == 0 && 
                        hdr.rsv3 == 0;
                    
                    if (!rsv_valid)
                    {
                        ec = http::ws_read_bad_rsv;
                        break;
                    }

                    // Update state
                    is_masked = hdr.masked;
                    is_last   = hdr.fin;
                    paylen    = hdr.paylen;
                    if (hdr.opcode > 0)
                        opcode = (websocket_opcode)hdr.opcode;
                    
                    // Calculate size of next header bit
                    hdr_extra_size = 0;
                    if (paylen == 126)
                        hdr_extra_size = 2;
                    else if (paylen == 127)
                        hdr_extra_size = 8;
                    if (is_masked)
                        hdr_extra_size += 4;
                    
                    if (hdr_extra_size > 0)
                        state = header_extra;
                    else
                        state = body;
                }

                // Insufficient
                else
                    break;
            }

            else if (state == header_extra)
            {
                // Sufficient
                if (buf.size() >= hdr_extra_size)
                {
                    size_t off{0};

                    // Read 16-bit paylen
                    if (paylen == 126)
                    {
                        uint16_t len{0};
                        memcpy(&len, &buf[off], 2);
                        paylen = host_to_b16(len);
                        off += 2;
                    }
                
                    // Read 64-bit paylen
                    else if (paylen == 127)
                    {
                        uint64_t len{0};
                        memcpy(&len, &buf[off], 8);
                        paylen = host_to_b64(len);
                        off += 8;
                    }

                    // Read mask
                    if (is_masked)
                    {
                        memcpy(mask_key, &buf[off], 4);
                        off += 4;
                    }

                    assert(off == hdr_extra_size);
                    buf.erase(begin(buf), begin(buf) + off);
                    state = body;
                }

                // Insufficient
                else
                    break;
            }

            else if (state == body)
            {
                // Sufficient
                if (buf.size() >= paylen)
                {
                    // Un-mask if necessary
                    if (is_masked)
                    {
                        for (size_t i = 0 ; i < paylen ; ++i)
                            buf[i] ^= mask_key[i%4];
                    }

                    // Add to message
                    msg.append(&buf[0], paylen);
                    buf.erase(begin(buf), begin(buf) + paylen);
                    state = is_last ? done : header_frame;
                }

                // Insufficient
                else
                    break;
            }
        }

        return state == done;
    }

    websocket_opcode websocket_parser::get_opcode() const
    {
        return opcode;
    }

    bool websocket_parser::is_server() const
    {
        return !is_masked;
    }

//----------------------------------------------------------------------------------------------------------------

    void serialize_websocket_message(boost::asio::const_buffer msg, websocket_opcode opcode, bool do_mask, std::string& buf)
    {
        // Header
        websocket_frame hdr{};
        memset(&hdr, 0, sizeof(websocket_frame));
        size_t hdr_len = sizeof(websocket_frame);
        hdr.fin     = 1;
        hdr.masked  = do_mask;
        hdr.opcode  = opcode;

        // Header 
        if (msg.size() < 126)
        {
            hdr.paylen = msg.size();
        }     
        else if (msg.size() <= 65535)
        {
            hdr.paylen = 126;
            hdr_len += 2;
        }
        else
        {
            hdr.paylen = 127;
            hdr_len += 8;
        }

        if (do_mask)
        {
            hdr_len += 4;
        }

        // Initialize buffer
        buf.resize(hdr_len + msg.size());
        
        // Add header
        size_t off{0};
        memcpy(&buf[off], &hdr, sizeof(websocket_frame));
        off += sizeof(websocket_frame);

        if (hdr.paylen == 126)
        {
            uint16_t len = host_to_b16((uint16_t)msg.size());
            memcpy(&buf[off], &len, 2);
            off += 2;
        }

        else if (hdr.paylen == 127)
        {
            uint64_t len = host_to_b64((uint64_t)msg.size());
            memcpy(&buf[off], &len, 8);
            off += 8;
        }

        uint8_t mask_key[4];

        if (do_mask)
        {
            // Create mask key
            mask_key[0] = std::rand() % 0xff;
            mask_key[1] = std::rand() % 0xff;
            mask_key[2] = std::rand() % 0xff;
            mask_key[3] = std::rand() % 0xff;

            // Write mask key
            memcpy(&buf[off], mask_key, 4);
            off += 4;
        }

        assert(off == hdr_len);

        // Add data
        if (do_mask)
        {
            auto data = static_cast<const uint8_t*>(msg.data());
            for (size_t i = 0 ; i < msg.size() ; ++i)
                buf[hdr_len+i] = data[i] ^ mask_key[i%4];
        }
        else
        {
            memcpy(&buf[hdr_len], msg.data(), msg.size());
        }
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
            case http_read_header_line_too_big:             return "Header line is too big";
            case http_read_bad_method:                      return "Request method bad";
            case http_read_unsupported_http_version:        return "HTTP version either bad or unsupported";
            case http_read_bad_status:                      return "HTTP status code bad";
            case http_read_bad_query_string:                return "Bad query string formatting";
            case http_read_header_kv_delimiter_not_found:   return "Missing delimiter in HTTP header line";
            case http_read_header_unsupported_field:        return "HTTP header field unsupported";
            case http_write_request_bad_verb:               return "HTTP request contains bad verb";
            case http_write_request_missing_uri:            return "HTTP request missing URI";
            case http_write_request_missing_host:           return "HTTP request missing 'host' filed";
            case http_write_response_missing_status:        return "Missing status code";
            case ws_handshake_bad_status:                   return "Status code not 101 (Switching Protocol) in websocket upgrade response";
            case ws_handshake_bad_headers:                  return "Missing connection: upgrade or upgrade: websocket in HTTP headers";
            case ws_handshake_missing_seq_accept:           return "Missing seq-websocket-accept in HTTP websocket switching response message";
            case ws_handshake_bad_sec_accept:               return "Bad sec-websocket-accept in HTTP websocket switching response message";
            case ws_accept_missing_seq_key:                 return "Missing seq-websocket-key in HTTP websocket upgrade request message";
            case ws_read_bad_opcode:                        return "websocket_frame invalid opcode";
            case ws_read_bad_rsv:                           return "websocket_frame invalid rsv bits";
            case ws_closing_handshake_non_matching_opcode:  return "Did not receive a CLOSE frame in closing handshake";
            case ws_closing_handshake_non_matching_reason:  return "The CLOSE frame does not have matching status code (reason) as the endpoint who sent the original";
            case ws_invalid_opcode:                         return "Received invalid opcode";
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
