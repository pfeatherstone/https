#include <cstring>
#include <algorithm>
#include <filesystem>
#include <system_error>
#include <boost/asio/version.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include "http.h"

namespace fs = std::filesystem;

namespace http
{

//---------------------------------------------------push_back-------------------------------------------------------------

    const auto BOOST_ASIO_VERSION_STRING = []() -> std::string 
    {
        char buf[16]= {0};
        snprintf(buf, sizeof(buf), "%d.%d.%d", BOOST_ASIO_VERSION / 100000, 
                                               BOOST_ASIO_VERSION / 100 % 1000, 
                                               BOOST_ASIO_VERSION % 100);
        return buf;
    }();

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
        fprintf(stderr, "Could not find field enum for %.*s\n", (int)f.size(), f.data());
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
        //10xx - websocket
        case status_type::normal_closure:                        return "Normal closure";
        case status_type::going_away:                            return "Going away";
        case status_type::protocol_error:                        return "Protocol error";
        case status_type::unsupported_data:                      return "Unsupported data";
        case status_type::no_code_received:                      return "No code received";
        case status_type::connection_closed_abnormally:          return "Connection closed abnormally";
        case status_type::invalid_payload_data:                  return "Invalid payload data";
        case status_type::policy_violated:                       return "Policy violated";
        case status_type::message_too_big:                       return "Message too big";
        case status_type::unsupported_extension:                 return "Unsupported extension. The client should write the extensions it expected the server to support in the payload";
        case status_type::internal_server_error_ws:              return "nternal server error";
        case status_type::tls_handshake_failure:                 return "TLS handshake failure";
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

    std::string base64_encode(std::string_view data)
    {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* bio = BIO_new(BIO_s_mem());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64, bio);
        
        BIO_write(bio, data.data(), data.size());
        BIO_flush(bio);

        BUF_MEM* buffer_ptr{nullptr};
        BIO_get_mem_ptr(bio, &buffer_ptr);

        std::string encoded(buffer_ptr->data, buffer_ptr->length);
        BIO_free_all(bio);
        return encoded;
    }

    std::string base64_decode(std::string_view data)
    {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* bio = BIO_new_mem_buf(data.data(), data.size());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64, bio);

        std::string output(data.size(), '\0'); // Base64 expands by 4/3, so input is always >= output
        int decoded_len = BIO_read(bio, output.data(), output.size());
        if (decoded_len < 0)
            fprintf(stderr, "Failed to base64 decode data\n");

        output.resize(std::max(decoded_len, 0));
        BIO_free_all(bio);
        return output;
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

//----------------------------------------------------------------------------------------------------------------

    void request::clear()
    {
        method.clear();
        uri.clear();
        headers.clear();
        content.clear();
        http_version_major = 0;
        http_version_minor = 0;
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

        // HTTP 1.0 - default is to close
        if (http_version_major == 1 && http_version_minor == 0)
            return false;

        // HTTP 1.1 - default is to keep open
        else if (http_version_major == 1 && http_version_minor == 1)
            return true;
        
        // Default - just close
        return false;
    }

    bool request::is_websocket_req() const
    {
        auto conn_field     = find(field::connection);
        auto upgrade_field  = find(field::upgrade);

        return conn_field       != end(headers)         && 
               upgrade_field    != end(headers)         &&
               conn_field->contains_value("Upgrade")    &&
               upgrade_field->contains_value("websocket");
    }

//----------------------------------------------------------------------------------------------------------------

    void response::clear()
    {
        status              = unknown;
        http_version_major  = 0;
        http_version_minor  = 0;
        headers.clear();
        content_str.clear();
        content_file.reset();
    }   
    
    void response::add_header(field f, std::string_view value)
    {
        headers.push_back({f, std::string(value)});
    }

    void response::keep_alive(bool keep_alive_)
    {
        add_header(field::connection, keep_alive_ ? "keep-alive" : "close");
    }

//----------------------------------------------------------------------------------------------------------------

    namespace details
    {

//----------------------------------------------------------------------------------------------------------------

        int parse_header(request& req, const size_t ndata, char* data)
        {
            bool    first_line{true};
            bool    end_of_header{false};
            char*   pos{data};

            while (pos < data+ndata && !end_of_header)
            {
                // Find EOL
                char* end = strstr(pos, "\r\n");
                if (end == nullptr)
                    return -1; // error
                
                // null-terminate line
                *end = '\0';   
                
                // Handle start line
                if (first_line)
                {
                    first_line = false;
                    req.method.resize(8, '\0');
                    req.uri.resize(strlen(pos));
                    const int ret = sscanf(pos, "%s %s HTTP/%i.%i", &req.method[0], &req.uri[0], &req.http_version_major, &req.http_version_minor);
                    if (ret != 4)
                        return -1;
                    req.method.resize(strlen(req.method.c_str()));
                    req.uri.resize(strlen(req.uri.c_str()));
                }

                // Handle header line
                else if (strlen(pos) > 0)
                {
                    char* kend = strstr(pos, ": ");
                    if (kend == nullptr)
                        return -1;
                    
                    header hdr;
                    hdr.key   = field_enum(std::string_view(pos, kend-pos));
                    hdr.value = std::string(kend+2, end-kend-2);
                    req.headers.push_back(std::move(hdr));
                }

                // Handle end of header
                else
                    end_of_header = true;

                // advance pos
                pos = end + 2; 
            }

            return std::distance(data, pos);
        }

//----------------------------------------------------------------------------------------------------------------

        void serialize_header(response& resp, std::string& buf)
        {
            // Set status string
            char status_str[64] = {0};
            snprintf(status_str, sizeof(status_str), "HTTP/%i.%i %i %s\r\n", resp.http_version_major, resp.http_version_minor, resp.status, status_label(resp.status).data());

            // Add default server string if empty
            if (!contains(resp.headers, field::server))
                resp.add_header(field::server, BOOST_ASIO_VERSION_STRING);

            // Add default connection string if empty
            if (!contains(resp.headers, field::connection))
                resp.add_header(field::connection, "close");

            // Handle empty body
            if (resp.content_str.empty() && resp.content_file == nullptr)
            {
                remove_field(resp.headers, field::content_type);
                remove_field(resp.headers, field::content_length);
            }

            // Handle string body
            else if (!resp.content_str.empty())
            {
                // Add default Content type if empty
                if (!contains(resp.headers, field::content_type))
                    resp.add_header(field::content_type, "text/plain");
                
                // Set Content length
                auto it = find_field(resp.headers, field::content_length);
                if (it == end(resp.headers))
                    resp.add_header(field::content_length, std::to_string(resp.content_str.size()));
                else
                    it->value = std::to_string(resp.content_str.size());                
            }

            // Handle file body
            else if (resp.content_file)
            {
                // Content type - assume it's already set
                if (!contains(resp.headers, field::content_type))
                    fprintf(stderr, "Content-Type is not set for file\n");
                
                // Content length
                fseek(resp.content_file.get(), 0, SEEK_END);
                const size_t file_size = ftell(resp.content_file.get());
                fseek(resp.content_file.get(), 0, SEEK_SET);

                auto it = find_field(resp.headers, field::content_length);
                if (it == end(resp.headers))
                    resp.add_header(field::content_length, std::to_string(file_size));
                else
                    it->value = std::to_string(file_size);
            }

            // Serialize
            buf.append(status_str);

            for (const auto& [k, v] : resp.headers)
            {
                buf.append(field_label(k));
                buf.append(": ");
                buf.append(v);
                buf.append("\r\n");
            }
            buf.append("\r\n");
        }

//----------------------------------------------------------------------------------------------------------------

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

//----------------------------------------------------------------------------------------------------------------

}
