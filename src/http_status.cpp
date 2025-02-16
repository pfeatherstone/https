#include "http_status.h"

namespace http
{
    const char* status_string(const status_type v)
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
}
