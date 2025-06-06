#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <memory>
#include <system_error>

namespace http
{

//----------------------------------------------------------------------------------------------------------------

    enum verb_type : unsigned int
    {
        UNKNOWN_VERB = 0,
        GET,
        HEAD,
        POST,
        PUT,
        DELETE,
        CONNECT,
        OPTIONS,
        TRACE,
        PATCH
    };

//----------------------------------------------------------------------------------------------------------------

    std::string_view verb_label(verb_type v);
    verb_type        verb_enum(std::string_view);

//----------------------------------------------------------------------------------------------------------------

    enum field : unsigned int
    {
        unknown_field = 0,

        a_im,
        accept,
        accept_additions,
        accept_charset,
        accept_datetime,
        accept_encoding,
        accept_features,
        accept_language,
        accept_patch,
        accept_post,
        accept_ranges,
        access_control,
        access_control_allow_credentials,
        access_control_allow_headers,
        access_control_allow_methods,
        access_control_allow_origin,
        access_control_expose_headers,
        access_control_max_age,
        access_control_request_headers,
        access_control_request_method,
        age,
        allow,
        alpn,
        also_control,
        alt_svc,
        alt_used,
        alternate_recipient,
        alternates,
        apparently_to,
        apply_to_redirect_ref,
        approved,
        archive,
        archived_at,
        article_names,
        article_updates,
        authentication_control,
        authentication_info,
        authentication_results,
        authorization,
        auto_submitted,
        autoforwarded,
        autosubmitted,
        base,
        bcc,
        body,
        c_ext,
        c_man,
        c_opt,
        c_pep,
        c_pep_info,
        cache_control,
        caldav_timezones,
        cancel_key,
        cancel_lock,
        cc,
        close,
        comments,
        compliance,
        connection,
        content_alternative,
        content_base,
        content_description,
        content_disposition,
        content_duration,
        content_encoding,
        content_features,
        content_id,
        content_identifier,
        content_language,
        content_length,
        content_location,
        content_md5,
        content_range,
        content_return,
        content_script_type,
        content_style_type,
        content_transfer_encoding,
        content_type,
        content_version,
        control,
        conversion,
        conversion_with_loss,
        cookie,
        cookie2,
        cost,
        dasl,
        date,
        date_received,
        dav,
        default_style,
        deferred_delivery,
        delivery_date,
        delta_base,
        depth,
        derived_from,
        destination,
        differential_id,
        digest,
        discarded_x400_ipms_extensions,
        discarded_x400_mts_extensions,
        disclose_recipients,
        disposition_notification_options,
        disposition_notification_to,
        distribution,
        dkim_signature,
        dl_expansion_history,
        downgraded_bcc,
        downgraded_cc,
        downgraded_disposition_notification_to,
        downgraded_final_recipient,
        downgraded_from,
        downgraded_in_reply_to,
        downgraded_mail_from,
        downgraded_message_id,
        downgraded_original_recipient,
        downgraded_rcpt_to,
        downgraded_references,
        downgraded_reply_to,
        downgraded_resent_bcc,
        downgraded_resent_cc,
        downgraded_resent_from,
        downgraded_resent_reply_to,
        downgraded_resent_sender,
        downgraded_resent_to,
        downgraded_return_path,
        downgraded_sender,
        downgraded_to,
        ediint_features,
        eesst_version,
        encoding,
        encrypted,
        errors_to,
        etag,
        expect,
        expires,
        expiry_date,
        ext,
        followup_to,
        forwarded,
        from,
        generate_delivery_report,
        getprofile,
        hobareg,
        host,
        http2_settings,
        if_,
        if_match,
        if_modified_since,
        if_none_match,
        if_range,
        if_schedule_tag_match,
        if_unmodified_since,
        im,
        importance,
        in_reply_to,
        incomplete_copy,
        injection_date,
        injection_info,
        jabber_id,
        keep_alive,
        keywords,
        label,
        language,
        last_modified,
        latest_delivery_time,
        lines,
        link,
        list_archive,
        list_help,
        list_id,
        list_owner,
        list_post,
        list_subscribe,
        list_unsubscribe,
        list_unsubscribe_post,
        location,
        lock_token,
        man,
        max_forwards,
        memento_datetime,
        message_context,
        message_id,
        message_type,
        meter,
        method_check,
        method_check_expires,
        mime_version,
        mmhs_acp127_message_identifier,
        mmhs_authorizing_users,
        mmhs_codress_message_indicator,
        mmhs_copy_precedence,
        mmhs_exempted_address,
        mmhs_extended_authorisation_info,
        mmhs_handling_instructions,
        mmhs_message_instructions,
        mmhs_message_type,
        mmhs_originator_plad,
        mmhs_originator_reference,
        mmhs_other_recipients_indicator_cc,
        mmhs_other_recipients_indicator_to,
        mmhs_primary_precedence,
        mmhs_subject_indicator_codes,
        mt_priority,
        negotiate,
        newsgroups,
        nntp_posting_date,
        nntp_posting_host,
        non_compliance,
        obsoletes,
        opt,
        optional,
        optional_www_authenticate,
        ordering_type,
        organization,
        origin,
        original_encoded_information_types,
        original_from,
        original_message_id,
        original_recipient,
        original_sender,
        original_subject,
        originator_return_address,
        overwrite,
        p3p,
        path,
        pep,
        pep_info,
        pics_label,
        position,
        posting_version,
        pragma,
        prefer,
        preference_applied,
        prevent_nondelivery_report,
        priority,
        privicon,
        profileobject,
        protocol,
        protocol_info,
        protocol_query,
        protocol_request,
        proxy_authenticate,
        proxy_authentication_info,
        proxy_authorization,
        proxy_connection,
        proxy_features,
        proxy_instruction,
        public_,
        public_key_pins,
        public_key_pins_report_only,
        range,
        received,
        received_spf,
        redirect_ref,
        references,
        referer,
        referer_root,
        relay_version,
        reply_by,
        reply_to,
        require_recipient_valid_since,
        resent_bcc,
        resent_cc,
        resent_date,
        resent_from,
        resent_message_id,
        resent_reply_to,
        resent_sender,
        resent_to,
        resolution_hint,
        resolver_location,
        retry_after,
        return_path,
        safe,
        schedule_reply,
        schedule_tag,
        sec_ch_ua,
        sec_ch_ua_mobile,
        sec_ch_ua_platform,
        sec_fetch_dest,
        sec_fetch_mode,
        sec_fetch_site,
        sec_fetch_user,
        sec_websocket_accept,
        sec_websocket_extensions,
        sec_websocket_key,
        sec_websocket_protocol,
        sec_websocket_version,
        security_scheme,
        see_also,
        sender,
        sensitivity,
        server,
        set_cookie,
        set_cookie2,
        setprofile,
        sio_label,
        sio_label_history,
        slug,
        soapaction,
        solicitation,
        status_uri,
        strict_transport_security,
        subject,
        subok,
        subst,
        summary,
        supersedes,
        surrogate_capability,
        surrogate_control,
        tcn,
        te,
        timeout,
        title,
        to,
        topic,
        trailer,
        transfer_encoding,
        ttl,
        ua_color,
        ua_media,
        ua_pixels,
        ua_resolution,
        ua_windowpixels,
        upgrade,
        upgrade_insecure_requests,
        urgency,
        uri,
        user_agent,
        variant_vary,
        vary,
        vbr_info,
        version,
        via,
        want_digest,
        warning,
        www_authenticate,
        x_archived_at,
        x_device_accept,
        x_device_accept_charset,
        x_device_accept_encoding,
        x_device_accept_language,
        x_device_user_agent,
        x_frame_options,
        x_mittente,
        x_pgp_sig,
        x_ricevuta,
        x_riferimento_message_id,
        x_tiporicevuta,
        x_trasporto,
        x_verificasicurezza,
        x400_content_identifier,
        x400_content_return,
        x400_content_type,
        x400_mts_identifier,
        x400_originator,
        x400_received,
        x400_recipients,
        x400_trace,
        xref
    };

//----------------------------------------------------------------------------------------------------------------

    std::string_view field_label(field f);
    field            field_enum(std::string_view);

//----------------------------------------------------------------------------------------------------------------

    enum status_type : unsigned int
    {
        unknown = 0,
        continue_                           = 100,
        switching_protocols                 = 101,
        processing                          = 102,
        early_hints                         = 103,

        ok                                  = 200,
        created                             = 201,
        accepted                            = 202,
        non_authoritative_information       = 203,
        no_content                          = 204,
        reset_content                       = 205,
        partial_content                     = 206,
        multi_status                        = 207,
        already_reported                    = 208,
        im_used                             = 226,

        multiple_choices                    = 300,
        moved_permanently                   = 301,
        found                               = 302,
        see_other                           = 303,
        not_modified                        = 304,
        use_proxy                           = 305,
        temporary_redirect                  = 307,
        permanent_redirect                  = 308,

        bad_request                         = 400,
        unauthorized                        = 401,
        payment_required                    = 402,
        forbidden                           = 403,
        not_found                           = 404,
        method_not_allowed                  = 405,
        not_acceptable                      = 406,
        proxy_authentication_required       = 407,
        request_timeout                     = 408,
        conflict                            = 409,
        gone                                = 410,
        length_required                     = 411,
        precondition_failed                 = 412,
        payload_too_large                   = 413,
        uri_too_long                        = 414,
        unsupported_media_type              = 415,
        range_not_satisfiable               = 416,
        expectation_failed                  = 417,
        i_am_a_teapot                       = 418,
        misdirected_request                 = 421,
        unprocessable_entity                = 422,
        locked                              = 423,
        failed_dependency                   = 424,
        too_early                           = 425,
        upgrade_required                    = 426,
        precondition_required               = 428,
        too_many_requests                   = 429,
        request_header_fields_too_large     = 431,
        unavailable_for_legal_reasons       = 451,

        internal_server_error               = 500,
        not_implemented                     = 501,
        bad_gateway                         = 502,
        service_unavailable                 = 503,
        gateway_timeout                     = 504,
        http_version_not_supported          = 505,
        variant_also_negotiates             = 506,
        insufficient_storage                = 507,
        loop_detected                       = 508,
        not_extended                        = 510,
        network_authentication_required     = 511,
    };

//----------------------------------------------------------------------------------------------------------------

    std::string_view status_label(const status_type v);

//----------------------------------------------------------------------------------------------------------------

    std::string_view get_mime_type(std::string_view path);

//----------------------------------------------------------------------------------------------------------------

    struct file_deleter {void operator()(FILE* ptr) {fclose(ptr);}};
    using file_ptr = std::unique_ptr<FILE, file_deleter>;

//----------------------------------------------------------------------------------------------------------------

    class sha1
    {
    private:
        uint32_t hash[5]    = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
        uint8_t  block[64]  = {0};
        size_t   off{0};
        size_t   total{0};
    public:
        using digest = std::array<uint8_t, 20>;
        sha1&   push(size_t ndata, const uint8_t* data);
        digest  finish();
    };

//----------------------------------------------------------------------------------------------------------------

    std::string          base64_encode(const size_t ndata, const uint8_t* data);
    std::vector<uint8_t> base64_decode(std::string_view data);

//----------------------------------------------------------------------------------------------------------------

    struct query_param
    {
        std::string key;
        std::string val;
    };

//----------------------------------------------------------------------------------------------------------------

    struct header
    {
        field       key;
        std::string value;
        bool contains_value(std::string_view v) const;
    };

//----------------------------------------------------------------------------------------------------------------

    struct request
    {
        verb_type                   verb{UNKNOWN_VERB};
        int                         http_version_minor{-1};
        std::string                 uri;
        std::vector<query_param>    params;
        std::vector<header>         headers;
        std::string                 content;

        void clear();
        void add_header(field f, std::string_view value);
        auto find(field f) const -> std::vector<header>::const_iterator;
        bool keep_alive() const;
        bool is_websocket_req() const;
    };

//----------------------------------------------------------------------------------------------------------------

    struct response
    {
        status_type         status{unknown};
        int                 http_version_minor{-1};
        std::vector<header> headers;
        std::string         content_str;
        file_ptr            content_file;

        void clear();
        void add_header(field f, std::string_view value);
        auto find(field f) const -> std::vector<header>::const_iterator;
        void keep_alive(bool keep_alive_);
        bool is_websocket_response() const;
    };

//----------------------------------------------------------------------------------------------------------------

    void parse_url(std::string_view url, std::string& target, std::vector<query_param>& params, std::error_code& ec);

//----------------------------------------------------------------------------------------------------------------

    template<class Message>
    class parser
    {
    private:
        static constexpr std::size_t max_header_size = 8192;
        enum {method, uri, http_version, status_code, status_msg, header_line, body, done} state;
        size_t body_read{0};

    public:
        parser();
        void reset();
        bool parse(Message& req, std::string& buf, std::error_code& ec);
    };

//----------------------------------------------------------------------------------------------------------------

    void serialize_header(request& req, std::string& buf, std::error_code& ec);
    void serialize_header(response& resp, std::string& buf, std::error_code& ec);

//----------------------------------------------------------------------------------------------------------------

    namespace details
    {
        inline std::string& get_content(request& req)      {return req.content;}
        inline std::string& get_content(response& resp)    {return resp.content_str;}
        inline FILE*        get_file(request& req)         {return nullptr;}
        inline FILE*        get_file(response& resp)       {return resp.content_file.get();} 
    }

//----------------------------------------------------------------------------------------------------------------

    enum error
    {
        http_read_header_line_too_big = 1,
        http_read_bad_method,
        http_read_unsupported_http_version,
        http_read_bad_status,
        http_read_bad_query_string,
        http_read_header_kv_delimiter_not_found,
        http_read_header_unsupported_field,
        http_write_unsupported_http_version,
        http_write_request_bad_verb,
        http_write_request_missing_uri,
        http_write_request_missing_host,
        ws_handshake_bad_status,
        ws_handshake_bad_headers,
        ws_handshake_missing_seq_accept,
        ws_handshake_bad_sec_accept,
        ws_accept_missing_seq_key,
        ws_invalid_opcode,
        ws_closing_handshake_non_matching_opcode,
        ws_closing_handshake_non_matching_reason
    };

    std::error_code make_error_code(error ec);

//----------------------------------------------------------------------------------------------------------------

    enum ws_code : unsigned short
    {
        ws_normal_closure               = 1000,
        ws_going_away                   = 1001,
        ws_protocol_error               = 1002,
        ws_unsupported_data             = 1003,
        ws_no_code_received             = 1005,
        ws_connection_closed_abnormally = 1006,
        ws_invalid_payload_data         = 1007,
        ws_policy_violated              = 1008,
        ws_message_too_big              = 1009,
        ws_unsupported_extension        = 1010,
        ws_internal_server_error        = 1011,
        ws_tls_handshake_failure        = 1015
    };

    std::error_code make_error_code(ws_code ec);
}

namespace std
{
    template <> struct is_error_code_enum<http::error>      : std::true_type {};
    template <> struct is_error_code_enum<http::ws_code>    : std::true_type {};
}