module HTTP;

# Original version credit to Mike Sconzo modified from https://github.com/ClickSecurity/data_hacking/blob/master/browser_fingerprinting/bro_scripts/http-headers.bro

export {
    type header_info_record: record
    {
        ## Header name and value.
        name:         string;
        value:        string;
    };

    redef record Info += { header_info_vector: vector of header_info_record &optional; };
}


module HTTPHeaders;

export
{
    redef enum Log::ID += { LOG };

    type Info: record
    {
        ts:                 time &log;
        uid:                string &log;
        origin:             string &log;
        identifier:         string &log;
        header_events_kv:   string &log;
        # header_events_json: string &log;
    };

    type header_info_record_type: record
    {
        ## Header name and value.
        name:         string;
        value:        string;
    };

    ## A type alias for a vector of header_info_records.
    type header_info_vector_type: vector of header_info_record_type;

}

redef record connection += {
    header_info_vector:        header_info_vector_type  &optional;
};

event bro_init()
{
    Log::create_stream(HTTPHeaders::LOG, [$columns=Info]);
}

# These events just init the vector, the whole http object gets wiped w/each request/reply
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
        {
        c$http$header_info_vector = vector();
        }

event http_reply(c: connection, version: string, code: count, reason: string)
        {
        c$http$header_info_vector = vector();
        }

function sanitize_string(s: string): string
{
    local sanitized: string;
    local escape_chars: string;
    # escape_chars = "\\\/\b\f\n\r\t\"\:\,";
    escape_chars = "\"";

    sanitized = s;
    sanitized = to_string_literal(s);
    sanitized = subst_string(sanitized, "\\x", "\\u00"); # Replacing any hex escapes
    # sanitized = string_escape(sanitized, escape_chars);

    return sanitized;
}

function vector_to_kv_string(info_vector: header_info_vector_type): string
{
    local kv_string: string;
    local key: string;
    local value: string;

    kv_string = "";
    for ( i in info_vector )
        {
            key = sanitize_string(info_vector[i]$name);
            value = sanitize_string(info_vector[i]$value);

            # Stubbing out Cookie for now
            if (key == "COOKIE") { value = "-COOKIE-"; }

            kv_string += "\"" + key + "\"" + ":" + "\"" + value + "\",";
        }

    # Remove the last comma
    return cut_tail(kv_string, 1);
}

function vector_to_json_string(info_vector: header_info_vector_type): string
{
    local json_string: string;
    local key: string;
    local value: string;

    json_string = "[";
    for ( i in info_vector )
        {
            key = sanitize_string(info_vector[i]$name);
            value = sanitize_string(info_vector[i]$value);

            # Stubbing out Cookie for now
            if (key == "COOKIE") { value = "-COOKIE-"; }

            json_string += "{\"" + key + "\"" + ":" + "\"" + value + "\"},";
        }

    # Remove the last comma and add the closing bracket
    return cut_tail(json_string, 1) + "]";
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    local header_record: HTTP::header_info_record;
    local vector_size: int;

    if ( ! c?$http || ! c$http?$header_info_vector )
        return;

    # Add this http header info to the vector
    header_record$name = name;
    header_record$value = value;

    # Get current size of vector and add the record to the end
    c$http$header_info_vector[|c$http$header_info_vector|] = header_record;
}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
{
    local my_log: Info;
    local origin: string;
    local identifier: string;
    # local event_json_string: string;
    local event_kv_string: string;

    # Is the header from a client request or server response
    if ( is_orig )
        origin = "client";
    else
        origin = "server";

    # If we don't have a header_info_vector than punt
    if ( ! c?$http || ! c$http?$header_info_vector )
        return;

    print c$http$header_info_vector;

    # At this point our c$header_info_vector should contain all the
    # name/value pairs associated with the header, so will turn the
    # vector into a JSON string and add it to our log file.
    # event_json_string = vector_to_json_string(c$http$header_info_vector);
    event_kv_string = vector_to_kv_string(c$http$header_info_vector);

    # Okay now set the user agent field
    identifier = "NOTPRESENT";
    for ( i in hlist )
    {
        if ( origin == "client" )
            if ( hlist[i]$name == "USER-AGENT" ){identifier = hlist[i]$value;}
        if ( origin == "server" )
            if ( hlist[i]$name == "SERVER" ){identifier = hlist[i]$value;}
    }

    # Now add all the info and the event list to the log
    my_log = [$ts=c$start_time,
        $uid=c$uid,
        $origin=fmt("%s", origin),
        $identifier=fmt("%s", identifier),
        $header_events_kv=fmt("%s", event_kv_string)];

        # $header_events_kv=fmt("%s", event_kv_string),
        # $header_events_json=fmt("%s", event_json_string)];

    Log::write(HTTPHeaders::LOG, my_log);
}
