import re

# !IMPORTANT - don't forget about the multi-line "\" (backslash).

header = ("action", "protocol", "source_address", "source_port", "direction", "destination_address", "destination_port")

actions = ("alert", "log", "pass", "activate", "dynamic", "drop", "reject", "sdrop")
protocols = ("tcp", "udp", "icnp", "ip")

ports = "([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])"
portR = "{0}|{0}:|:{0}|{0}:{0}".format(ports)

rule_header = re.compile(
    r"^(?P<comment>#)*\s*"          # Commented or not
    r"(?P<action>alert|log|pass|activate|dynamic|drop|reject|sdrop)\s*"     # Action
    r"(?P<protocol>tcp|udp|icmp|ip)\s*"                                     # Protocol
    r"(?P<srcaddress>[^\s]*)\s*"      # Source address (<!>1-255.1-255.1-255.1-255/0-32 | lists of ips ex. [192.1.1.1/5,10.254.32.1/5]
    #r"(?P<srcport>[^\s]*)\s*"        # Source port (1-65535 | (1-65535|):(1-65535|) | any)
    r"(?P<srcport>any|!?(([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])|([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]):|:([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])|([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]):([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?)\s*"     # Source ports (1-65535 | (1-65535|):(1-65535|) | any)
    r"(?P<direction>[-><]+)\s*"       # Direction <- | <> | ->
    r"(?P<dstaddress>[^\s]*)\s*"      # Destination address
    #r"(?P<dstport>[^\s]*)\s*"        # Destination port (<!>1-65535 | <!>(1-65535|):(1-65535|) | any | $var)
    r"(?P<dstport>any|!?(([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])|([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]):|:([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])|([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]):([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?)\s*"     # Destination port (1-65535 | (1-65535|):(1-65535|) | any)
    r"\((?P<options>.*)\)\s*"       # Options within ()s
)

# These options provide information about the rule but do not have any affect during detection
generalOptions = {
    "msg" : re.compile("msg\s*:\s*\"(?P<msg>.*?)\";"),
    "reference" : re.compile(""),
    "gid" : re.compile(""),
    "sid" : re.compile(""),
    "rev" : re.compile(""),
    "classtype" : re.compile(""),
    "priority" : re.compile(""),
    "metadata" : re.compile("")
}


# These options all look for data inside the packet payload and can be inter-related
payloadDetection = {
    "content" : re.compile(""),
    "protected_content" : re.compile(""),
    "hash" : re.compile(""),
    "offset" : re.compile(""),
    "length" : re.compile(""),
    "rawbytes" : re.compile(""),
    "depth" : re.compile(""),
    "distance" : re.compile(""),
    "within" : re.compile(""),
    "http_client_body" : re.compile(""),
    "http_cookie" : re.compile(""),
    "http_raw_cookie" : re.compile(""),
    "http_header" : re.compile(""),
    "http_raw_header" : re.compile(""),
    "http_raw_header" : re.compile(""),
    "http_uri" : re.compile(""),
    "http_raw_uri" : re.compile(""),
    "http_stat_code" : re.compile(""),
    "http_stat_msg" : re.compile(""),
    "http_encode" : re.compile(""),
    "fast_pattern" : re.compile(""),
    "uricontent" : re.compile(""),
    "urilen" : re.compile(""),
    "isdataat" : re.compile(""),
    "pcre" : re.compile(""),
    "pkt_data" : re.compile(""),
    "file_data" : re.compile(""),
    "base64_decode": re.compile(""),
    "base64_data" : re.compile(""),
    "byte_test" : re.compile(""),
    "byte_jump" : re.compile(""),
    "byte_extract" : re.compile(""),
    "ftpbounce" : re.compile(""),
    "asn1" : re.compile(""),
    "cvs" : re.compile(""),
    "dce_iface" : re.compile(""),
    "dce_opnum" : re.compile(""),
    "dce_stub_data" : re.compile(""),
    "sip_method" : re.compile(""),
    "sip_stat_code" : re.compile(""),
    "sip_header" : re.compile(""),
    "sip_body" : re.compile(""),
    "gtp_type" : re.compile(""),
    "gtp_info" : re.compile(""),
    "gtp_version" : re.compile(""),
    "ssl_version" : re.compile(""),
    "ssl_state" : re.compile("")
}


# These options look for non-payload data
nonpayloadDetection = {
    "fragoffset" : re.compile(""),
    "ttl" : re.compile(""),
    "tos" : re.compile(""),
    "id" : re.compile(""),
    "ipopts" : re.compile(""),
    "fragbits" : re.compile(""),
    "dsize" : re.compile(""),
    "flags" : re.compile(""),
    "flow" : re.compile(""),
    "flowbits" : re.compile(""),
    "seq" : re.compile(""),
    "ack" : re.compile(""),
    "window" : re.compile(""),
    "itype" : re.compile(""),
    "icode" : re.compile(""),
    "icmp_id" : re.compile(""),
    "cmp_seq" : re.compile(""),
    "rpc" : re.compile(""),
    "ip_proto" : re.compile(""),
    "sameip" : re.compile(""),
    "stream_reassemble" : re.compile(""),
    "stream_size" : re.compile("")
}


# These options are rule specific triggers that happen after a rule has fired.
postDetection = {
    "logto" : re.compile(""),
    "session" : re.compile(""),
    "resp" : re.compile(""),
    "react" : re.compile(""),
    "tag" : re.compile(""),
    "activates" : re.compile(""),
    "activated_by" : re.compile(""),
    "count" : re.compile(""),
    "replace" : re.compile(""),
    "detection_filter": re.compile("")
}

# Make sure all the options are valid
checkOptions = {

}

# Check between all the options to make sure there is nothing unknown
checkGutters = {

}




