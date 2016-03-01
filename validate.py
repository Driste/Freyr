import re

# !IMPORTANT - don't forget about the multi-line "\" (backslash).

header = ("action", "protocol", "source_address", "source_port", "direction", "destination_address", "destination_port")
actions = ("alert", "log", "pass", "activate", "dynamic", "drop", "reject", "sdrop")
protocols = ("tcp", "udp", "icnp", "ip")

rule_header = re.compile(
    r"^(?P<comment>#)*\s*"          # Commented or not
    r"(?P<action>alert|log|pass|activate|dynamic|drop|reject|sdrop)\s*"     # Action
    r"(?P<protocol>tcp|udp|icmp|ip)\s*"                                     # Protocol
    r"(?P<saddress>[^\s]*)\s*"      # Source addresses (1-255.1-255.1-255.1-255/1-255 | lists of ips ex. [192.1.1.1/5,10.254.32.1/5]
    #r"(?P<sport>[^\s]*)\s*"         # Source ports (1-65535 | (1-65535|):(1-65535|) | any)
    r"(?P<sport>any|[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])\s*"         # Source ports (1-65535 | (1-65535|):(1-65535|) | any)
    r"(?P<direction>[-><]+)\s*"     # Direction <- | <> | ->
    r"(?P<daddress>[^\s]*)\s*"      # Destination addresses
    r"(?P<dport>[^\s]*)\s*"         # Destination ports (1-65535 | (1-65535|):(1-65535|) | any)
    r"\((?P<options>.*)\)\s*"       # Options within ()s
)

# These options provide information about the rule but do not have any affect during detection
general_options = ("msg", "reference", "gid", "sid", "rev", "classtype", "priority", "metadata")

# These options all look for data inside the packet payload and can be inter-related
payload_detection = ("content", "protected_content", "hash", "offset", "length", "rawbytes", "depth", "distance", 
                     "within", "http_client_body", "http_cookie", "http_raw_cookie", "http_header", "http_raw_header",
                     "http_raw_header", "http_uri", "http_raw_uri", "http_stat_code", "http_stat_msg", "http_encode",
                     "fast_pattern", "uricontent", "urilen", "isdataat", "pcre", "pkt_data", "file_data", "base64_decode",
                     "base64_data", "byte_test", "byte_jump", "byte_extract", "ftpbounce", "asn1", "cvs", "dce_iface", 
                     "dce_opnum", "dce_stub_data", "sip_method", "sip_stat_code", "sip_header", "sip_body", "gtp_type",
                     "gtp_info", "gtp_version", "ssl_version", "ssl_state")

# These options look for non-payload data
nonpayload_detect = ("fragoffset", "ttl", "tos", "id", "ipopts", "fragbits", "dsize", "flags", "flow", "flowbits", "seq",
                     "ack", "window", "itype", "icode", "icmp_id", "cmp_seq", "rpc", "ip_proto", "sameip", "stream_reassemble",
                     "stream_size")

# These options are rule specific triggers that happen after a rule has fired.
post_detection = ("logto", "session", "resp", "react", "tag", "activates", "activated_by", "count", "replace", "detection_filter")

# body pattern
rule_options = re.compile(
    r""     
)

myFile = open("rules/community.rules")
rules = []

# bring the lines into memory
for line in myFile:
    rules.append(line)
    
# go through each rule
for rule in rules[0:8]:
    if re.match(rule_header, rule):
        #print re.match(rule_head, rule).group('sport')
        print ""
    else:
        print "fail"






