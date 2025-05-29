# SIP Message Headers and Fuzzing Patterns
import random
import string

# Common SIP Headers
SIP_HEADERS = {
    "Via": "SIP/2.0/{proto} {ip}:{port};branch=z9hG4bK{branch}",
    "Max-Forwards": "70",
    "From": "<sip:{from_user}@{ip}>;tag={tag}",
    "To": "<sip:{to_user}@{ip}>",
    "Call-ID": "{call_id}@{ip}",
    "CSeq": "{cseq} {method}",
    "User-Agent": "SIPFuzzer/1.0",
    "Contact": "<sip:{from_user}@{ip}:{port}>",
    "Content-Length": "0"
}

# Fuzzing Patterns
FUZZ_PATTERNS = {
    # Length-based fuzzing
    "length": {
        "short": ["A" * i for i in range(1, 100, 10)],
        "medium": ["A" * i for i in range(100, 1000, 100)],
        "long": ["A" * i for i in range(1000, 10000, 1000)]
    },
    
    # Character-based fuzzing
    "chars": {
        "printable": ["".join(random.choices(string.printable, k=100)) for _ in range(10)],
        "punctuation": ["".join(random.choices(string.punctuation, k=100)) for _ in range(10)],
        "whitespace": ["".join(random.choices(string.whitespace, k=100)) for _ in range(10)],
        "digits": ["".join(random.choices(string.digits, k=100)) for _ in range(10)],
        "ascii_letters": ["".join(random.choices(string.ascii_letters, k=100)) for _ in range(10)]
    },
    
    # Format-based fuzzing
    "format": {
        "empty": ["", " ", "\t", "\n", "\r\n", "\0"],
        "special": ["\x00", "\x01", "\x02", "\x03", "\x04", "\x05"],
        "unicode": ["\u0000", "\u0001", "\u0002", "\u0003", "\u0004", "\u0005"]
    },
    
    # Protocol-specific fuzzing
    "protocol": {
        "methods": ["OPTIONS", "INVITE", "REGISTER", "BYE", "CANCEL", "ACK"],
        "versions": ["SIP/2.0", "SIP/1.0", "SIP/3.0", "SIP/4.0"],
        "transports": ["UDP", "TCP", "TLS", "SCTP", "WS", "WSS"]
    },
    
    # Header-specific fuzzing
    "headers": {
        "via": ["Via: SIP/2.0/{proto} {ip}:{port};branch=z9hG4bK{branch};rport;received={ip}",
                "Via: SIP/2.0/{proto} {ip}:{port};branch=z9hG4bK{branch};rport",
                "Via: SIP/2.0/{proto} {ip}:{port};branch=z9hG4bK{branch}"],
        "from": ["From: <sip:{from_user}@{ip}>;tag={tag}",
                 "From: \"{from_user}\" <sip:{from_user}@{ip}>;tag={tag}",
                 "From: {from_user} <sip:{from_user}@{ip}>;tag={tag}"],
        "to": ["To: <sip:{to_user}@{ip}>",
               "To: \"{to_user}\" <sip:{to_user}@{ip}>",
               "To: {to_user} <sip:{to_user}@{ip}>"]
    }
}

# SIP Message Templates
SIP_MESSAGES = {
    "OPTIONS": """{method} sip:{ip} SIP/2.0\r
{headers}\r
\r
""",
    "INVITE": """{method} sip:{ip} SIP/2.0\r
{headers}\r
Content-Type: application/sdp\r
Content-Length: {content_length}\r
\r
{body}""",
    "REGISTER": """{method} sip:{ip} SIP/2.0\r
{headers}\r
Expires: {expires}\r
\r
"""
}

# SDP Templates
SDP_TEMPLATES = {
    "basic": """v=0\r
o=- {call_id} {call_id} IN IP4 {ip}\r
s=-\r
c=IN IP4 {ip}\r
t=0 0\r
m=audio {port} RTP/AVP 0\r
a=rtpmap:0 PCMU/8000\r
""",
    "advanced": """v=0\r
o=- {call_id} {call_id} IN IP4 {ip}\r
s=-\r
c=IN IP4 {ip}\r
t=0 0\r
m=audio {port} RTP/AVP 0 8 9 18 101\r
a=rtpmap:0 PCMU/8000\r
a=rtpmap:8 PCMA/8000\r
a=rtpmap:9 G722/8000\r
a=rtpmap:18 G729/8000\r
a=rtpmap:101 telephone-event/8000\r
a=fmtp:101 0-16\r
"""
} 