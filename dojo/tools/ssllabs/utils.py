
detail_definitions = {
    "DELEGATION":{
        1: "Non-prefixed access",
        2: "Prefixed access"
    },
    "RENEGSUPPORT":{
        1: "Insecure client-initiated renegotiation supported",
        2: "Secure renegotiation supported",
        3: "Secure client-initiated renegotiation supported",
        4: "Server requires secure renegotiation support"
    },
    "SESSIONRESUMPTION":{
        0: "Session resumption is not enabled, No session IDs found",
        1: "Endpoint returns session IDs, but sessions are not resumed",
        2: "session resumption is enabled"
    },
    "COMPRESSIONMETHODS":{
        0: "DEFLATE"
    },
    "SESSIONTICKETS":{
        1: "Session Tickets supported",
        2: "The implementation is faulty",
        4: "The server is intolerant to the extension"
    },
    "FORWARDSECRECY":{
        1: "At least one browser has negotiated a Forward Secrecy suite",
        2: "FS Enabled, but limited",
        4: "FS Enabled"
    },
    "PROTOCOLINTOLERANCE":{
        0: "Unknown",
        1: "TLS 1.0",
        2: "TLS 1.1",
        4: "TLS 1.2",
        8: "TLS 1.3",
        16: "TLS 1.152",
        32: "TLS 2.152"
    },
    "MISCINTOLERANCE":{
        0: "Unknown",
        1: "Extension intolerance",
        2: "Long handshake intolerance",
        4: "Long handshake intolerance workaround success"
    },
    "OPENSSLCCS":{
        -1: "test failed",
        0: "unknown",
        1: "not vulnerable",
        2: "possibly vulnerable, but not exploitable",
        3: "vulnerable and exploitable",
    },
    "OPENSSLLUCKYMINUS20":{
        -1: "Test failed",
        0: "Unknown",
        1: "Not vulnerable",
        2: "Vulnerable and insecure"
    },
    "TICKETBLEED":{
        -1: "Test failed",
        0: "Unknown",
        1: "Not vulnerable",
        2: "Vulnerable and insecure"
    },
    "BLEICHENBACHER":{
        -1: "Test failed",
        0: "Unknown",
        1: "Not vulnerable",
        2: "Vulnerable (weak oracle)",
        3: "Vulnerable (strong oracle)",
        4: "Inconsistent results"
    },
    "POODLETLS":{
        -3: "Timeout",
        -2: "TLS not supported",
        -1: "Test failed",
        0: "Unknown",
        1: "Mot vulnerable",
        2: "Vulnerable"
    },
    "HASSCT":{
        1: "SCT in certificate",
        2: "SCT in the stapled OCSP response",
        4: "SCT in the TLS extension (ServerHello)"
    },
    "DHUSESKNOWNPRIMES":{
        0: "No",
        1: "Yes, but they're not weak",
        2: "Yes and they're weak"
    }
}



















