
STRICT_RULES = {
    "Tampering": {
        "must_any": [
            r"\bdigital signature(s)?\b",
            r"\bcode signing\b",
            r"\bchecksum(s)?\b",
            r"\b(hash|hmac)\b",
            r"\bfile integrity monitoring\b",
            r"\btamper[- ]evident\b",
            r"\bsigned (update|artifact|package|image)\b",
            r"\bintegrity (check|verification)\b",
        ],
        "forbid_any": [
            r"\bauthentication\b",
            r"\bauthorization\b",
            r"\bpassword\b",
            r"\brbac\b"
        ]
    },
    "Spoofing": {
        "must_any": [
            r"\bauthentication\b",
            r"\bmulti[- ]factor\b",
            r"\bmfa\b",
            r"\bclient certificate\b",
            r"\bchallenge[- ]response\b",
            r"\banti[- ]replay\b",
            r"\bidentity verification\b"
        ],
        "forbid_any": []
    },
    "Repudiation": {
        "must_any": [
            r"\baudit log(s)?\b",
            r"\bnon[- ]repudiation\b",
            r"\btamper[- ]evident log(s)?\b",
            r"\bdigitally signed log(s)?\b",
            r"\bimmutable (audit )?trail\b",
            r"\btime[- ]synchroni[sz]ed logging\b"
        ],
        "forbid_any": []
    },
    "Information Disclosure": {
        "must_any": [
            r"\bencryption\b",
            r"\btls\b",
            r"\bhttps\b",
            r"\bkey management\b",
            r"\bdata masking\b",
            r"\btokenization\b"
        ],
        "forbid_any": []
    },
    "Denial of Service": {
        "must_any": [
            r"\brate limit(ing)?\b",
            r"\bthrottling\b",
            r"\bresource quota(s)?\b",
            r"\bddos\b",
            r"\bcircuit breaker\b",
            r"\bbackpressure\b",
            r"\bauto[- ]scal(ing|e)\b",
            r"\bredundan(cy|t)\b"
        ],
        "forbid_any": []
    },
    "Elevation of Privilege": {
        "must_any": [
            r"\bleast privilege\b",
            r"\bprivilege separation\b",
            r"\brole[- ]based access control\b",
            r"\brbac\b",
            r"\badmin privilege\b"
        ],
        "forbid_any": []
    }
}
