many_args_test_data = [
    {"@data-type": "count", "data": 42},
    {"@data-type": "integer", "data": -32},
    {"@data-type": "timestamp", "data": "2026-05-27T17:01:33.044"},
    {"@data-type": "timespan", "data": "1446451896905ns"},
    {"@data-type": "timespan", "data": "-1446451904058ns"},
    {"@data-type": "address", "data": "127.0.0.1"},
    {"@data-type": "address", "data": "::1"},
    {"@data-type": "subnet", "data": "192.168.0.0/16"},
    {"@data-type": "subnet", "data": "2008::/96"},
    {"@data-type": "boolean", "data": True},
    {"@data-type": "boolean", "data": False},
    {
        "@data-type": "vector",
        "data": [
            {"@data-type": "address", "data": "127.0.0.1"},
            {"@data-type": "address", "data": "2008::1"},
        ],
    },
    {
        "@data-type": "vector",
        "data": [
            {
                "@data-type": "vector",
                "data": [
                    {"@data-type": "count", "data": 42},
                    {"@data-type": "address", "data": "127.0.0.1"},
                ],
            }
        ],
    },
    {"@data-type": "port", "data": "42/tcp"},
    {"@data-type": "port", "data": "1337/udp"},
    {"@data-type": "port", "data": "1/?"},
    {
        "@data-type": "vector",
        "data": [
            {"@data-type": "port", "data": "1/tcp"},
            {"@data-type": "port", "data": "2/udp"},
            {"@data-type": "port", "data": "3/icmp"},
            {"@data-type": "port", "data": "4/?"},
        ],
    },
]

pubsub_add_rules_test_data = [
    {"@data-type": "string", "data": "reply-topic-42"},  # reply_topic
    {"@data-type": "count", "data": 42},  # pubsub_id
    {
        "@data-type": "vector",
        "data": [  # rules
            {
                "@data-type": "vector",
                "data": [
                    {
                        "@data-type": "enum-value",  # ty
                        "data": "NetControl::DROP",
                    },
                    {
                        "@data-type": "string",  # arg
                        "data": "192.168.0.1/32",
                    },
                    {
                        "@data-type": "string",  # comment
                        "data": "comment",
                    },
                    {
                        "@data-type": "string",  # rule_id
                        "data": "worker-5:32",
                    },
                    {
                        "@data-type": "vector",  # rule
                        "data": [
                            {
                                "@data-type": "count",
                                "data": 4711,
                            },
                            {
                                "@data-type": "string",
                                "data": "not-parsed",
                            },
                        ],
                    },
                ],
            },
        ],
    },
]
