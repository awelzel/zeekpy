from datetime import datetime, timedelta
import dataclasses
import typing

from zeekpy import RawArg, Zeek, addr, count, enum, port, subnet


def test_pubsub_add_rules(zeek: Zeek, pubsub_add_rules_test_data):
    """
    Parses a pubsub_add_rules(reply_topic: string, id: count, rules: vector of PubSubRule)
    """

    @dataclasses.dataclass
    class PubSubRule:
        ty: enum
        arg: str
        comment: str
        rule_id: str
        rule: RawArg  # RawArg isn't parsed

    called = False

    @zeek.on("NetControl::pubsub_add_rules")
    def pubsub_add_rules(reply_topic: str, id: count, rules: list[PubSubRule]):
        nonlocal called
        called = True
        assert reply_topic == "reply-topic-42"
        assert id == 42
        assert len(rules) == 1
        rule = rules[0]
        assert rule.ty == "NetControl::DROP"
        assert rule.arg == "192.168.0.1/32"
        # The rule.rule isn't parsed because of the RawArg usage,
        # but one can access the raw data directly.
        assert "@data-type" in rule.rule
        assert rule.rule["data"][0]["data"] == 4711
        assert rule.rule["data"][1]["data"] == "not-parsed"

    zeek.dispatch("/topic", "NetControl::pubsub_add_rules", pubsub_add_rules_test_data)

    assert called


def test_many_args(zeek: Zeek, many_args_test_data):
    """
    global many_args: event(
        c: count, i: int,
        t: time, td1: interval, td2: interval,
        a1: addr, a2: addr, s1: subnet, s2: subnet,
        tr: bool, fa: bool,
        avec: vector of addr, rvec: vector of R,
        p1: port, p2: port, p3: port,
        pvec: vector of port
    );
    """

    @dataclasses.dataclass
    class R:
        a: count
        aa: addr

    called_variadic = False
    called_with_types = False

    @zeek.on("many_args")
    def many_args_variadic(*args):
        nonlocal called_variadic
        called_variadic = True
        assert len(args) == 17

    @zeek.on("many_args")
    def many_args_with_types(
        c: count,
        i: int,
        t: datetime,
        td1: timedelta,
        td2: timedelta,
        a1: addr,
        a2: addr,
        s1: subnet,
        s2: subnet,
        tr: bool,
        fa: bool,
        avec: list[addr],
        rvec: list[R],
        p1: port,
        p2: port,
        p3: port,
        pvec: list[port],
    ):
        """
        Handler for many args.
        """
        nonlocal called_with_types
        called_with_types = True
        assert p1.port == 42
        assert p1.proto == "tcp"
        assert p2.port == 1337
        assert p2.proto == "udp"
        assert p3.port == 1
        assert p3.proto == "unknown"

    zeek.dispatch("/topic", "many_args", many_args_test_data)

    assert called_with_types
    assert called_variadic


def test_typing_optional(zeek):
    """
    Check typing.Optiona[count] which results in typing.Union
    instead of a types.UnionType.
    """

    @dataclasses.dataclass
    class R:
        c1: count
        c2: typing.Optional[count] = None

    ev_r: R | None = None

    @zeek.on("ev")
    def ev(r: R):
        nonlocal ev_r
        ev_r = r

    # R is represented as a vector of fields
    data1 = [
        {
            "@data-type": "vector",
            "data": [
                {"@data-type": "count", "data": 42},
                {"@data-type": "none", "data": {}},
            ],
        },
    ]

    zeek.dispatch("/topic", "ev", data1)

    assert ev_r is not None
    assert ev_r.c1 == 42
    assert ev_r.c2 is None
    ev_r = None

    # R is represented as a vector of fields
    data2 = [
        {
            "@data-type": "vector",
            "data": [
                {"@data-type": "count", "data": 4242},
                {"@data-type": "count", "data": 4711},
            ],
        },
    ]

    zeek.dispatch("/topic", "ev", data2)

    assert ev_r is not None
    assert ev_r.c1 == 4242
    assert ev_r.c2 == 4711


def test_typing_optional_addr(zeek):
    """
    There was a bug with optional addr when using TypeAlias.
    """

    @dataclasses.dataclass
    class R:
        a1: addr
        a2: typing.Optional[addr] = None

    ev_r: R | None = None

    @zeek.on("ev")
    def ev(r: R):
        nonlocal ev_r
        ev_r = r

    # R is represented as a vector of fields
    data1 = [
        {
            "@data-type": "vector",
            "data": [
                {"@data-type": "address", "data": "192.168.0.1"},
                {"@data-type": "address", "data": "192.168.0.2"},
            ],
        },
    ]

    zeek.dispatch("/topic", "ev", data1)

    assert ev_r is not None
    assert str(ev_r.a1) == "192.168.0.1"
    assert str(ev_r.a2) == "192.168.0.2"


def test_typing_optional_subnet(zeek):
    """
    There was a bug with optional subnet when using TypeAlias.
    """

    @dataclasses.dataclass
    class R:
        a1: subnet
        a2: subnet | None = None

    ev_r: R | None = None

    @zeek.on("ev")
    def ev(r: R):
        nonlocal ev_r
        ev_r = r

    # R is represented as a vector of fields
    data1 = [
        {
            "@data-type": "vector",
            "data": [
                {"@data-type": "subnet", "data": "192.168.0.0/16"},
                {"@data-type": "subnet", "data": "10.0.0.0/8"},
            ],
        },
    ]

    zeek.dispatch("/topic", "ev", data1)

    assert ev_r is not None
    assert str(ev_r.a1) == "192.168.0.0/16"
    assert str(ev_r.a2) == "10.0.0.0/8"
