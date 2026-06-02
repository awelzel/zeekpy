from datetime import datetime, timedelta
import dataclasses
import unittest
import typing

from zeekpy import Zeek, RawArg, addr, count, enum, port, subnet

from .test_data import many_args_test_data, pubsub_add_rules_test_data


class Test(unittest.TestCase):
    def setUp(self):
        self.zeek = Zeek("ws://127.0.0.1:-1/path", topics=["/test/topic/"])

    def test_pubsub_add_rules_test_data(self):
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

        self.called = False

        @self.zeek.on("NetControl::pubsub_add_rules")
        def pubsub_add_rules(reply_topic: str, id: count, rules: list[PubSubRule]):
            self.called = True
            self.assertEqual(reply_topic, "reply-topic-42")
            self.assertEqual(id, 42)
            self.assertEqual(len(rules), 1)
            rule = rules[0]
            self.assertEqual(rule.ty, "NetControl::DROP")
            self.assertEqual(rule.arg, "192.168.0.1/32")
            # The rule.rule isn't parsed because of the RawArg usage,
            # but one can access the raw data directly.
            self.assertIn("@data-type", rule.rule)
            self.assertEqual(rule.rule["data"][0]["data"], 4711)
            self.assertEqual(rule.rule["data"][1]["data"], "not-parsed")

        self.zeek.dispatch(
            "/topic", "NetControl::pubsub_add_rules", pubsub_add_rules_test_data
        )

        self.assertTrue(self.called)

    def test_many_args_test_data(self):
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

        self.called_variadic = False

        @self.zeek.on("many_args")
        def many_args_variadic(*args):
            self.called_variadic = True
            self.assertEqual(17, len(args))

        self.called_with_types = False

        @self.zeek.on("many_args")
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
            self.called_with_types = True
            self.assertEqual(p1.port, 42)
            self.assertEqual(p1.proto, "tcp")
            self.assertEqual(p2.port, 1337)
            self.assertEqual(p2.proto, "udp")
            self.assertEqual(p3.port, 1)
            self.assertEqual(p3.proto, "unknown")

        self.zeek.dispatch("/topic", "many_args", many_args_test_data)

        self.assertTrue(self.called_with_types)
        self.assertTrue(self.called_variadic)

    def test_typing_optional(self):
        """
        Check typing.Optiona[count] which results in typing.Union
        instead of a types.UnionType.
        """

        @dataclasses.dataclass
        class R:
            c1: count
            c2: typing.Optional[count] = None

        self.r: R | None = None

        @self.zeek.on("ev")
        def ev(r: R):
            self.r = r

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

        self.zeek.dispatch("/topic", "ev", data1)

        self.assertIsNotNone(self.r)
        assert self.r
        self.assertEqual(self.r.c1, 42)
        self.assertIsNone(self.r.c2)
        self.r = None

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
        self.zeek.dispatch("/topic", "ev", data2)

        self.assertIsNotNone(self.r)
        assert self.r
        self.assertEqual(self.r.c1, 4242)
        self.assertEqual(self.r.c2, 4711)

    def test_typing_optional_addr(self):
        """
        There was a bug with optional addr when using TypeAlias.
        """

        @dataclasses.dataclass
        class R:
            a1: addr
            a2: typing.Optional[addr] = None

        self.r: R | None = None

        @self.zeek.on("ev")
        def ev(r: R):
            self.r = r

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

        self.zeek.dispatch("/topic", "ev", data1)
        self.assertIsNotNone(self.r)
        assert self.r
        self.assertEqual(str(self.r.a1), "192.168.0.1")
        self.assertEqual(str(self.r.a2), "192.168.0.2")

    def test_typing_optional_subnet(self):
        """
        There was a bug with optional subnet when using TypeAlias.
        """

        @dataclasses.dataclass
        class R:
            a1: subnet
            a2: subnet | None = None

        self.r: R | None = None

        @self.zeek.on("ev")
        def ev(r: R):
            self.r = r

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

        self.zeek.dispatch("/topic", "ev", data1)
        self.assertIsNotNone(self.r)
        assert self.r
        self.assertEqual(str(self.r.a1), "192.168.0.0/16")
        self.assertEqual(str(self.r.a2), "10.0.0.0/8")
