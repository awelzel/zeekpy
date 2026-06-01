zeekpy
======

A little pure Python and async-less library for consuming and publishing
Zeek events events via Zeek's WebSocket API, leveraging Python type
annotations for conversion purposes.

Usage
-----

You construct a zeekpy.Zeek object, passing it the WebSocket URI of the Zeek
cluster to connect to and the topics to which to subscribe. The WebSocket
connection and handshake is done when entering the object's context manager.

    with Zeek("ws://127.0.0.1:27759/v1/messages/json", ["/test/"]) as zeek:
        ...

To handle events, you implement handler functions that have appropriate type
annotations. You use types listed in the EventArg union in this module.

For example, to register a handler function for the NetControl::pubsub_add_rules
event that receives a topic string, a pubsub_id that's a count and a vector of
Rule records, the Python looks like:

    import dataclasses
    from zeekpy import Zeek, addr, count

    @dataclasses.dataclass
    class Rule:
        a: addr
        c: count

    zeek = Zeek("ws://127.0.0.1:27759/v1/messages/json", ["/test/"])

    @zeek.on("NetControl::pubsub_add_rules")
    def handle_pubsub_add_rules(topic: str, pubsub_id: count, rules: list[Rule]):
        print(topic, pubsub_id, rules)

    with zeek:
        zeek.consume()


Publishing Events
-----------------

Use Zeek.publish() to publish events into the Zeek cluster. If an argument is
of a type that's in EventArg, it's serialized properly (think count, enum or port).
If an argument is a dict and has only "@data-type" and "data" keys, it is used
directly in the JSON payload. To publish a Python int as a Zeek count, you need
to wrap the int in a count instance: count(42). Otherwise, the 42 would be encoded
as an integer. This is similar to the ZeekJS BigInt case. Similarly, for enum,
the library treats an enum like a str. For publishing a string as enum, wrap
it: enum("NetControl::DROP").

    # Zeek event declaration:
    # global ev: event(c: count);

    with Zeek("ws://127.0.0.1:27759/v1/messages/json", ["/test/"]) as zeek:
        zeek.publish("/the/topic/", "ev", [count(42)])


Type Conversions
----------------

If a parameter of an event handler has no type annotation, the handler function
receives the corresponding dict from the parsed WebSocket JSON payload. You can
also annotate such parameters with RawArg to make this behavior explicit.

When you annotate a parameter with addr, the handler function will receive
either an ipaddress.IPv4Address or ipaddress.IPv6Address as produced by
ipaddress.ip_address(). Similarly for subnet. When annotating a parameter with
port, the result will be an object that has two fields: port (int) and proto (str).

For records, use dataclasses.dataclass and types. The implementation knows how
to instantiate and populate instances based on the listed fields. For &optional,
use typing.Optional or the type | None notation. A fairly complex example of a
vector of records containing optional fields follows:

    # The Zeek side:
    type R: {
        c: count;
        a: addr;
        oa: addr &optional;
        f: double &optional;
    }

    global ev: event(rvec: vector of R);

    # The Python side:
    @dataclasses.dataclass
    class R:
        c: count
        a: addr
        oa: addr | None = None  # optional
        f: float | None = None  # optional

    zeek = Zeek(...)

    @zeek.on("ev")
    def ev(rvec: list[R]):
        pass

    with zeek:
        zeek.consume()


Sets and Tables
---------------

Sets and tables are not implemented. The author doesn't think it's a good idea
to use them for remote events. Annotate them with RawArg and convert them
yourself from the dict. Zeek's support for composite keys makes this cumbersome
and the use cases aren't clear. It could technically make sense to allow composite
keys using tuples, e.g., set[tuple[int, str]].

Note
----

The context manager, consume() and stop() approach might be a bit clunky and
racy, if you have better ideas, feel free to fix it up or fork a version that
uses async. There's no plan for this code to support async.
