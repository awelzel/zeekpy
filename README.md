zeekpy
======

Pure Python library for consuming and publishing events via Zeek's WebSocket
API heavily using type hints.

> This library isn't an official Zeek project. It's an exploration of
> an alternative Python binding API for Zeek and inspired primarily by
> [ZeekJS](https://github.com/corelight/zeekjs) and [FastAPI](https://github.com/fastapi/fastapi).

Usage
-----

You construct a zeekpy.Zeek object, passing it the WebSocket URI of the Zeek
cluster to connect to and the optional topics to which you want to subscribe.
The WebSocket connection and Zeek handshake are done when entering the Zeek
object's context manager:

```python
zeek = Zeek("ws://127.0.0.1:27759/v1/messages/json", topics=["/test/"])

with zeek:
    # Now connected to Zeek and subscribed to /test/
    ...
```

To handle events, you implement handler functions that have appropriate type annotations.
You use the types listed in the EventArg union in the zeekpy module.

For example, to register a handler function for the NetControl::pubsub_add_rules
event that receives a topic string, a pubsub_id that's a count and a vector of
Rule records, the Python code looks like:

```python
import dataclasses
from zeekpy import Zeek, addr, count

@dataclasses.dataclass
class Rule:
    a: addr
    c: count
    comment: None | str = None

zeek = Zeek("ws://127.0.0.1:27759/v1/messages/json", topics=["/test/"])

@zeek.on("NetControl::pubsub_add_rules")
def handle_pubsub_add_rules(topic: str, pubsub_id: count, rules: list[Rule]):
    print(topic, pubsub_id, rules)

with zeek:
    zeek.consume()
```


Publishing Events
-----------------

Use Zeek.publish() to publish Zeek events to a topic. If an event argument is
of a type that's in EventArg, it's serialized properly (think count, enum or port).
If an argument is a dict and has only "@data-type" and "data" keys, it is used
directly in the JSON payload. To publish a Python int as a Zeek count, you need
to wrap the int in a count instance: count(42). Otherwise, the 42 would be encoded
as an integer. This is similar to the ZeekJS BigInt case. Similarly, for enum,
the library treats an enum like a str. For publishing a string as an enum, wrap
it: enum("NetControl::DROP").

```python
# Zeek event declaration:
# global ev: event(c: count);
from zeekpy import Zeek, count

with Zeek("ws://127.0.0.1:27759/v1/messages/json") as zeek:
    zeek.publish("/the/topic/", "ev", [count(42)])
```

It's okay to publish from within event handlers, replying to every ping
event with a pong event looks as follows:

```python
from zeekpy import Zeek, count

zeek = Zeek("ws://127.0.0.1:27759/v1/messages/json", topics=["/pings/"])

@zeek.on("ping")
def handle_ping(c: count):
    print("got ping, sending pong", c)
    zeek.publish("/pongs/", "pong", [c])

with zeek:
    zeek.consume()
```

Event handlers are executed by the thread blocked in consume(), so the publish()
is done in the context of that thread. You can also call zeek.publish() from a
different thread.

Type Conversions
----------------

If a parameter of an event handler has no type annotation, the handler function
receives the corresponding dict from the parsed WebSocket JSON payload. You can
also annotate such parameters with RawArg to make this behavior explicit.

When you annotate a parameter with addr, the handler function will receive
either an ipaddress.IPv4Address or ipaddress.IPv6Address as produced by
ipaddress.ip_address(). The same applies to subnet. When annotating a parameter with
port, the result will be an object that has two fields: port (int) and proto (str).

For records, use dataclasses.dataclass and standard type hints. The implementation
knows how to instantiate and populate instances based on the listed fields.
For &optional, use typing.Optional or the type | None notation. A fairly complex
example of a vector of records containing optional fields follows:

```python
# Zeek type and event declaration:
# type R: {
#     c: count;
#     a: addr;
#     oa: addr &optional;
#     f: double &optional;
# }
#
# global ev: event(rvec: vector of R);
from zeekpy import Zeek, addr, count

# Python type declaration for R.
@dataclasses.dataclass
class R:
    c: count
    a: addr
    oa: addr | None = None
    f: float | None = None

# Usage
zeek = Zeek(...)

@zeek.on("ev")
def ev(rvec: list[R]):
    pass

with zeek:
    zeek.consume()
```

Note on Types
-------------

If you look at the types listed in the EventArg union, you'll find a mix of native
Zeek and native Python types. This is on purpose. The rough rule is that the native
Python type is used when there's a direct mapping possible (bool, datetime, list,
float, str, dataclasses). Otherwise, when there's no direct mapping (addr, subnet),
it's just a tagged Python type (count, enum), or the port type that's really a
composite type.

Sets and Tables
---------------

Sets and tables are not implemented. The author doesn't think it's a good idea
to use them for remote events. Annotate them with RawArg and convert them
yourself from the raw dictionary. Zeek's support for composite keys makes this
cumbersome and the use cases aren't clear. It could technically make sense to
allow composite keys using tuples, e.g., set[tuple[int, str]]. Feel free top
open a PR if you need this.

Async Support
-------------

The zeekpy module contains an AsyncZeek class that mirrors the Zeek class.
You use async with and await to work with it. It's otherwise very similar
to the Zeek class. Not that you'll get concurrent event handler invocations
when handlers use await for IO which will change execution order and may be
confusing. Only use if you're comfortable writing async code.

```python
import asyncio
from zeekpy import AsyncZeek, count

zeek = AsyncZeek("ws://127.0.0.1:27759/v1/messages/json", topics=["/pings/"])

@zeek.on("ping")
async def handle_ping(c: count):
    print("got ping, sending pong", c)
    await zeek.publish("/pongs/", "pong", [c])

async def main():
    async with zeek:
        await zeek.consume()

asyncio.run(main())
```

Contributing
------------

Contributions are welcome. Keep it simple.

The context manager is used to connect and disconnect properly and consume()
and stop() to cancel. If you find edge cases or bugs in that area, feel free
to open PRs to improve this logic, I'm not an asyncio expert.

After committing changes, run the following commands to verify everything
is still working and looks good:

```bash
uv run ruff check
All checks passed!

uv run ruff format
11 files left unchanged

uv run ruff check
All checks passed!

uv run pytest
...
```

If ``zeek`` is in your PATH, integration tests against a live
Zeek WebSocket will be executed, otherwise they're skipped.
