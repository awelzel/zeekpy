"""
zeekpy
"""

import collections
import dataclasses
import datetime
import inspect
import ipaddress
import json
import logging
import os
import re
import threading
import types
import typing

from websockets.sync.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosedOK, ConnectionClosedError
from websockets.frames import CloseCode


LOGGER = logging.getLogger(__name__)


# Annotating a parameter or field with RawArg will pass
# the raw data into the handler instead of converting.
RawArg: typing.TypeAlias = dict[str, typing.Any]
RawArgs: typing.TypeAlias = list[RawArg]


# Zeek specific type hints.
subnet: typing.TypeAlias = ipaddress.IPv4Network | ipaddress.IPv6Network
addr: typing.TypeAlias = ipaddress.IPv4Address | ipaddress.IPv6Address


class count(int):
    """Tagged int for count values."""


class enum(str):
    """Tagged str for enum values."""


class port(typing.NamedTuple):
    """port is just a named tuple with two fields."""

    port: int
    proto: str


EventArg: typing.TypeAlias = typing.Union[
    None,
    RawArg,
    addr,
    bool,
    count,
    datetime.datetime,
    datetime.timedelta,
    enum,
    float,
    int,
    list,
    port,
    str,
    subnet,
]

EventArgs: typing.TypeAlias = list[EventArg]
EventHandler: typing.TypeAlias = typing.Callable[..., None]


class Error(Exception): ...


__all__ = [
    "Zeek",
    "EventArg",
    "EventHandler",
    "Error",
    "RawArg",
    "addr",
    "count",
    "enum",
    "port",
    "subnet",
]


def load_json_msg(buf: bytes | str) -> tuple[str, str, RawArgs]:
    """
    Given a raw WebSocket message, unpack it into topic, event name and
    args. args is just the Python list and dict objects from the parsed JSON.
    """
    try:
        msg = json.loads(buf)
    except ValueError:
        # Invalid JSON?
        raise

    try:
        ty, topic, data = msg.pop("type"), msg.pop("topic"), msg.pop("data")
    except KeyError:
        raise Error(msg.get("code"), msg)

    if ty != "data-message":
        raise ValueError(f"top-level type is {ty!r}, not data-message")

    if msg["@data-type"] != "vector":
        t = msg["@data-type"]
        raise ValueError(f"top-level @data-type is {t!r}, not vector")

    if data[0]["data"] != 1:  # proto version
        pv = data[0]["data"]
        raise ValueError(f"top-level data[0][data] is {pv!r}, not 1")

    if data[1]["data"] != 1:  # message type: event
        mt = data[1]["data"]
        raise ValueError(f"top-level data[1][data] is {mt!r}, not 1")

    evraw = data[2]["data"]

    name = evraw[0]["data"]
    args = evraw[1]["data"]

    return topic, name, args


# Used for splitting away the float until the suffix follows.
_suffix_re = re.compile(r"[.0-9]+")

# Suffix to multiplier map. Not sure it was ever a good idea to
# encode timespans in a string form.
_suffix_multiplier = {
    "ns": 1.0 / 1_000_000_000,
    "us": 1.0 / 1_000_000,
    "ms": 1.0 / 1_000,
    "s": 1.0,
    "min": 60.0,
    "h": 60.0 * 60.0,
    "d": 24 * 60.0 * 60.0,
}


def _py_td_to_zeek_td(td: datetime.timedelta):
    """
    Just make it nanoseconds, always.
    """
    return f"{td.total_seconds() * 1000_000_000}ns"


# type name and conversion function
_py_to_zeek_lut = {
    bool: ("boolean", lambda v: v),
    str: ("string", lambda v: v),
    int: ("integer", lambda v: v),
    count: ("count", lambda v: v),
    port: ("port", lambda v: f"{v.port}/{'?' if v.proto == 'unknown' else v.proto}"),
    enum: ("enum-value", str),
    float: ("real", lambda v: v),
    types.NoneType: ("none", lambda _: {}),  # encode None as empty dict
    ipaddress.IPv4Address: ("address", str),
    ipaddress.IPv6Address: ("address", str),
    ipaddress.IPv4Network: ("subnet", str),
    ipaddress.IPv6Network: ("subnet", str),
    datetime.timedelta: ("timespan", _py_td_to_zeek_td),
    datetime.datetime: ("timestamp", lambda v: v.isoformat()),
}


def convert_py_to_zeek(arg: EventArg) -> RawArg:
    """
    From Python into Zeek, hooray.
    """
    dt = ""
    d = None

    t = type(arg)
    if t in _py_to_zeek_lut:
        dt, conv = _py_to_zeek_lut[t]
        d = conv(arg)
    else:
        # Not in _py_to_zeek, special case a few things:
        if dataclasses.is_dataclass(arg):
            dt = "vector"
            d = [convert_py_to_zeek(a) for a in dataclasses.astuple(arg)]
        elif isinstance(arg, dict) and arg.keys() == {"@data-type", "data"}:
            # This is a dict that contains @data-type and data? Just pass
            # it through. This happens when RawArg is used.
            return arg
        else:
            # Assume it's a list otherwise.
            dt = "vector"
            assert isinstance(arg, list)  # please type check
            d = [convert_py_to_zeek(e) for e in arg]

    assert dt, arg
    return {"@data-type": dt, "data": d}


def convert_zeek_to_py(th: typing.Any, arg: RawArg) -> EventArg:
    """
    Given a type hint, convert the incoming raw event argument to a Python type.
    """
    if th is RawArg:  # leave RawEventArg
        return arg

    if arg["@data-type"] == "none":  # none in, none out
        return None

    if th is str:
        if arg["@data-type"] != "string":
            raise ValueError(arg)
        return arg["data"]
    elif th is bool:
        if arg["@data-type"] != "boolean" or arg["data"] not in (True, False):
            raise ValueError(arg)
        return arg["data"]
    elif th is count:
        if (
            arg["@data-type"] != "count"
            or not isinstance(arg["data"], int)
            or arg["data"] < 0
        ):
            raise ValueError(arg)
        return count(arg["data"])
    elif th is int:
        if arg["@data-type"] != "integer":
            raise ValueError(arg)
        return arg["data"]
    elif th is float:
        if arg["@data-type"] != "real" or not isinstance(arg["data"], float):
            raise ValueError(arg)
        return arg["data"]
    elif th is enum:
        if arg["@data-type"] != "enum-value":
            raise ValueError(arg)
        return enum(arg["data"])
    elif th is addr:
        if arg["@data-type"] != "address" or not isinstance(arg["data"], str):
            raise ValueError(arg)
        return ipaddress.ip_address(arg["data"])
    elif th is subnet:
        if arg["@data-type"] != "subnet" or not isinstance(arg["data"], str):
            raise ValueError(arg)
        # XXX: ip_network() does not like it when hostbits are
        #      set. Not sure we spec that out, but Zeek should
        #      not have them set, so should work out.
        return ipaddress.ip_network(arg["data"])
    elif th is port:
        p, proto = arg["data"].split("/", 1)
        if proto == "?":  # What the heck, apparently we do ?
            proto = "unknown"
        return port(int(p, 10), proto)
    elif th is datetime.datetime:
        if arg["@data-type"] != "timestamp":
            raise ValueError(arg)
        return datetime.datetime.fromisoformat(arg["data"]).astimezone(
            datetime.timezone.utc
        )
    elif th is datetime.timedelta:
        if arg["@data-type"] != "timespan" or not isinstance(arg["data"], str):
            raise ValueError(arg)
        s = arg["data"]
        _, suffix_s = re.split(_suffix_re, s)
        value_s = s[: -len(suffix_s)]
        value = float(value_s)
        multiplier = _suffix_multiplier[suffix_s]
        return datetime.timedelta(seconds=value * multiplier)
    elif dataclasses.is_dataclass(th):
        fields = dataclasses.fields(th)
        if arg["@data-type"] != "vector":
            raise ValueError(arg)
        if len(arg["data"]) != len(fields):
            raise ValueError(
                f"got {len(arg['data'])} args, dataclass {th} has {len(fields)} fields"
            )
        field_values = []
        for i, a in enumerate(arg["data"]):
            field_values.append(convert_zeek_to_py(fields[i].type, a))
        return th(*field_values)
    else:
        # composite or optional types?
        typ_origin = typing.get_origin(th)
        typ_args = typing.get_args(th)

        if typ_origin is list:
            if arg["@data-type"] != "vector":
                raise ValueError(arg)

            if len(typ_args) != 1:  # Can do this during registration!
                raise TypeError(arg)
            values = []
            for a in arg["data"]:
                values.append(convert_zeek_to_py(typ_args[0], a))
            return values
        elif typ_origin is types.UnionType or typ_origin is typing.Union:
            # Handle union types for optional fields types (t, None) uniontype
            candidates = [t for t in typ_args if t is not types.NoneType]
            if len(candidates) == 1:
                return convert_zeek_to_py(candidates[0], arg)

    raise NotImplementedError(th)


def convert_event_args_for(
    h: "HandlerInfo", args: RawArgs
) -> RawArgs | list[EventArg | RawArg]:
    """
    Inspect type annotation on h's signature and convert recursively
    to supported Python.
    """
    sig = h.signature
    hints = h.hints

    # If the signature of the handler has a single variadic parameter just
    # return the raw input and assume the user knows what they are doing.
    if len(sig.parameters) == 1:
        param = next(iter(sig.parameters.values()))
        if param.kind == inspect.Parameter.VAR_POSITIONAL:
            return args

    if len(args) != len(sig.parameters):
        raise ValueError(f"got {len(args)} args, handler has {len(sig.parameters)}")

    cargs = []
    for i, p in enumerate(sig.parameters.values()):
        th = RawArg  # just use the raw dict when there's no type annotation
        if p.annotation is not inspect.Parameter.empty:
            th = hints[p.name]

        cargs.append(convert_zeek_to_py(th, args[i]))

    return cargs


class HandlerInfo:
    """
    Cache the signature and type hints.
    """

    def __init__(self, *, handler: EventHandler):
        self.handler = handler
        self.hints = typing.get_type_hints(handler)
        self.signature = inspect.signature(handler)


class Zeek:
    """
    A synchronous and thread-safe event emitter to interact with Zeek using
    the websockets library.

    Register event handlers using on() method.

    Publish events to Zeek using publish().
    """

    def __init__(
        self,
        uri: str | None = None,
        *,
        topics: list[str] | None = None,
        app_name: str | None = None,
        timeout: float | None = 10.0,
        ws: None | ClientConnection = None,
    ) -> None:
        if uri is None:
            uri = os.getenv("ZEEK_URI", "ws://127.0.0.1:27759/v1/messages/json")

        if not uri:
            raise ValueError(f"no valid uri ({uri!r})")

        self.uri = uri
        self.topics = topics or []
        self.ws = ws
        self.app_name = app_name
        self.timeout = timeout
        self.endpoint: str | None = None
        self.version: str | None = None

        # Set by stop() to cancel a running consume()
        self._stop = threading.Event()
        # Exception as passed from stop()
        self._stop_exc_val: Exception | None = None

        self.handlers: dict[str, list[HandlerInfo]] = collections.defaultdict(list)

    def on(self, name: str, handler: None | EventHandler = None):
        """
        Register a handler events with the given name.

        The signature and type hints of the handler are used for magic
        conversion of Zeek's WebSocket format to Python types.

        Can also be used as decorator:

            @client.on("my_event")
            def handler(c: count):
                ...
        """
        if handler is not None:
            self.handlers[name].append(HandlerInfo(handler=handler))
            return handler

        def decorator(h: EventHandler):
            self.handlers[name].append(HandlerInfo(handler=h))
            return h

        return decorator

    def unknown_event(self, topic: str, name: str, args: RawArgs):
        """
        Hook method that subclasses may implement for unhandled
        events, by default logs a warning so the user knows about it.
        """
        LOGGER.warning("unhandled event %s on topic %s", name, topic)

    def dispatch(self, topic: str, name: str, args: RawArgs):
        """
        Find a matching handler and convert args recursively to the requested
        types, then invoke the handler.
        """
        if name in self.handlers:
            for h in self.handlers[name]:
                converted_args = convert_event_args_for(h, args)
                h.handler(*converted_args)
        else:
            self.unknown_event(topic, name, args)

    def publish(self, topic: str, name: str, args: EventArgs):
        """
        Construct and publish and event.
        """
        zargs = [convert_py_to_zeek(a) for a in args]

        data = {
            "topic": topic,
            "type": "data-message",
            "@data-type": "vector",
            "data": [
                {"@data-type": "count", "data": 1},
                {"@data-type": "count", "data": 1},
                {
                    "@data-type": "vector",
                    "data": [
                        {"@data-type": "string", "data": name},
                        {"@data-type": "vector", "data": zargs},
                        # metadata here
                    ],
                },
            ],
        }

        if self._stop.is_set():
            return

        if self.ws is None:
            raise RuntimeError("missing enter")

        msg = json.dumps(data)
        self.ws.send(msg)

    def stop(self, exc_val: Exception | None = None):
        """
        Stop a running consume() and close the WebSocket connection.
        If exc_val is provided, consume() will raise it.
        """
        if self._stop.is_set():
            return

        if self.ws is not None:
            code = CloseCode.NORMAL_CLOSURE
            if exc_val is not None:
                self._stop_exc_val = exc_val
                code = CloseCode.INTERNAL_ERROR

            # Shutdown Connection.
            self.ws.close(code=code)

        self._stop.set()

    def __enter__(self) -> "Zeek":
        if self.ws is not None:
            raise RuntimeError("double enter")

        additional_headers = {}
        if self.app_name:
            additional_headers["X-Application-Name"] = self.app_name

        self.ws = connect(
            self.uri,
            open_timeout=self.timeout,
            close_timeout=self.timeout,
            additional_headers=additional_headers,
        )

        self.ws.send(json.dumps(self.topics))
        ack = json.loads(self.ws.recv(timeout=self.timeout))
        if ack.get("type") != "ack" or "endpoint" not in ack or "version" not in ack:
            raise Error("bad ack received", ack)

        self.endpoint = ack["endpoint"]
        self.version = ack["version"]

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.ws is not None:
            self._stop.set()

            code = CloseCode.NORMAL_CLOSURE
            if exc_val is not None:
                code = CloseCode.INTERNAL_ERROR

            self.ws.close(code=code)

            # Join the receive thread.
            self.ws.recv_events_thread.join()

            self.ws = None

    def consume(self, timeout: float | None = None):
        """
        Consume message until stopped.
        """
        if self.ws is None:
            raise RuntimeError("missing __enter__")

        while True:
            try:
                msg = self.ws.recv(timeout=timeout, decode=False)
                topic, name, args = load_json_msg(msg)
                self.dispatch(topic, name, args)
            except ConnectionClosedOK:
                # If the server spuriously closed the connection, re-raise
                # the ConnectionClosedOK exception.
                if not self._stop.is_set():
                    raise
            except ConnectionClosedError:
                # If stop() got passed an exception, ignore
                # ConnectionClosedError exceptions, otherwise
                # re-raise it for the user to decide.
                if self._stop_exc_val is not None:
                    break

                raise

            if self._stop.is_set():
                break

        if self._stop_exc_val:
            raise self._stop_exc_val from None
