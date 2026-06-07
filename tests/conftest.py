import dataclasses
import logging
import os
import pathlib
import socket
import subprocess
import time

import pytest

from zeekpy import Zeek

LOGGER = logging.getLogger(__name__)


@pytest.fixture
def zeek():
    """
    Return a synchronous Zeek object for testing.
    """
    # Using port 0 here just in case this ever mistakenly is used
    # to connect out (it's only used for dispatch testing today).
    return Zeek("ws://127.0.0.1:0/path", topics=["/test/topic/"])


@pytest.fixture(scope="module")
def zeek_websocket_server(request):
    """
    A fixture that starts a Zeek process loading some scripts.
    """

    @dataclasses.dataclass
    class ZeekProc:
        url: str
        proc: subprocess.Popen

    ping_pong = pathlib.Path(__file__).parent / "ping-pong.zeek"

    args = [
        "zeek",
        "-b",
        str(ping_pong),
    ]

    ws_listen_addr = "127.0.0.1"
    ws_listen_port = 17759

    env = os.environ.copy()
    env.update(
        ZEEK_WEBSOCKET_LISTEN_ADDRESS=ws_listen_addr,
        ZEEK_WEBSOCKET_LISTEN_PORT=str(ws_listen_port),
    )

    proc = subprocess.Popen(args, env=env)

    # Wait for the port to be reachable for 10 seconds,
    # otherwise give up...
    tries = 100
    sleep_s = 0.1

    for i in range(tries):
        with socket.socket() as s:
            try:
                s.connect((ws_listen_addr, ws_listen_port))
                break
            except socket.error as e:
                if i == (tries - 1):
                    raise Exception("failed to start zeek") from e

                time.sleep(sleep_s)

    url = f"ws://{ws_listen_addr}:{ws_listen_port}/v1/messages/json"
    zp = ZeekProc(url, proc)

    yield zp

    try:
        proc.terminate()
        proc.wait()
    except Exception:
        LOGGER.exception("failed to wait for")
        proc.kill()


@pytest.fixture
def many_args_test_data():
    return [
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


@pytest.fixture
def pubsub_add_rules_test_data():
    return [
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
