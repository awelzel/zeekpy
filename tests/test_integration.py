import asyncio
import shutil

import pytest

from zeekpy import AsyncZeek, Zeek, count

have_zeek = shutil.which("zeek") is not None
no_zeek_executable = (
    'Could not find zeek executable in PATH (using shutil.which("zeek")'
)


@pytest.mark.skipif(not have_zeek, reason=no_zeek_executable)
@pytest.mark.timeout(5)
def test_ping_pong(zeek_websocket_server):

    zeek = Zeek(zeek_websocket_server.url, topics=["zeekpy.test.ping"])

    @zeek.on("test::zeekpy::pong")
    def pong_handler(c: count):
        assert c == 42
        zeek.stop()

    with zeek:
        zeek.publish("zeekpy.test.ping", "test::zeekpy::ping", [count(42)])
        zeek.consume()


@pytest.mark.skipif(not have_zeek, reason=no_zeek_executable)
@pytest.mark.timeout(5)
def test_set_ping_pong(zeek_websocket_server):

    zeek = Zeek(zeek_websocket_server.url, topics=["zeekpy.test.ping"])

    @zeek.on("test::zeekpy::set_pong")
    def pong_handler(s: set[tuple[count, int, str]]):
        assert s == set([(count(42), 43, "44"), (count(45), 46, "47")])
        zeek.stop()

    with zeek:
        s = set([(count(42), 43, "44"), (count(45), 46, "47")])
        zeek.publish("zeekpy.test.ping", "test::zeekpy::set_ping", [s])
        zeek.consume()


@pytest.mark.skipif(not have_zeek, reason=no_zeek_executable)
@pytest.mark.timeout(5)
def test_tbl_ping_pong(zeek_websocket_server):

    zeek = Zeek(zeek_websocket_server.url, topics=["zeekpy.test.ping"])

    @zeek.on("test::zeekpy::tbl_pong")
    def pong_handler(tbl: dict[tuple[count, int, str], count]):
        assert tbl == {
            (count(42), 43, "44"): count(4711),
            (count(45), 46, "47"): count(4712),
        }
        zeek.stop()

    with zeek:
        tbl = {
            (count(42), 43, "44"): count(4711),
            (count(45), 46, "47"): count(4712),
        }
        zeek.publish("zeekpy.test.ping", "test::zeekpy::tbl_ping", [tbl])
        zeek.consume()


@pytest.mark.skipif(not have_zeek, reason=no_zeek_executable)
@pytest.mark.timeout(5)
def test_async_ping_pong(zeek_websocket_server):

    zeek = AsyncZeek(zeek_websocket_server.url, topics=["zeekpy.test.ping"])

    @zeek.on("test::zeekpy::pong")
    async def pong_handler(c: count):
        assert c == 42
        await zeek.stop()

    async def run():
        async with zeek:
            await zeek.publish("zeekpy.test.ping", "test::zeekpy::ping", [count(42)])
            await zeek.consume()

    asyncio.run(run())
