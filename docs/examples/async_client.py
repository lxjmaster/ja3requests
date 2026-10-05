"""Run public async APIs against an event-controlled local HTTP peer."""

import asyncio
import gzip
import json
import zlib

import brotli

from ja3requests import (
    AsyncConnectionPool,
    AsyncSession,
    HTTPRetry,
    StreamConsumedError,
)


class DemoPeer:
    """A bounded loopback peer; no Internet, certificates or file writes."""

    def __init__(self):
        self.server = None
        self.writers = set()
        self.tasks = set()
        self.errors = []
        self.release_tail = asyncio.Event()
        self.cancelled_body_closed = asyncio.Event()
        self.retry_calls = 0

    async def start(self):
        self.server = await asyncio.start_server(self.serve, '127.0.0.1', 0)
        return 'http://127.0.0.1:%d' % self.server.sockets[0].getsockname()[1]

    @staticmethod
    async def reply(writer, body, status=200, headers=b''):
        writer.write(
            (
                'HTTP/1.1 %d Response\r\nContent-Length: %d\r\n' % (status, len(body))
            ).encode()
            + headers
            + b'\r\n'
            + body
        )
        await writer.drain()

    async def serve(self, reader, writer):
        self.writers.add(writer)
        self.tasks.add(asyncio.current_task())
        try:
            while True:
                try:
                    raw = await reader.readuntil(b'\r\n\r\n')
                except asyncio.IncompleteReadError as error:
                    if error.partial:
                        raise
                    break
                request, *lines = raw.split(b'\r\n')
                _, path, _ = request.split(b' ')
                headers = {
                    name.strip().lower(): value.strip()
                    for name, value in (line.split(b':', 1) for line in lines if line)
                }
                body = await reader.readexactly(
                    int(headers.get(b'content-length', b'0'))
                )
                if path == b'/json':
                    assert json.loads(body) == {'message': 'hello'}
                    await self.reply(
                        writer,
                        body,
                        headers=b'Content-Type: application/json\r\nSet-Cookie: demo=kept; Path=/\r\n',
                    )
                elif path == b'/cookie':
                    await self.reply(writer, headers.get(b'cookie', b''))
                elif path == b'/retry':
                    self.retry_calls += 1
                    await self.reply(
                        writer,
                        b'retry complete',
                        status=503 if self.retry_calls == 1 else 200,
                    )
                elif path == b'/stream':
                    writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nfirst')
                    await writer.drain()
                    await asyncio.wait_for(self.release_tail.wait(), 5)
                    writer.write(b'second')
                    await writer.drain()
                elif path == b'/cancel':
                    writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n')
                    await writer.drain()
                    assert await reader.read() == b''
                    self.cancelled_body_closed.set()
                    break
                elif path in (b'/gzip', b'/deflate', b'/br'):
                    encoding = path[1:]
                    encoder = {
                        b'gzip': gzip.compress,
                        b'deflate': zlib.compress,
                        b'br': brotli.compress,
                    }[encoding]
                    await self.reply(
                        writer,
                        encoder(b'decoded content\n' * 100),
                        headers=b'Content-Encoding: ' + encoding + b'\r\n',
                    )
                elif path == b'/lines':
                    await self.reply(writer, b'alpha\r\nbeta\nlast')
                else:
                    await self.reply(writer, b'unknown', status=404)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.errors.append(error)
        finally:
            writer.close()
            await writer.wait_closed()
            self.writers.discard(writer)

    async def aclose(self):
        self.release_tail.set()
        self.server.close()
        # Close accepted connections before wait_closed(), which can otherwise
        # wait for active writers on newer Python versions.
        for writer in tuple(self.writers):
            writer.close()
        if self.tasks:
            await asyncio.wait_for(asyncio.gather(*self.tasks), 5)
        await self.server.wait_closed()
        if self.errors:
            raise self.errors[0]


async def run_demo():
    """Exercise streaming, awaited bodies, cancellation and a borrowed pool."""
    peer = DemoPeer()
    base_url = await peer.start()
    events = []

    async def after_request(response):
        events.append(response.status_code)

    try:
        async with AsyncConnectionPool(max_connections_per_host=2) as pool:
            async with AsyncSession(
                pool=pool,
                retry=HTTPRetry(total=1, backoff_factor=0),
                hooks={'after_request': [after_request]},
            ) as session:
                response = await session.post(
                    base_url + '/json', json={'message': 'hello'}, timeout=3
                )
                response.raise_for_status()
                assert await response.json() == {'message': 'hello'}
                assert response.content == b'{"message": "hello"}'
                cookie = await session.get(base_url + '/cookie', timeout=3)
                assert await cookie.text() == 'demo=kept'
                retried = await session.get(base_url + '/retry', timeout=3)
                assert await retried.text() == 'retry complete'
                assert peer.retry_calls == 2

                async with await session.get(
                    base_url + '/stream', stream=True, timeout=(3, 3)
                ) as response:
                    chunks = response.aiter_content(5)
                    assert await chunks.__anext__() == b'first'
                    assert not peer.release_tail.is_set()
                    peer.release_tail.set()
                    assert b''.join([part async for part in chunks]) == b'second'
                    try:
                        _ = response.content
                    except StreamConsumedError:
                        pass
                    else:
                        raise AssertionError('An uncached stream was replayed')

                for encoding in ('gzip', 'deflate', 'br'):
                    async with await session.get(
                        base_url + '/' + encoding, stream=True, timeout=3
                    ) as response:
                        body = bytearray()
                        async for chunk in response.aiter_content(17):
                            body.extend(chunk)
                        assert body == b'decoded content\n' * 100

                async with await session.get(
                    base_url + '/lines', stream=True, timeout=3
                ) as response:
                    assert [line async for line in response.aiter_lines(3)] == [
                        b'alpha',
                        b'beta',
                        b'last',
                    ]

                async with await session.get(
                    base_url + '/cancel', stream=True, timeout=None
                ) as response:
                    reading = asyncio.ensure_future(response.read())
                    await asyncio.sleep(0)
                    reading.cancel()
                    try:
                        await reading
                    except asyncio.CancelledError:
                        pass
                    else:
                        raise AssertionError('Caller cancellation was lost')
                    await asyncio.wait_for(peer.cancelled_body_closed.wait(), 3)

            # Closing the first borrower does not close the caller-owned pool.
            async with AsyncSession(pool=pool) as second:
                response = await second.get(base_url + '/lines', timeout=3)
                assert await response.text() == 'alpha\r\nbeta\nlast'
        assert len(events) == 9 and all(status == 200 for status in events)
    finally:
        await peer.aclose()
    print(
        'PASS: native async JSON, Cookies, retry/hooks, first-chunk streaming, '
        'gzip/deflate/br, lines, cancellation, borrowed pool'
    )


if __name__ == '__main__':
    asyncio.run(run_demo())
