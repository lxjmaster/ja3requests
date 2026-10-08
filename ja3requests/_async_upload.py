"""One HTTP/1 streaming exchange: concurrent upload and response ownership."""

import asyncio

from ja3requests._async_utils import owner_task, phase_wait
from ja3requests.async_response import AsyncResponse
from ja3requests.exceptions import Timeout


class HTTP1Upload:
    """Keep a response readable while stopping its bounded request producer."""

    def __init__(self, lease, source, timeout):
        self.lease = lease
        self.transport = lease.entry.transport
        self.source = source
        self.timeout = timeout
        self.stopped = False
        self.complete = False
        self.error = None
        self._closing = False
        self._pull = None
        self._producer = None
        self._producer_stopping = False
        self._cleanup = None
        self._upload_finished = asyncio.Event()

    @property
    def closed(self):
        return self.transport.closed

    async def read(self, size):
        if self.error is not None:
            raise self.error
        reading = asyncio.ensure_future(self.transport.read(size))
        finished = None
        try:
            if not self.stopped and not self._upload_finished.is_set():
                # A normal peer may wait for the entire request. Source and
                # write deadlines already govern progress during that upload;
                # observe early responses without imposing a total upload limit.
                finished = owner_task(self._upload_finished.wait())
                await asyncio.wait(
                    (reading, finished), return_when=asyncio.FIRST_COMPLETED
                )
            if not reading.done():
                done, _ = await asyncio.wait((reading,), timeout=self.timeout)
                if not done:
                    error = Timeout('Response read timed out')
                    error.phase = 'read'
                    raise error
            result = reading.result()
        except Exception:
            if self.error is not None:
                raise self.error
            raise
        finally:
            if finished is not None:
                finished.cancel()
                await self._join(finished)
            if not reading.done():
                reading.cancel()
            await self._join(reading)
        if self.error is not None:
            raise self.error
        return result

    def stop(self):
        self.stopped = True
        # Source cancellation cannot damage the socket. An active bounded
        # transport write is allowed to finish while the response is consumed.
        if self._pull is not None and not self._pull.done():
            self._stop_producer()

    def _stop_producer(self):
        # A second cancellation can interrupt an async generator's finally.
        # Once stopping begins, join the same task until its cleanup returns.
        if self._producer is not None and not self._producer_stopping:
            self._producer_stopping = True
            self._producer.cancel()

    def _response_finished(self):
        # Called synchronously when the parser reaches EOF/close, before its
        # cleanup task is scheduled. A later write failure cannot invalidate
        # an already complete response merely by winning cleanup scheduling.
        self._closing = True
        self.stop()
        if not self.complete:
            self.transport.close()

    async def _piece(self):
        # Keep every __anext__ call in the same producer task: ContextVar tokens
        # created by a generator must still belong to its context after a yield.
        self._pull = asyncio.current_task()

        def expire():
            if not self.stopped:
                error = Timeout('Async request timed out during upload source read')
                error.phase = 'write'
                self.error = error
                # Stop network work before joining a potentially blocking file
                # job. Its borrowed handle cannot be returned until that join.
                self.transport.close()
                self._stop_producer()

        timer = (
            None
            if self.timeout is None
            else asyncio.get_running_loop().call_later(self.timeout, expire)
        )
        try:
            return await self.source.aread_piece(65536)
        finally:
            if timer is not None:
                timer.cancel()
            self._pull = None

    async def _send(self):
        try:
            while not self.stopped:
                piece = await self._piece()
                if self.stopped or self.error is not None:
                    return
                if not piece:
                    if self.source.length is None:
                        await phase_wait(
                            self.transport.write(b'0\r\n\r\n'), self.timeout, 'write'
                        )
                    self.complete = True
                    return
                wire = (
                    ('%x\r\n' % len(piece)).encode('ascii') + piece + b'\r\n'
                    if self.source.length is None
                    else piece
                )
                await phase_wait(self.transport.write(wire), self.timeout, 'write')
        except asyncio.CancelledError as error:
            if not self.stopped:
                if self.error is None:
                    self.error = error
                self.transport.close()
            raise
        except Exception as error:
            if not self._closing:
                self.error = error
                self.transport.close()
        finally:
            self._producer_stopping = True
            try:
                await self.source.afinish_producer()
            except Exception as error:
                if self.error is None and not self._closing:
                    self.error = error
                    self.transport.close()
            finally:
                self._upload_finished.set()

    @staticmethod
    async def _join(task):
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if not task.cancelled():
            task.exception()

    async def release(self, reusable):
        if self._cleanup is None:
            self._cleanup = owner_task(self._finish(reusable))
        cancelled = None
        while not self._cleanup.done():
            try:
                await asyncio.shield(self._cleanup)
            except asyncio.CancelledError as error:
                cancelled = error
            except Exception:
                break
        if cancelled is not None:
            self._cleanup.exception()
            raise cancelled
        self._cleanup.result()

    async def _finish(self, reusable):
        failure = self.error
        self._response_finished()
        if not self.complete or not reusable:
            # Response EOF/close now permits discarding the connection. Closing
            # first wakes native writes without cancelling a readable response.
            self.transport.close()
        if self._producer is not None:
            if not self._producer.done():
                self._stop_producer()
            await self._join(self._producer)
        await self.lease.release(reusable and self.complete and failure is None)
        if failure is not None:
            raise failure

    async def response(self, wire, request):
        try:
            await phase_wait(self.transport.write(wire), self.timeout, 'write')
            self._producer = asyncio.get_running_loop().create_task(self._send())
            response = await AsyncResponse.from_http1(
                self,
                method=request.method,
                url=request.url,
                request=request,
                release=self.release,
                # This exchange applies response read budgets after upload (or
                # an early final response); the parser must not add a second,
                # independently running timer while the request is still sent.
                timeout=None,
            )
            self.stop()
            return response
        except BaseException:
            try:
                await self.release(False)
            except Exception:
                pass
            raise
