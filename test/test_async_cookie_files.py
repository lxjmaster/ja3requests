"""Async Cookie files use detached workers and loop-owned commit boundaries."""

import asyncio
import json
import os
import threading
from http.cookiejar import CookieJar, DefaultCookiePolicy

import pytest

from ja3requests import AsyncConnectionPool, AsyncSession, Session
from ja3requests import _cookie_file, async_sessions
from ja3requests.cookies import Ja3RequestsCookieJar
from test.test_cookie_files import header, scoped_cookie
from test.test_async_session import Peer


class WorkerGate:
    def __init__(self):
        self.loop = asyncio.get_running_loop()
        self.loop_thread = threading.get_ident()
        self.started = asyncio.Event()
        self.release = threading.Event()

    def wait(self):
        assert threading.get_ident() != self.loop_thread
        self.loop.call_soon_threadsafe(self.started.set)
        assert self.release.wait(5), 'worker was not released'

    async def entered(self):
        await asyncio.wait_for(self.started.wait(), 2)


def jar(*cookies, policy=None, standard=False):
    result = (
        CookieJar(policy=policy) if standard else Ja3RequestsCookieJar(policy=policy)
    )
    for cookie in cookies:
        result.set_cookie(cookie)
    return result


def names(jar):
    return {cookie.name: cookie.value for cookie in jar}


class NoLiveLock:
    def __enter__(self):
        raise AssertionError('an async helper acquired a live CookieJar lock')

    def __exit__(self, *_args):
        pass


def assert_idle(session):
    assert not session._cookie_tasks
    assert session._cookie_file_lock is None or not session._cookie_file_lock.locked()


@pytest.mark.parametrize('standard', [False, True])
def test_sync_async_interoperate_and_preserve_cookie_scope(tmp_path, standard):
    path = tmp_path / 'cookies.json'
    source = jar(
        scoped_cookie(),
        scoped_cookie('session', expires=None, discard=True),
        scoped_cookie('discarded', discard=True),
        scoped_cookie('expired', expires=1),
        standard=standard,
    )
    with Session(use_pooling=False) as sync:
        sync.cookies = source
        assert sync.save_cookies(path, include_session=True) == 3

    async def scenario():
        policy = DefaultCookiePolicy(blocked_domains=['blocked.example'])
        target = jar(policy=policy, standard=standard)
        async with AsyncSession() as session:
            session.cookies = target
            assert await session.load_cookies(path) == 1
            assert session.cookies is target and target._policy is policy
            assert names(target) == {'sid': 'test-token'}
            assert await session.load_cookies(path, include_session=True) == 3
            assert await session.save_cookies(path) == 1
            assert await session.save_cookies(path, include_session=True) == 3
        assert_idle(session)
        return target

    restored = asyncio.run(scenario())
    with Session(use_pooling=False) as sync:
        assert sync.load_cookies(path, include_session=True) == 3
        assert [cookie.__dict__ for cookie in sync.cookies] == [
            cookie.__dict__ for cookie in restored
        ]
    for url in (
        'https://first.example.com/account/',
        'http://first.example.com/account/',
        'https://sub.first.example.com/account/',
        'https://first.example.com/other',
    ):
        assert header(jar(*restored), url) == header(jar(*source), url)
    if os.name == 'posix':
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('merge', [False, True])
@pytest.mark.parametrize('replace_jar', [False, True])
def test_load_commits_to_current_jar_without_locking_or_replacing_policy(
    tmp_path, monkeypatch, merge, replace_jar
):
    path = tmp_path / 'cookies.json'
    jar(scoped_cookie(value='loaded')).save(path)
    load = async_sessions.load_cookie_file

    async def scenario():
        gate = WorkerGate()
        original = jar(scoped_cookie('before'))

        def paused(detached, *args, **kwargs):
            assert detached is not original
            count = load(detached, *args, **kwargs)
            gate.wait()
            return count

        monkeypatch.setattr(async_sessions, 'load_cookie_file', paused)
        async with AsyncSession() as session:
            session.cookies = original
            task = asyncio.create_task(session.load_cookies(path, merge=merge))
            try:
                await gate.entered()
                policy = DefaultCookiePolicy(blocked_domains=['blocked.example'])
                if replace_jar:
                    session.cookies = jar(policy=policy, standard=True)
                else:
                    session.cookies.set_policy(policy)
                target = session.cookies
                target.set_cookie(scoped_cookie('during', value='new'))
                target.set_cookie(scoped_cookie(value='stale'))
                lock = target._cookies_lock
                target._cookies_lock = NoLiveLock()
                try:
                    gate.release.set()
                    assert await asyncio.wait_for(task, 2) == 1
                finally:
                    target._cookies_lock = lock
                expected = {'sid': 'loaded'}
                if merge:
                    expected['during'] = 'new'
                    if not replace_jar:
                        expected['before'] = 'test-token'
                assert names(target) == expected
                assert session.cookies is target and target._policy is policy
                if replace_jar:
                    assert names(original) == {'before': 'test-token'}
            finally:
                gate.release.set()
        assert_idle(session)

    asyncio.run(scenario())


@pytest.mark.parametrize('merge', [False, True])
def test_response_set_cookie_during_load_is_part_of_commit_time_state(
    tmp_path, monkeypatch, merge
):
    path = tmp_path / 'cookies.json'
    jar(scoped_cookie('from-file')).save(path)
    load = async_sessions.load_cookie_file

    async def scenario():
        gate = WorkerGate()

        def paused(detached, *args, **kwargs):
            count = load(detached, *args, **kwargs)
            gate.wait()
            return count

        async def route(*_args):
            return 200, {'Set-Cookie': 'from-response=fresh; Path=/'}, b'ok'

        monkeypatch.setattr(async_sessions, 'load_cookie_file', paused)
        async with Peer(route) as peer, AsyncSession() as session:
            target = session.cookies
            policy = target._policy
            loading = asyncio.create_task(session.load_cookies(path, merge=merge))
            try:
                await gate.entered()
                response = await session.get(peer.url, timeout=1)
                assert await response.read() == b'ok'
                assert names(target) == {'from-response': 'fresh'}
                gate.release.set()
                assert await asyncio.wait_for(loading, 2) == 1
                expected = {'from-file': 'test-token'}
                if merge:
                    expected['from-response'] = 'fresh'
                assert names(target) == expected
                assert session.cookies is target and target._policy is policy
            finally:
                gate.release.set()
        assert_idle(session)

    asyncio.run(scenario())


def test_save_snapshot_is_independent_including_extensions_and_loop_responsive(
    tmp_path, monkeypatch
):
    path = tmp_path / 'cookies.json'
    save = async_sessions.save_cookie_file

    async def scenario():
        gate = WorkerGate()
        source = scoped_cookie()
        live = jar(source)

        def paused(detached, *args, **kwargs):
            copied = next(iter(detached))
            assert detached is not live and copied is not source
            assert copied._rest is not source._rest
            gate.wait()
            return save(detached, *args, **kwargs)

        monkeypatch.setattr(async_sessions, 'save_cookie_file', paused)
        async with AsyncSession() as session:
            session.cookies = live
            lock = live._cookies_lock
            live._cookies_lock = NoLiveLock()
            task = asyncio.create_task(session.save_cookies(path))
            try:
                await gate.entered()
                source.value = 'changed'
                source._rest['SameSite'] = 'None'
                source._rest['new'] = True
                live._cookies.clear()
                for _ in range(5):
                    await asyncio.sleep(0)
                    assert not task.done()
                gate.release.set()
                assert await asyncio.wait_for(task, 2) == 1
            finally:
                gate.release.set()
                live._cookies_lock = lock
        assert_idle(session)

    asyncio.run(scenario())
    restored = jar()
    assert restored.load(path) == 1
    copied = next(iter(restored))
    assert copied.value == 'test-token'
    assert copied._rest == {'HttpOnly': None, 'SameSite': 'Strict', 'Priority': 'High'}


@pytest.mark.parametrize('merge', [False, True])
@pytest.mark.parametrize('contents', ['empty-jar', 'expired', 'empty-file'])
def test_empty_and_expired_files_have_atomic_replace_or_merge_semantics(
    tmp_path, merge, contents
):
    path = tmp_path / 'cookies.json'
    source = jar() if contents == 'empty-jar' else jar(scoped_cookie())
    source.save(path)
    if contents == 'expired':
        data = json.loads(path.read_text())
        data['cookies'][0]['expires'] = 1
        path.write_text(json.dumps(data))
    elif contents == 'empty-file':
        path.write_bytes(b'')

    async def scenario():
        async with AsyncSession() as session:
            session.cookies.set_cookie(scoped_cookie('retained'))
            before = session.cookies._cookies
            if contents == 'empty-file':
                with pytest.raises(ValueError, match='JSON'):
                    await session.load_cookies(path, merge=merge)
                assert session.cookies._cookies is before
            else:
                assert await session.load_cookies(path, merge=merge) == 0
                assert bool(list(session.cookies)) is merge
        assert_idle(session)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    'fault', ['schema', 'duplicate', 'utf8', 'size', 'count', 'missing']
)
def test_load_validation_and_io_errors_preserve_live_jar(tmp_path, fault):
    path = tmp_path / 'cookies.json'
    jar(scoped_cookie()).save(path)
    data = json.loads(path.read_text())
    expected = ValueError
    if fault == 'schema':
        data['version'] = 2
    elif fault == 'duplicate':
        data['cookies'].append(data['cookies'][0])
    elif fault == 'count':
        data['cookies'][0].update(domain='', path='/', value='', rest={})
        data['cookies'] *= _cookie_file.MAX_COOKIES + 1
    path.write_text(json.dumps(data, separators=(',', ':')))
    if fault == 'utf8':
        path.write_bytes(b'\xff')
    elif fault == 'size':
        path.write_bytes(b' ' * (_cookie_file.MAX_FILE_BYTES + 1))
    elif fault == 'missing':
        path.unlink()
        expected = FileNotFoundError

    async def scenario():
        async with AsyncSession() as session:
            old = scoped_cookie('old')
            session.cookies.set_cookie(old)
            before = session.cookies._cookies
            match = 'Too many cookies' if fault == 'count' else None
            with pytest.raises(expected, match=match):
                await session.load_cookies(path)
            assert session.cookies._cookies is before and list(session.cookies) == [old]
        assert_idle(session)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    'fault', ['metadata', 'size', 'fsync', 'replace', 'missing-parent']
)
def test_save_errors_preserve_target_and_clean_temporary_files(
    tmp_path, monkeypatch, fault
):
    path = tmp_path / 'cookies.json'
    jar(scoped_cookie()).save(path)
    before = path.read_bytes()
    target = path if fault != 'missing-parent' else tmp_path / 'missing' / path.name

    def fail(*_args):
        raise OSError('simulated I/O failure')

    if fault in ('fsync', 'replace'):
        monkeypatch.setattr(_cookie_file.os, fault, fail)

    async def scenario():
        async with AsyncSession() as session:
            cookie = scoped_cookie(value='new')
            if fault == 'metadata':
                cookie._rest['bad'] = {'nested': True}
            elif fault == 'size':
                cookie.value = 'x' * _cookie_file.MAX_FILE_BYTES
            session.cookies.set_cookie(cookie)
            expected = ValueError if fault in ('metadata', 'size') else OSError
            with pytest.raises(expected):
                await session.save_cookies(target)
            assert path.read_bytes() == before
            assert list(tmp_path.iterdir()) == [path]
        assert_idle(session)

    asyncio.run(scenario())


@pytest.mark.parametrize('placement', ['session-metadata', 'metadata', 'extra-state'])
def test_save_opaque_objects_match_sync_filtering_and_validation(tmp_path, placement):
    cookie = scoped_cookie()
    opaque = threading.Lock()
    if placement == 'extra-state':
        cookie.application_lock = opaque
    else:
        cookie._rest['opaque'] = opaque
        if placement == 'session-metadata':
            cookie.expires = None
            cookie.discard = True
    source = jar(cookie)
    sync_path, async_path = tmp_path / 'sync.json', tmp_path / 'async.json'
    with Session(use_pooling=False) as sync:
        sync.cookies = source
        if placement == 'metadata':
            with pytest.raises(ValueError, match='Invalid cookie extension metadata'):
                sync.save_cookies(sync_path)
        else:
            expected = 0 if placement == 'session-metadata' else 1
            assert sync.save_cookies(sync_path) == expected

    async def scenario():
        async with AsyncSession() as session:
            session.cookies = source
            if placement == 'metadata':
                with pytest.raises(
                    ValueError, match='Invalid cookie extension metadata'
                ):
                    await session.save_cookies(async_path)
            else:
                assert await session.save_cookies(async_path) == expected
        assert_idle(session)

    asyncio.run(scenario())
    if placement == 'metadata':
        assert not sync_path.exists() and not async_path.exists()
    else:
        assert async_path.read_bytes() == sync_path.read_bytes()
    if placement == 'extra-state':
        assert cookie.application_lock is opaque
    else:
        assert cookie._rest['opaque'] is opaque


def test_helpers_serialize_and_save_takes_snapshot_after_earlier_load(
    tmp_path, monkeypatch
):
    first, incoming, last = (
        tmp_path / name for name in ('first.json', 'in.json', 'last.json')
    )
    jar(scoped_cookie(value='loaded')).save(incoming)
    save, load = async_sessions.save_cookie_file, async_sessions.load_cookie_file

    async def scenario():
        gate = WorkerGate()
        calls = []

        def paused(detached, path, **kwargs):
            calls.append(('save', path))
            if path == first:
                gate.wait()
            return save(detached, path, **kwargs)

        def observed_load(detached, path, **kwargs):
            calls.append(('load', path))
            return load(detached, path, **kwargs)

        monkeypatch.setattr(async_sessions, 'save_cookie_file', paused)
        monkeypatch.setattr(async_sessions, 'load_cookie_file', observed_load)
        async with AsyncSession() as session:
            session.cookies.set_cookie(scoped_cookie(value='initial'))
            pending = asyncio.create_task(session.save_cookies(first))
            try:
                await gate.entered()
                loading = asyncio.create_task(session.load_cookies(incoming))
                saving = asyncio.create_task(session.save_cookies(last))
                await asyncio.sleep(0)
                await asyncio.sleep(0)
                assert len(session._cookie_tasks) == 3
                assert calls == [('save', first)]
                next(iter(session.cookies)).value = 'while-queued'
                gate.release.set()
                results = await asyncio.wait_for(
                    asyncio.gather(pending, loading, saving), 2
                )
                assert results == [1, 1, 1]
                assert calls == [('save', first), ('load', incoming), ('save', last)]
            finally:
                gate.release.set()
        assert_idle(session)

    asyncio.run(scenario())
    assert json.loads(first.read_text())['cookies'][0]['value'] == 'initial'
    assert json.loads(last.read_text())['cookies'][0]['value'] == 'loaded'


@pytest.mark.parametrize('operation', ['save_cookies', 'load_cookies'])
def test_cancellation_before_dispatch_starts_no_io(tmp_path, monkeypatch, operation):
    calls = []
    monkeypatch.setattr(
        async_sessions, 'save_cookie_file', lambda *_a, **_k: calls.append('save')
    )
    monkeypatch.setattr(
        async_sessions, 'load_cookie_file', lambda *_a, **_k: calls.append('load')
    )

    async def scenario():
        async with AsyncSession() as session:
            task = asyncio.create_task(getattr(session, operation)(tmp_path / 'absent'))
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert calls == []
        assert_idle(session)

    asyncio.run(scenario())


@pytest.mark.parametrize('operation', ['save_cookies', 'load_cookies'])
def test_queued_cancellation_does_not_start_worker(tmp_path, monkeypatch, operation):
    save = async_sessions.save_cookie_file

    async def scenario():
        gate = WorkerGate()
        calls = []

        def paused(detached, path, **kwargs):
            calls.append(path)
            gate.wait()
            return save(detached, path, **kwargs)

        monkeypatch.setattr(async_sessions, 'save_cookie_file', paused)
        async with AsyncSession() as session:
            first = asyncio.create_task(session.save_cookies(tmp_path / 'first.json'))
            try:
                await gate.entered()
                queued = asyncio.create_task(
                    getattr(session, operation)(tmp_path / 'absent')
                )
                await asyncio.sleep(0)
                await asyncio.sleep(0)
                queued.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(queued, 1)
                assert calls == [tmp_path / 'first.json']
                assert not first.done()
                assert not (tmp_path / 'absent').exists()
                gate.release.set()
                assert await asyncio.wait_for(first, 2) == 0
            finally:
                gate.release.set()
        assert_idle(session)

    asyncio.run(scenario())


@pytest.mark.parametrize('phase', ['before-replace', 'after-replace', 'failed-replace'])
def test_cancelled_save_owns_worker_until_atomic_write_and_cleanup_finish(
    tmp_path, monkeypatch, phase
):
    path = tmp_path / 'cookies.json'
    jar(scoped_cookie(value='old')).save(path)
    replace = _cookie_file.os.replace

    async def scenario():
        gate = WorkerGate()
        errors = []
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(lambda _loop, context: errors.append(context))

        def paused(source, target):
            if phase == 'after-replace':
                replace(source, target)
            gate.wait()
            if phase == 'failed-replace':
                raise OSError('cancelled worker failed')
            if phase == 'before-replace':
                replace(source, target)

        monkeypatch.setattr(_cookie_file.os, 'replace', paused)
        async with AsyncSession() as session:
            session.cookies.set_cookie(scoped_cookie(value='new'))
            task = asyncio.create_task(session.save_cookies(path))
            try:
                await gate.entered()
                for _ in range(3):
                    task.cancel()
                    await asyncio.sleep(0)
                    assert not task.done()
                assert session._cookie_tasks
                if phase != 'after-replace':
                    assert len(list(tmp_path.iterdir())) == 2
                gate.release.set()
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(task, 2)
                assert_idle(session)
            finally:
                gate.release.set()
        await asyncio.sleep(0)
        assert errors == []
        assert list(tmp_path.iterdir()) == [path]

    asyncio.run(scenario())
    expected = 'old' if phase == 'failed-replace' else 'new'
    assert json.loads(path.read_text())['cookies'][0]['value'] == expected


@pytest.mark.parametrize('phase', ['before-parse', 'after-parse', 'failed-read'])
def test_cancelled_load_never_applies_after_worker_exit(tmp_path, monkeypatch, phase):
    path = tmp_path / 'cookies.json'
    jar(scoped_cookie(value='loaded')).save(path)
    load = async_sessions.load_cookie_file

    async def scenario():
        gate = WorkerGate()
        errors = []
        asyncio.get_running_loop().set_exception_handler(
            lambda _loop, context: errors.append(context)
        )

        def paused(detached, *args, **kwargs):
            if phase == 'after-parse':
                count = load(detached, *args, **kwargs)
            gate.wait()
            if phase == 'failed-read':
                raise OSError('cancelled reader failed')
            return count if phase == 'after-parse' else load(detached, *args, **kwargs)

        monkeypatch.setattr(async_sessions, 'load_cookie_file', paused)
        async with AsyncSession() as session:
            session.cookies.set_cookie(scoped_cookie(value='unchanged'))
            before = session.cookies._cookies
            task = asyncio.create_task(session.load_cookies(path))
            try:
                await gate.entered()
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done()
                gate.release.set()
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(task, 2)
                assert session.cookies._cookies is before
                assert names(session.cookies) == {'sid': 'unchanged'}
            finally:
                gate.release.set()
        assert_idle(session)
        await asyncio.sleep(0)
        assert errors == []

    asyncio.run(scenario())


def test_cancel_when_worker_is_ready_but_owner_has_not_committed(tmp_path, monkeypatch):
    path = tmp_path / 'cookies.json'
    jar(scoped_cookie(value='loaded')).save(path)
    load = async_sessions.load_cookie_file

    async def scenario():
        gate = WorkerGate()
        loop = asyncio.get_running_loop()
        executor = loop.run_in_executor

        def paused(detached, *args, **kwargs):
            count = load(detached, *args, **kwargs)
            gate.wait()
            return count

        def cancel_before_commit(pool, callback, *args):
            future = executor(pool, callback, *args)
            # This callback runs before shield releases the owner. Schedule
            # cancellation in the same loop turn as that owner's next step.
            future.add_done_callback(lambda _future: loop.call_soon(task.cancel))
            return future

        monkeypatch.setattr(async_sessions, 'load_cookie_file', paused)
        monkeypatch.setattr(loop, 'run_in_executor', cancel_before_commit)
        async with AsyncSession() as session:
            session.cookies.set_cookie(scoped_cookie(value='unchanged'))
            before = session.cookies._cookies
            task = asyncio.create_task(session.load_cookies(path))
            try:
                await gate.entered()
                gate.release.set()
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(task, 2)
                assert session.cookies._cookies is before
                assert names(session.cookies) == {'sid': 'unchanged'}
            finally:
                gate.release.set()
        assert_idle(session)

    asyncio.run(scenario())


def test_separate_sessions_keep_last_atomic_writer_semantics(tmp_path, monkeypatch):
    path = tmp_path / 'shared.json'
    replace = _cookie_file.os.replace

    async def scenario():
        gates = {name: WorkerGate() for name in ('first', 'second')}

        def paused(source, target):
            with open(source, encoding='utf-8') as stream:
                value = json.load(stream)['cookies'][0]['value']
            gates[value].wait()
            replace(source, target)

        monkeypatch.setattr(_cookie_file.os, 'replace', paused)
        async with AsyncSession() as first, AsyncSession() as second:
            first.cookies.set_cookie(scoped_cookie(value='first'))
            second.cookies.set_cookie(scoped_cookie(value='second'))
            saving_first = asyncio.create_task(first.save_cookies(path))
            saving_second = asyncio.create_task(second.save_cookies(path))
            try:
                await asyncio.gather(*(gate.entered() for gate in gates.values()))
                gates['first'].release.set()
                assert await asyncio.wait_for(saving_first, 2) == 1
                gates['second'].release.set()
                assert await asyncio.wait_for(saving_second, 2) == 1
            finally:
                for gate in gates.values():
                    gate.release.set()
        assert_idle(first)
        assert_idle(second)
        assert list(tmp_path.iterdir()) == [path]

    asyncio.run(scenario())
    assert json.loads(path.read_text())['cookies'][0]['value'] == 'second'


@pytest.mark.parametrize('operation', ['save_cookies', 'load_cookies'])
@pytest.mark.parametrize('borrowed_pool', [False, True])
def test_close_joins_helpers_without_joining_application_or_closing_borrowed_pool(
    tmp_path, monkeypatch, operation, borrowed_pool
):
    path = tmp_path / 'cookies.json'
    jar(scoped_cookie(value='from-file')).save(path)
    helper = 'save_cookie_file' if operation == 'save_cookies' else 'load_cookie_file'
    original = getattr(async_sessions, helper)

    async def scenario():
        gate = WorkerGate()
        finish_app = asyncio.Event()
        app_cancelled = asyncio.Event()
        calls = []
        pool = AsyncConnectionPool() if borrowed_pool else None
        session = AsyncSession(pool=pool)
        session.cookies.set_cookie(scoped_cookie(value='initial'))
        before = set(asyncio.all_tasks())

        def paused(detached, *args, **kwargs):
            calls.append(detached)
            gate.wait()
            return original(detached, *args, **kwargs)

        monkeypatch.setattr(async_sessions, helper, paused)

        async def application():
            try:
                await getattr(session, operation)(path)
            except asyncio.CancelledError:
                app_cancelled.set()
            finally:
                # Session shutdown must not join arbitrary caller code.
                await finish_app.wait()

        app = asyncio.create_task(application())
        try:
            await gate.entered()
            queued = asyncio.create_task(session.save_cookies(tmp_path / 'queued.json'))
            await asyncio.sleep(0)
            closer = asyncio.create_task(session.aclose())
            await asyncio.sleep(0)
            assert not closer.done()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(queued, 1)
            closer.cancel()
            with pytest.raises(asyncio.CancelledError):
                await closer
            assert not session._close_task.done()
            gate.release.set()
            await asyncio.wait_for(session.aclose(), 2)
            await asyncio.wait_for(app_cancelled.wait(), 1)
            assert len(calls) == 1 and not app.done()
            assert not (tmp_path / 'queued.json').exists()
            assert names(session.cookies) == {'sid': 'initial'}
            assert session.pool._closed is (not borrowed_pool)
            assert_idle(session)
            for name in ('save_cookies', 'load_cookies'):
                with pytest.raises(RuntimeError, match='closed'):
                    await getattr(session, name)(path)
        finally:
            gate.release.set()
            finish_app.set()
            await asyncio.wait_for(session.aclose(), 2)
            await app
            if pool is not None:
                await pool.aclose()
        await asyncio.sleep(0)
        assert set(asyncio.all_tasks()) == before

    asyncio.run(scenario())


def test_helpers_bind_session_to_one_loop_even_when_constructed_outside_loop(tmp_path):
    session = AsyncSession()
    first, second = asyncio.new_event_loop(), asyncio.new_event_loop()
    path = tmp_path / 'cookies.json'
    try:
        assert first.run_until_complete(session.save_cookies(path)) == 0
        for operation in ('save_cookies', 'load_cookies'):
            with pytest.raises(RuntimeError, match='across event loops'):
                second.run_until_complete(getattr(session, operation)(path))
        first.run_until_complete(session.aclose())
        assert_idle(session)
    finally:
        first.close()
        second.close()


def test_invalid_options_and_replaced_nonjar_are_rejected_without_io(tmp_path):
    path = tmp_path / 'absent'

    async def scenario():
        async with AsyncSession() as session:
            for operation in ('save_cookies', 'load_cookies'):
                with pytest.raises(TypeError, match='include_session'):
                    await getattr(session, operation)(path, include_session='false')
            with pytest.raises(TypeError, match='merge'):
                await session.load_cookies(path, merge='false')
            session.cookies = {'invalid': 'jar'}
            for operation in ('save_cookies', 'load_cookies'):
                with pytest.raises(TypeError, match='CookieJar'):
                    await getattr(session, operation)(path)
            assert not path.exists()
        assert_idle(session)

    asyncio.run(scenario())
