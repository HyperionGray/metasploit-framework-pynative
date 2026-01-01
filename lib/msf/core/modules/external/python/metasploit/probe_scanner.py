"""
Asynchronous network probe scanner for Metasploit external Python modules.

This module provides utilities for building network service detection and
banner-grabbing scanners with async I/O for performance.
"""

import asyncio
import functools
import re

from async_timeout import timeout
from metasploit import module


def make_scanner(payload='', pattern='', onmatch=None, connect_timeout=3, read_timeout=10):
    """
    Create a probe scanner function.

    Args:
        payload: Bytes to send to the service (default: empty)
        pattern: Regular expression pattern to match in response
        onmatch: Callback function called when pattern matches, takes (target, response)
        connect_timeout: Connection timeout in seconds (default: 3)
        read_timeout: Read timeout in seconds (default: 10)

    Returns:
        Scanner function that can be passed to module.run()

    Example:
        def on_match(target, response):
            module.report_service(target[0], port=target[1], proto='tcp')

        scanner = make_scanner(
            payload=b'HELLO\\r\\n',
            pattern='Welcome',
            onmatch=on_match
        )
        module.run(metadata, scanner)
    """
    return lambda args: start_scanner(payload, pattern, args, onmatch, connect_timeout=connect_timeout, read_timeout=read_timeout)


def start_scanner(payload, pattern, args, onmatch, **timeouts):
    """
    Start the async scanner event loop.

    Args:
        payload: Bytes to send to each host
        pattern: Regular expression pattern to match
        args: Dictionary containing 'rhosts' and 'rport'
        onmatch: Callback for successful matches
        **timeouts: connect_timeout and read_timeout
    """
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run_scanner(payload, pattern, args, onmatch, **timeouts))


async def run_scanner(payload, pattern, args, onmatch, **timeouts):
    """
    Run the async scanner across all targets.

    Args:
        payload: Bytes to send to each host
        pattern: Regular expression pattern to match
        args: Dictionary containing 'rhosts' and 'rport'
        onmatch: Callback for successful matches
        **timeouts: connect_timeout and read_timeout
    """
    probes = [probe_host(host, int(args['rport']), payload, **timeouts) for host in args['rhosts']]
    async for (target, res) in Scan(probes):
        if isinstance(res, Exception):
            module.log('{}:{} - Error connecting: {}'.format(*target, res), level='error')
        elif res and re.search(pattern, res):
            module.log('{}:{} - Matches'.format(*target), level='good')
            module.log('{}:{} - Matches with: {}'.format(*target, res), level='debug')
            onmatch(target, res)
        else:
            module.log('{}:{} - Does not match'.format(*target), level='info')
            module.log('{}:{} - Does not match with: {}'.format(*target, res), level='debug')


class Scan:
    """
    Asynchronous scan coordinator that manages multiple probe tasks.

    Handles concurrent execution of probes and collects results via a queue.
    """

    def __init__(self, runs):
        """
        Initialize the scan with a list of async probe tasks.

        Args:
            runs: List of coroutines (probe tasks) to execute
        """
        self.queue = asyncio.queues.Queue()
        self.total = len(runs)
        self.done = 0

        for r in runs:
            f = asyncio.ensure_future(r)
            args = r.cr_frame.f_locals
            target = (args['host'], args['port'])
            f.add_done_callback(functools.partial(self.__queue_result, target))

    def __queue_result(self, target, f):
        """
        Callback to queue completed probe results.

        Args:
            target: Tuple of (host, port)
            f: Completed Future object
        """
        res = None

        try:
            res = f.result()
        except Exception as e:
            res = e

        self.queue.put_nowait((target, res))

    def __aiter__(self):
        """Return async iterator."""
        return self

    async def __anext__(self):
        """
        Get the next completed probe result.

        Returns:
            Tuple of (target, result) where target is (host, port)

        Raises:
            StopAsyncIteration: When all probes are complete
        """
        if self.done == self.total:
            raise StopAsyncIteration

        res = await self.queue.get()
        self.done += 1
        return res


async def probe_host(host, port, payload, connect_timeout, read_timeout):
    """
    Probe a single host by connecting, sending payload, and reading response.

    Args:
        host: Target hostname or IP address
        port: Target port number
        payload: Bytes to send after connecting
        connect_timeout: Connection timeout in seconds
        read_timeout: Read timeout in seconds

    Returns:
        Bytearray containing response data (up to 4096 bytes)

    Raises:
        asyncio.TimeoutError: If connection or read times out with no data
    """
    buf = bytearray()

    try:
        async with timeout(connect_timeout):
            r, w = await asyncio.open_connection(host, port)
            remote = w.get_extra_info('peername')
            if remote[0] == host:
                module.log('{}:{} - Connected'.format(host, port), level='debug')
            else:
                module.log('{}({}):{} - Connected'.format(host, *remote), level='debug')
            w.write(payload)
            await w.drain()

        async with timeout(read_timeout):
            while len(buf) < 4096:
                data = await r.read(4096)
                if data:
                    module.log('{}:{} - Received {} bytes'.format(host, port, len(data)), level='debug')
                    buf.extend(data)
                else:
                    break
    except asyncio.TimeoutError:
        if buf:
            pass
        else:
            raise
    finally:
        try:
            w.close()
        except Exception:
            # Either we got something and the socket got in a bad state, or the
            # original error will point to the root cause
            pass

    return buf
