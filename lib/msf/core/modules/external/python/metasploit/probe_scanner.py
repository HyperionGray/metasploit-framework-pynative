"""
Asynchronous probe scanner utilities for Metasploit external Python modules.

This module provides functionality for creating asynchronous network probes
that can send payloads to multiple hosts and analyze responses using pattern matching.
"""

import asyncio
import functools
import re

from async_timeout import timeout
from metasploit import module


def make_scanner(payload='', pattern='', onmatch=None, connect_timeout=3, read_timeout=10):
    """
    Create a probe scanner function with the specified parameters.
    
    Args:
        payload (str, optional): Data to send to each target. Defaults to ''.
        pattern (str, optional): Regex pattern to match against responses. Defaults to ''.
        onmatch (callable, optional): Function to call when pattern matches. Defaults to None.
        connect_timeout (int, optional): Connection timeout in seconds. Defaults to 3.
        read_timeout (int, optional): Read timeout in seconds. Defaults to 10.
        
    Returns:
        callable: Scanner function that can be used as a module callback
    """
    return lambda args: start_scanner(payload, pattern, args, onmatch, connect_timeout=connect_timeout, read_timeout=read_timeout)


def start_scanner(payload, pattern, args, onmatch, **timeouts):
    """
    Start the asynchronous probe scanner.
    
    Args:
        payload (str): Data to send to each target
        pattern (str): Regex pattern to match against responses
        args (dict): Module arguments containing rhosts and rport
        onmatch (callable): Function to call when pattern matches
        **timeouts: Timeout parameters (connect_timeout, read_timeout)
    """
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run_scanner(payload, pattern, args, onmatch, **timeouts))


async def run_scanner(payload, pattern, args, onmatch, **timeouts):
    """
    Run the asynchronous probe scanner against multiple hosts.
    
    Args:
        payload (str): Data to send to each target
        pattern (str): Regex pattern to match against responses
        args (dict): Module arguments containing rhosts and rport
        onmatch (callable): Function to call when pattern matches
        **timeouts: Timeout parameters (connect_timeout, read_timeout)
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
    Asynchronous iterator for managing multiple concurrent probe operations.
    
    This class handles the execution and result collection of multiple
    asynchronous probe operations, providing an async iterator interface
    for processing results as they become available.
    """
    
    def __init__(self, runs):
        """
        Initialize the scan with a list of coroutines to execute.
        
        Args:
            runs (list): List of coroutines representing probe operations
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
        Queue the result of a completed probe operation.
        
        Args:
            target (tuple): Target (host, port) tuple
            f (asyncio.Future): Completed future object
        """
        res = None

        try:
            res = f.result()
        except Exception as e:
            res = e

        self.queue.put_nowait((target, res))

    def __aiter__(self):
        """Return self as async iterator."""
        return self

    async def __anext__(self):
        """
        Get the next completed probe result.
        
        Returns:
            tuple: (target, result) where target is (host, port) and result
                  is either the probe response or an Exception
                  
        Raises:
            StopAsyncIteration: When all probes have completed
        """
        if self.done == self.total:
            raise StopAsyncIteration

        res = await self.queue.get()
        self.done += 1
        return res


async def probe_host(host, port, payload, connect_timeout, read_timeout):
    """
    Probe a single host by sending a payload and reading the response.
    
    Args:
        host (str): Target host IP address or hostname
        port (int): Target port number
        payload (str): Data to send to the target
        connect_timeout (int): Connection timeout in seconds
        read_timeout (int): Read timeout in seconds
        
    Returns:
        bytearray: Response data received from the target
        
    Raises:
        asyncio.TimeoutError: If connection or read times out
        Exception: For other connection or I/O errors
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
