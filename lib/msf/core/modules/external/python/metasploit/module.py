"""
Metasploit external module API for Python.

This module provides the interface for external Python modules to communicate
with the Metasploit Framework via JSON-RPC. It handles logging, reporting,
and execution of module callbacks.
"""

import json
import logging
import os
import sys

from metasploit import cli

__CLI_MODE__ = False


class LogFormatter(logging.Formatter):
    """Custom log formatter that adds a configurable prefix to log messages."""
    def __init__(self, prefix, *args, **kwargs):
        """
        Initialize the log formatter with a prefix.

        Args:
            prefix: String to prepend to all log messages
            *args: Additional arguments passed to parent Formatter
            **kwargs: Additional keyword arguments passed to parent Formatter
        """
        super(LogFormatter, self).__init__(*args, **kwargs)
        self.prefix = prefix

    def format(self, record):
        """
        Format a log record with the configured prefix.

        Args:
            record: LogRecord instance to format

        Returns:
            Formatted log message string with prefix
        """
        return self.prefix + super().format(record)


class LogHandler(logging.Handler):
    """Custom logging handler that routes log messages to Metasploit."""

    def emit(self, record):
        """
        Emit a log record to Metasploit via the module.log() function.

        Args:
            record: LogRecord instance to emit
        """
        level = 'debug'
        if record.levelno >= logging.ERROR:
            level = 'error'
        elif record.levelno >= logging.WARNING:
            level = 'warning'
        elif record.levelno >= logging.INFO:
            level = 'info'
        log(self.format(record), level)
        return

    @classmethod
    def setup(cls, level=logging.DEBUG, name=None, msg_prefix=None):
        """
        Set up a log handler for a logger.

        Args:
            level: Logging level (default: logging.DEBUG)
            name: Logger name (default: None for root logger)
            msg_prefix: Optional prefix for all log messages

        Returns:
            Configured LogHandler instance
        """
        logger = logging.getLogger(name)
        handler = cls()

        if level is not None:
            logger.setLevel(level)
        if msg_prefix is not None:
            handler.setFormatter(LogFormatter(msg_prefix))
        logger.addHandler(handler)
        return handler

def log(message, level='info'):
    """
    Send a log message to Metasploit.

    Args:
        message: Log message string
        level: Log level ('debug', 'info', 'warning', 'error', 'good')
    """
    if not __CLI_MODE__:
        rpc_send({'jsonrpc': '2.0', 'method': 'message', 'params': {
            'level': level,
            'message': message
        }})
    else:
        cli.log(message, level)


def report_host(ip, **opts):
    """
    Report a discovered host to Metasploit.

    Args:
        ip: IP address of the host
        **opts: Additional host properties (os_name, os_flavor, etc.)
    """
    host = opts.copy()
    host.update({'host': ip})
    report('host', host)


def report_service(ip, **opts):
    """
    Report a discovered service to Metasploit.

    Args:
        ip: IP address of the host
        **opts: Service properties (port, proto, name, info, etc.)
    """
    service = opts.copy()
    service.update({'host': ip})
    report('service', service)


def report_vuln(ip, name, **opts):
    """
    Report a discovered vulnerability to Metasploit.

    Args:
        ip: IP address of the vulnerable host
        name: Vulnerability name or identifier
        **opts: Additional vulnerability properties (info, refs, etc.)
    """
    vuln = opts.copy()
    vuln.update({'host': ip, 'name': name})
    report('vuln', vuln)


def report_valid_username(username, **opts):
    """
    Report a valid username discovered during authentication attempts.

    Args:
        username: Valid username
        **opts: Additional credential properties (host, port, etc.)
    """
    info = opts.copy()
    info.update({'username': username})
    report('credential_login', info)


def report_correct_password(username, password, **opts):
    """
    Report successful authentication credentials.

    Args:
        username: Valid username
        password: Correct password
        **opts: Additional credential properties (host, port, etc.)
    """
    info = opts.copy()
    info.update({'username': username, 'password': password})
    report('correct_password', info)


def report_wrong_password(username, password, **opts):
    """
    Report failed authentication attempt.

    Args:
        username: Username attempted
        password: Incorrect password
        **opts: Additional properties (host, port, etc.)
    """
    info = opts.copy()
    info.update({'username': username, 'password': password})
    report('wrong_password', info)


def run(metadata, module_callback, soft_check=None):
    """
    Main entry point for external Python modules.

    This function handles the JSON-RPC communication protocol with Metasploit,
    dispatches to the appropriate callback based on the requested method
    (describe, soft_check, or run), and returns results.

    Args:
        metadata: Module metadata dictionary containing name, description,
                  authors, options, etc.
        module_callback: Function to call when the 'run' method is invoked
        soft_check: Optional function to call for soft vulnerability checks

    Example:
        metadata = {
            'name': 'Example Module',
            'description': 'Module description',
            'options': {...}
        }
        module.run(metadata, run_function, check_function)
    """
    global __CLI_MODE__

    caps = []
    if soft_check:
        caps.append('soft_check')

    meta = metadata.copy()
    meta.update({'capabilities': caps})

    if len(sys.argv) > 1:
        __CLI_MODE__ = True

    req = None
    if __CLI_MODE__:
        req = cli.parse(meta)
    else:
        req = json.loads(os.read(0, 10000).decode("utf-8"))

    callback = None
    if req['method'] == 'describe':
        rpc_send({'jsonrpc': '2.0', 'id': req['id'], 'result': meta})
    elif req['method'] == 'soft_check':
        if soft_check:
            callback = soft_check
        else:
            rpc_send({'jsonrpc': '2.0', 'id': req['id'], 'error': {'code': -32601, 'message': 'Soft checks are not supported'}})
    elif req['method'] == 'run':
        callback = module_callback

    if callback:
        args = req['params']
        ret = callback(args)
        if ret and __CLI_MODE__:
            cli.ret(ret)

        rpc_send({'jsonrpc': '2.0', 'id': req['id'], 'result': {
            'message': 'Module completed',
            'return': ret
        }})


def report(kind, data):
    """
    Report data to Metasploit.

    Args:
        kind: Type of data being reported (host, service, vuln, etc.)
        data: Dictionary containing the data to report
    """
    if not __CLI_MODE__:
        rpc_send({'jsonrpc': '2.0', 'method': 'report', 'params': {
            'type': kind, 'data': data
        }})
    else:
        cli.report(kind, data)


def rpc_send(req):
    """
    Send a JSON-RPC request to Metasploit.

    Args:
        req: Dictionary containing the JSON-RPC request

    Note:
        Silently ignored when run in CLI mode. The calling code should
        handle important messages appropriately.
    """
    if not __CLI_MODE__:
        print(json.dumps(req))
        sys.stdout.flush()
