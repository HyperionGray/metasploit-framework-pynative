"""
Metasploit Framework External Python Module Support

This module provides the core functionality for creating external Python modules
that can be integrated with the Metasploit Framework. It handles communication
between Python modules and the framework via JSON-RPC.
"""

import json
import logging
import os
import sys

from metasploit import cli

__CLI_MODE__ = False


class LogFormatter(logging.Formatter):
    """Custom log formatter that adds a prefix to log messages."""
    
    def __init__(self, prefix, *args, **kwargs):
        """
        Initialize the log formatter with a message prefix.
        
        Args:
            prefix (str): Prefix to add to all log messages
            *args: Additional arguments passed to parent formatter
            **kwargs: Additional keyword arguments passed to parent formatter
        """
        super(LogFormatter, self).__init__(*args, **kwargs)
        self.prefix = prefix

    def format(self, record):
        """
        Format a log record by adding the prefix.
        
        Args:
            record (logging.LogRecord): The log record to format
            
        Returns:
            str: The formatted log message with prefix
        """
        return self.prefix + super().format(record)


class LogHandler(logging.Handler):
    """Custom log handler that routes log messages through the Metasploit framework."""
    
    def emit(self, record):
        """
        Emit a log record by routing it through the framework's logging system.
        
        Args:
            record (logging.LogRecord): The log record to emit
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
        Set up a logger with this handler.
        
        Args:
            level (int, optional): Logging level. Defaults to logging.DEBUG.
            name (str, optional): Logger name. Defaults to None.
            msg_prefix (str, optional): Message prefix for formatter. Defaults to None.
            
        Returns:
            LogHandler: The configured log handler instance
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
    Log a message through the framework's logging system.
    
    Args:
        message (str): The message to log
        level (str, optional): Log level ('debug', 'info', 'warning', 'error'). 
                              Defaults to 'info'.
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
    Report a discovered host to the framework.
    
    Args:
        ip (str): IP address of the host
        **opts: Additional host information (e.g., os_name, os_flavor, arch)
    """
    host = opts.copy()
    host.update({'host': ip})
    report('host', host)


def report_service(ip, **opts):
    """
    Report a discovered service to the framework.
    
    Args:
        ip (str): IP address of the host running the service
        **opts: Service information (e.g., port, proto, name, info)
    """
    service = opts.copy()
    service.update({'host': ip})
    report('service', service)


def report_vuln(ip, name, **opts):
    """
    Report a discovered vulnerability to the framework.
    
    Args:
        ip (str): IP address of the vulnerable host
        name (str): Name/identifier of the vulnerability
        **opts: Additional vulnerability information (e.g., info, refs)
    """
    vuln = opts.copy()
    vuln.update({'host': ip, 'name': name})
    report('vuln', vuln)


def report_valid_username(username, **opts):
    """
    Report a valid username discovered during authentication attempts.
    
    Args:
        username (str): The valid username
        **opts: Additional credential information (e.g., host, port, service_name)
    """
    info = opts.copy()
    info.update({'username': username})
    report('credential_login', info)


def report_correct_password(username, password, **opts):
    """
    Report a successful authentication with username and password.
    
    Args:
        username (str): The username
        password (str): The correct password
        **opts: Additional credential information (e.g., host, port, service_name)
    """
    info = opts.copy()
    info.update({'username': username, 'password': password})
    report('correct_password', info)


def report_wrong_password(username, password, **opts):
    """
    Report a failed authentication attempt.
    
    Args:
        username (str): The username attempted
        password (str): The incorrect password attempted
        **opts: Additional credential information (e.g., host, port, service_name)
    """
    info = opts.copy()
    info.update({'username': username, 'password': password})
    report('wrong_password', info)


def run(metadata, module_callback, soft_check=None):
    """
    Main entry point for running external Python modules.
    
    This function handles the JSON-RPC communication protocol between the
    Metasploit framework and external Python modules. It processes requests
    for module description, soft checks, and execution.
    
    Args:
        metadata (dict): Module metadata including name, description, options, etc.
        module_callback (callable): Function to call when executing the module
        soft_check (callable, optional): Function to call for soft vulnerability checks.
                                        Defaults to None.
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
    Send a report to the framework.
    
    Args:
        kind (str): Type of report ('host', 'service', 'vuln', etc.)
        data (dict): Report data
    """
    if not __CLI_MODE__:
        rpc_send({'jsonrpc': '2.0', 'method': 'report', 'params': {
            'type': kind, 'data': data
        }})
    else:
        cli.report(kind, data)


def rpc_send(req):
    """
    Send a JSON-RPC request to the framework.
    
    This function outputs JSON-RPC messages to stdout for communication
    with the Metasploit framework. In CLI mode, it silently ignores
    the request.
    
    Args:
        req (dict): JSON-RPC request dictionary
    """
    # Silently ignore when run manually, the calling code should know how to
    # handle if it is important
    if not __CLI_MODE__:
        print(json.dumps(req))
        sys.stdout.flush()
