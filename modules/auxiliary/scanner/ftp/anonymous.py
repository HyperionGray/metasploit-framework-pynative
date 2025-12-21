#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# standard modules
import logging
import random
import string

# extra modules
dependencies_missing = False
try:
    import ftplib
except ImportError:
    dependencies_missing = True

from metasploit import module


metadata = {
    'name': 'Anonymous FTP Access Detection',
    'description': '''
        Detect anonymous (read/write) FTP server access.
        This module attempts to login to FTP servers using anonymous credentials
        and tests whether the server allows read-only or read/write access.
    ''',
    'authors': [
        'Matteo Cantoni <goony[at]nothink.org>',
        'Python conversion by AI Assistant'
    ],
    'date': '2024-01-01',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://en.wikipedia.org/wiki/File_Transfer_Protocol#Anonymous_FTP'}
    ],
    'type': 'single_scanner',
    'options': {
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None},
        'rport': {'type': 'port', 'description': 'Target port', 'required': True, 'default': 21},
        'timeout': {'type': 'int', 'description': 'Connection timeout in seconds', 'required': False, 'default': 10},
        'ftpuser': {'type': 'string', 'description': 'FTP username for anonymous login', 'required': False, 'default': 'anonymous'},
        'ftppass': {'type': 'string', 'description': 'FTP password for anonymous login', 'required': False, 'default': 'anonymous@example.com'}
    }
}


def generate_random_string(length=8):
    """Generate a random string for testing directory creation"""
    return ''.join(random.choices(string.ascii_letters, k=length))


def test_anonymous_access(host, port, username, password, timeout):
    """Test anonymous FTP access and determine read/write permissions"""
    try:
        # Connect to FTP server
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout)
        
        # Get the banner
        banner = ftp.getwelcome()
        
        # Attempt anonymous login
        try:
            ftp.login(username, password)
            logging.info(f'Anonymous login successful to {host}:{port}')
        except ftplib.error_perm as e:
            logging.error(f'Anonymous login failed: {e}')
            ftp.quit()
            return None, None
        
        # Test write permissions by trying to create a directory
        test_dir = generate_random_string(8)
        access_type = 'Read-only'
        
        try:
            # Try to create a directory
            ftp.mkd(test_dir)
            logging.info(f'Directory creation successful, testing removal...')
            
            # If creation succeeded, try to remove it
            try:
                ftp.rmd(test_dir)
                access_type = 'Read/Write'
                logging.info(f'Directory removal successful - Read/Write access confirmed')
            except ftplib.error_perm as e:
                logging.warning(f'Directory removal failed: {e}')
                access_type = 'Read/Write'  # Still consider it R/W if we could create
        except ftplib.error_perm as e:
            logging.info(f'Directory creation failed: {e} - Read-only access')
            access_type = 'Read-only'
        
        ftp.quit()
        return banner, access_type
        
    except ftplib.error_temp as e:
        logging.error(f'Temporary FTP error: {e}')
        return None, None
    except ftplib.error_perm as e:
        logging.error(f'FTP permission error: {e}')
        return None, None
    except Exception as e:
        logging.error(f'FTP connection error: {e}')
        return None, None


def sanitize_banner(banner):
    """Sanitize banner text for safe display"""
    if not banner:
        return ''
    
    # Remove leading/trailing whitespace and control characters
    sanitized = banner.strip()
    
    # Convert non-printable characters to hex representation
    result = ''
    for char in sanitized:
        if ord(char) >= 32 and ord(char) <= 126:
            result += char
        else:
            result += f'\\x{ord(char):02x}'
    
    return result


def register_credentials(host, port, username, password, access_type, banner):
    """Register discovered credentials (placeholder for Metasploit integration)"""
    cred_info = {
        'host': host,
        'port': port,
        'service': 'ftp',
        'protocol': 'tcp',
        'username': username,
        'password': password,
        'access_level': access_type,
        'banner': banner,
        'status': 'successful'
    }
    
    logging.info(f'Credentials registered: {cred_info}')
    return cred_info


def run(args):
    module.LogHandler.setup(msg_prefix='{} - '.format(args['rhost']))
    
    if dependencies_missing:
        logging.error('Module dependency (ftplib) is missing, cannot continue')
        return
    
    host = args['rhost']
    port = args['rport']
    timeout = args.get('timeout', 10)
    username = args.get('ftpuser', 'anonymous')
    password = args.get('ftppass', 'anonymous@example.com')
    
    logging.info(f'Testing anonymous FTP access on {host}:{port}')
    
    try:
        # Test anonymous access
        banner, access_type = test_anonymous_access(host, port, username, password, timeout)
        
        if banner is not None and access_type is not None:
            # Sanitize banner for display
            banner_clean = sanitize_banner(banner)
            
            if access_type == 'Read/Write':
                logging.info(f'{host}:{port} - Anonymous READ/WRITE ({banner_clean})')
            else:
                logging.info(f'{host}:{port} - Anonymous READ ({banner_clean})')
            
            # Register the credentials
            register_credentials(host, port, username, password, access_type, banner_clean)
            
            # Report service information
            service_info = {
                'host': host,
                'port': port,
                'protocol': 'tcp',
                'service': 'ftp',
                'banner': banner_clean,
                'anonymous_access': True,
                'access_type': access_type,
                'credentials': {
                    'username': username,
                    'password': password
                }
            }
            
            logging.info(f'Anonymous FTP access detected: {service_info}')
            
        else:
            logging.info(f'{host}:{port} - No anonymous access detected')
            
    except KeyboardInterrupt:
        logging.info('Scan interrupted by user')
    except Exception as e:
        logging.error(f'Unexpected error during scan: {e}')


if __name__ == '__main__':
    module.run(metadata, run)