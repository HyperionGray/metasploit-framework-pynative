#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# standard modules
import logging
import socket
import re

# extra modules
dependencies_missing = False
try:
    import ftplib
except ImportError:
    dependencies_missing = True

from metasploit import module


metadata = {
    'name': 'FTP Version Scanner',
    'description': '''
        Detect FTP Version by connecting to FTP servers and retrieving their banners.
        This scanner will attempt to connect to FTP services and extract version
        information from the server banner.
    ''',
    'authors': [
        'hdm',
        'Python conversion by AI Assistant'
    ],
    'date': '2024-01-01',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://tools.ietf.org/html/rfc959'}
    ],
    'type': 'single_scanner',
    'options': {
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None},
        'rport': {'type': 'port', 'description': 'Target port', 'required': True, 'default': 21},
        'timeout': {'type': 'int', 'description': 'Connection timeout in seconds', 'required': False, 'default': 10}
    }
}


def sanitize_banner(banner):
    """Sanitize banner text for safe display"""
    if not banner:
        return ''
    
    # Convert non-printable characters to hex representation
    sanitized = ''
    for char in banner:
        if ord(char) >= 32 and ord(char) <= 126:
            sanitized += char
        else:
            sanitized += f'\\x{ord(char):02x}'
    
    return sanitized


def connect_ftp(host, port, timeout):
    """Connect to FTP server and retrieve banner"""
    try:
        # Create a raw socket connection to get the banner
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Receive the banner (FTP servers typically send a welcome message)
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        return banner
    except socket.timeout:
        logging.error(f'Connection to {host}:{port} timed out')
        return None
    except socket.error as e:
        logging.error(f'Socket error connecting to {host}:{port}: {e}')
        return None
    except Exception as e:
        logging.error(f'Unexpected error connecting to {host}:{port}: {e}')
        return None


def extract_ftp_info(banner):
    """Extract useful information from FTP banner"""
    if not banner:
        return {}
    
    info = {'banner': banner}
    
    # Common FTP server patterns
    patterns = {
        'vsftpd': r'vsftpd\s+([\d\.]+)',
        'proftpd': r'ProFTPD\s+([\d\.]+)',
        'pureftpd': r'Pure-FTPd\s+([\d\.]+)',
        'filezilla': r'FileZilla Server\s+([\d\.]+)',
        'microsoft': r'Microsoft FTP Service',
        'wu-ftpd': r'wu-([\d\.]+)',
        'ncftpd': r'NcFTPd\s+([\d\.]+)',
        'serv-u': r'Serv-U FTP Server\s+([\d\.]+)',
        'gene6': r'Gene6 FTP Server\s+([\d\.]+)',
        'glftpd': r'glFTPd\s+([\d\.]+)',
    }
    
    for server_type, pattern in patterns.items():
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            info['server_type'] = server_type
            if match.groups():
                info['version'] = match.group(1)
            break
    
    return info


def run(args):
    module.LogHandler.setup(msg_prefix='{} - '.format(args['rhost']))
    
    if dependencies_missing:
        logging.error('Module dependency (ftplib) is missing, cannot continue')
        return
    
    host = args['rhost']
    port = args['rport']
    timeout = args.get('timeout', 10)
    
    logging.info(f'Scanning FTP service on {host}:{port}')
    
    try:
        # Connect and get banner
        banner = connect_ftp(host, port, timeout)
        
        if banner:
            # Sanitize banner for safe display
            banner_sanitized = sanitize_banner(banner)
            logging.info(f"FTP Banner: '{banner_sanitized}'")
            
            # Extract additional information
            ftp_info = extract_ftp_info(banner)
            
            if 'server_type' in ftp_info:
                server_info = f"Server: {ftp_info['server_type']}"
                if 'version' in ftp_info:
                    server_info += f" {ftp_info['version']}"
                logging.info(server_info)
            
            # Report the service (this would integrate with Metasploit's reporting system)
            service_info = {
                'host': host,
                'port': port,
                'protocol': 'tcp',
                'service': 'ftp',
                'banner': banner_sanitized
            }
            
            if 'server_type' in ftp_info:
                service_info['name'] = ftp_info['server_type']
                if 'version' in ftp_info:
                    service_info['version'] = ftp_info['version']
            
            logging.info(f"Service detected: {service_info}")
            
        else:
            logging.error(f'No banner received from {host}:{port}')
            
    except KeyboardInterrupt:
        logging.info('Scan interrupted by user')
    except Exception as e:
        logging.error(f'Unexpected error during scan: {e}')


if __name__ == '__main__':
    module.run(metadata, run)