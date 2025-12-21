#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# standard modules
import logging
import os
import re

# extra modules
dependencies_missing = False
try:
    import impacket
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, rrp
    from impacket.dcerpc.v5.dtypes import NULL
except ImportError:
    dependencies_missing = True

from metasploit import module


metadata = {
    'name': 'Windows Registry Security Descriptor Utility',
    'description': '''
        Read or write a Windows registry security descriptor remotely.

        In READ mode, the FILE option can be set to specify where the
        security descriptor should be written to.

        The following format is used:
        ```
        key: <registry key>
        security_info: <security information>
        sd: <security descriptor as a hex string>
        ```

        In WRITE mode, the FILE option can be used to specify the information
        needed to write the security descriptor to the remote registry. The file must
        follow the same format as described above.
    ''',
    'authors': [
        'Christophe De La Fuente',
        'Python conversion by AI Assistant'
    ],
    'date': '2024-01-01',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/23e75ca3-98fd-4396-84e5-86cd9d40d343'}
    ],
    'type': 'auxiliary',
    'actions': [
        {'name': 'READ', 'description': 'Read a Windows registry security descriptor'},
        {'name': 'WRITE', 'description': 'Write a Windows registry security descriptor'}
    ],
    'default_action': 'READ',
    'options': {
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None},
        'rport': {'type': 'port', 'description': 'Target port', 'required': True, 'default': 445},
        'username': {'type': 'string', 'description': 'Username for authentication', 'required': False, 'default': ''},
        'password': {'type': 'string', 'description': 'Password for authentication', 'required': False, 'default': ''},
        'domain': {'type': 'string', 'description': 'Domain for authentication', 'required': False, 'default': ''},
        'key': {'type': 'string', 'description': 'Registry key to read or write', 'required': False, 'default': ''},
        'sd': {'type': 'string', 'description': 'Security Descriptor to write as a hex string', 'required': False, 'default': ''},
        'security_information': {
            'type': 'int', 
            'description': 'Security Information to read or write (default: OWNER|GROUP|DACL)', 
            'required': True, 
            'default': 7  # OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
        },
        'file': {'type': 'string', 'description': 'File path to store/read security descriptor', 'required': False, 'default': ''},
        'action': {'type': 'enum', 'description': 'Action to perform', 'required': True, 'default': 'READ', 'values': ['READ', 'WRITE']}
    }
}


def validate_hex_string(hex_str):
    """Validate that a string contains only hexadecimal characters"""
    if not hex_str:
        return True
    return bool(re.match(r'^([a-fA-F0-9]{2})+$', hex_str))


def hex_to_bytes(hex_str):
    """Convert hex string to bytes"""
    return bytes.fromhex(hex_str)


def bytes_to_hex(data):
    """Convert bytes to hex string"""
    return data.hex()


def connect_smb(args):
    """Establish SMB connection"""
    try:
        conn = SMBConnection(args['rhost'], args['rhost'], None, args['rport'])
        
        if args.get('username'):
            conn.login(args['username'], args.get('password', ''), args.get('domain', ''))
        else:
            # Try anonymous login
            conn.login('', '')
            
        return conn
    except Exception as e:
        logging.error(f'SMB connection failed: {e}')
        return None


def connect_registry(smb_conn):
    """Connect to remote registry via DCE/RPC"""
    try:
        # Create DCE/RPC transport over SMB
        dce = transport.DCERPCTransportFactory(f'ncacn_np:{smb_conn.getRemoteHost()}[\\pipe\\winreg]')
        dce.set_smb_connection(smb_conn)
        
        # Connect and bind to winreg interface
        rpc_conn = dce.get_dce_rpc()
        rpc_conn.connect()
        rpc_conn.bind(rrp.MSRPC_UUID_RRP)
        
        return rpc_conn
    except Exception as e:
        logging.error(f'Registry connection failed: {e}')
        return None


def parse_registry_key(key_path):
    """Parse registry key path into hive and subkey"""
    key_path = key_path.replace('/', '\\')
    if key_path.startswith('\\'):
        key_path = key_path[1:]
    
    parts = key_path.split('\\', 1)
    hive_name = parts[0].upper()
    subkey = parts[1] if len(parts) > 1 else ''
    
    # Map hive names to constants
    hive_map = {
        'HKEY_LOCAL_MACHINE': rrp.hOpenLocalMachine,
        'HKLM': rrp.hOpenLocalMachine,
        'HKEY_CURRENT_USER': rrp.hOpenCurrentUser,
        'HKCU': rrp.hOpenCurrentUser,
        'HKEY_USERS': rrp.hOpenUsers,
        'HKU': rrp.hOpenUsers,
        'HKEY_CLASSES_ROOT': rrp.hOpenClassesRoot,
        'HKCR': rrp.hOpenClassesRoot,
    }
    
    if hive_name not in hive_map:
        raise ValueError(f'Unknown registry hive: {hive_name}')
    
    return hive_map[hive_name], subkey


def read_security_descriptor(rpc_conn, key_path, security_info):
    """Read security descriptor from registry key"""
    try:
        hive_func, subkey = parse_registry_key(key_path)
        
        # Open the hive
        hive_handle = hive_func(rpc_conn)['phKey']
        
        # Open the subkey
        if subkey:
            key_handle = rrp.hOpenKey(rpc_conn, hive_handle, subkey)['phkResult']
        else:
            key_handle = hive_handle
        
        # Get security descriptor
        sd_data = rrp.hGetKeySecurity(rpc_conn, key_handle, security_info)['pRpcSecurityDescriptor']
        
        # Close handles
        if subkey:
            rrp.hCloseKey(rpc_conn, key_handle)
        rrp.hCloseKey(rpc_conn, hive_handle)
        
        return sd_data['lpSecurityDescriptor']
    except Exception as e:
        logging.error(f'Failed to read security descriptor: {e}')
        return None


def write_security_descriptor(rpc_conn, key_path, sd_data, security_info):
    """Write security descriptor to registry key"""
    try:
        hive_func, subkey = parse_registry_key(key_path)
        
        # Open the hive
        hive_handle = hive_func(rpc_conn)['phKey']
        
        # Open the subkey
        if subkey:
            key_handle = rrp.hOpenKey(rpc_conn, hive_handle, subkey, samDesired=rrp.MAXIMUM_ALLOWED)['phkResult']
        else:
            key_handle = hive_handle
        
        # Set security descriptor
        rrp.hSetKeySecurity(rpc_conn, key_handle, security_info, sd_data)
        
        # Close handles
        if subkey:
            rrp.hCloseKey(rpc_conn, key_handle)
        rrp.hCloseKey(rpc_conn, hive_handle)
        
        return True
    except Exception as e:
        logging.error(f'Failed to write security descriptor: {e}')
        return False


def save_to_file(key_path, sd_data, security_info, file_path):
    """Save security descriptor to file"""
    try:
        with open(file_path, 'w') as f:
            f.write(f'key: {key_path}\n')
            f.write(f'security_info: {security_info}\n')
            f.write(f'sd: {bytes_to_hex(sd_data)}\n')
        return True
    except Exception as e:
        logging.error(f'Failed to save to file: {e}')
        return False


def read_from_file(file_path):
    """Read security descriptor info from file"""
    try:
        sd_info = {}
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('key:'):
                    sd_info['key'] = line.split(':', 1)[1].strip()
                elif line.startswith('security_info:'):
                    sd_info['security_info'] = int(line.split(':', 1)[1].strip())
                elif line.startswith('sd:'):
                    sd_info['sd'] = line.split(':', 1)[1].strip()
        return sd_info
    except Exception as e:
        logging.error(f'Failed to read from file: {e}')
        return None


def action_read(args, rpc_conn):
    """Perform READ action"""
    if not args.get('key'):
        logging.error('Unknown registry key, please set the KEY option')
        return False
    
    sd_data = read_security_descriptor(rpc_conn, args['key'], args['security_information'])
    if sd_data is None:
        return False
    
    logging.info(f"Raw security descriptor for {args['key']}: {bytes_to_hex(sd_data)}")
    
    if args.get('file'):
        if save_to_file(args['key'], sd_data, args['security_information'], args['file']):
            logging.info(f"Saved to file {args['file']}")
        else:
            return False
    
    return True


def action_write(args, rpc_conn):
    """Perform WRITE action"""
    if args.get('file'):
        logging.info(f"Getting security descriptor info from file {args['file']}")
        sd_info = read_from_file(args['file'])
        if sd_info is None:
            return False
        
        sd_hex = sd_info['sd']
        key = sd_info['key']
        security_info = sd_info['security_info']
        
        logging.info(f"  key: {key}")
        logging.info(f"  security information: {security_info}")
        logging.info(f"  security descriptor: {sd_hex}")
    else:
        if not args.get('sd'):
            logging.error('Unknown security descriptor, please set the SD option')
            return False
        if not args.get('key'):
            logging.error('Unknown registry key, please set the KEY option')
            return False
        
        sd_hex = args['sd']
        key = args['key']
        security_info = args['security_information']
    
    # Validate hex string
    if not validate_hex_string(sd_hex):
        logging.error('Invalid security descriptor hex string format')
        return False
    
    try:
        sd_data = hex_to_bytes(sd_hex)
        if write_security_descriptor(rpc_conn, key, sd_data, security_info):
            logging.info(f"Security descriptor set for {key}")
            return True
        else:
            return False
    except Exception as e:
        logging.error(f'Unable to set the security descriptor for {key}: {e}')
        return False


def run(args):
    module.LogHandler.setup(msg_prefix='{} - '.format(args['rhost']))
    
    if dependencies_missing:
        logging.error('Module dependency (impacket) is missing, cannot continue')
        return
    
    # Validate action
    action = args.get('action', 'READ').upper()
    if action not in ['READ', 'WRITE']:
        logging.error(f'Unknown action: {action}')
        return
    
    # Validate WRITE-specific options
    if action == 'WRITE':
        if not args.get('file') and not args.get('sd'):
            logging.error('WRITE action requires either FILE or SD option')
            return
        if args.get('sd') and not validate_hex_string(args['sd']):
            logging.error('SD option must be a valid hex string')
            return
    
    # Connect to SMB
    logging.info(f"Connecting to {args['rhost']}:{args['rport']}")
    smb_conn = connect_smb(args)
    if smb_conn is None:
        return
    
    try:
        # Connect to registry
        logging.info("Connecting to remote registry")
        rpc_conn = connect_registry(smb_conn)
        if rpc_conn is None:
            return
        
        try:
            # Perform action
            if action == 'READ':
                success = action_read(args, rpc_conn)
            else:  # WRITE
                success = action_write(args, rpc_conn)
            
            if success:
                logging.info(f"Action {action} completed successfully")
            else:
                logging.error(f"Action {action} failed")
        
        finally:
            # Clean up RPC connection
            rpc_conn.disconnect()
    
    finally:
        # Clean up SMB connection
        smb_conn.close()


if __name__ == '__main__':
    module.run(metadata, run)