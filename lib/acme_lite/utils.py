#!/usr/bin/env python

import base64
import binascii
import hashlib
import re

def b64(data):
    return base64.urlsafe_b64encode(data).decode("utf-8").replace('=', '')

def long2hex(n):
    hex_data = "{0:x}".format(n)
    hex_data = "0{0}".format(hex_data) if len(hex_data) % 2 else hex_data
    return hex_data

def long2b64(n):
    hex_data = long2hex(n)
    return b64(binascii.unhexlify(hex_data))

def thumbprint(data):
    return b64(hashlib.sha256(data).digest())

def linkurl(link):
    # Link: <https://acme-staging.api.letsencrypt.org/acme/issuer-cert>;rel="up"
    m = re.match(r"^<(.*)>;rel=\"up\"$", link)
    return m.group(1) if m else None

