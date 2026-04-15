#!/usr/bin/env python3
"""
jwt-check.py — Apache RewriteMap prg: script
Validates JWT tokens (HMAC-SHA256) and returns comma-separated app list.

Usage in Apache VHost:
    RewriteMap jwtcheck "prg:/opt/idp/jwt-check.py"

Reads JWT_SECRET from env or /opt/idp/jwt-secret.env file.
Stdin: one token per line.
Stdout: comma-separated apps if valid, empty line if invalid.
"""
import sys
import hmac
import hashlib
import base64
import json
import os
import time

SECRET_FILE = '/opt/idp/jwt-secret.env'

def load_secret():
    s = os.environ.get('JWT_SECRET', '')
    if not s and os.path.exists(SECRET_FILE):
        for line in open(SECRET_FILE):
            if line.startswith('JWT_SECRET='):
                s = line.split('=', 1)[1].strip()
                break
    return s.encode()

SECRET = load_secret()

def check_token(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return ''
        h, p, s = parts
        sig = base64.urlsafe_b64encode(
            hmac.new(SECRET, f'{h}.{p}'.encode(), hashlib.sha256).digest()
        ).rstrip(b'=').decode()
        if not hmac.compare_digest(sig, s):
            return ''
        payload = json.loads(base64.urlsafe_b64decode(p + '=='))
        if payload.get('exp', 0) < time.time():
            return ''
        return ','.join(payload.get('apps', []))
    except Exception:
        return ''

for line in sys.stdin:
    token = line.strip()
    if not token:
        print('', flush=True)
    else:
        print(check_token(token), flush=True)
