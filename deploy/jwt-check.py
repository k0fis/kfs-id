#!/usr/bin/env python3
"""
jwt-check.py — Apache RewriteMap prg: script
Validates JWT tokens (HMAC-SHA256) and returns comma-separated app list.

Usage in Apache VHost:
    RewriteMap jwtcheck "prg:/opt/id-backend/jwt-check.py"

Reads JWT_SECRET from environment. Stdin: one token per line.
Stdout: comma-separated apps if valid, empty line if invalid.
"""
import sys
import hmac
import hashlib
import base64
import json
import os
import time

SECRET = os.environ.get('JWT_SECRET', '').encode()

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
