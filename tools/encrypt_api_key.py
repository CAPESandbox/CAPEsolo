#!/usr/bin/env python3
"""Encrypt a VirusTotal / MalwareBazaar API key for CAPEsolo, OUTSIDE the analysis VM.

Run this on a trusted host so the plaintext key never enters the guest. It prints an
encrypted blob you paste into the guest's cfg.ini (`[virustotal]`/`[malwarebazaar]`
`api_key_enc =`) or set as `CAPESOLO_VT_APIKEY_ENC` / `CAPESOLO_MB_APIKEY_ENC`. CAPEsolo
decrypts it with a password you enter at startup.

Encrypt every provider you use with the SAME password, so one startup prompt unlocks both.

Dependency: `pip install cryptography`. This file has NO CAPEsolo imports so it runs on any
host Python. Its scheme MUST match CAPEsolo/utils/download_sample.py (PBKDF2-HMAC-SHA256,
600k iterations, Fernet, blob = urlsafe_b64(salt(16) || fernet_token)).
"""

import base64
import getpass
import os
import sys

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_LEN = 16
KDF_ITERATIONS = 600_000


def _derive_fernet_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_key(plaintext, password):
    salt = os.urandom(SALT_LEN)
    token = Fernet(_derive_fernet_key(password, salt)).encrypt(plaintext.encode("utf-8"))
    return base64.urlsafe_b64encode(salt + token).decode("ascii")


def _prompt_twice(label):
    first = getpass.getpass(f"{label}: ")
    if not first:
        print("Empty value, aborting.", file=sys.stderr)
        sys.exit(1)
    if first != getpass.getpass(f"{label} (confirm): "):
        print(f"{label} entries did not match, aborting.", file=sys.stderr)
        sys.exit(1)
    return first


def main():
    api_key = _prompt_twice("API key")
    password = _prompt_twice("Password")
    print()
    print("Encrypted blob (paste as api_key_enc, or the *_ENC env var):")
    print(encrypt_key(api_key, password))


if __name__ == "__main__":
    main()
