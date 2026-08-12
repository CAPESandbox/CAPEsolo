"""Download a malware sample by hash from VirusTotal or MalwareBazaar.

The API keys are stored ENCRYPTED at rest (env `<VAR>_ENC` or cfg.ini `api_key_enc`) and
decrypted with a password the analyst supplies at runtime. The plaintext key never lives on
disk in the guest. In the GUI this module runs as a broker subprocess (`--serve`) that holds
the password so the key is never in the GUI's memory; the broker is killed before detonation.

Setup (producing the encrypted blob) is done OFF the VM with tools/encrypt_api_key.py, which
inlines the same PBKDF2 + Fernet scheme documented here. Keep the two in sync.
"""

import base64
import configparser
import json
import logging
import os
import sys
import threading
import zipfile
from contextlib import suppress
from pathlib import Path

import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from CAPEsolo.capelib.config_paths import config_paths

log = logging.getLogger(__name__)

MB_API_URL = "https://mb-api.abuse.ch/api/v1/"
VT_DOWNLOAD_URL = "https://www.virustotal.com/api/v3/files/{sample_hash}/download"

# Provider table, in preference order (VirusTotal first). Each has its cfg.ini section, the
# env var holding the encrypted blob, and whether it can serve non-SHA256 hashes.
PROVIDERS = {
    "VirusTotal": {"section": "virustotal", "env": "CAPESOLO_VT_APIKEY_ENC", "sha256_only": False},
    "MalwareBazaar": {"section": "malwarebazaar", "env": "CAPESOLO_MB_APIKEY_ENC", "sha256_only": True},
}

# --- Crypto scheme (MUST match tools/encrypt_api_key.py) ---------------------------------
SALT_LEN = 16
KDF_ITERATIONS = 600_000

_HEX_DIGITS = set("0123456789abcdef")


class DownloadError(Exception):
    """A sample download failed for a reason worth showing the user."""


def _derive_fernet_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def decrypt_key(blob, password):
    """Decrypt a `urlsafe_b64(salt || fernet_token)` blob. Raise DownloadError on any failure."""
    try:
        raw = base64.urlsafe_b64decode(blob.encode("ascii"))
        salt, token = raw[:SALT_LEN], raw[SALT_LEN:]
        return Fernet(_derive_fernet_key(password, salt)).decrypt(token).decode("utf-8")
    except Exception as e:
        raise DownloadError("wrong password or corrupt key") from e


def _read_blob(section, env_var):
    blob = os.environ.get(env_var, "").strip()
    if blob:
        return blob
    config = configparser.ConfigParser()
    with suppress(configparser.Error):
        config.read(config_paths())
    return config.get(section, "api_key_enc", fallback="").strip()


def configured_sources():
    """Providers that have an encrypted key present. No password needed (blob presence only)."""
    return [name for name, p in PROVIDERS.items() if _read_blob(p["section"], p["env"])]


def download_enabled():
    """Whether the Start-panel download feature is turned on ([download] enabled, default False)."""
    config = configparser.ConfigParser()
    with suppress(configparser.Error):
        config.read(config_paths())
    return config.getboolean("download", "enabled", fallback=False)


def desktop_dir():
    """The user's Desktop via the Windows known-folder API (handles redirection/localization),
    falling back to ~/Desktop. Shared by the download-dir default and the Zip Results feature."""
    try:
        import ctypes
        from ctypes import windll, wintypes

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8),
            ]

        # FOLDERID_Desktop {B4BFCC3A-DB2C-424C-B029-7FE99A87C641}
        folder_id = GUID(
            0xB4BFCC3A, 0xDB2C, 0x424C,
            (ctypes.c_ubyte * 8)(0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41),
        )
        path_ptr = ctypes.c_wchar_p()
        if windll.shell32.SHGetKnownFolderPath(ctypes.byref(folder_id), 0, None, ctypes.byref(path_ptr)) == 0:
            path = path_ptr.value
            windll.ole32.CoTaskMemFree(path_ptr)
            if path:
                return path
    except Exception:
        pass
    return os.path.join(os.path.expanduser("~"), "Desktop")


def download_dir():
    """Where downloaded samples are saved: [download] directory, default the user's Desktop."""
    config = configparser.ConfigParser()
    with suppress(configparser.Error):
        config.read(config_paths())
    configured = config.get("download", "directory", fallback="").strip()
    return configured or desktop_dir()


def _resolve_key(name, password, direct_keys):
    """Plaintext key for *name*: a directly-entered key wins; otherwise decrypt the stored blob."""
    direct = (direct_keys or {}).get(name)
    if direct:
        return direct
    p = PROVIDERS[name]
    blob = _read_blob(p["section"], p["env"])
    if not blob:
        raise DownloadError(f"no {name} key")
    if not password:
        raise DownloadError(f"{name} key is stored but no password was entered")
    return decrypt_key(blob, password)


def _available_sources(direct_keys):
    """Providers usable now: a directly-entered key OR a stored encrypted blob."""
    return [
        name
        for name, p in PROVIDERS.items()
        if (direct_keys or {}).get(name) or _read_blob(p["section"], p["env"])
    ]


def _normalize_hash(sample_hash):
    normalized = sample_hash.strip().lower()
    if len(normalized) not in (32, 40, 64) or any(c not in _HEX_DIGITS for c in normalized):
        raise DownloadError("Enter a valid MD5 (32), SHA1 (40) or SHA256 (64) hex hash.")
    return normalized


def _candidates(sample_hash, configured):
    """Ordered providers to try: VirusTotal first, filtered to configured + hash-capable."""
    is_sha256 = len(sample_hash) == 64
    order = []
    for name, p in PROVIDERS.items():
        if name in configured and not (p["sha256_only"] and not is_sha256):
            order.append(name)
    return order


def download_sample(sample_hash, dest_dir, password, direct_keys=None):
    """Download *sample_hash* into *dest_dir*, auto-selecting the source. Return the saved Path.

    Each provider's key is a directly-entered key if given, else the stored blob decrypted with
    *password*. Tries each capable, available provider in preference order (VirusTotal, then
    MalwareBazaar), falling back on failure; raises an aggregated DownloadError if all fail.
    """
    normalized = _normalize_hash(sample_hash)
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    available = _available_sources(direct_keys)
    if not available:
        raise DownloadError(
            "No API key entered or configured. Enter a key at startup, or add api_key_enc to cfg.ini."
        )
    candidates = _candidates(normalized, available)
    if not candidates:
        raise DownloadError(
            "MD5/SHA1 hashes require VirusTotal (MalwareBazaar needs a SHA256), which is not available."
        )

    errors = []
    for name in candidates:
        try:
            api_key = _resolve_key(name, password, direct_keys)
            if name == "VirusTotal":
                return _download_virustotal(normalized, dest_dir, api_key)
            return _download_malwarebazaar(normalized, dest_dir, api_key)
        except DownloadError as e:
            errors.append(f"{name}: {e}")
    raise DownloadError("; ".join(errors))


def _download_virustotal(sample_hash, dest_dir, api_key):
    resp = requests.get(
        VT_DOWNLOAD_URL.format(sample_hash=sample_hash),
        headers={"x-apikey": api_key},
        timeout=120,
    )
    if resp.status_code == 404:
        raise DownloadError("not found (404)")
    if resp.status_code == 401:
        raise DownloadError("rejected API key (401)")
    if resp.status_code == 403:
        raise DownloadError("403 no download privilege (needs a VT Enterprise/Intelligence key)")
    resp.raise_for_status()
    dest = dest_dir / sample_hash
    dest.write_bytes(resp.content)
    return dest


def _download_malwarebazaar(sample_hash, dest_dir, api_key):
    resp = requests.post(
        MB_API_URL,
        data={"query": "get_file", "sha256_hash": sample_hash},
        headers={"Auth-Key": api_key},
        timeout=60,
    )
    resp.raise_for_status()
    # On any error MalwareBazaar returns JSON (query_status), not a zip.
    if resp.content[:2] != b"PK":
        status = ""
        with suppress(ValueError):
            status = resp.json().get("query_status", "")
        raise DownloadError(status or "file not found")

    zip_path = dest_dir / f"{sample_hash}.zip"
    zip_path.write_bytes(resp.content)
    try:
        with zipfile.ZipFile(zip_path) as archive:
            members = [name for name in archive.namelist() if not name.endswith("/")]
            if not members:
                raise DownloadError("archive was empty")
            # MalwareBazaar zips are legacy ZipCrypto with the password "infected".
            archive.extractall(path=dest_dir, pwd=b"infected")
    except DownloadError:
        raise
    except Exception as e:
        raise DownloadError(f"could not extract archive ({e}); may be an unsupported AES zip")
    finally:
        with suppress(OSError):
            zip_path.unlink()

    extracted = dest_dir / members[0]
    if not extracted.exists():
        raise DownloadError("sample was not extracted")
    return extracted


def _serve():
    """Broker mode: read credentials from the first stdin line as JSON
    (`{"password":..., "keys":{provider:key}}`), then service commands, one JSON per line.

    A download (`{"hash","dest"}`) runs in a worker thread so a `{"action":"cancel"}` command
    can abandon a stuck or slow download and reply immediately - the broker and its held
    password stay alive. Exactly one reply is sent per download (either its result or
    "cancelled"), coordinated under write_lock."""
    try:
        creds = json.loads(sys.stdin.readline() or "{}")
    except Exception:
        creds = {}
    password = creds.get("password") or ""
    direct_keys = creds.get("keys") or {}

    write_lock = threading.Lock()

    def send(obj):
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    def worker(cmd, state):
        try:
            path = download_sample(cmd["hash"], cmd["dest"], password, direct_keys)
            result = {"ok": True, "path": str(path)}
        except Exception as e:
            result = {"ok": False, "error": str(e)}
        with write_lock:
            if not state["cancelled"]:
                state["done"] = True
                send(result)

    state = {"cancelled": True, "done": True}  # no active download initially
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            cmd = json.loads(line)
        except Exception:
            continue
        if cmd.get("action") == "cancel":
            with write_lock:
                if not state["done"] and not state["cancelled"]:
                    state["cancelled"] = True
                    send({"ok": False, "error": "cancelled"})
            continue
        state = {"cancelled": False, "done": False}
        threading.Thread(target=worker, args=(cmd, state), daemon=True).start()


if __name__ == "__main__":
    if "--serve" in sys.argv:
        _serve()
