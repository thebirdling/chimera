"""
chimera.crypto — Encryption and authenticated log primitives.

Provides:
    - AES-256-GCM symmetric encryption (one unique nonce per record)
    - HMAC-SHA256 chained log integrity (deletion of any record detectable)
    - Key generation and secure key file management

Design goals
------------
- **No external crypto libraries required** beyond the Python stdlib
  ``cryptography`` package (already a common dependency in defense Python
  environments). Falls back to ``pycryptodome`` if available.
- **Offline-first**: all operations are fully local, no cloud KMS.
- **Audit-friendly format**: each encrypted log line is self-contained
  (nonce + ciphertext + auth tag) so individual lines can be decrypted
  and verified independently for forensic analysis.

Wire format (per log line, base64url-encoded, pipe-separated)
--------------------------------------------------------------
    <nonce_b64>|<ciphertext_b64>|<tag_b64>|<chain_hmac_b64>

Where:
    nonce         12 random bytes (GCM standard nonce)
    ciphertext    AES-256-GCM encryption of UTF-8 JSON
    tag           16-byte GCM authentication tag
    chain_hmac    HMAC-SHA256(prev_chain_hmac || ciphertext || tag)

The chain_hmac binds each record to all previous records. Deleting or
reordering any record invalidates all subsequent chain_hmac values.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger(__name__)

# AES-256 key length
_KEY_LEN = 32
# GCM nonce length (96-bit recommended by NIST SP 800-38D)
_NONCE_LEN = 12
# Initial chain state (known constant — no secret needed for chain head)
_CHAIN_INIT = b"chimera_chain_v1"


class SecureBuffer:
    """B1: Provides in-memory protection for sensitive data (keys).

    Attempts to lock the buffer in physical RAM (using mlock if available)
    to prevent it from being swapped to disk. Wipes bytes with zeros
    upon disposal to reduce the window for memory scraping attacks.
    """

    def __init__(self, data: bytes) -> None:
        self._data = bytearray(data)
        self._locked = False
        try:
            # Unix-like only
            import ctypes
            libc = ctypes.CDLL(None if os.name == "posix" else "msvcrt")
            if hasattr(libc, "mlock"):
                # Lock only if root or RLIMIT_MEMLOCK permits
                if libc.mlock(ctypes.byref((ctypes.c_char * len(self._data)).from_buffer(self._data)), len(self._data)) == 0:
                    self._locked = True
        except (ImportError, AttributeError, OSError):
            pass

    def get(self) -> bytes:
        return bytes(self._data)

    def wipe(self) -> None:
        """Overwrite memory with zeros."""
        for i in range(len(self._data)):
            self._data[i] = 0
        if self._locked:
            try:
                import ctypes
                libc = ctypes.CDLL(None if os.name == "posix" else "msvcrt")
                if hasattr(libc, "munlock"):
                    libc.munlock(ctypes.byref((ctypes.c_char * len(self._data)).from_buffer(self._data)), len(self._data))
            except (ImportError, AttributeError, OSError):
                pass
        self._locked = False

    def __enter__(self) -> "SecureBuffer":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.wipe()


class GenesisBlock:
    """B2: Unique header record for a log file to prevent chain replay attacks."""

    def __init__(self, log_id: Optional[str] = None) -> None:
        import uuid
        from datetime import datetime, timezone
        self.log_id = log_id or str(uuid.uuid4())
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.version = "0.4.2"

    def to_dict(self) -> dict:
        return {
            "type": "CHIMERA_GENESIS",
            "log_id": self.log_id,
            "timestamp": self.timestamp,
            "version": self.version,
        }

    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict()).encode("utf-8")



def generate_key(path: str | Path) -> bytes:
    """Generate a 256-bit AES key and write it to ``path``.

    The file is created with mode 0o600 (owner read/write only).
    If the file already exists it is NOT overwritten — call
    ``path.unlink()`` first if rotation is required.

    Parameters
    ----------
    path:
        Destination for the key file.

    Returns
    -------
    bytes
        The generated key (32 bytes).
    """
    path = Path(path)
    if path.exists():
        raise FileExistsError(
            f"Key file already exists: {path}. "
            "Delete it manually to rotate the key."
        )
    key = secrets.token_bytes(_KEY_LEN)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write with restrictive permissions
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        # Prevent newline translation on Windows when writing raw key bytes.
        flags |= os.O_BINARY
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    logger.info("[crypto] Generated AES-256 key → %s", path)
    return key


def load_key(path: str | Path) -> bytes:
    """Load a key from disk and validate its length.

    Parameters
    ----------
    path:
        Path to the key file produced by :func:`generate_key`.

    Raises
    ------
    FileNotFoundError:
        If the key file doesn't exist.
    ValueError:
        If the key is not exactly 32 bytes.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Key file not found: {path}")
    key = path.read_bytes()
    if len(key) != _KEY_LEN:
        raise ValueError(
            f"Invalid key length {len(key)}: expected {_KEY_LEN} bytes."
        )
    return key


def _get_aes_gcm():
    """Return (Cipher, modes) from the best available AES-GCM implementation."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM, None
    except ImportError:
        pass
    try:
        from Crypto.Cipher import AES as _AES
        return None, _AES
    except ImportError:
        pass
    raise ImportError(
        "AES-GCM requires 'cryptography' or 'pycryptodome'. "
        "Install with: pip install cryptography"
    )


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM.

    Parameters
    ----------
    key:
        32-byte AES key.
    plaintext:
        Bytes to encrypt.
    aad:
        Additional authenticated data (integrity-protected but not encrypted).

    Returns
    -------
    (nonce, ciphertext, tag)
        All as raw bytes. nonce is 12 bytes, tag is 16 bytes.
    """
    nonce = secrets.token_bytes(_NONCE_LEN)
    AESGCM, pycrypto_aes = _get_aes_gcm()

    if AESGCM is not None:
        aesgcm = AESGCM(key)
        # cryptography library concatenates tag to ciphertext
        ct_with_tag = aesgcm.encrypt(nonce, plaintext, aad if aad else None)
        ciphertext = ct_with_tag[:-16]
        tag = ct_with_tag[-16:]
    else:
        cipher = pycrypto_aes.new(key, pycrypto_aes.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return nonce, ciphertext, tag


def aes_gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes = b"",
) -> bytes:
    """Decrypt and verify AES-256-GCM ciphertext.

    Raises
    ------
    ValueError:
        If authentication fails (tampered ciphertext or tag).
    """
    AESGCM, pycrypto_aes = _get_aes_gcm()

    try:
        if AESGCM is not None:
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ciphertext + tag, aad if aad else None)
        else:
            cipher = pycrypto_aes.new(key, pycrypto_aes.MODE_GCM, nonce=nonce)
            if aad:
                cipher.update(aad)
            plaintext = cipher.decrypt(ciphertext)
            cipher.verify(tag)
            return plaintext
    except Exception as e:
        raise ValueError(f"AES-GCM decryption failed (authentication error): {e}") from e


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("ascii"))


# ------------------------------------------------------------------
# HMAC chain
# ------------------------------------------------------------------

class HMACChain:
    """Append-only HMAC chain for tamper-evident log sequences.

    Each record's chain value depends on all previous records.
    Deleting, inserting, or reordering any record invalidates all
    subsequent chain values.

    Parameters
    ----------
    key:
        HMAC-SHA256 key (32 bytes recommended, can be same as encryption key
        or a separate key for separation of duties).
    """

    def __init__(self, key: bytes, genesis: Optional[GenesisBlock] = None) -> None:
        self._key = key
        # B2: Initialize with constant + genesis block if provided
        self._state: bytes = _CHAIN_INIT
        if genesis:
            h = hmac.new(self._key, self._state + genesis.to_bytes(), hashlib.sha256)
            self._state = h.digest()

    def update(self, payload: bytes) -> str:
        """Advance the chain with a new payload. Returns the new chain HMAC (hex)."""
        h = hmac.new(self._key, self._state + payload, hashlib.sha256)
        self._state = h.digest()
        return h.hexdigest()

    def verify_sequence(self, records: list[dict]) -> tuple[bool, int]:
        """Verify a sequence of records loaded from disk.

        Parameters
        ----------
        records:
            List of dicts, each with ``"_chain"`` and ``"_payload_hash"`` fields
            as produced by :class:`EncryptedNDJSONWriter`.

        Returns
        -------
        (valid, first_bad_index)
            ``valid=True`` if the chain is intact throughout. On failure,
            ``first_bad_index`` is the 0-based index of the first broken link.
        """
        state = _CHAIN_INIT
        for i, rec in enumerate(records):
            payload_bytes = rec.get("_payload_hash", "").encode("utf-8")
            expected_chain = rec.get("_chain", "")
            h = hmac.new(self._key, state + payload_bytes, hashlib.sha256)
            computed = h.hexdigest()
            if not hmac.compare_digest(computed, expected_chain):
                return False, i
            state = h.digest()
        return True, -1

    @property
    def current_state_hex(self) -> str:
        return self._state.hex()


# ------------------------------------------------------------------
# Encrypted NDJSON writer / reader
# ------------------------------------------------------------------

class EncryptedNDJSONWriter:
    """Appends AES-256-GCM encrypted + HMAC-chained records to a file.

    Each line in the output file is:
        <nonce_b64>|<ciphertext_b64>|<tag_b64>|<chain_hmac_hex>

    Parameters
    ----------
    path:
        Output file path.
    key:
        32-byte AES-256 key (also used as HMAC key).
    """

    def __init__(self, path: str | Path, key: bytes) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._key = key
        self._chain = HMACChain(key)
        
        # If file is new, write a GenesisBlock
        if not self.path.exists() or self.path.stat().st_size == 0:
            genesis = GenesisBlock()
            self._chain = HMACChain(key, genesis=genesis)
            # Genesis record is written in plaintext header format
            header = f"CHIMERA_GENESIS|{_b64(genesis.to_bytes())}|{self._chain.current_state_hex}\n"
            with open(self.path, "w", encoding="ascii") as f:
                f.write(header)
        else:
            # Replay to catch up chain state
            self._replay_chain()

    def write(self, record: dict) -> None:
        """Encrypt and append one record."""
        plaintext = json.dumps(record, default=str).encode("utf-8")
        nonce, ciphertext, tag = aes_gcm_encrypt(self._key, plaintext)
        # Chain advances over ciphertext + tag (not plaintext — forward secrecy)
        payload_for_chain = ciphertext + tag
        chain_hmac = self._chain.update(payload_for_chain)

        line = f"{_b64(nonce)}|{_b64(ciphertext)}|{_b64(tag)}|{chain_hmac}\n"
        with open(self.path, "a", encoding="ascii") as f:
            f.write(line)

    def _replay_chain(self) -> None:
        """Re-derive chain state from all existing records on disk."""
        if not self.path.exists():
            return
        with open(self.path, "r", encoding="ascii") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split("|")
                if parts[0] == "CHIMERA_GENESIS":
                    # Initialize chain from header
                    try:
                        genesis_bytes = _unb64(parts[1])
                        genesis_data = json.loads(genesis_bytes.decode("utf-8"))
                        genesis = GenesisBlock(log_id=genesis_data.get("log_id"))
                        genesis.timestamp = genesis_data.get("timestamp")
                        self._chain = HMACChain(self._key, genesis=genesis)
                    except Exception:
                        continue
                    continue

                if len(parts) != 4:
                    continue
                try:
                    ciphertext = _unb64(parts[1])
                    tag = _unb64(parts[2])
                    payload_for_chain = ciphertext + tag
                    self._chain.update(payload_for_chain)
                except Exception:
                    continue


class EncryptedNDJSONReader:
    """Reads and verifies an encrypted NDJSON log file.

    Parameters
    ----------
    path:
        Log file produced by :class:`EncryptedNDJSONWriter`.
    key:
        32-byte AES-256 key used when writing.
    """

    def __init__(self, path: str | Path, key: bytes) -> None:
        self.path = Path(path)
        self._key = key

    def read_all(self, verify_chain: bool = True) -> list[dict]:
        """Decrypt all records. Optionally verifies the HMAC chain."""
        records = []
        chain = HMACChain(self._key)
        found_genesis = False

        if not self.path.exists():
            return []

        with open(self.path, "r", encoding="ascii") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                parts = line.split("|")

                if parts[0] == "CHIMERA_GENESIS":
                    try:
                        genesis_bytes = _unb64(parts[1])
                        genesis_data = json.loads(genesis_bytes.decode("utf-8"))
                        genesis = GenesisBlock(log_id=genesis_data.get("log_id"))
                        genesis.timestamp = genesis_data.get("timestamp")
                        chain = HMACChain(self._key, genesis=genesis)
                        found_genesis = True
                    except Exception as e:
                        raise ValueError(f"Failed to parse genesis block at line {i}: {e}")
                    continue

                if i == 0 and not found_genesis:
                    raise ValueError("Log file missing required GenesisBlock header")

                if len(parts) != 4:
                    raise ValueError(f"Malformed line {i}: expected 4 pipe-separated fields")

                try:
                    nonce = _unb64(parts[0])
                    ciphertext = _unb64(parts[1])
                    tag = _unb64(parts[2])
                    stored_chain = parts[3]
                except Exception as e:
                    raise ValueError(f"Base64 decode error on line {i}: {e}") from e

                payload_for_chain = ciphertext + tag
                expected_chain = chain.update(payload_for_chain)

                if verify_chain and not hmac.compare_digest(expected_chain, stored_chain):
                    raise ValueError(
                        f"HMAC chain broken at record {i}. "
                        "The log may have been tampered with."
                    )

                plaintext = aes_gcm_decrypt(self._key, nonce, ciphertext, tag)
                records.append(json.loads(plaintext.decode("utf-8")))

        return records

    def __iter__(self) -> Iterator[dict]:
        """Iterate over decrypted records (no chain verification)."""
        yield from self.read_all(verify_chain=False)
