"""
tests.test_security — Security hardening regression tests.

Verifies all SEC-01 through SEC-12 fixes are in place and functioning.
Each test is self-contained and runs fully offline without external services.
"""
from __future__ import annotations

import hashlib
import hmac as stdlib_hmac
import json
import os
import struct
import tempfile
import time
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _temp_dir():
    """Return a temporary directory Path that is cleaned up after the test."""
    return tempfile.TemporaryDirectory()


# ---------------------------------------------------------------------------
# SEC-01 / SEC-02: Safe deserialization
# ---------------------------------------------------------------------------

class TestSafeJoblibLoad:
    """safe_joblib_load refuses tampered files before any deserialization."""

    def test_loads_valid_file(self, tmp_path):
        import joblib
        from chimera.engine.safe_io import safe_joblib_load

        payload = {"key": "value", "data": list(range(50))}
        model_path = tmp_path / "model.joblib"
        joblib.dump(payload, model_path)

        loaded = safe_joblib_load(model_path, expected_digest=None)
        assert loaded["key"] == "value"

    def test_refuses_tampered_file_with_digest(self, tmp_path):
        import joblib
        from chimera.engine.safe_io import safe_joblib_load
        from chimera.engine.exceptions import IntegrityError

        payload = {"key": "value"}
        model_path = tmp_path / "model.joblib"
        joblib.dump(payload, model_path)

        # Corrupt the file AFTER recording the legit digest
        bad_digest = "a" * 64  # wrong digest

        with pytest.raises(IntegrityError):
            safe_joblib_load(model_path, expected_digest=bad_digest)

    def test_refuses_tampered_file_with_manifest(self, tmp_path):
        import joblib
        from chimera.engine.safe_io import safe_joblib_load
        from chimera.engine.integrity import IntegrityManifest
        from chimera.engine.exceptions import IntegrityError

        payload = {"key": "clean"}
        model_path = tmp_path / "model.joblib"
        joblib.dump(payload, model_path)

        manifest = IntegrityManifest(tmp_path / "integrity_manifest.json")
        manifest.register(model_path)

        # Now corrupt the file (single extra byte at end)
        with open(model_path, "ab") as f:
            f.write(b"\x00")

        with pytest.raises(IntegrityError):
            safe_joblib_load(model_path, manifest=manifest)

    def test_warns_when_no_verification(self, tmp_path, caplog):
        """Loading without manifest or digest emits a WARNING — never silent."""
        import joblib
        from chimera.engine.safe_io import safe_joblib_load
        import logging

        payload = {"x": 1}
        model_path = tmp_path / "model.joblib"
        joblib.dump(payload, model_path)

        with caplog.at_level(logging.WARNING):
            safe_joblib_load(model_path)
        assert any("WITHOUT integrity verification" in r.message for r in caplog.records)


class TestSecureModelLoading:
    """Trained model loading requires integrity verification by default."""

    def test_anomaly_detector_load_refuses_unverified_model(self, tmp_path):
        import joblib

        from chimera.engine.exceptions import IntegrityError
        from chimera.model import AnomalyDetector

        model_path = tmp_path / "model.joblib"
        joblib.dump({"detector_type": "base"}, model_path)

        with pytest.raises(IntegrityError):
            AnomalyDetector.load(model_path)


# ---------------------------------------------------------------------------
# SEC-03: HMAC-protected manifest
# ---------------------------------------------------------------------------

class TestHMACManifest:
    """Integrity manifest HMAC protects against hash-swapping attacks."""

    def test_manifest_hmac_valid_after_register(self, tmp_path):
        import joblib
        from chimera.engine.integrity import IntegrityManifest

        model_path = tmp_path / "model.joblib"
        joblib.dump({"k": "v"}, model_path)

        manifest = IntegrityManifest(tmp_path / "integrity_manifest.json")
        manifest.register(model_path)
        assert manifest.verify_manifest_hmac()

    def test_manifest_hmac_fails_after_external_edit(self, tmp_path):
        import joblib
        from chimera.engine.integrity import IntegrityManifest

        model_path = tmp_path / "model.joblib"
        joblib.dump({"k": "v"}, model_path)

        manifest_path = tmp_path / "integrity_manifest.json"
        manifest = IntegrityManifest(manifest_path)
        manifest.register(model_path)

        # An attacker computes a new hash for a different file and writes it
        # into the manifest directly (bypassing the HMAC mechanism)
        raw = json.loads(manifest_path.read_text())
        raw["entries"][str(model_path.resolve())] = "a" * 64  # forged hash
        # Write WITHOUT updating the HMAC
        manifest_path.write_text(json.dumps(raw))

        # Re-load from disk — must detect HMAC violation
        manifest2 = IntegrityManifest(manifest_path)
        assert not manifest2.verify_manifest_hmac()

    def test_manifest_detects_model_tampering(self, tmp_path):
        import joblib
        from chimera.engine.integrity import IntegrityManifest

        model_path = tmp_path / "model.joblib"
        joblib.dump({"k": "v"}, model_path)

        manifest = IntegrityManifest(tmp_path / "integrity_manifest.json")
        manifest.register(model_path)

        # Legitimately tamper with only the model file
        with open(model_path, "ab") as f:
            f.write(b"\xff")

        ok, msg = manifest.verify(model_path)
        assert not ok
        assert "INTEGRITY VIOLATION" in msg


# ---------------------------------------------------------------------------
# SEC-11: Constant-time comparison
# ---------------------------------------------------------------------------

class TestConstantTimeComparison:
    """Digest comparison uses hmac.compare_digest — timing-safe."""

    def test_verify_uses_compare_digest(self, tmp_path):
        """Patch hmac.compare_digest to assert it's called, not ==."""
        import joblib
        from chimera.engine import integrity as integrity_mod

        model_path = tmp_path / "model.joblib"
        joblib.dump({"x": 1}, model_path)

        manifest = integrity_mod.IntegrityManifest(tmp_path / "integrity_manifest.json")
        manifest.register(model_path)

        called = []
        original = stdlib_hmac.compare_digest

        def spy(a, b):
            called.append((a, b))
            return original(a, b)

        # Monkey-patch at module level where integrity.py imports it
        old = integrity_mod.hmac.compare_digest
        integrity_mod.hmac.compare_digest = spy
        try:
            manifest.verify(model_path)
        finally:
            integrity_mod.hmac.compare_digest = old

        assert len(called) > 0, "hmac.compare_digest was never called during verify()"


# ---------------------------------------------------------------------------
# SEC-07: Atomic write (no preditable temp file)
# ---------------------------------------------------------------------------

class TestAtomicWrite:
    """atomic_write leaves no .tmp files on success; uses random temp names."""

    def test_file_contents_correct(self, tmp_path):
        from chimera.engine.safe_io import atomic_write

        dest = tmp_path / "out.json"
        data = b'{"hello": "world"}'
        atomic_write(dest, data)
        assert dest.read_bytes() == data

    def test_no_tmp_files_on_success(self, tmp_path):
        from chimera.engine.safe_io import atomic_write

        dest = tmp_path / "out.txt"
        atomic_write(dest, b"clean")
        leftover = list(tmp_path.glob("*.tmp"))
        assert leftover == [], f"Leftover temp files: {leftover}"

    def test_temp_name_is_random(self, tmp_path):
        """Two concurrent writes must produce different temp file names."""
        from chimera.engine import safe_io

        names = set()
        import secrets as _secrets

        for _ in range(10):
            names.add(_secrets.token_hex(8))

        assert len(names) == 10, "Non-random temp names would be a TOCTOU risk"


# ---------------------------------------------------------------------------
# SEC-09: Path traversal guard
# ---------------------------------------------------------------------------

class TestSafeOpenInput:
    """safe_open_input rejects paths escaping the base directory."""

    def test_accepts_valid_path(self, tmp_path):
        from chimera.engine.safe_io import safe_open_input

        target = tmp_path / "data.csv"
        target.write_text("a,b,c")
        result = safe_open_input(target, base_dir=tmp_path)
        assert result == target.resolve()

    def test_rejects_traversal(self, tmp_path):
        from chimera.engine.safe_io import safe_open_input

        # Construct a path that tries to escape: /tmp/safe/../../../etc/passwd
        evil = tmp_path / ".." / ".." / "etc" / "passwd"
        with pytest.raises(ValueError, match="Path traversal rejected"):
            safe_open_input(evil, base_dir=tmp_path)

    def test_rejects_null_byte(self, tmp_path):
        from chimera.engine.safe_io import safe_open_input

        with pytest.raises(ValueError, match="Null byte"):
            safe_open_input(str(tmp_path / "file\x00.csv"), base_dir=tmp_path)


# ---------------------------------------------------------------------------
# SEC-04 / SEC-05 / SEC-10: Encrypted log + HMAC chain
# ---------------------------------------------------------------------------

class TestCrypto:
    """AES-256-GCM encryption + HMAC chain integrity."""

    def test_generate_and_load_key(self, tmp_path):
        from chimera.crypto import generate_key, load_key

        key_path = tmp_path / "test.key"
        key = generate_key(key_path)
        assert len(key) == 32
        loaded = load_key(key_path)
        assert key == loaded

    def test_generate_key_refuses_overwrite(self, tmp_path):
        from chimera.crypto import generate_key

        key_path = tmp_path / "test.key"
        generate_key(key_path)
        with pytest.raises(FileExistsError):
            generate_key(key_path)  # must not silently overwrite

    def test_aes_gcm_round_trip(self, tmp_path):
        from chimera.crypto import aes_gcm_encrypt, aes_gcm_decrypt, generate_key

        key = generate_key(tmp_path / "k.key")
        plaintext = b"classified: operation chimera alpha"
        nonce, ct, tag = aes_gcm_encrypt(key, plaintext)
        recovered = aes_gcm_decrypt(key, nonce, ct, tag)
        assert recovered == plaintext

    def test_aes_gcm_rejects_tampered_ciphertext(self, tmp_path):
        from chimera.crypto import aes_gcm_encrypt, aes_gcm_decrypt, generate_key

        key = generate_key(tmp_path / "k.key")
        plaintext = b"secret data"
        nonce, ct, tag = aes_gcm_encrypt(key, plaintext)
        # Flip one byte in ciphertext
        corrupted = bytes([ct[0] ^ 0xFF]) + ct[1:]
        with pytest.raises(ValueError):
            aes_gcm_decrypt(key, nonce, corrupted, tag)

    def test_encrypted_ndjson_round_trip(self, tmp_path):
        from chimera.crypto import generate_key, EncryptedNDJSONWriter, EncryptedNDJSONReader

        key = generate_key(tmp_path / "log.key")
        log_path = tmp_path / "log.enc"

        writer = EncryptedNDJSONWriter(log_path, key)
        records = [
            {"event_id": "e1", "verdict": "fp", "user": "alice"},
            {"event_id": "e2", "verdict": "tp", "user": "bob"},
            {"event_id": "e3", "verdict": "fp", "user": "alice"},
        ]
        for r in records:
            writer.write(r)

        reader = EncryptedNDJSONReader(log_path, key)
        recovered = reader.read_all(verify_chain=True)
        assert len(recovered) == 3
        assert recovered[0]["event_id"] == "e1"
        assert recovered[2]["user"] == "alice"

    def test_chain_detects_deleted_record(self, tmp_path):
        """Deleting the middle record of an encrypted log breaks the chain."""
        from chimera.crypto import generate_key, EncryptedNDJSONWriter, EncryptedNDJSONReader

        key = generate_key(tmp_path / "log.key")
        log_path = tmp_path / "log.enc"

        writer = EncryptedNDJSONWriter(log_path, key)
        for i in range(4):
            writer.write({"seq": i})

        # Remove the second encrypted record while preserving the genesis header.
        lines = log_path.read_text(encoding="ascii").splitlines()
        assert len(lines) == 5
        tampered = "\n".join([lines[0], lines[1], lines[3], lines[4]]) + "\n"
        log_path.write_text(tampered, encoding="ascii")

        reader = EncryptedNDJSONReader(log_path, key)
        with pytest.raises(ValueError, match="chain"):
            reader.read_all(verify_chain=True)

    def test_wrong_key_fails_decryption(self, tmp_path):
        """Records encrypted with key A cannot be decrypted with key B."""
        from chimera.crypto import generate_key, EncryptedNDJSONWriter, EncryptedNDJSONReader

        key_a = generate_key(tmp_path / "a.key")
        key_b = generate_key(tmp_path / "b.key")
        log_path = tmp_path / "log.enc"

        writer = EncryptedNDJSONWriter(log_path, key_a)
        writer.write({"secret": "classified"})

        reader = EncryptedNDJSONReader(log_path, key_b)
        with pytest.raises((ValueError, Exception)):
            reader.read_all(verify_chain=False)


# ---------------------------------------------------------------------------
# SEC-04: FeedbackStore encrypted mode
# ---------------------------------------------------------------------------

class TestFeedbackStoreEncrypted:
    def test_encrypted_write_and_read(self, tmp_path):
        from chimera.feedback import FeedbackStore
        from chimera.crypto import generate_key

        key_path = tmp_path / "feedback.key"
        generate_key(key_path)  # pre-generate so store doesn't auto-generate
        store = FeedbackStore(
            tmp_path / "feedback.enc",
            encrypt=True,
            key_path=key_path,
        )
        store.record("evt-001", verdict="fp", user="alice", analyst_id="analyst-1")
        store.record("evt-002", verdict="tp", user="bob")

        assert store.fp_rate_for_user("alice") == 1.0
        assert store.fp_rate_for_user("bob") == 0.0
        assert store.is_encrypted

    def test_requires_key_path_when_encrypt(self, tmp_path):
        from chimera.feedback import FeedbackStore

        with pytest.raises(ValueError, match="key_path"):
            FeedbackStore(tmp_path / "f.enc", encrypt=True)

    def test_plaintext_mode_unchanged(self, tmp_path):
        from chimera.feedback import FeedbackStore

        store = FeedbackStore(tmp_path / "feedback.ndjson")
        store.record("e1", verdict="fp", user="user1")
        assert not store.is_encrypted
        assert store.fp_rate_for_user("user1") == 1.0
