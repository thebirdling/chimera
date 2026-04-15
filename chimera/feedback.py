"""
chimera.feedback — Analyst verdict store for human-in-the-loop learning.

When an analyst reviews an alert and determines it is a false positive,
Chimera should learn from that verdict to avoid alerting on the same pattern
in the future. This module provides the storage and query interface for
analyst verdicts.

Security (v0.4.1)
-----------------
Optional **AES-256-GCM encryption** with **HMAC chain integrity**:
    store = FeedbackStore(
        "chimera_feedback.enc",
        encrypt=True,
        key_path="/var/chimera/secrets/feedback.key",
    )

When encrypted:
- Each record is individually encrypted (unique 12-byte nonce per record)
- An HMAC chain links every record to all previous ones
- Deleting any record breaks the chain — detectable on next read
- The key file is created with mode 0o600 on first run

Design
------
Verdicts are stored as append-only NDJSON (plaintext) or encrypted NDJSON.
The FeedbackStore is consulted by BootstrapProtocol.refit() to apply
learning from confirmed false positives.

Usage
-----
    store = FeedbackStore("chimera_feedback.ndjson")
    store.record("evt-abc123", verdict="fp", context="Known cron job login")
    print(store.fp_rate_for_user("alice"))
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

logger = logging.getLogger(__name__)

Verdict = Literal["fp", "tp", "unsure"]


class FeedbackStore:
    """Append-only persistent store for analyst alert verdicts.

    Parameters
    ----------
    path:
        Path to the NDJSON (or encrypted) feedback log file.
    encrypt:
        If True, use AES-256-GCM encryption with HMAC chain integrity.
        Requires ``key_path``.
    key_path:
        Path to the AES-256 key file. If it doesn't exist it is generated
        automatically with mode 0o600. Only used when ``encrypt=True``.
    """

    def __init__(
        self,
        path: str | Path,
        encrypt: bool = False,
        key_path: Optional[str | Path] = None,
        min_quorum: int = 1,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._encrypt = encrypt
        self._writer = None
        self._records: list[dict] = []
        self._min_quorum = min_quorum

        # In-memory index for quorum tracking: event_id -> {verdict: [analyst_ids]}
        self._quorum_index: dict[str, dict[str, set[str]]] = {}

        if encrypt:
            if key_path is None:
                raise ValueError(
                    "encrypt=True requires a key_path. "
                    "Generate one with: chimera crypto generate-key <path>"
                )
            from chimera.crypto import load_key, generate_key, EncryptedNDJSONWriter
            key_path = Path(key_path)
            if not key_path.exists():
                generate_key(key_path)
                logger.info("[feedback] Generated new encryption key → %s", key_path)
            self._key = load_key(key_path)
            self._writer = EncryptedNDJSONWriter(self.path, self._key)
            self._load_encrypted()
        else:
            self._load_existing()
        self._rebuild_index()

    def _rebuild_index(self) -> None:
        """Rebuild the quorum index from loaded records."""
        self._quorum_index.clear()
        for r in self._records:
            eid = r.get("event_id")
            v = r.get("verdict")
            aid = r.get("analyst_id", "unknown")
            if eid and v:
                if eid not in self._quorum_index:
                    self._quorum_index[eid] = {}
                if v not in self._quorum_index[eid]:
                    self._quorum_index[eid][v] = set()
                self._quorum_index[eid][v].add(aid)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def record(
        self,
        event_id: str,
        verdict: Verdict,
        user: str = "",
        score: float = 0.0,
        signals_fired: Optional[list[str]] = None,
        analyst_id: str = "anon",
        context: str = "",
    ) -> bool:
        """Record an analyst verdict for an alert.

        Returns True if this verdict completed a quorum for the event.
        """
        # C3: Quorum tracking
        if event_id not in self._quorum_index:
            self._quorum_index[event_id] = {}
        if verdict not in self._quorum_index[event_id]:
            self._quorum_index[event_id][verdict] = set()

        if analyst_id in self._quorum_index[event_id][verdict]:
            logger.debug("[feedback] Duplicate verdict from analyst %s ignored", analyst_id)
            return False

        record = {
            "event_id": event_id,
            "verdict": verdict,
            "user": user,
            "score": score,
            "signals_fired": signals_fired or [],
            "analyst_id": analyst_id,
            "context": context,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if self._encrypt and self._writer is not None:
            self._writer.write(record)
        else:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")

        self._records.append(record)
        self._quorum_index[event_id][verdict].add(analyst_id)

        completed = len(self._quorum_index[event_id][verdict]) >= self._min_quorum
        if completed:
            logger.info(
                "[feedback] QUORUM REACHED for event %s (verdict=%s, score=%.3f)",
                event_id, verdict, score
            )
        return completed

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def _is_confirmed(self, event_id: str, verdict: Verdict) -> bool:
        """True if the event has enough agreed verdicts."""
        if event_id not in self._quorum_index:
            return False
        return len(self._quorum_index[event_id].get(verdict, [])) >= self._min_quorum

    def fp_rate_for_user(self, user: str) -> float:
        """Fraction of alerts for ``user`` with confirmed FP quorum."""
        user_eids = {r["event_id"] for r in self._records if r.get("user") == user}
        if not user_eids:
            return 0.0
        fp_confirmed = sum(1 for eid in user_eids if self._is_confirmed(eid, "fp"))
        return fp_confirmed / len(user_eids)

    def confirmed_fps_since(self, cutoff: datetime) -> list[dict]:
        """All records where FP quorum was reached after cutoff."""
        # Note: returns one representative record per quorum
        seen_eids = set()
        confirmed = []
        for r in reversed(self._records):
            eid = r["event_id"]
            if eid in seen_eids:
                continue
            if r["verdict"] == "fp" and self._is_confirmed(eid, "fp"):
                ts = datetime.fromisoformat(r["timestamp"])
                if ts >= cutoff:
                    confirmed.append(r)
                    seen_eids.add(eid)
        return confirmed

    def detect_analyst_poisoning(self) -> list[str]:
        """C3: Detect analysts whose labeling deviates significantly from the quorum.

        Flags analysts who frequently disagree with the consensus or exclusively
        label high-score events as 'fp' (possible poisoning attempt).
        """
        poisoned = []
        analysts = {r.get("analyst_id", "anon") for r in self._records}
        for aid in analysts:
            if aid == "anon": continue
            analyst_work = [r for r in self._records if r.get("analyst_id") == aid]
            if len(analyst_work) < 5: continue

            # Count disagreements with final quorum
            disagreements = 0
            for r in analyst_work:
                eid = r["event_id"]
                actual = r["verdict"]
                # If a quorum was reached for a DIFFERENT verdict
                for other_v in ["fp", "tp", "unsure"]:
                    if other_v != actual and self._is_confirmed(eid, other_v):
                        disagreements += 1
                        break

            disagree_rate = disagreements / len(analyst_work)
            if disagree_rate > 0.40:  # 40% disagreement
                logger.warning(
                    "[feedback] ALERT: Analyst %s has high disagreement rate (%.1f%%). "
                    "Potential poisoning or incompetence suspected.",
                    aid, disagree_rate * 100
                )
                poisoned.append(aid)
        return poisoned

    def confirmed_tps_since(self, cutoff: datetime) -> list[dict]:
        """All confirmed TP records after a given datetime."""
        return [
            r for r in self._records
            if r["verdict"] == "tp"
            and datetime.fromisoformat(r["timestamp"]) >= cutoff
        ]

    def all_records(self) -> list[dict]:
        """Return all records (in-memory copy)."""
        return list(self._records)

    def summary(self) -> dict:
        """High-level summary of all verdicts."""
        total = len(self._records)
        fps = sum(1 for r in self._records if r["verdict"] == "fp")
        tps = sum(1 for r in self._records if r["verdict"] == "tp")
        unsure = total - fps - tps
        return {
            "total": total,
            "false_positives": fps,
            "true_positives": tps,
            "unsure": unsure,
            "fp_rate": fps / total if total > 0 else 0.0,
        }

    def users_with_high_fp_rate(self, threshold: float = 0.30) -> list[str]:
        """Return users whose FP rate exceeds ``threshold``.

        Used by BootstrapProtocol.refit() to relax per-user thresholds.
        """
        users = {r.get("user", "") for r in self._records if r.get("user")}
        return [u for u in users if u and self.fp_rate_for_user(u) >= threshold]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _load_existing(self) -> None:
        """Load existing plaintext records from disk into memory."""
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        self._records.append(json.loads(line))
                    except json.JSONDecodeError:
                        logger.warning("[feedback] Skipping malformed line: %r", line)
        logger.debug("[feedback] Loaded %d records from %s", len(self._records), self.path)

    def _load_encrypted(self) -> None:
        """Load and verify existing encrypted records."""
        if not self.path.exists() or self.path.stat().st_size == 0:
            return
        from chimera.crypto import EncryptedNDJSONReader
        reader = EncryptedNDJSONReader(self.path, self._key)
        try:
            self._records = reader.read_all(verify_chain=True)
            logger.info(
                "[feedback] Loaded %d encrypted records (chain verified) from %s",
                len(self._records), self.path,
            )
        except ValueError as e:
            logger.critical(
                "[feedback] CHAIN INTEGRITY FAILURE: %s — feedback log may have "
                "been tampered with. Records loaded without chain verification.",
                e,
            )
            self._records = reader.read_all(verify_chain=False)

    @property
    def is_encrypted(self) -> bool:
        """True if this store writes encrypted records."""
        return self._encrypt
