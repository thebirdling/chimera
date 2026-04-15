from __future__ import annotations

import csv
from datetime import datetime, timedelta
from pathlib import Path
import random


def main() -> None:
    rng = random.Random(42)
    out = Path(__file__).resolve().parents[1] / "tmp_large_auth.csv"
    base = datetime(2026, 1, 1, 6, 0, 0)
    users = [f"user_{i:02d}" for i in range(1, 21)]

    rows = []
    for i in range(1200):
        user = users[i % len(users)]
        ts = base + timedelta(minutes=10 * i)
        if i % 37 == 0:
            event_type = "failed_login"
            success = "false"
        else:
            event_type = "login"
            success = "true"

        rows.append(
            {
                "timestamp": ts.isoformat(),
                "user_id": user,
                "event_type": event_type,
                "ip_address": f"10.{i % 7}.{i % 19}.{(i % 200) + 1}",
                "asn": f"645{10 + (i % 6)}",
                "country_code": "NG" if i % 13 else "US",
                "user_agent": f"ua-{i % 4}",
                "device_fingerprint": f"dev-{user}-{i % 3}",
                "session_id": f"s-{user}-{i // 3}",
                "session_duration_seconds": 600 + ((i % 9) * 120),
                "auth_method": "sso" if i % 8 == 0 else "password",
                "mfa_used": "false" if i % 6 == 0 else "true",
                "success": success,
            }
        )

    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(out)


if __name__ == "__main__":
    main()
