"""Bounded readiness probe for the task-internal local telemetry stack."""

from __future__ import annotations

import json
import time
from urllib.error import URLError
from urllib.request import urlopen

_TARGETS = (
    ("collector", "http://collector:13133/"),
    ("prometheus", "http://prometheus:9090/-/ready"),
    ("jaeger", "http://jaeger:16686/"),
    ("grafana", "http://grafana:3000/api/health"),
)


def main() -> None:
    deadline = time.monotonic() + 90
    pending = dict(_TARGETS)
    while pending and time.monotonic() < deadline:
        for name, url in tuple(pending.items()):
            try:
                with urlopen(url, timeout=2) as response:  # noqa: S310 - fixed internal URLs
                    if 200 <= response.status < 300:
                        del pending[name]
            except (OSError, URLError):
                pass
        if pending:
            time.sleep(1)
    if pending:
        raise SystemExit(
            json.dumps(
                {
                    "event": "local_telemetry_readiness",
                    "pending": sorted(pending),
                    "status": "failed",
                    "synthetic": True,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    print(
        json.dumps(
            {
                "event": "local_telemetry_readiness",
                "status": "ready",
                "synthetic": True,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
