#!/usr/bin/env python3
"""Generate offline synthetic evaluation and latency evidence."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from gluevenir._evidence import generate_evidence_bundle


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_directory")
    parser.add_argument("--samples", type=int, default=200)
    arguments = parser.parse_args(argv)
    paths = generate_evidence_bundle(
        arguments.output_directory, sample_count=arguments.samples
    )
    print(json.dumps({name: str(path) for name, path in sorted(paths.items())}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
