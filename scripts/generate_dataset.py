"""Genera un dataset sintético reproducible en data/synthetic/.

Uso:
    python scripts/generate_dataset.py --seed 42 --out data/synthetic/dev
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from sentinelops.ingestion.synthetic import ScenarioConfig, generate


def _jsonable(obj: dict[str, Any]) -> dict[str, Any]:
    return {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in obj.items()}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", type=Path, default=Path("data/synthetic/dev"))
    args = parser.parse_args()

    data = generate(ScenarioConfig(seed=args.seed))
    args.out.mkdir(parents=True, exist_ok=True)
    with (args.out / "events.jsonl").open("w", encoding="utf-8") as fh:
        for e in data.events:
            record = {
                "schema_version": "1.0",
                "event_id": e.event_id,
                "service": e.service,
                "kind": e.kind.value,
                "severity": e.severity.name.lower(),
                "occurred_at": e.occurred_at.isoformat(),
                "message": e.message,
                "attributes": dict(e.attributes),
            }
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    (args.out / "deployments.json").write_text(
        json.dumps([_jsonable(asdict(d)) for d in data.deployments], indent=2), encoding="utf-8"
    )
    (args.out / "labels.json").write_text(
        json.dumps([_jsonable(asdict(lb)) for lb in data.labels], indent=2), encoding="utf-8"
    )
    print(f"{len(data.events)} eventos, {len(data.labels)} incidentes etiquetados → {args.out}")


if __name__ == "__main__":
    main()
