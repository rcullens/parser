"""Load ``targets.txt``, classify each valid URL, and persist verified assets."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .classify import classify_asset_severity
from .db import batch_insert_assets, connect
from .parser import ParsedAsset, parse_asset_endpoint

ClassifyFn = Callable[[ParsedAsset], str]


@dataclass(frozen=True)
class IngestResult:
    read: int
    valid: int
    inserted: int
    duplicates: int
    skipped: int


def ingest_asset_endpoints(
    targets_path: str | Path,
    db_path: str | Path,
    *,
    classify: ClassifyFn = classify_asset_severity,
    batch_size: int = 500,
) -> IngestResult:
    """Open a plaintext endpoint list, verify URLs, classify, and batch-insert.

    Invalid lines are skipped. Duplicate canonical URLs are ignored by SQLite
    (``INSERT OR IGNORE`` on the unique ``url`` column).
    """
    path = Path(targets_path)
    parsed: list[ParsedAsset] = []
    seen: set[str] = set()
    read = 0
    skipped = 0

    with path.open(encoding="utf-8") as handle:
        for raw_line in handle:
            read += 1
            asset = parse_asset_endpoint(raw_line)
            if asset is None:
                skipped += 1
                continue
            if asset.url in seen:
                skipped += 1
                continue
            seen.add(asset.url)
            parsed.append(asset)

    classified = ((asset, classify(asset)) for asset in parsed)
    with connect(db_path) as conn:
        inserted = batch_insert_assets(conn, classified, batch_size=batch_size)

    valid = len(parsed)
    return IngestResult(
        read=read,
        valid=valid,
        inserted=inserted,
        duplicates=valid - inserted,
        skipped=skipped,
    )


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Ingest a plaintext list of asset endpoints into SQLite."
    )
    parser.add_argument("targets", help="Path to targets.txt")
    parser.add_argument("database", help="Path to the SQLite database")
    args = parser.parse_args(argv)
    result = ingest_asset_endpoints(args.targets, args.database)
    print(
        f"read={result.read} valid={result.valid} "
        f"inserted={result.inserted} duplicates={result.duplicates} "
        f"skipped={result.skipped}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
