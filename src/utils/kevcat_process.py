"""
Standalone KEV index builder.

This script is meant to run in isolation (cron, systemd timer, k8s
CronJob, etc.) — completely decoupled from the API process. It reads whatever CSVs are sitting in INPUT_DIR,
picks the one whose filename carries the most recent timestamp, and
writes the resulting JSON index to OUTPUT_DIR. The API only ever reads
what this script produces (see kev_catalog.py).

Input:
    INPUT_DIR / *.csv
        Filenames must start with a timestamp in "YYYYMMDDTHHMMSS"
        format, e.g.:
            20261015T203327.csv
            20261016T030055_somehash.csv
        The file with the latest timestamp (parsed from the name, not
        from filesystem mtime) is used as the source for this run.
        Files that don't match the pattern are ignored.

Output:
    OUTPUT_DIR / kev_index.json            -> current index
    OUTPUT_DIR / kev_index.previous.json   -> index to diff the current one
                                               against

    There are exactly two ways "previous" gets populated, and the script
    never leaves stray/duplicate files behind:

    - Normal run (a current index already exists in OUTPUT_DIR): that
      existing current index is promoted to "previous" (overwriting
      whatever was already there), then a fresh "current" is built from
      the single newest timestamped CSV in INPUT_DIR.

    - First run (no current index yet in OUTPUT_DIR) with 2+ timestamped
      CSVs sitting in INPUT_DIR: both snapshots are bootstrapped in one
      shot straight from the input directory — newest CSV becomes
      "current", second-newest becomes "previous", anything older than
      that is ignored. With only one CSV available there is nothing to
      build "previous" from, so only "current" is produced (and any
      leftover previous file is removed rather than kept stale).

Input and output directories are two independent variables — the script
may read from one location and deposit the index somewhere else
entirely (e.g. a different volume/bucket mount). Both default to
./input and ./data next to this file, and each can be overridden on its
own via the KEV_INPUT_DIR / KEV_OUTPUT_DIR environment variables. There
is no argument parsing: just point the env vars (or leave the defaults)
and schedule it.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent

# Independent read/write locations: INPUT_DIR is where the raw CSVs land
# (e.g. dropped by a separate downloader job); OUTPUT_DIR is where this
# script deposits the index for the API to read. They can point to
# completely different volumes/paths — set each env var on its own.
INPUT_DIR = Path(os.environ.get("KEV_INPUT_DIR", BASE_DIR / "../../kev_data"))
OUTPUT_DIR = Path(os.environ.get("KEV_OUTPUT_DIR", BASE_DIR / "../../kev_data/index"))

INDEX_FILENAME = "kev_index.json"
PREVIOUS_INDEX_FILENAME = "kev_index.previous.json"

KEY_FIELD = "cveID"

# Matches the leading timestamp in filenames like:
#   20261015T203327.csv
#   20261016T030055_4e256f32a339....csv
TIMESTAMP_PATTERN = re.compile(r"^(\d{8}T\d{6})")
TIMESTAMP_FORMAT = "%Y%m%dT%H%M%S"


def _extract_timestamp(csv_path: Path) -> datetime | None:
    match = TIMESTAMP_PATTERN.match(csv_path.name)
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), TIMESTAMP_FORMAT)
    except ValueError:
        return None


def _sorted_csvs(input_dir: Path) -> list[Path]:
    """All timestamp-named CSVs in input_dir, newest first."""
    if not input_dir.exists():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")

    candidates: list[tuple[datetime, Path]] = []
    skipped: list[str] = []
    for csv_path in input_dir.glob("*.csv"):
        ts = _extract_timestamp(csv_path)
        if ts is None:
            skipped.append(csv_path.name)
            continue
        candidates.append((ts, csv_path))

    if not candidates:
        hint = f" (ignored, no timestamp prefix: {skipped})" if skipped else ""
        raise FileNotFoundError(
            f"No CSV with a 'YYYYMMDDTHHMMSS...' timestamped filename found "
            f"in {input_dir}{hint}"
        )

    # Newest first; filename as a tiebreaker for determinism.
    candidates.sort(key=lambda pair: (pair[0], pair[1].name), reverse=True)
    return [path for _, path in candidates]


def _read_csv_rows(csv_path: Path) -> list[dict[str, Any]]:
    with csv_path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        return [dict(row) for row in reader]


def _build_index_from_csv(csv_path: Path) -> dict[str, Any]:
    entries: dict[str, dict[str, Any]] = {}
    for row in _read_csv_rows(csv_path):
        cve_id = (row.get(KEY_FIELD) or "").strip()
        if not cve_id:
            continue
        entries[cve_id] = row

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": str(csv_path.resolve()),
        "source_timestamp": _extract_timestamp(csv_path).isoformat(),
        "count": len(entries),
        "entries": entries,
    }


def _write_index(index: dict[str, Any], path: Path) -> None:
    with path.open("w", encoding="utf-8") as fh:
        json.dump(index, fh, ensure_ascii=False, indent=2)


def build_index(input_dir: Path, output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    index_path = output_dir / INDEX_FILENAME
    previous_path = output_dir / PREVIOUS_INDEX_FILENAME

    csv_files = _sorted_csvs(input_dir)  # newest first

    if index_path.exists():
        # Normal run: promote the existing current index to "previous".
        # os.replace() overwrites the destination atomically, so a
        # previous run's previous file is swapped out, never duplicated.
        os.replace(index_path, previous_path)
        index = _build_index_from_csv(csv_files[0])
    else:
        # First run (or OUTPUT_DIR was wiped): bootstrap both snapshots
        # straight from INPUT_DIR, if there is enough history for it.
        index = _build_index_from_csv(csv_files[0])
        if len(csv_files) >= 2:
            _write_index(_build_index_from_csv(csv_files[1]), previous_path)
        elif previous_path.exists():
            # Only one CSV available — nothing to build "previous" from,
            # so don't leave a stale one sitting there.
            previous_path.unlink()

    _write_index(index, index_path)
    return index


def main() -> int:
    try:
        index = build_index(INPUT_DIR, OUTPUT_DIR)
    except FileNotFoundError as exc:
        print(f"[kev-index-builder] erro: {exc}", file=sys.stderr)
        return 1

    print(
        f"[kev-index-builder] {index['count']} entradas indexadas de "
        f"{index['source_file']} (timestamp {index['source_timestamp']}) "
        f"-> {OUTPUT_DIR / INDEX_FILENAME}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())