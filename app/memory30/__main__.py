"""CLI: python -m app.memory30 <command>

  synth   --days 30 --identities 200 --seed 42 [--out data/synth] [--ingest]   generate synthetic 30-day data
  ingest  [paths ...]                                                          ingest JSON files or folders
  prune   [--vacuum]                                                           apply 7-day / 30-day retention
  stats                                                                        storage and memory statistics
  report  [--labels data/synth/labels.json]                                    findings vs synthetic labels
  reset   --yes                                                                empty the memory database
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import config, synth
from .engine import MemoryEngine


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.memory30")
    ap.add_argument("--db", default=None, help="SQLite path (default data/memory30.sqlite)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("synth")
    s.add_argument("--days", type=int, default=30)
    s.add_argument("--identities", type=int, default=200)
    s.add_argument("--seed", type=int, default=42)
    s.add_argument("--out", default=str(config.SYNTH_DIR))
    s.add_argument("--ingest", action="store_true")
    i = sub.add_parser("ingest")
    i.add_argument("paths", nargs="*")
    p = sub.add_parser("prune")
    p.add_argument("--vacuum", action="store_true")
    sub.add_parser("stats")
    r = sub.add_parser("report")
    r.add_argument("--labels", default=str(config.SYNTH_DIR / "labels.json"))
    x = sub.add_parser("reset")
    x.add_argument("--yes", action="store_true")
    args = ap.parse_args(argv)

    if args.cmd == "synth":
        info = synth.write(args.out, args.days, args.identities, args.seed)
        _print(info)
        if args.ingest:
            eng = MemoryEngine(args.db)
            _print(eng.ingest_paths([Path(args.out) / "okta", Path(args.out) / "cloudtrail"]))
            labels = json.loads((Path(args.out) / "labels.json").read_text(encoding="utf-8"))
            _print(synth.report(eng, labels))
        return 0
    eng = MemoryEngine(args.db)
    if args.cmd == "ingest":
        _print(eng.ingest_paths(args.paths or None))
    elif args.cmd == "prune":
        _print(eng.prune(vacuum=args.vacuum))
    elif args.cmd == "stats":
        _print(eng.stats())
    elif args.cmd == "report":
        lp = Path(args.labels)
        if not lp.exists():
            print(f"labels file not found: {lp}", file=sys.stderr)
            return 2
        _print(synth.report(eng, json.loads(lp.read_text(encoding="utf-8"))))
    elif args.cmd == "reset":
        if not args.yes:
            print("refusing to reset without --yes", file=sys.stderr)
            return 2
        eng.reset()
        print("memory reset")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
