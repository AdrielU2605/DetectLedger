"""Command-line interface: `detectledger <command>`."""

import argparse
import sys

from . import datasets
from .db import connect
from .ingest import ingest_file

DEFAULT_DB = "data/events.db"


def cmd_list(args) -> int:
    for ds in datasets.CATALOG.values():
        print(f"{ds.name:<26} {ds.technique:<10} {ds.summary}")
    return 0


def cmd_fetch(args) -> int:
    names = list(datasets.CATALOG) if args.all else args.names
    if not names:
        print("Name one or more datasets, or use --all. See `detectledger list`.", file=sys.stderr)
        return 2
    conn = connect(args.db)
    for name in names:
        if name not in datasets.CATALOG:
            print(f"unknown dataset: {name}", file=sys.stderr)
            return 2
        path = datasets.fetch(name)
        result = ingest_file(conn, path, dataset=name)
        print(f"{name}: {result.inserted} events loaded ({result.skipped} bad lines skipped)")
    return 0


def cmd_ingest(args) -> int:
    conn = connect(args.db)
    for path in args.files:
        result = ingest_file(conn, path)
        print(f"{result.dataset}: {result.inserted} events loaded ({result.skipped} bad lines skipped)")
    return 0


def cmd_stats(args) -> int:
    conn = connect(args.db)
    rows = conn.execute(
        "SELECT dataset, COUNT(*) AS n, COUNT(DISTINCT host) AS hosts FROM events GROUP BY dataset ORDER BY dataset"
    ).fetchall()
    if not rows:
        print("No events loaded yet. Try: detectledger fetch lsass_comsvcs")
        return 0
    print(f"{'dataset':<26} {'events':>7} {'hosts':>6}")
    for r in rows:
        print(f"{r['dataset']:<26} {r['n']:>7} {r['hosts']:>6}")
    print("\nTop event types:")
    for r in conn.execute(
        "SELECT channel, event_id, COUNT(*) AS n FROM events GROUP BY channel, event_id ORDER BY n DESC LIMIT 10"
    ):
        print(f"  {r['n']:>6}  {r['event_id']!s:>5}  {r['channel']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="detectledger", description=__doc__)
    p.add_argument("--db", default=DEFAULT_DB, help=f"SQLite database path (default: {DEFAULT_DB})")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="show available attack datasets").set_defaults(func=cmd_list)

    f = sub.add_parser("fetch", help="download datasets and load them")
    f.add_argument("names", nargs="*")
    f.add_argument("--all", action="store_true", help="fetch every dataset in the catalog")
    f.set_defaults(func=cmd_fetch)

    i = sub.add_parser("ingest", help="load local .zip/.json event files")
    i.add_argument("files", nargs="+")
    i.set_defaults(func=cmd_ingest)

    sub.add_parser("stats", help="summarize what's loaded").set_defaults(func=cmd_stats)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
