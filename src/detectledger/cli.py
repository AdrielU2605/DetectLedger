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


def cmd_hunt(args) -> int:
    from .sigma import load_rules, run_rule

    conn = connect(args.db)
    rules = load_rules(args.rules)
    loaded = [r["dataset"] for r in conn.execute("SELECT DISTINCT dataset FROM events ORDER BY dataset")]
    if not loaded:
        print("No events loaded yet. Try: detectledger fetch --all")
        return 0

    results = []
    for rule in rules:
        alerts = run_rule(conn, rule, args.dataset)
        counts = {d: 0 for d in loaded}
        for a in alerts:
            counts[a.dataset] += 1
        results.append((rule, alerts, counts))

    if args.markdown:
        print("| Rule | ATT&CK | " + " | ".join(loaded) + " |")
        print("|---|---|" + "---:|" * len(loaded))
        for rule, _, counts in results:
            cells = " | ".join(str(counts[d] or "-") for d in loaded)
            print(f"| {rule.title} | {', '.join(rule.techniques)} | {cells} |")
        return 0

    width = max(len(r.title) for r in rules)
    print(f"{'rule':<{width}}  " + " ".join(f"{d[:10]:>10}" for d in loaded))
    for rule, alerts, counts in results:
        cells = " ".join(f"{(counts[d] or '.'):>10}" for d in loaded)
        print(f"{rule.title:<{width}}  {cells}")
        if args.show:
            for a in alerts:
                detail = a.event.get("CommandLine") or a.event.get("SourceImage") or ""
                print(f"    [{a.dataset}] {a.ts} {a.host}  {detail}")
    return 0


def cmd_timeline(args) -> int:
    from .alerts import all_alerts, key_fields
    from .sigma import load_rules

    conn = connect(args.db)
    alerts = all_alerts(conn, load_rules(args.rules), args.dataset)
    if not alerts:
        print("No alerts.")
        return 0
    for a in alerts:
        fields = key_fields(a.event, max_len=110)
        detail = fields.get("CommandLine") or fields.get("ImagePath") or fields.get("Details") \
            or fields.get("SourceImage") or fields.get("SubjectUserName") or ""
        extra = f"  (+{len(a.merged)} duplicate)" if a.merged else ""
        print(f"{a.ts}  {a.rule.level.upper():<8} {a.id:<15} {a.host or '?':<28} {a.rule.title}{extra}")
        if detail:
            print(f"{'':>26}└ {detail}")
    return 0


def cmd_context(args) -> int:
    from .alerts import context, find_alert, key_fields
    from .sigma import load_rules

    conn = connect(args.db)
    alert = find_alert(conn, load_rules(args.rules), args.alert_id)
    if alert is None:
        print(f"alert not found: {args.alert_id} (see `detectledger timeline`)", file=sys.stderr)
        return 1
    print(f"{alert.rule.title}  [{alert.rule.level}]  {', '.join(alert.rule.techniques)}")
    print(f"{alert.ts}  {alert.host}  ({alert.dataset})")
    for k, v in key_fields(alert.event).items():
        print(f"  {k}: {v}")
    print(f"\nProcess launches on {alert.host} within ±{args.minutes} min:")
    for c in context(conn, alert, args.minutes):
        mark = ">>" if c["is_alert_event"] else "  "
        print(f"{mark} {c['time_utc']}  {c['user'] or '':<22} {c['command_line'] or c['image']}")
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

    h = sub.add_parser("hunt", help="run Sigma rules against loaded events")
    h.add_argument("--rules", default="rules", help="folder of Sigma .yml rules (default: rules)")
    h.add_argument("--dataset", help="only search this dataset")
    h.add_argument("--show", action="store_true", help="print each alert under its rule")
    h.add_argument("--markdown", action="store_true", help="print the results as a Markdown table")
    h.set_defaults(func=cmd_hunt)

    t = sub.add_parser("timeline", help="all alerts from all rules, in time order (UTC)")
    t.add_argument("--rules", default="rules")
    t.add_argument("--dataset", help="only this dataset")
    t.set_defaults(func=cmd_timeline)

    x = sub.add_parser("context", help="investigate one alert: its fields + nearby process launches")
    x.add_argument("alert_id", help="ID from `detectledger timeline`, e.g. ae7ddfb2-123")
    x.add_argument("--minutes", type=int, default=5, help="window before/after the alert (default 5)")
    x.add_argument("--rules", default="rules")
    x.set_defaults(func=cmd_context)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
