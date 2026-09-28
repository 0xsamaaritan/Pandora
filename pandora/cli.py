"""Command-line entry point.

Two run modes:
  --mode surface   query surface-web sources
  --mode dark      query dark-web / threat-intel sources

Two scheduling styles:
  (default)        run ONCE and exit -> drive it with cron / Task Scheduler
  --loop           stay running, repeat every --interval hours (Ctrl-C to stop)

Examples:
  python -m pandora --config config.yaml --mode surface
  python -m pandora --config config.yaml --mode dark --loop --interval 12
"""
from __future__ import annotations

import argparse
import logging
import sys
import time

import yaml

from .banner import print_banner
from .report import console_summary, notify, write_reports
from .sources import build_dorks, dork_categories
from .sources import REGISTRY
from .store import Store


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def run_once(cfg: dict, mode: str) -> int:
    log = logging.getLogger("pandora")
    cfg = dict(cfg)
    cfg["_mode"] = mode  # let mode-aware sources (intelx) know which run this is

    state_dir = cfg.get("state_dir", "state")
    store = Store(f"{state_dir}/{mode}-findings.json")

    collected = []
    for name, meta in REGISTRY.items():
        if mode not in meta["modes"]:
            continue
        key_of = meta["key_of"]
        if key_of and not cfg.get(key_of):
            log.info("skip source '%s' (no '%s' configured)", name, key_of)
            continue
        log.info("running source '%s' ...", name)
        try:
            collected.extend(meta["fn"](cfg))
        except Exception as e:  # noqa: BLE001
            log.warning("source '%s' errored: %s", name, e)

    new = store.reconcile(collected)
    store.save()
    total = [f for f in store.all_findings() if f.mode == mode]

    md = write_reports(mode, cfg.get("report_dir", "reports"), new, total)
    console_summary(mode, new, total)
    notify(cfg, mode, new)
    log.info("report written: %s", md)
    return len(new)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="pandora", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", required=True, help="path to config YAML")
    p.add_argument("--mode", choices=["surface", "dark"],
                   help="required unless using --list-dorks")
    p.add_argument("--loop", action="store_true",
                   help="keep running; repeat every --interval hours")
    p.add_argument("--interval", type=float, default=12.0,
                   help="hours between runs in --loop mode (default 12)")
    p.add_argument("--dork", default="all", metavar="CATEGORY",
                   help="dork category for search sources, or 'all' (default). "
                        "See choices with --list-dorks.")
    p.add_argument("--max-queries", type=int, default=None, metavar="N",
                   help="hard cap on total dork queries this run (protects free-tier "
                        "quota); overrides max_queries_per_run in config")
    p.add_argument("--list-dorks", action="store_true",
                   help="print the dork categories and exact queries that would "
                        "run for your config, then exit")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # keep the run summary visible even without -v
    logging.getLogger("pandora").setLevel(logging.INFO)

    print_banner()
    cfg = load_config(args.config)
    if args.max_queries is not None:
        cfg["_max_queries"] = args.max_queries

    # --list-dorks: show exactly what would run, then exit (no scan, no --mode needed)
    if args.list_dorks:
        cats = dork_categories(cfg)
        caps = cfg.get("dork_caps") or {}
        print(f"Dork categories for org='{cfg.get('org_name','')}', "
              f"domains={cfg.get('domains', [])}:\n")
        for name in sorted(cats):
            queries = build_dorks(cfg, name)
            cap = caps.get(name)
            cap_note = f"  (cap {cap})" if isinstance(cap, int) else ""
            print(f"[{name}]  ({len(queries)} queries){cap_note}")
            for q in queries:
                print(f"    {q}")
            print()
        total = len(build_dorks(cfg, "all"))
        gmax = cfg.get("_max_queries", cfg.get("max_queries_per_run"))
        gnote = f"  (total cap {gmax})" if isinstance(gmax, int) else ""
        print(f"Total with --dork all: {total} queries.{gnote}")
        print("Run one category with:  --dork <category>")
        return 0

    if not args.mode:
        p.error("--mode is required (surface or dark) unless using --list-dorks")

    cfg["_dork"] = args.dork  # selected dork category for search sources

    if not args.loop:
        run_once(cfg, args.mode)
        return 0

    interval = max(0.05, args.interval) * 3600
    logging.getLogger("pandora").info(
        "loop mode: every %.1f h. Ctrl-C to stop.", args.interval)
    try:
        while True:
            run_once(cfg, args.mode)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nstopped.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
