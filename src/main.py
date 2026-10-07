import argparse
import logging
import sys
from pathlib import Path

from engine.scoring import score_vulnerability
from fetchers.epss import get_epss_scores
from fetchers.kev import load_kev
from utils.io import read_input, write_results

# Paths are built from this file's location, so the script runs from any directory
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "data" / "sample_cves.csv"
KEV_CACHE = ROOT / "data" / "cache" / "kev.json"


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Vulnerability prioritization engine")
    p.add_argument("--input", type=Path, default=DEFAULT_INPUT,
                   help="findings CSV (default: data/sample_cves.csv)")
    p.add_argument("--output", type=Path, default=None,
                   help="write ranked results to .csv or .json")
    p.add_argument("--offline", action="store_true",
                   help="no network: skip EPSS, use cached/--kev-file KEV only")
    p.add_argument("--kev-file", type=Path, default=None,
                   help="use a local CISA KEV JSON instead of downloading")
    p.add_argument("--top", type=int, default=None, help="only print the top N")
    return p.parse_args(argv)


def run(args):
    # 1. Load and validate the input; bad rows are reported, not fatal
    vulns, skipped = read_input(args.input)
    for msg in skipped:
        logging.warning("Skipped %s", msg)
    if not vulns:
        logging.error("No valid rows to process")
        return 1

    cves = [v.cve_id for v in vulns]

    # 2. EPSS: one batched set of calls for all unique CVEs
    epss = {} if args.offline else get_epss_scores(cves)

    # 3. KEV: None = catalog unavailable (unknown), NOT "nothing is exploited"
    kev = load_kev(KEV_CACHE, kev_file=args.kev_file, offline=args.offline)
    if kev is None:
        logging.warning("KEV data unavailable: KEV flags are NOT applied to scores")

    # 4. Enrich and score every finding
    for v in vulns:
        v.epss = epss.get(v.cve_id)  # None if EPSS has no data for it
        v.kev = bool(kev) and v.cve_id in kev
        score_vulnerability(v)

    # 5. Rank. KEV bonus caps at 100, so break ties on the pre-bonus score, then CVSS
    vulns.sort(key=lambda v: (-v.risk_score, -v.breakdown["base_score"], -v.cvss, v.cve_id))

    # 6. Print a table
    shown = vulns[:args.top] if args.top else vulns
    print(f"\n{'#':<3} {'CVE':<16} {'Pri':<4} {'Score':>6} {'CVSS':>5} "
          f"{'EPSS':>7} {'KEV':<4} {'Asset':<9} Missing")
    print("-" * 72)
    for i, v in enumerate(shown, 1):
        epss_txt = f"{v.epss:.4f}" if v.epss is not None else "n/a"
        print(f"{i:<3} {v.cve_id:<16} {v.priority:<4} {v.risk_score:>6.1f} "
              f"{v.cvss:>5.1f} {epss_txt:>7} {'yes' if v.kev else 'no':<4} "
              f"{v.asset_criticality:<9} {','.join(v.breakdown['missing'])}")

    # 7. Optional file export
    if args.output:
        write_results(vulns, args.output)
        print(f"\nWrote {len(vulns)} rows to {args.output}")
    return 0


def main(argv=None):
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    return run(parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
