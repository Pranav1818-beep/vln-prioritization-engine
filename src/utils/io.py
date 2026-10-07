import csv
import json
import logging
import re
from pathlib import Path

from models.vuln import Vulnerability

log = logging.getLogger(__name__)

# Valid CVE format, e.g. CVE-2021-44228
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
REQUIRED_COLUMNS = ["cve_id", "cvss_score", "asset_criticality"]
# Optional, vendor-neutral columns (e.g. Qualys: vendor=qualys, vendor_id=QID)
OPTIONAL_COLUMNS = ["asset", "vendor", "vendor_id", "vendor_severity"]

OUTPUT_FIELDS = [
    "rank", "cve_id", "asset", "priority", "risk_score", "cvss", "epss", "kev",
    "asset_criticality", "vendor", "vendor_id", "vendor_severity", "missing_inputs",
]


def _clean(value):
    """Strip whitespace; turn empty strings into None."""
    value = (value or "").strip()
    return value or None


def read_input(path):
    """
    Read a findings CSV. Returns (vulnerabilities, skipped_row_messages).

    Bad rows are skipped with a message instead of crashing the whole run.
    """
    vulns, skipped = [], []

    # utf-8-sig strips the BOM that Excel adds when saving CSVs
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise ValueError(f"{path}: file is empty")
        # Case/space-insensitive headers
        reader.fieldnames = [h.strip().lower() for h in reader.fieldnames]

        missing = [c for c in REQUIRED_COLUMNS if c not in reader.fieldnames]
        if missing:
            raise ValueError(
                f"{path}: missing required column(s): {', '.join(missing)}"
            )

        for line_no, row in enumerate(reader, start=2):  # line 1 is the header
            # Validate the CVE ID
            cve = (row.get("cve_id") or "").strip().upper()
            if not CVE_RE.match(cve):
                skipped.append(f"line {line_no}: invalid CVE id {row.get('cve_id')!r}")
                continue

            # Validate CVSS (must be a number from 0 to 10)
            try:
                cvss = float(row["cvss_score"])
            except (TypeError, ValueError):
                skipped.append(f"line {line_no}: invalid cvss_score for {cve}")
                continue
            if not 0.0 <= cvss <= 10.0:
                skipped.append(f"line {line_no}: cvss_score {cvss} out of range for {cve}")
                continue

            # Optional vendor severity: bad values are ignored, not fatal
            vendor_severity = None
            raw_sev = _clean(row.get("vendor_severity"))
            if raw_sev is not None:
                try:
                    vendor_severity = int(float(raw_sev))
                except ValueError:
                    skipped.append(f"line {line_no}: invalid vendor_severity for {cve} (ignored)")

            vulns.append(Vulnerability(
                cve_id=cve,
                cvss=cvss,
                asset_criticality=(row.get("asset_criticality") or "low").strip().lower(),
                asset=_clean(row.get("asset")),
                vendor=_clean(row.get("vendor")),
                vendor_id=_clean(row.get("vendor_id")),
                vendor_severity=vendor_severity,
            ))

    return vulns, skipped


def _as_row(rank, v):
    """Flatten a Vulnerability into one output row."""
    return {
        "rank": rank,
        "cve_id": v.cve_id,
        "asset": v.asset,
        "priority": v.priority,
        "risk_score": v.risk_score,
        "cvss": v.cvss,
        "epss": v.epss,
        "kev": v.kev,
        "asset_criticality": v.asset_criticality,
        "vendor": v.vendor,
        "vendor_id": v.vendor_id,
        "vendor_severity": v.vendor_severity,
        "missing_inputs": ";".join(v.breakdown.get("missing", [])),
    }


def write_results(vulns, path):
    """Write ranked results to .csv or .json (chosen by file extension)."""
    path = Path(path)
    rows = [_as_row(i, v) for i, v in enumerate(vulns, start=1)]
    suffix = path.suffix.lower()

    path.parent.mkdir(parents=True, exist_ok=True)
    if suffix == ".csv":
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
    elif suffix == ".json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)
    else:
        raise ValueError(f"Unsupported output format {suffix!r}; use .csv or .json")
