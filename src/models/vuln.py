from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Vulnerability:
    """
    Core data model: one finding (a CVE on an asset) plus all enriched attributes.
    The CVE ID is the join key for enrichment (EPSS, KEV).
    Vendor fields (e.g. Qualys QID / severity) are optional so the engine
    stays vendor-neutral.
    """

    cve_id: str

    # --- Base attributes (come from the input CSV) ---
    cvss: Optional[float] = None
    asset_criticality: str = "low"
    asset: Optional[str] = None

    # --- Optional vendor attributes (e.g. vendor="qualys", vendor_id=QID) ---
    vendor: Optional[str] = None
    vendor_id: Optional[str] = None
    vendor_severity: Optional[int] = None  # assumed 1-5 scale

    # --- Enrichment attributes (filled in by the fetchers) ---
    epss: Optional[float] = None  # None = unknown, which is different from 0.0
    kev: bool = False             # True = listed in CISA KEV

    # --- Computed attributes (filled in by the scoring engine) ---
    risk_score: Optional[float] = None  # 0-100
    priority: Optional[str] = None      # P1 (fix first) .. P4
    breakdown: dict = field(default_factory=dict)  # explains how the score was built
