"""
Risk scoring.

Every input is normalized to 0-1 BEFORE weighting, so no single input
dominates because of its native scale. (The v1 prototype mixed scales:
EPSS*100*0.3 could reach 30 while CVSS*0.5 reached 5.)

Final score is 0-100. The weights and tier cut-offs below are heuristic
defaults for prototyping, not empirically validated. Tune them for your
environment.
"""

# Relative importance of each input. They don't need to sum to 1 because
# the score is renormalized over whichever inputs are actually available.
DEFAULT_WEIGHTS = {
    "cvss": 0.30,    # impact severity
    "epss": 0.30,    # likelihood of exploitation
    "asset": 0.30,   # business criticality of the asset
    "vendor": 0.10,  # optional vendor severity (e.g. Qualys severity 1-5)
}

# Added (on the 0-1 scale) when the CVE is in CISA KEV, meaning it is
# known to be exploited in the wild.
KEV_BONUS = 0.25

# Label -> numeric level, same mapping as the v1 prototype
ASSET_LEVELS = {"low": 1, "medium": 2, "high": 4, "critical": 5}
ASSET_MAX = 5
VENDOR_SEVERITY_MAX = 5

# (minimum score, tier), checked top-down
PRIORITY_TIERS = [(75, "P1"), (50, "P2"), (30, "P3")]
LOWEST_TIER = "P4"


def map_asset_criticality(value):
    """Map a label (low/medium/high/critical) to 1-5. Unknown labels -> 1."""
    return ASSET_LEVELS.get(str(value).strip().lower(), 1)


def priority_for(score):
    """Convert a 0-100 score into a P1-P4 tier."""
    for minimum, tier in PRIORITY_TIERS:
        if score >= minimum:
            return tier
    return LOWEST_TIER


def _clamp01(x):
    """Keep a value inside 0-1 so bad input can't push the score out of range."""
    return max(0.0, min(1.0, x))


def _normalize(cvss, epss, asset_label, vendor_severity):
    """Return {component: 0-1 value, or None if that input is unavailable}."""
    parts = {
        "cvss": _clamp01(cvss / 10.0) if cvss is not None else None,
        "epss": _clamp01(epss) if epss is not None else None,  # EPSS is already 0-1
        "asset": map_asset_criticality(asset_label) / ASSET_MAX,
        "vendor": None,
    }
    # Only use vendor severity if it is inside the expected 1-5 range
    if vendor_severity is not None and 1 <= vendor_severity <= VENDOR_SEVERITY_MAX:
        parts["vendor"] = vendor_severity / VENDOR_SEVERITY_MAX
    return parts


def calculate_risk_score(cvss, epss, asset_label, vendor_severity=None,
                         kev=False, weights=None):
    """
    Returns a dict: score (0-100), base_score, priority, components,
    missing, kev.

    Inputs that are unavailable (EPSS not returned, no vendor severity) are
    left out and the remaining weights are renormalized. They are recorded
    in `missing` so the output stays honest about what the score was based on.
    """
    weights = weights or DEFAULT_WEIGHTS
    parts = _normalize(cvss, epss, asset_label, vendor_severity)

    available = {k: v for k, v in parts.items() if v is not None}
    missing = [k for k, v in parts.items() if v is None]

    # Weighted average over only the inputs we actually have
    total_weight = sum(weights[k] for k in available)
    if total_weight == 0:
        base = 0.0
    else:
        base = sum(weights[k] * v for k, v in available.items()) / total_weight

    # KEV bonus is applied after the average, capped at 1.0 (= score 100)
    final = _clamp01(base + KEV_BONUS) if kev else base
    score = round(final * 100, 2)

    return {
        "score": score,
        "base_score": round(base * 100, 2),  # score before the KEV bonus (used for tie-breaking)
        "priority": priority_for(score),
        "components": {k: round(v, 4) for k, v in available.items()},
        "missing": missing,
        "kev": bool(kev),
    }


def score_vulnerability(vuln, weights=None):
    """Score a Vulnerability object in place and return it."""
    result = calculate_risk_score(
        vuln.cvss, vuln.epss, vuln.asset_criticality,
        vendor_severity=vuln.vendor_severity, kev=vuln.kev, weights=weights,
    )
    vuln.risk_score = result["score"]
    vuln.priority = result["priority"]
    vuln.breakdown = result
    return vuln
