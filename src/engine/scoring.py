"""
Scoring engine for vulnerability prioritization.

NOTE:
The current scoring model is a simple demonstration model and is
not based on any industry-standard methodology.

Future versions may incorporate:
- KEV status
- CVSS vector metrics
- Asset exposure
- Business impact
- Threat intelligence
"""


def map_asset_criticality(value):
    """
    Convert asset criticality labels into numerical values.
    """

    mapping = {
        "low": 1,
        "medium": 2,
        "high": 4,
        "critical": 5
    }

    return mapping.get(str(value).lower(), 1)


def calculate_risk_score(cvss, epss, asset_criticality_score):
    """
    Simple weighted prioritization model.

    Formula:
        (CVSS × 0.5)
      + (EPSS × 100 × 0.3)
      + (Asset Criticality × 0.2)

    This is a demonstration model only.
    """

    if epss is None:
        epss = 0.0

    return (
        (cvss * 0.5)
        + (epss * 100 * 0.3)
        + (asset_criticality_score * 0.2)
    )
