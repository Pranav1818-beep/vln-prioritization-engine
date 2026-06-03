import pandas as pd
from fetchers.epss import get_epss_score
from models.vuln import Vulnerability


def calculate_risk_score(cvss, epss, asset_criticality_score):
    """
    Simple weighted scoring function for vulnerability prioritization.
    """
    if epss is None:
        epss = 0.0

    return (cvss * 0.5) + (epss * 100 * 0.3) + (asset_criticality_score * 0.2)


def map_asset_criticality(value):
    mapping = {
        "low": 1,
        "medium": 2,
        "high": 4,
        "critical": 5
    }

    return mapping.get(str(value).lower(), 1)

def main():
    df = pd.read_csv("data/sample_cves.csv")

    print("\n=== Vulnerability EPSS Enrichment ===\n")

    results = []

    for _, row in df.iterrows():
        cve_id = row["cve_id"]
        cvss = float(row["cvss_score"])
        asset_criticality_label = row["asset_criticality"]
        asset_criticality_score = map_asset_criticality(asset_criticality_label)

        print(f"Processing {cve_id}...")

        epss = get_epss_score(cve_id)
        risk_score = calculate_risk_score(cvss, epss, asset_criticality_score)

        results.append({
            "cve_id": cve_id,
            "cvss": cvss,
            "epss": epss,
            "asset_criticality_label": asset_criticality_label,
            "asset_criticality_score": asset_criticality_score,
            "risk_score": risk_score
        })

    # Sort by risk score (highest priority first)
    results.sort(key=lambda x: x["risk_score"], reverse=True)

    print("\n=== PRIORITIZED VULNERABILITIES ===\n")

    for i, item in enumerate(results, 1):
        print(
             f"Rank {i}\n"
             f"CVE: {item['cve_id']}\n"
             f"Risk Score: {item['risk_score']:.2f}\n"
             f"CVSS: {item['cvss']}\n"
             f"EPSS: {item['epss']}\n"
             f"Asset Criticality: {item['asset_criticality_label']} "
             f"({item['asset_criticality_score']})\n"
             f"----------------------------\n"
        )


if __name__ == "__main__":
    main()
