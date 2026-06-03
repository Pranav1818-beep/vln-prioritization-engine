class Vulnerability:
    """
    Core data model representing a CVE and all enriched attributes.
    This acts as the single source of truth for the pipeline.
    """

    def __init__(self, cve_id: str):
        self.cve_id = cve_id

        # Base attributes (from CSV / NVD)
        self.cvss = None
        self.asset_criticality = None

        # Enrichment attributes
        self.epss = None
        self.kev = False

        # Computed attributes
        self.risk_score = None

    def __repr__(self):
        return (
            f"<Vulnerability {self.cve_id} | "
            f"CVSS={self.cvss} | "
            f"EPSS={self.epss} | "
            f"KEV={self.kev} | "
            f"Risk={self.risk_score}>"
        )

class Vulnerability:
    """
    Core data model representing a CVE and all enriched attributes.
    This acts as the single source of truth for the pipeline.
    """

    def __init__(self, cve_id: str):
        self.cve_id = cve_id

        # Base attributes (from CSV / NVD)
        self.cvss = None
        self.asset_criticality = None

        # Enrichment attributes
        self.epss = None
        self.kev = False

        # Computed attributes
        self.risk_score = None

    def __repr__(self):
        return (
            f"<Vulnerability {self.cve_id} | "
            f"CVSS={self.cvss} | "
            f"EPSS={self.epss} | "
            f"KEV={self.kev} | "
            f"Risk={self.risk_score}>"
        )

