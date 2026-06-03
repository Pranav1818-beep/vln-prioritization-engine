import requests

EPSS_API_URL = "https://api.first.org/data/v1/epss"

def get_epss_score(cve_id):
    """
    Fetch EPSS score for a CVE from FIRST.org API.
    """

    try:
        response = requests.get(
            EPSS_API_URL,
            params={"cve": cve_id},
            timeout=10
        )
        response.raise_for_status()

        data = response.json()

        results = data.get("data", [])
        if not results:
            print(f"[WARN] No EPSS data found for {cve_id}")
            return None

        epss_score = results[0].get("epss")

        return float(epss_score) if epss_score is not None else None

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Network/API failure for {cve_id}: {e}")
        return None

    except (ValueError, KeyError, TypeError) as e:
        print(f"[ERROR] Parsing failure for {cve_id}: {e}")
        return None
