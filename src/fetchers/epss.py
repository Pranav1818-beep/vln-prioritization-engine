import logging

import requests

EPSS_API_URL = "https://api.first.org/data/v1/epss"
CHUNK_SIZE = 50  # CVEs per request; the API accepts a comma-separated cve list

log = logging.getLogger(__name__)


def get_epss_scores(cve_ids, chunk_size=CHUNK_SIZE, timeout=15):
    """
    Fetch EPSS scores for many CVEs in batched requests.

    Returns {CVE_ID: float}. CVEs the API has no data for (or whose batch
    failed) are simply absent, so callers can tell "unknown" apart from 0.0.
    """
    # Deduplicate and normalize case so the same CVE is never requested twice
    unique = sorted({c.strip().upper() for c in cve_ids if c and c.strip()})
    scores = {}

    # Send CVEs in chunks instead of one request per CVE
    for i in range(0, len(unique), chunk_size):
        chunk = unique[i:i + chunk_size]
        try:
            response = requests.get(
                EPSS_API_URL,
                params={"cve": ",".join(chunk)},
                timeout=timeout,
            )
            response.raise_for_status()
            for item in response.json().get("data", []):
                cve = str(item.get("cve", "")).upper()
                epss = item.get("epss")
                if cve and epss is not None:
                    scores[cve] = float(epss)
        except requests.exceptions.RequestException as e:
            # One failed batch must not kill the whole run
            log.error("EPSS request failed for batch starting %s: %s", chunk[0], e)
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            # Unexpected response shape
            log.error("EPSS parse failure for batch starting %s: %s", chunk[0], e)

    missing = [c for c in unique if c not in scores]
    if missing:
        log.warning("No EPSS data for %d CVE(s): %s", len(missing), ", ".join(missing[:5])
                    + (" ..." if len(missing) > 5 else ""))
    return scores


def get_epss_score(cve_id):
    """Single-CVE convenience wrapper (kept for backward compatibility)."""
    return get_epss_scores([cve_id]).get(cve_id.strip().upper())
