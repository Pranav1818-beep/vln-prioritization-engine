import json
import logging
import os
import tempfile
import time
from pathlib import Path

import requests

# Official CISA Known Exploited Vulnerabilities catalog (JSON feed)
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")

log = logging.getLogger(__name__)


def parse_kev(data):
    """Extract the set of CVE IDs from a CISA KEV catalog dict."""
    return {
        str(v["cveID"]).strip().upper()
        for v in data.get("vulnerabilities", [])
        if v.get("cveID")
    }


def _read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _write_cache(path, data):
    """Write to a temp file, then rename, so a crash can't leave a half-written cache."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, path)  # atomic rename
    except OSError:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def load_kev(cache_path, kev_file=None, offline=False,
             max_age_hours=24, timeout=20):
    """
    Return the set of KEV CVE IDs, or None if the catalog is unavailable.

    None means "unknown", which is different from an empty set ("nothing is
    KEV"), so the caller must not treat unavailable data as "not exploited".

    Order: explicit kev_file > fresh cache > download > stale cache.
    With offline=True, never touches the network (cache only).
    """
    # 1. An explicit local file always wins
    if kev_file:
        return parse_kev(_read_json(kev_file))

    cache = Path(cache_path)
    cache_exists = cache.exists()

    # 2. Use the cache if it is fresh enough (or if we are offline)
    if cache_exists:
        age_hours = (time.time() - cache.stat().st_mtime) / 3600
        if offline or age_hours <= max_age_hours:
            try:
                return parse_kev(_read_json(cache))
            except (OSError, ValueError) as e:
                log.warning("KEV cache unreadable (%s); ignoring it", e)
                cache_exists = False

    if offline:
        log.warning("Offline and no usable KEV cache; KEV flags unavailable")
        return None

    # 3. Download a fresh copy and refresh the cache
    try:
        response = requests.get(KEV_URL, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        kev = parse_kev(data)
        try:
            _write_cache(cache, data)
        except OSError as e:
            log.warning("Could not write KEV cache: %s", e)  # not fatal
        return kev
    except (requests.exceptions.RequestException, ValueError) as e:
        log.error("KEV download failed: %s", e)

    # 4. Download failed: fall back to an old cache rather than nothing
    if cache_exists:
        log.warning("Using stale KEV cache")
        try:
            return parse_kev(_read_json(cache))
        except (OSError, ValueError):
            pass
    return None
