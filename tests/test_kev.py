import json
import os
import time

import requests

from fetchers import kev as kev_mod

# Minimal fake KEV catalog (includes a lowercase ID and an empty entry on purpose)
CATALOG = {"vulnerabilities": [{"cveID": "CVE-2021-44228"}, {"cveID": "cve-2023-44487"}, {}]}


class FakeResp:
    def raise_for_status(self):
        pass

    def json(self):
        return CATALOG


def test_parse_kev_normalizes_and_skips_blanks():
    assert kev_mod.parse_kev(CATALOG) == {"CVE-2021-44228", "CVE-2023-44487"}


def test_kev_file_takes_precedence(tmp_path):
    f = tmp_path / "k.json"
    f.write_text(json.dumps(CATALOG))
    assert "CVE-2021-44228" in kev_mod.load_kev(tmp_path / "cache.json", kev_file=f)


def test_download_writes_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(kev_mod.requests, "get", lambda *a, **k: FakeResp())
    cache = tmp_path / "sub" / "kev.json"
    assert "CVE-2021-44228" in kev_mod.load_kev(cache)
    assert cache.exists()


def test_fresh_cache_skips_network(tmp_path, monkeypatch):
    cache = tmp_path / "kev.json"
    cache.write_text(json.dumps(CATALOG))

    def boom(*a, **k):
        raise AssertionError("network should not be used")

    monkeypatch.setattr(kev_mod.requests, "get", boom)
    assert "CVE-2021-44228" in kev_mod.load_kev(cache)


def test_stale_cache_used_when_download_fails(tmp_path, monkeypatch):
    cache = tmp_path / "kev.json"
    cache.write_text(json.dumps(CATALOG))
    old = time.time() - 72 * 3600  # make the cache 3 days old
    os.utime(cache, (old, old))

    def fail(*a, **k):
        raise requests.exceptions.ConnectionError("down")

    monkeypatch.setattr(kev_mod.requests, "get", fail)
    assert "CVE-2021-44228" in kev_mod.load_kev(cache)


def test_unavailable_returns_none_not_empty_set(tmp_path, monkeypatch):
    def fail(*a, **k):
        raise requests.exceptions.ConnectionError("down")

    monkeypatch.setattr(kev_mod.requests, "get", fail)
    assert kev_mod.load_kev(tmp_path / "none.json") is None
    assert kev_mod.load_kev(tmp_path / "none.json", offline=True) is None


def test_corrupt_cache_offline_returns_none(tmp_path):
    cache = tmp_path / "kev.json"
    cache.write_text("{not json")
    assert kev_mod.load_kev(cache, offline=True) is None
