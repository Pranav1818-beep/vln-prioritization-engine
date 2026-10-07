import requests

from fetchers import epss as epss_mod


class FakeResp:
    """Stand-in for a requests.Response so tests never hit the network."""
    def __init__(self, payload, status=200):
        self._p, self.status_code = payload, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(str(self.status_code))

    def json(self):
        return self._p


def test_batches_and_dedupes(monkeypatch):
    calls = []

    def fake_get(url, params=None, timeout=None):
        calls.append(params["cve"])
        data = [{"cve": c, "epss": "0.5"} for c in params["cve"].split(",")]
        return FakeResp({"data": data})

    monkeypatch.setattr(epss_mod.requests, "get", fake_get)
    cves = [f"CVE-2024-{1000 + i}" for i in range(120)] + ["cve-2024-1000"]  # dup, lowercase
    scores = epss_mod.get_epss_scores(cves, chunk_size=50)

    assert len(calls) == 3  # 120 unique CVEs / 50 -> 3 requests, not 121
    assert len(scores) == 120
    assert scores["CVE-2024-1000"] == 0.5


def test_unknown_cve_is_absent_not_zero(monkeypatch):
    monkeypatch.setattr(epss_mod.requests, "get",
                        lambda *a, **k: FakeResp({"data": [{"cve": "CVE-2024-0001", "epss": "0.1"}]}))
    scores = epss_mod.get_epss_scores(["CVE-2024-0001", "CVE-2024-0002"])
    assert scores == {"CVE-2024-0001": 0.1}


def test_failed_batch_does_not_kill_other_batches(monkeypatch):
    state = {"n": 0}

    def fake_get(url, params=None, timeout=None):
        state["n"] += 1
        if state["n"] == 1:  # first batch fails
            raise requests.exceptions.ConnectionError("boom")
        return FakeResp({"data": [{"cve": c, "epss": "0.2"} for c in params["cve"].split(",")]})

    monkeypatch.setattr(epss_mod.requests, "get", fake_get)
    cves = [f"CVE-2024-{2000 + i}" for i in range(4)]
    scores = epss_mod.get_epss_scores(cves, chunk_size=2)
    assert len(scores) == 2  # only the second batch succeeded


def test_garbage_response_is_handled(monkeypatch):
    monkeypatch.setattr(epss_mod.requests, "get", lambda *a, **k: FakeResp(["not", "a", "dict"]))
    assert epss_mod.get_epss_scores(["CVE-2024-0001"]) == {}


def test_single_wrapper(monkeypatch):
    monkeypatch.setattr(epss_mod.requests, "get",
                        lambda *a, **k: FakeResp({"data": [{"cve": "CVE-2024-0001", "epss": "0.3"}]}))
    assert epss_mod.get_epss_score("CVE-2024-0001") == 0.3
