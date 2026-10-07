import csv
import json

import pytest

import main as main_mod
from utils.io import read_input, write_results


def write_csv(path, text):
    path.write_text(text, encoding="utf-8")
    return path


def test_read_input_skips_bad_rows_and_keeps_good(tmp_path):
    p = write_csv(tmp_path / "in.csv",
                  "cve_id,cvss_score,asset_criticality\n"
                  "CVE-2021-44228,10.0,critical\n"
                  "not-a-cve,5,low\n"
                  "CVE-2022-22965,abc,high\n"
                  "CVE-2022-22966,11,high\n")
    vulns, skipped = read_input(p)
    assert [v.cve_id for v in vulns] == ["CVE-2021-44228"]
    assert len(skipped) == 3


def test_read_input_handles_bom_case_and_optional_vendor_cols(tmp_path):
    p = tmp_path / "in.csv"
    # b"\xef\xbb\xbf" is the BOM Excel adds to CSV files
    p.write_bytes(b"\xef\xbb\xbfCVE_ID,CVSS_Score,Asset_Criticality,asset,vendor,vendor_id,vendor_severity\n"
                  b"cve-2021-44228,10,Critical,web01,qualys,123456,5\n")
    (v,), _ = read_input(p)
    assert (v.cve_id, v.asset, v.vendor, v.vendor_id, v.vendor_severity) == \
           ("CVE-2021-44228", "web01", "qualys", "123456", 5)
    assert v.asset_criticality == "critical"


def test_missing_required_column_raises_clear_error(tmp_path):
    p = write_csv(tmp_path / "in.csv", "cve_id,cvss_score\nCVE-2021-44228,10\n")
    with pytest.raises(ValueError, match="asset_criticality"):
        read_input(p)


def test_write_results_unsupported_format(tmp_path):
    with pytest.raises(ValueError):
        write_results([], tmp_path / "out.txt")


KEV_JSON = {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}


def test_end_to_end_offline(tmp_path, capsys):
    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps(KEV_JSON))
    out_csv, out_json = tmp_path / "r.csv", tmp_path / "r.json"

    for out in (out_csv, out_json):
        rc = main_mod.main(["--offline", "--kev-file", str(kev), "--output", str(out)])
        assert rc == 0

    rows = list(csv.DictReader(open(out_csv)))
    assert rows[0]["cve_id"] == "CVE-2021-44228"  # KEV + critical ranks first
    assert rows[0]["kev"] == "True" and rows[0]["rank"] == "1"
    assert "epss" in rows[0]["missing_inputs"]     # offline => EPSS flagged missing
    assert json.load(open(out_json))[0]["cve_id"] == "CVE-2021-44228"


def test_end_to_end_with_mocked_network(tmp_path, monkeypatch):
    # Replace the network functions imported into main with fakes
    monkeypatch.setattr(main_mod, "get_epss_scores",
                        lambda cves: {c: 0.9 for c in cves})
    monkeypatch.setattr(main_mod, "load_kev", lambda *a, **k: {"CVE-2023-44487"})
    out = tmp_path / "r.json"
    assert main_mod.main(["--output", str(out)]) == 0
    rows = json.load(open(out))
    assert all(r["epss"] == 0.9 for r in rows)
    assert next(r for r in rows if r["cve_id"] == "CVE-2023-44487")["kev"] is True


def test_empty_input_returns_nonzero(tmp_path):
    p = write_csv(tmp_path / "in.csv", "cve_id,cvss_score,asset_criticality\n")
    assert main_mod.main(["--offline", "--input", str(p)]) == 1


def test_ties_at_cap_are_broken_by_base_score(tmp_path):
    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44228"},
                                                   {"cveID": "CVE-2023-44487"}]}))
    out = tmp_path / "r.json"
    main_mod.main(["--offline", "--kev-file", str(kev), "--output", str(out)])
    rows = json.load(open(out))
    kev_rows = [r for r in rows if r["kev"]]
    assert [r["cve_id"] for r in kev_rows] == ["CVE-2021-44228", "CVE-2023-44487"]
    assert rows[0]["risk_score"] == rows[1]["risk_score"] == 100.0  # tied after cap, ordered by base
