import pytest

from engine.scoring import (calculate_risk_score, map_asset_criticality,
                            priority_for, score_vulnerability, KEV_BONUS)
from models.vuln import Vulnerability


def test_asset_mapping_and_unknown_default():
    assert map_asset_criticality("Critical") == 5
    assert map_asset_criticality(" high ") == 4
    assert map_asset_criticality("banana") == 1  # unknown label falls back to low
    assert map_asset_criticality(None) == 1


def test_score_bounded_0_to_100():
    top = calculate_risk_score(10.0, 1.0, "critical", vendor_severity=5, kev=True)
    bottom = calculate_risk_score(0.0, 0.0, "low")
    assert top["score"] == 100.0
    assert 0 <= bottom["score"] < 25


def test_no_single_input_dominates():
    # v1 bug: EPSS contributed up to 30 points vs 5 for CVSS. Now equal-weighted.
    only_cvss = calculate_risk_score(10.0, 0.0, "low")["score"]
    only_epss = calculate_risk_score(0.0, 1.0, "low")["score"]
    assert only_cvss == pytest.approx(only_epss, abs=0.01)


def test_missing_epss_renormalizes_and_is_reported():
    r = calculate_risk_score(10.0, None, "critical")
    assert "epss" in r["missing"] and "vendor" in r["missing"]
    assert r["score"] == 100.0  # cvss and asset are both maxed; weights renormalized


def test_missing_epss_is_not_treated_as_zero():
    unknown = calculate_risk_score(8.0, None, "high")["score"]
    zero = calculate_risk_score(8.0, 0.0, "high")["score"]
    assert unknown > zero


def test_kev_adds_bonus_and_caps():
    base = calculate_risk_score(5.0, 0.1, "medium")
    kev = calculate_risk_score(5.0, 0.1, "medium", kev=True)
    assert kev["score"] == pytest.approx(base["score"] + KEV_BONUS * 100, abs=0.01)
    assert calculate_risk_score(10, 1, "critical", kev=True)["score"] == 100.0


def test_kev_lifts_priority_tier():
    base = calculate_risk_score(6.0, 0.05, "medium")
    kev = calculate_risk_score(6.0, 0.05, "medium", kev=True)
    assert kev["priority"] < base["priority"] or kev["score"] > base["score"]


def test_vendor_severity_used_when_present_and_ignored_when_out_of_range():
    low = calculate_risk_score(5, 0.1, "medium", vendor_severity=1)["score"]
    high = calculate_risk_score(5, 0.1, "medium", vendor_severity=5)["score"]
    assert high > low
    bad = calculate_risk_score(5, 0.1, "medium", vendor_severity=9)
    assert "vendor" in bad["missing"]


def test_priority_tiers():
    assert priority_for(90) == "P1"
    assert priority_for(75) == "P1"
    assert priority_for(60) == "P2"
    assert priority_for(35) == "P3"
    assert priority_for(5) == "P4"


def test_score_vulnerability_sets_fields():
    v = Vulnerability("CVE-2021-44228", cvss=10.0, asset_criticality="critical",
                      epss=0.97, kev=True)
    score_vulnerability(v)
    assert v.risk_score == 100.0 and v.priority == "P1" and v.breakdown["kev"]
