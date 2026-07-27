import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from suppressions import Suppression, is_suppressed, load_suppressions


def test_active_suppression_matches():
    suppressions = [Suppression("CVE-2018-18074", "requests", "test reason", "2099-01-01")]
    match = is_suppressed(["CVE-2018-18074"], "requests", suppressions, today=date(2026, 1, 1))
    assert match is not None
    assert match.reason == "test reason"


def test_suppression_is_case_insensitive_on_package_name():
    suppressions = [Suppression("CVE-2018-18074", "requests", "test reason", None)]
    match = is_suppressed(["CVE-2018-18074"], "Requests", suppressions, today=date(2026, 1, 1))
    assert match is not None


def test_wrong_package_does_not_match():
    suppressions = [Suppression("CVE-2018-18074", "requests", "test reason", None)]
    match = is_suppressed(["CVE-2018-18074"], "flask", suppressions, today=date(2026, 1, 1))
    assert match is None


def test_wrong_cve_does_not_match():
    suppressions = [Suppression("CVE-2018-18074", "requests", "test reason", None)]
    match = is_suppressed(["CVE-1999-0001"], "requests", suppressions, today=date(2026, 1, 1))
    assert match is None


def test_no_expiry_means_always_active():
    suppressions = [Suppression("CVE-2018-18074", "requests", "test reason", None)]
    match = is_suppressed(["CVE-2018-18074"], "requests", suppressions, today=date(2099, 1, 1))
    assert match is not None


def test_expired_suppression_does_not_match():
    suppressions = [Suppression("CVE-2018-18074", "requests", "test reason", "2020-01-01")]
    match = is_suppressed(["CVE-2018-18074"], "requests", suppressions, today=date(2026, 1, 1))
    assert match is None


def test_expiry_boundary_is_inclusive():
    suppressions = [Suppression("CVE-2018-18074", "requests", "test reason", "2026-01-01")]
    still_active = is_suppressed(["CVE-2018-18074"], "requests", suppressions, today=date(2026, 1, 1))
    already_expired = is_suppressed(["CVE-2018-18074"], "requests", suppressions, today=date(2026, 1, 2))
    assert still_active is not None
    assert already_expired is None


def test_load_suppressions_missing_file_returns_empty(tmp_path):
    assert load_suppressions(tmp_path / "does_not_exist.json") == []


def test_load_suppressions_parses_real_file(tmp_path):
    path = tmp_path / "suppressions.json"
    path.write_text(json.dumps([
        {"cve_id": "CVE-2018-18074", "package": "requests", "reason": "why", "expires": "2099-01-01"}
    ]))
    loaded = load_suppressions(path)
    assert len(loaded) == 1
    assert loaded[0].cve_id == "CVE-2018-18074"
    assert loaded[0].expires == "2099-01-01"


def test_load_suppressions_expires_is_optional(tmp_path):
    path = tmp_path / "suppressions.json"
    path.write_text(json.dumps([
        {"cve_id": "CVE-2018-18074", "package": "requests", "reason": "why"}
    ]))
    loaded = load_suppressions(path)
    assert loaded[0].expires is None
