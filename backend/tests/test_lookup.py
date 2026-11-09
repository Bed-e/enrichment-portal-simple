"""Tests for lookup(): it should combine classification, sources and verdict.

The three query_* functions are patched in lookup.py's namespace, so no source is
contacted and these tests need no sample files.
"""
from unittest.mock import patch

import pytest

from lookup import SourcesUnavailableError, lookup


def fake_source(name):
    """A minimal source result with nothing found."""
    return {
        "name": name,
        "display_name": name,
        "status": "no_data",
        "summary": None,
        "raw": None,
        "error": None,
    }


def test_lookup_public_ip_returns_expected_shape():
    with patch("lookup.query_internetdb", return_value=fake_source("internetdb")), \
            patch("lookup.query_rdap", return_value=fake_source("rdap")), \
            patch("lookup.query_abuseipdb", return_value=fake_source("abuseipdb")):
        result = lookup("8.8.8.8")

    assert set(result) == {"ip", "classification", "verdict", "sources"}
    assert result["ip"] == "8.8.8.8"
    assert result["classification"]["category"] == "global"
    assert [s["name"] for s in result["sources"]] == ["internetdb", "rdap", "abuseipdb"]


def test_lookup_private_ip_skips_every_source():
    with patch("lookup.query_internetdb") as internetdb, \
            patch("lookup.query_rdap") as rdap, \
            patch("lookup.query_abuseipdb") as abuseipdb:
        result = lookup("10.0.0.5")

    assert [s["status"] for s in result["sources"]] == ["skipped", "skipped", "skipped"]
    # Private addresses must never be sent to outside services.
    internetdb.assert_not_called()
    rdap.assert_not_called()
    abuseipdb.assert_not_called()


def test_lookup_garbage_raises_value_error():
    with pytest.raises(ValueError):
        lookup("not an ip")


# --- M7: when every queried source fails there is nothing honest to score ---
def failed_source(name):
    result = fake_source(name)
    result["status"] = "error"
    result["error"] = "Request timed out"
    return result


def test_lookup_all_sources_error_raises_sources_unavailable():
    with patch("lookup.query_internetdb", return_value=failed_source("internetdb")), \
            patch("lookup.query_rdap", return_value=failed_source("rdap")), \
            patch("lookup.query_abuseipdb", return_value=failed_source("abuseipdb")):
        with pytest.raises(SourcesUnavailableError):
            lookup("8.8.8.8")


def test_lookup_error_plus_not_configured_still_counts_as_all_failed():
    # No AbuseIPDB key means we never tried it, so the two sources we did try decide.
    not_configured = fake_source("abuseipdb")
    not_configured["status"] = "not_configured"
    with patch("lookup.query_internetdb", return_value=failed_source("internetdb")), \
            patch("lookup.query_rdap", return_value=failed_source("rdap")), \
            patch("lookup.query_abuseipdb", return_value=not_configured):
        with pytest.raises(SourcesUnavailableError):
            lookup("8.8.8.8")


def test_lookup_one_failed_source_still_returns_a_scored_result():
    with patch("lookup.query_internetdb", return_value=failed_source("internetdb")), \
            patch("lookup.query_rdap", return_value=fake_source("rdap")), \
            patch("lookup.query_abuseipdb", return_value=fake_source("abuseipdb")):
        result = lookup("8.8.8.8")

    assert isinstance(result["verdict"]["score"], int)


def test_lookup_private_ip_scores_zero_and_is_not_applicable():
    result = lookup("10.0.0.5")
    assert result["verdict"]["level"] == "not_applicable"
    assert result["verdict"]["score"] == 0
