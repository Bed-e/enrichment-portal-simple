"""Tests for lookup(): it should combine classification, sources and verdict.

The three query_* functions are patched in lookup.py's namespace, so no source is
contacted and these tests need no sample files.
"""
from unittest.mock import patch

import pytest

from lookup import lookup


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
