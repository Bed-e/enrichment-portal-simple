"""Tests for the three source functions.

Tests marked "recorded" replay a real response saved in tests/samples/.
Tests marked "simulated" fake a failure we can't record on demand (a timeout,
a 429, a rejected key). No test here touches the network: every one patches requests.get.
"""
import json
import os
from unittest.mock import patch

import requests

from sources import query_abuseipdb, query_internetdb, query_rdap

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")
FAKE_KEY = "fake-test-key-not-real"  # never a real key; only used to check it doesn't leak


def load_sample(filename):
    with open(os.path.join(SAMPLES_DIR, filename)) as f:
        return json.load(f)


class FakeResponse:
    """Stands in for a real response: has just the two things sources.py reads."""

    def __init__(self, status_code, json_data=None):
        self.status_code = status_code
        self._json_data = json_data

    def json(self):
        return self._json_data


def fake_get(status_code, json_data=None):
    """Patch requests.get (as seen by sources.py) to return a FakeResponse."""
    return patch("sources.requests.get", return_value=FakeResponse(status_code, json_data))


def fake_get_raising(error):
    """Patch requests.get to raise an error, like a real network failure would."""
    return patch("sources.requests.get", side_effect=error)


# ---------- InternetDB ----------

def test_internetdb_ok_recorded():
    sample = load_sample("internetdb_ok.json")
    with fake_get(200, sample):
        result = query_internetdb("8.8.8.8")
    assert result["status"] == "ok"
    assert result["raw"] == sample  # the raw JSON is kept
    assert set(result["summary"]) == {"ports", "tags", "vulns", "hostnames", "cpes"}
    assert result["summary"]["ports"] == [53, 443]


def test_internetdb_no_data_recorded():
    with fake_get(404, load_sample("internetdb_no_data.json")):
        result = query_internetdb("1.0.1.4")
    assert result["status"] == "no_data"


def test_internetdb_timeout_simulated():
    with fake_get_raising(requests.exceptions.Timeout()):
        result = query_internetdb("8.8.8.8")
    assert result["status"] == "error"
    assert "timed out" in result["error"]


def test_internetdb_rate_limited_simulated():
    with fake_get(429):
        result = query_internetdb("8.8.8.8")
    assert result["status"] == "error"
    assert "429" in result["error"]


# ---------- RDAP ----------

def test_rdap_ok_recorded():
    sample = load_sample("rdap_ok.json")
    with fake_get(200, sample):
        result = query_rdap("8.8.8.8")
    assert result["status"] == "ok"
    assert result["raw"] == sample
    assert set(result["summary"]) == {
        "network_name", "organization", "country",
        "start_address", "end_address", "registered",
    }
    assert result["summary"]["start_address"] == "8.8.8.0"
    assert result["summary"]["end_address"] == "8.8.8.255"


def test_rdap_no_data_simulated():
    # Simulated: RDAP never answered 404 for a real address, so there is no sample.
    with fake_get(404):
        result = query_rdap("8.8.8.8")
    assert result["status"] == "no_data"


def test_rdap_timeout_simulated():
    with fake_get_raising(requests.exceptions.Timeout()):
        result = query_rdap("8.8.8.8")
    assert result["status"] == "error"


def test_rdap_rate_limited_simulated():
    with fake_get(429):
        result = query_rdap("8.8.8.8")
    assert result["status"] == "error"
    assert "Rate limited" in result["error"]


# ---------- AbuseIPDB ----------
# AbuseIPDB needs a key, so these tests put a fake one in the environment.
# patch.dict puts the environment back as it was when the test ends.

def test_abuseipdb_ok_recorded():
    sample = load_sample("abuseipdb_ok.json")
    with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": FAKE_KEY}), fake_get(200, sample):
        result = query_abuseipdb("8.8.8.8")
    assert result["status"] == "ok"
    assert result["raw"] == sample["data"]
    assert set(result["summary"]) == {
        "abuse_confidence_score", "total_reports", "last_reported_at", "usage_type",
        "isp", "is_tor", "is_whitelisted", "country_code",
    }
    assert result["summary"]["total_reports"] > 0


def test_abuseipdb_no_data_recorded():
    sample = load_sample("abuseipdb_no_data.json")  # a real 200 with totalReports 0
    with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": FAKE_KEY}), fake_get(200, sample):
        result = query_abuseipdb("1.0.1.4")
    assert result["status"] == "no_data"


def test_abuseipdb_rejected_key_simulated():
    with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": FAKE_KEY}), fake_get(401):
        result = query_abuseipdb("8.8.8.8")
    assert result["status"] == "error"
    assert "API key rejected" in result["error"]
    assert FAKE_KEY not in result["error"]  # the key must never appear in a message


def test_abuseipdb_rate_limited_simulated():
    with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": FAKE_KEY}), fake_get(429):
        result = query_abuseipdb("8.8.8.8")
    assert result["status"] == "error"
    assert "Rate limited" in result["error"]


def test_abuseipdb_timeout_simulated():
    with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": FAKE_KEY}), \
            fake_get_raising(requests.exceptions.Timeout()):
        result = query_abuseipdb("8.8.8.8")
    assert result["status"] == "error"


def test_abuseipdb_no_key_means_not_configured_and_no_request():
    # clear=True empties the environment for this test, so there is no key at all.
    with patch.dict(os.environ, {}, clear=True), fake_get(200) as mock_get:
        result = query_abuseipdb("8.8.8.8")
    assert result["status"] == "not_configured"
    mock_get.assert_not_called()  # no key means we must not even try the request
