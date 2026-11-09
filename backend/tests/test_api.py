"""Tests for the backend endpoint GET /api/ip/<ip>.

Flask's test_client calls a route inside the test with no server running, so nothing
listens on a port. lookup is patched in api.py's namespace, so no source is contacted.
"""
from unittest.mock import patch

from api import app
from lookup import SourcesUnavailableError

# Created once: test_client() gives us an object that can .get() a URL like a browser would.
client = app.test_client()


def test_good_ip_returns_200_with_the_lookup_dict():
    fake_result = {"ip": "8.8.8.8", "classification": {}, "verdict": {}, "sources": []}
    with patch("api.lookup", return_value=fake_result):
        response = client.get("/api/ip/8.8.8.8")

    assert response.status_code == 200
    # get_json() reads the JSON body back into a dict.
    assert set(response.get_json()) == {"ip", "classification", "verdict", "sources"}


def test_invalid_ip_returns_400_invalid_ip():
    # No patch needed: lookup() rejects bad text before any source is contacted.
    response = client.get("/api/ip/not-an-ip")

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "invalid_ip",
        "message": "That is not a valid IP address.",
    }


def test_ipv6_returns_400_unsupported_ip_version():
    response = client.get("/api/ip/::1")

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "unsupported_ip_version",
        "message": "IPv6 is not supported yet.",
    }


def test_unexpected_error_returns_500_without_details():
    # Simulated failure: lookup blows up with a message that must NOT reach the caller.
    with patch("api.lookup", side_effect=RuntimeError("secret internal detail")):
        response = client.get("/api/ip/8.8.8.8")

    assert response.status_code == 500
    assert response.get_json() == {"error": "internal_error", "message": "Something went wrong."}
    assert "secret internal detail" not in response.get_data(as_text=True)
    assert "Traceback" not in response.get_data(as_text=True)


def test_all_sources_down_returns_503_without_details():
    # Simulated: lookup() raises the error it raises when every queried source failed.
    with patch("api.lookup", side_effect=SourcesUnavailableError()):
        response = client.get("/api/ip/8.8.8.8")

    assert response.status_code == 503
    assert response.get_json() == {
        "error": "sources_unavailable",
        "message": "No data source could be reached. Try again shortly.",
    }
