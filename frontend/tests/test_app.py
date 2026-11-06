"""Tests for the frontend: POST /lookup should call the backend and show what comes back.

requests.get is patched in app.py's namespace, so the real backend is never contacted.
The success test replays a real backend answer recorded with curl (tests/samples/).
"""
import json
import os
from unittest.mock import patch

import requests

from app import app

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")
UNAVAILABLE = "The lookup service is unavailable. Is the backend running?"

client = app.test_client()


class FakeResponse:
    """Stands in for a real response: has just what app.py reads from one."""

    def __init__(self, status_code, json_data=None):
        self.status_code = status_code
        self._json_data = json_data

    def json(self):
        if self._json_data is None:
            raise ValueError("not JSON")
        return self._json_data


def post_lookup(ip_text, fake):
    """Submit the form with requests.get replaced by `fake` (a FakeResponse or an exception)."""
    patcher = patch("app.requests.get", side_effect=fake) if isinstance(fake, Exception) \
        else patch("app.requests.get", return_value=fake)
    with patcher as mock_get:
        response = client.post("/lookup", data={"ip": ip_text})
    return response, mock_get


def test_success_shows_verdict_and_three_cards():
    with open(os.path.join(SAMPLES_DIR, "backend_ok.json"), encoding="utf-8") as f:
        sample = json.load(f)

    response, mock_get = post_lookup("8.8.8.8", FakeResponse(200, sample))
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "verdict-no_known_bad" in page
    for source in sample["sources"]:
        assert source["display_name"] in page
    # The frontend asks the backend for this address, with a timeout so it can't hang forever.
    assert mock_get.call_args.args[0].endswith("/api/ip/8.8.8.8")
    assert mock_get.call_args.kwargs["timeout"] == 30


def test_400_shows_the_backends_message():
    # Simulated: the message text is the contract's invalid_ip body, not a recording.
    body = {"error": "invalid_ip", "message": "That is not a valid IP address."}
    response, _ = post_lookup("abc", FakeResponse(400, body))

    assert "That is not a valid IP address." in response.get_data(as_text=True)


def test_500_shows_unavailable_message():
    response, _ = post_lookup("8.8.8.8", FakeResponse(500, {"error": "internal_error"}))

    assert UNAVAILABLE in response.get_data(as_text=True)


def test_connection_error_shows_unavailable_message():
    # Simulated: the backend is stopped.
    response, _ = post_lookup("8.8.8.8", requests.exceptions.ConnectionError("refused"))

    assert UNAVAILABLE in response.get_data(as_text=True)


def test_timeout_shows_unavailable_message():
    # Simulated: the backend takes longer than 30 seconds.
    response, _ = post_lookup("8.8.8.8", requests.exceptions.Timeout("too slow"))

    assert UNAVAILABLE in response.get_data(as_text=True)


def test_answer_that_is_not_json_shows_unavailable_message():
    # Simulated: a 200 whose body can't be read as JSON.
    response, _ = post_lookup("8.8.8.8", FakeResponse(200, None))

    assert UNAVAILABLE in response.get_data(as_text=True)
