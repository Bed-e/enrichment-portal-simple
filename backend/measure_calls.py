"""Count how many HTTP requests a fixed run of lookups sends to each source.

Run it from inside backend/:   python measure_calls.py

Nothing goes to the internet and no quota is spent: requests.get is swapped for a fake
(the same idea as the tests) that counts each call and hands back a recorded sample from
tests/samples/. Run it before and after a change and compare the numbers.
"""
import json
import os
from collections import Counter
from unittest.mock import patch
from urllib.parse import urlparse

import requests

from lookup import lookup

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "tests", "samples")

# The fixed run: 26 lookups. Repeats, the same IP spelled with extra spaces, private IPs
# (never sent anywhere) and one IP whose InternetDB request always times out (an error,
# which must never be cached, so it is asked again every time).
RUN = [
    "8.8.8.8", " 8.8.8.8", "8.8.8.8 ", "8.8.8.8\t",
    "1.1.1.1", "1.1.1.1", " 1.1.1.1 ",
    "1.0.1.4", "1.0.1.4",          # sources know nothing about it: "not found" answers
    "9.9.9.9", "9.9.9.9",
    "8.8.4.4", "8.8.4.4", "8.8.4.4",
    "208.67.222.222", "208.67.222.222",
    "4.2.2.2", "4.2.2.2",          # InternetDB times out for this one
    "10.0.0.5", "192.168.1.1", "10.0.0.5",   # private: skipped, never sent
    "8.8.8.8", "1.1.1.1", "9.9.9.9", "1.0.1.4", "8.8.4.4",
]
NO_DATA_IP = "1.0.1.4"
TIMEOUT_IP = "4.2.2.2"


def load_sample(filename):
    with open(os.path.join(SAMPLES_DIR, filename), encoding="utf-8") as f:
        return json.load(f)


class FakeResponse:
    """Just what sources.py reads from a response: status_code and .json()."""

    def __init__(self, status_code, json_data):
        self.status_code = status_code
        self._json_data = json_data

    def json(self):
        return self._json_data


calls = Counter()  # host name -> number of requests


def fake_get(url, headers=None, timeout=None):
    """Count the request, then answer with a recorded sample instead of the network."""
    host = urlparse(url).hostname
    calls[host] += 1
    if host == "internetdb.shodan.io":
        if TIMEOUT_IP in url:
            raise requests.exceptions.Timeout()
        if NO_DATA_IP in url:
            return FakeResponse(404, load_sample("internetdb_no_data.json"))
        return FakeResponse(200, load_sample("internetdb_ok.json"))
    if host == "rdap.org":
        return FakeResponse(200, load_sample("rdap_ok.json"))
    if host == "api.abuseipdb.com":
        if NO_DATA_IP in url:
            return FakeResponse(200, load_sample("abuseipdb_no_data.json"))
        return FakeResponse(200, load_sample("abuseipdb_ok.json"))
    raise AssertionError(f"unexpected host {host}")


def main():
    # A fake key, set only inside this process, so the AbuseIPDB path runs. Never a real key.
    with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "fake-key-for-measuring"}), \
            patch("sources.requests.get", side_effect=fake_get):
        for ip_text in RUN:
            lookup(ip_text)

    print(f"Lookups run: {len(RUN)}")
    for host in ("internetdb.shodan.io", "rdap.org", "api.abuseipdb.com"):
        print(f"  {host:22} {calls[host]:3} requests")
    print(f"  {'total':22} {sum(calls.values()):3} requests")


if __name__ == "__main__":
    main()
