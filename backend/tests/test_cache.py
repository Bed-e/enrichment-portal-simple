"""Tests for the source cache: a miss, a hit, an expired entry and errors that are not cached.

No test here touches the network. Most patch the three query_* functions in lookup.py, so
we can count how often each source would have been asked. The clock is moved by patching
time.time as seen by cache.py, so "6 hours later" takes no real time.
"""
import os
from unittest.mock import patch

import requests

import cache
from lookup import lookup

HOUR = 60 * 60
FAKE_KEY = "fake-test-key-not-real"  # never a real key


def answer(name, status="ok"):
    """A minimal source result, as a query_* function would return it."""
    return {
        "name": name,
        "display_name": name,
        "status": status,
        "summary": {} if status == "ok" else None,
        "raw": None,
        "error": "boom" if status == "error" else None,
    }


def fake_sources(internetdb="ok", rdap="ok", abuseipdb="ok"):
    """Patch the three source functions in lookup.py. Returns the three patchers."""
    return (
        patch("lookup.query_internetdb", return_value=answer("internetdb", internetdb)),
        patch("lookup.query_rdap", return_value=answer("rdap", rdap)),
        patch("lookup.query_abuseipdb", return_value=answer("abuseipdb", abuseipdb)),
    )


def at_time(seconds):
    """Pretend the clock (as cache.py sees it) says `seconds`."""
    return patch("cache.time.time", return_value=seconds)


def test_miss_then_hit():
    p1, p2, p3 = fake_sources()
    with p1 as internetdb, p2 as rdap, p3 as abuseipdb:
        first = lookup("8.8.8.8")   # miss: every source is asked
        second = lookup("8.8.8.8")  # hit: nobody is asked again

    assert internetdb.call_count == 1
    assert rdap.call_count == 1
    assert abuseipdb.call_count == 1
    assert second["sources"] == first["sources"]  # the same answers, reused


def test_cached_answer_has_exactly_the_contract_fields():
    # The API contract (design.md section 7) must not change: a reused answer has the
    # same six fields as a fresh one, and nothing extra.
    contract_fields = {"name", "display_name", "status", "summary", "raw", "error"}
    p1, p2, p3 = fake_sources()
    with p1, p2, p3:
        fresh = lookup("8.8.8.8")
        reused = lookup("8.8.8.8")

    for result in (fresh, reused):
        for source in result["sources"]:
            assert set(source) == contract_fields


def test_same_ip_spelled_differently_shares_one_entry():
    p1, p2, p3 = fake_sources()
    with p1 as internetdb, p2, p3:
        for text in ["8.8.8.8", " 8.8.8.8", "8.8.8.8 ", "\t8.8.8.8\n"]:
            lookup(text)

    assert internetdb.call_count == 1


def test_two_different_ips_never_share_an_entry():
    p1, p2, p3 = fake_sources()
    with p1 as internetdb, p2, p3:
        lookup("8.8.8.8")
        lookup("8.8.4.4")

    assert internetdb.call_count == 2


def test_expired_entry_asks_the_source_again():
    p1, p2, p3 = fake_sources()
    with p1 as internetdb, p2, p3:
        with at_time(1000):
            lookup("8.8.8.8")
        with at_time(1000 + 24 * HOUR - 1):  # one second before InternetDB's 24 h expiry
            lookup("8.8.8.8")
        assert internetdb.call_count == 1
        with at_time(1000 + 24 * HOUR):      # expired
            lookup("8.8.8.8")

    assert internetdb.call_count == 2


def test_expired_entry_already_removed_by_another_request_is_not_an_error():
    # Simulated race (no threads needed): flask run handles requests in parallel, so two
    # requests can both find the same expired entry. We recreate the moment in between:
    # while get() checks the clock, "another request" removes the entry first.
    with at_time(1000):
        cache.put("internetdb", "8.8.8.8", answer("internetdb"))

    def clock_while_another_request_removes_it():
        cache._entries.pop(("internetdb", "8.8.8.8"), None)  # the other request got there first
        return 1000 + 24 * HOUR  # expired

    with patch("cache.time.time", side_effect=clock_while_another_request_removes_it):
        assert cache.get("internetdb", "8.8.8.8") is None  # no KeyError, just "not cached"


def test_not_found_expires_sooner_than_a_real_answer():
    p1, p2, p3 = fake_sources(internetdb="no_data")
    with p1 as internetdb, p2, p3:
        with at_time(1000):
            lookup("1.0.1.4")
        with at_time(1000 + 6 * HOUR):  # "not found" keeps 6 h, not 24 h
            lookup("1.0.1.4")

    assert internetdb.call_count == 2


def test_error_is_not_cached():
    p1, p2, p3 = fake_sources(internetdb="error")
    with p1 as internetdb, p2 as rdap, p3:
        lookup("8.8.8.8")
        lookup("8.8.8.8")

    assert internetdb.call_count == 2           # the error was asked again
    assert rdap.call_count == 1                 # the good answer next to it was reused


def test_missing_key_is_not_cached():
    p1, p2, p3 = fake_sources(abuseipdb="not_configured")
    with p1, p2, p3 as abuseipdb:
        lookup("8.8.8.8")
        lookup("8.8.8.8")

    assert abuseipdb.call_count == 2


def test_timeout_from_the_network_is_not_cached():
    # Simulated: the real source functions run, but every request times out.
    with patch.dict(os.environ, {}, clear=True), \
            patch("sources.requests.get", side_effect=requests.exceptions.Timeout()) as get:
        lookup("8.8.8.8")
        lookup("8.8.8.8")

    # InternetDB + RDAP, twice each (no key, so AbuseIPDB never sends a request).
    assert get.call_count == 4


def test_cache_key_never_contains_the_api_key():
    with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": FAKE_KEY}):
        p1, p2, p3 = fake_sources()
        with p1, p2, p3:
            lookup("8.8.8.8")

    assert ("abuseipdb", "8.8.8.8") in cache._entries
    assert FAKE_KEY not in repr(list(cache._entries))
