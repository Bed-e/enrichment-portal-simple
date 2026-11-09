"""A small in-memory cache for source answers, so repeat lookups don't spend quota.

The cache is a plain dict that lives inside the running backend. It is empty again
whenever the backend restarts. design.md section 12 explains the expiry times.
"""
import copy
import time

HOUR = 60 * 60
DAY = 24 * HOUR

# How long each kind of answer may be reused, per source (reasons in design.md section 12).
# Only "ok" and "no_data" are listed: errors and not_configured are never stored.
TTL_SECONDS = {
    "internetdb": {"ok": DAY, "no_data": 6 * HOUR},
    "rdap": {"ok": 7 * DAY, "no_data": DAY},
    "abuseipdb": {"ok": 6 * HOUR, "no_data": HOUR},
}

# (source name, ip) -> (time stored, source result). The key never holds an API key.
_entries = {}


def get(source, ip):
    """Return a copy of the stored result, or None if there is none or it has expired."""
    entry = _entries.get((source, ip))
    if entry is None:
        return None
    stored_at, result = entry
    if time.time() - stored_at >= TTL_SECONDS[source][result["status"]]:
        # Expired: forget it, so the source is asked again. pop(..., None) instead of del:
        # flask run handles requests in parallel threads, so another request for the same
        # expired entry may have removed it already, and del would then raise KeyError (a 500).
        _entries.pop((source, ip), None)
        return None
    # A copy, so a caller changing the dict can't change what is stored.
    return copy.deepcopy(result)


def put(source, ip, result):
    """Store a result, but only real answers. Errors and not_configured are never stored."""
    if result["status"] in TTL_SECONDS.get(source, {}):
        _entries[(source, ip)] = (time.time(), copy.deepcopy(result))


def clear():
    """Forget everything (used by the tests, so one test can't see another's answers)."""
    _entries.clear()
