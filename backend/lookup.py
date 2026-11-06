from datetime import datetime, timezone

import cache
from ip_tools import classify_ip
from sources import query_abuseipdb, query_internetdb, query_rdap
from verdict import score_verdict


def _skipped(name, display_name):
    """A source result for a source we deliberately did not query."""
    return {
        "name": name,
        "display_name": display_name,
        "status": "skipped",
        "summary": None,
        "raw": None,
        "error": None,
        "cached": False,
        "fetched_at": None,  # never asked
    }


def _from_cache_or_query(name, ip, query):
    """Reuse a stored answer if there is a fresh one; otherwise ask the source and store it.

    Adds two fields (design.md section 7): `cached` says whether this answer came from the
    cache, and `fetched_at` says when the source was really asked (None if it never was).
    """
    result = cache.get(name, ip)
    if result is not None:
        result["cached"] = True  # fetched_at stays as it was when first asked
        return result

    result = query(ip)
    result["cached"] = False
    if result["status"] == "not_configured":
        result["fetched_at"] = None  # no key, so the source was never asked
    else:
        result["fetched_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cache.put(name, ip, result)  # only stores ok / no_data
    return result


def lookup(ip_text):
    classification = classify_ip(ip_text)  # may raise ValueError; app.py catches it
    ip = classification["ip"]

    if classification["category"] != "global":
        # Never send private/reserved addresses to outside services.
        sources = [
            _skipped("internetdb", "Shodan InternetDB"),
            _skipped("rdap", "RDAP (registration)"),
            _skipped("abuseipdb", "AbuseIPDB"),
        ]
    else:
        # One after another (no threads): simple, and fast enough for one IP.
        # `ip` is already in standard form (classify_ip strips spaces), so " 8.8.8.8 " and
        # "8.8.8.8" share one cache entry.
        sources = [
            _from_cache_or_query("internetdb", ip, query_internetdb),
            _from_cache_or_query("rdap", ip, query_rdap),
            _from_cache_or_query("abuseipdb", ip, query_abuseipdb),
        ]

    verdict = score_verdict(classification, sources)

    return {
        "ip": ip,
        "classification": classification,
        "verdict": verdict,
        "sources": sources,
    }
