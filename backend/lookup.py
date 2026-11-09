import cache
from ip_tools import classify_ip
from sources import query_abuseipdb, query_internetdb, query_rdap
from verdict import score_verdict


class SourcesUnavailableError(Exception):
    """Every source we tried failed, so there is nothing honest to score.

    A small custom error type lets api.py tell this case apart from bad input (ValueError)
    and from unexpected bugs (any other Exception).
    """


def _all_queried_sources_failed(sources):
    """True when we asked at least one source and every one of them returned "error".

    not_configured (no API key) and skipped (private IP) mean we never tried that source,
    so they are not failures. Private addresses have only skipped sources, so they never match.
    """
    tried = [s for s in sources if s["status"] not in ("not_configured", "skipped")]
    return bool(tried) and all(s["status"] == "error" for s in tried)


def _skipped(name, display_name):
    """A source result for a source we deliberately did not query."""
    return {
        "name": name,
        "display_name": display_name,
        "status": "skipped",
        "summary": None,
        "raw": None,
        "error": None,
    }


def _from_cache_or_query(name, ip, query):
    """Reuse a stored answer if there is a fresh one; otherwise ask the source and store it.

    The answer has exactly the same fields either way, so the API contract (design.md
    section 7) is unchanged. Section 12 explains why no "cached" flag is needed.
    """
    result = cache.get(name, ip)
    if result is not None:
        return result

    result = query(ip)
    cache.put(name, ip, result)  # only stores ok / no_data, never errors or a missing key
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

    # If nothing we tried answered, the cause is probably the network or the providers, not
    # the IP. Any score would be made up, so we raise instead (api.py answers 503).
    if _all_queried_sources_failed(sources):
        raise SourcesUnavailableError()

    verdict = score_verdict(classification, sources)

    return {
        "ip": ip,
        "classification": classification,
        "verdict": verdict,
        "sources": sources,
    }
