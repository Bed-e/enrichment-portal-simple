from ip_tools import classify_ip
from sources import query_abuseipdb, query_internetdb, query_rdap


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
        sources = [query_internetdb(ip), query_rdap(ip), query_abuseipdb(ip)]

    return {"ip": ip, "classification": classification, "sources": sources}
