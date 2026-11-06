import os

import requests

TIMEOUT_SECONDS = 8


def _get_json(url, headers=None):
    """Make one GET request. Returns (response, error_message); exactly one is None."""
    try:
        response = requests.get(url, headers=headers, timeout=TIMEOUT_SECONDS)
    except requests.Timeout:
        return None, "Request timed out"
    except requests.RequestException as e:
        return None, f"Network error: {type(e).__name__}"
    return response, None


def query_internetdb(ip):
    """Shodan InternetDB: open ports, tags and CVEs. No API key needed."""
    result = {
        "name": "internetdb",
        "display_name": "Shodan InternetDB",
        "status": "error",
        "summary": None,
        "raw": None,
        "error": None,
    }

    response, error = _get_json(f"https://internetdb.shodan.io/{ip}")
    if error:
        result["error"] = error
        return result

    if response.status_code == 404:  # InternetDB's way of saying "nothing known"
        result["status"] = "no_data"
        return result

    if response.status_code != 200:
        # 429 (rate limit) and anything else unexpected end up here
        result["error"] = f"HTTP {response.status_code}"
        return result

    try:
        data = response.json()
    except ValueError:
        result["error"] = "Response was not valid JSON"
        return result

    result["status"] = "ok"
    result["raw"] = data
    result["summary"] = {
        "ports": data.get("ports", []),
        "tags": data.get("tags", []),
        "vulns": data.get("vulns", []),
        "hostnames": data.get("hostnames", []),
        "cpes": data.get("cpes", []),
    }
    return result


def query_rdap(ip):
    """RDAP: who registered this address block (owner, country, dates). No API key needed.

    RDAP says who OWNS an address, not whether it is bad, so it never affects the verdict.
    """
    result = {
        "name": "rdap",
        "display_name": "RDAP (registration)",
        "status": "error",
        "summary": None,
        "raw": None,
        "error": None,
    }

    # rdap.org answers with a redirect to the right regional registry (ARIN, RIPE...);
    # requests follows that redirect for us.
    response, error = _get_json(f"https://rdap.org/ip/{ip}")
    if error:
        result["error"] = error
        return result

    if response.status_code == 404:  # no registry known for this address
        result["status"] = "no_data"
        return result

    if response.status_code == 429:
        result["error"] = "Rate limited by rdap.org (about 10 requests per 10 seconds)"
        return result

    if response.status_code != 200:
        result["error"] = f"HTTP {response.status_code}"
        return result

    try:
        data = response.json()
    except ValueError:
        result["error"] = "Response was not valid JSON"
        return result

    # The organization name is buried in a list of "entities", each with a vCard
    # (a contact-card format): ["vcard", [["fn", {}, "text", "Google LLC"], ...]].
    # We take the first entity that has an "fn" (formatted name) line. If the
    # layout is different from what we expect, org stays None rather than crashing.
    org = None
    for entity in data.get("entities", []):
        vcard = entity.get("vcardArray")
        if not vcard or len(vcard) < 2:
            continue
        for field in vcard[1]:
            if field[0] == "fn":
                org = field[3]
                break
        if org:
            break

    # "events" is a list like [{"eventAction": "registration", "eventDate": "..."}]
    registered = None
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            registered = event.get("eventDate")

    result["status"] = "ok"
    result["raw"] = data
    result["summary"] = {
        "network_name": data.get("name"),
        "organization": org,
        "country": data.get("country"),  # many registries leave this out
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
        "registered": registered,
    }
    return result


def query_abuseipdb(ip):
    """AbuseIPDB: how often this IP was reported for abuse. Needs a free API key.

    This only READS (the /check endpoint). We never report an IP to AbuseIPDB.
    """
    result = {
        "name": "abuseipdb",
        "display_name": "AbuseIPDB",
        "status": "error",
        "summary": None,
        "raw": None,
        "error": None,
    }

    # The key comes from the environment (loaded from .env in app.py).
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        result["status"] = "not_configured"
        return result

    # The key goes only in a header: never in the URL, never in logs or the page.
    # `ip` is safe to put in the URL: classify_ip() already proved it is a valid IPv4 address.
    url ="https://api.abuseipdb.com/api/v2/check"
    response, error = _get_json(
        f"{url}?ipAddress={ip}&maxAgeInDays=90",
        headers={"Key": api_key, "Accept": "application/json"},
    )
    if error:
        result["error"] = error
        return result

    if response.status_code in (401, 403):
        result["error"] = "API key rejected"  # deliberately does not include the key
        return result

    if response.status_code == 429:
        result["error"] = "Rate limited (free tier allows 1,000 checks per day)"
        return result

    if response.status_code != 200:
        result["error"] = f"HTTP {response.status_code}"
        return result

    try:
        data = response.json()["data"]
    except (ValueError, KeyError):
        result["error"] = "Response was not in the expected format"
        return result

    result["raw"] = data

    # Zero reports means AbuseIPDB answered but knows nothing bad about this IP.
    if data.get("totalReports") == 0:
        result["status"] = "no_data"
        return result

    result["status"] = "ok"
    result["summary"] = {
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "last_reported_at": data.get("lastReportedAt"),
        "usage_type": data.get("usageType"),
        "isp": data.get("isp"),
        "is_tor": data.get("isTor"),
        "is_whitelisted": data.get("isWhitelisted"),
        "country_code": data.get("countryCode"),
    }
    return result
