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
