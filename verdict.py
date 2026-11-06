"""Turn the source results into one verdict, using a simple points score.

score_verdict() is a "pure function": it only looks at the dicts it is given. It makes no
network calls and does not touch Flask, so it is easy to test with hand-built dicts.
"""

# --- Tuning knobs. These weights and thresholds are placeholders; we review them in M3. ---
ABUSE_HIGH_SCORE = 75      # AbuseIPDB confidence at or above this is strong evidence
ABUSE_MEDIUM_SCORE = 25    # ...at or above this (but below HIGH) is weaker evidence
POINTS_ABUSE_HIGH = 5
POINTS_ABUSE_MEDIUM = 2
POINTS_TOR = 1
POINTS_BAD_TAG = 5
POINTS_ANON_TAG = 1
POINTS_CVES = 1
MALICIOUS_AT = 5           # total >= this -> malicious
SUSPICIOUS_AT = 2          # total >= this -> suspicious; anything lower -> no_known_bad

BAD_TAGS = {"c2", "malware", "compromised"}
ANON_TAGS = {"tor", "vpn", "proxy"}

# Only these sources can raise a red flag. RDAP just says who owns the address.
FLAGGING_SOURCES = ["internetdb", "abuseipdb"]


def _find(sources, name):
    """Return the source result with this name, or None."""
    for source in sources:
        if source["name"] == name:
            return source
    return None


def _score_abuseipdb(summary):
    """Return (points, reasons) for an AbuseIPDB summary dict."""
    points, reasons = 0, []
    score = summary.get("abuse_confidence_score") or 0
    if score >= ABUSE_HIGH_SCORE:
        points += POINTS_ABUSE_HIGH
        reasons.append(f"AbuseIPDB confidence score is {score}/100")
    elif score >= ABUSE_MEDIUM_SCORE:
        points += POINTS_ABUSE_MEDIUM
        reasons.append(f"AbuseIPDB confidence score is {score}/100")
    if summary.get("is_tor"):
        points += POINTS_TOR
        reasons.append("AbuseIPDB flags this as a Tor exit node")
    return points, reasons


def _score_internetdb(summary):
    """Return (points, reasons) for an InternetDB summary dict."""
    points, reasons = 0, []
    for tag in summary.get("tags") or []:
        if tag in BAD_TAGS:
            points += POINTS_BAD_TAG
            reasons.append(f"InternetDB tag: {tag}")
        elif tag in ANON_TAGS:
            points += POINTS_ANON_TAG
            reasons.append(f"InternetDB tag: {tag}")
    vulns = summary.get("vulns") or []
    if vulns:
        points += POINTS_CVES
        reasons.append(f"{len(vulns)} known CVEs on exposed services")
    return points, reasons


def _coverage_text(sources):
    """Say which flagging sources answered and which did not (missing evidence is never good news)."""
    answered, missing = [], []
    for name in FLAGGING_SOURCES:
        source = _find(sources, name)
        if source is None:
            continue
        if source["status"] in ("ok", "no_data"):
            answered.append(source["display_name"])
        else:
            missing.append(f"{source['display_name']} ({source['status']})")
    parts = []
    if answered:
        parts.append("Answered: " + ", ".join(answered) + ".")
    if missing:
        parts.append("No answer from: " + ", ".join(missing) + ", so this is weaker evidence.")
    return " ".join(parts)


def score_verdict(classification, sources):
    """Return {"level", "score", "summary", "reasons"}."""
    # Early exit 1: private/reserved addresses were never queried.
    if classification["category"] != "global":
        return {
            "level": "not_applicable",
            "score": 0,
            "summary": "Private or reserved address. External sources were not queried.",
            "reasons": [],
        }

    # Early exit 2: if no flagging source answered, we have nothing to judge on.
    # "Answered" means ok or no_data; errors and not_configured count as missing.
    coverage = _coverage_text(sources)
    answered_any = any(
        (_find(sources, name) or {}).get("status") in ("ok", "no_data")
        for name in FLAGGING_SOURCES
    )
    if not answered_any:
        return {
            "level": "unknown",
            "score": 0,
            "summary": "No source that can flag bad IPs gave an answer. " + coverage,
            "reasons": [],
        }

    # Scoring: each rule that fires adds points and a reason string.
    score, reasons = 0, []
    abuse = _find(sources, "abuseipdb")
    if abuse and abuse["status"] == "ok":
        points, why = _score_abuseipdb(abuse["summary"])
        score += points
        reasons += why
    internetdb = _find(sources, "internetdb")
    if internetdb and internetdb["status"] == "ok":
        points, why = _score_internetdb(internetdb["summary"])
        score += points
        reasons += why

    if score >= MALICIOUS_AT:
        level, headline = "malicious", "Strong signs of malicious activity."
    elif score >= SUSPICIOUS_AT:
        level, headline = "suspicious", "Some warning signs."
    else:
        # Deliberately not "clean" or "safe": we only know the sources found nothing.
        level, headline = "no_known_bad", "No known bad found."

    return {
        "level": level,
        "score": score,
        "summary": f"{headline} {coverage}",
        "reasons": reasons,
    }
