"""Turn the source results into one verdict: a 0 to 100 certainty of malicious activity.

score_verdict() is a "pure function": it only looks at the dicts it is given. It makes no
network calls and does not touch Flask, so it is easy to test with hand-built dicts.

The formula: scale AbuseIPDB's own 0-100 number, add a few fixed amounts for yes/no facts
(tags, Tor, CVEs), then cap the total at 100. The level label is derived from that number.
"""

# --- Tuning knobs. These weights and thresholds are placeholders. ---
ABUSE_SCALE = 0.8          # AbuseIPDB's 0-100 number is multiplied by this (so it gives 0-80 points)
POINTS_TOR = 5
POINTS_BAD_TAG = 60        # per tag: c2, malware, compromised
POINTS_ANON_TAG = 5        # per tag: tor, vpn, proxy
POINTS_CVES = 5            # once, if there are any known CVEs
MAX_SCORE = 100            # the total is capped here: a certainty above 100 makes no sense
MALICIOUS_AT = 60          # score >= this -> malicious
SUSPICIOUS_AT = 20         # score >= this -> suspicious; anything lower -> no_known_bad

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
    # Graded: points grow in proportion to AbuseIPDB's own number, so 76 and 100 differ.
    # round() makes it a whole number (87 * 0.8 = 69.6 -> 70).
    abuse_points = round(score * ABUSE_SCALE)
    if abuse_points > 0:  # a rule worth 0 points adds no reason line
        points += abuse_points
        reasons.append(f"AbuseIPDB confidence score is {score}/100 (+{abuse_points})")
    if summary.get("is_tor"):
        points += POINTS_TOR
        reasons.append(f"AbuseIPDB flags this as a Tor exit node (+{POINTS_TOR})")
    return points, reasons


def _score_internetdb(summary):
    """Return (points, reasons) for an InternetDB summary dict."""
    points, reasons = 0, []
    for tag in summary.get("tags") or []:
        if tag in BAD_TAGS:
            points += POINTS_BAD_TAG
            reasons.append(f"InternetDB tag: {tag} (+{POINTS_BAD_TAG})")
        elif tag in ANON_TAGS:
            points += POINTS_ANON_TAG
            reasons.append(f"InternetDB tag: {tag} (+{POINTS_ANON_TAG})")
    vulns = summary.get("vulns") or []
    if vulns:
        points += POINTS_CVES
        reasons.append(f"{len(vulns)} known CVEs on exposed services (+{POINTS_CVES})")
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
    """Return {"level", "score", "summary", "reasons"}.

    "score" is the certainty of malicious activity, 0 to 100, or None when there is no
    evidence to judge on. None is not 0: a 0 would read as "certainly not malicious".
    """
    # Early exit 1: private/reserved addresses were never queried.
    if classification["category"] != "global":
        return {
            "level": "not_applicable",
            "score": None,
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
            "score": None,
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

    # Two strong signals together (e.g. a c2 tag and a high AbuseIPDB score) would pass 100.
    # The reasons list still shows every rule that fired, so the cap hides nothing.
    score = min(score, MAX_SCORE)

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
