"""Turn the source results into one verdict: a score from 0 to 100, never None.

The score means: out of 100 IPs that came back with exactly this evidence, about how many
are malicious. So an IP that sources know little or nothing about is NOT treated as neutral:
many unregistered or undocumented IPs are malicious, and missing information adds points.

score_verdict() is a "pure function": it only looks at the dicts it is given. It makes no
network calls and does not touch Flask, so it is easy to test with hand-built dicts.

The formula: start from a small base, add points for each bad sign, add points for each
missing source or empty answer, subtract a few for a known-good flag, then clamp to 0-100.
The level label is derived from that number.

If EVERY queried source failed, lookup.py raises an error before this function is called
(the API answers 503), so there is no "unknown" level any more.
"""

# --- Tuning knobs. These weights and thresholds are judgement, not measured data. ---
BASE_SCORE = 2             # even a fully documented, clean IP is occasionally bad, so never 0

# Missing or empty evidence counts AGAINST the IP (the "undocumented is suspicious" rule).
POINTS_RDAP_NO_DATA = 40   # no registration record at all: the strongest "undocumented" sign
POINTS_RDAP_ERROR = 25     # we could not confirm the registration
POINTS_RDAP_NO_ORG = 10    # registered, but no owner name
POINTS_INTERNETDB_NO_DATA = 10  # never scanned (weak: many legitimate IPs are unscanned too)
POINTS_INTERNETDB_ERROR = 10    # could not check
POINTS_ABUSE_MISSING = 15  # AbuseIPDB error or no key: no reputation evidence
POINTS_ABUSE_NO_DATA = 10  # AbuseIPDB answered but has 0 reports: an undocumented IP, not a vouched-for one

# Evidence about badness.
ABUSE_SCALE = 0.9          # AbuseIPDB's own 0-100 number is multiplied by this
POINTS_TOR = 5
POINTS_BAD_TAG = 60        # per tag: c2, malware, compromised
POINTS_ANON_TAG = 10       # per tag: tor, vpn, proxy
POINTS_CVES = 5            # once, if there are any known CVEs

# The only "known good" signal we have: AbuseIPDB's own allow-list.
POINTS_WHITELISTED = -30

MAX_SCORE = 100
MIN_SCORE = 0              # needed because the whitelist rule subtracts
MALICIOUS_AT = 60          # score >= this -> malicious
SUSPICIOUS_AT = 20         # score >= this -> suspicious; anything lower -> no_known_bad

BAD_TAGS = {"c2", "malware", "compromised"}
ANON_TAGS = {"tor", "vpn", "proxy"}

# Only these sources can say an IP is bad. (RDAP only scores when it has nothing.)
FLAGGING_SOURCES = ["internetdb", "abuseipdb"]


def _find(sources, name):
    """Return the source result with this name, or None."""
    for source in sources:
        if source["name"] == name:
            return source
    return None


def _score_rdap(source):
    """Return (points, reasons) for the RDAP result. RDAP never says "bad", only "undocumented"."""
    if source["status"] == "no_data":
        return POINTS_RDAP_NO_DATA, [
            f"RDAP has no registration record for this address (+{POINTS_RDAP_NO_DATA})"
        ]
    if source["status"] == "error":
        return POINTS_RDAP_ERROR, [
            f"RDAP could not be checked, so registration is unconfirmed (+{POINTS_RDAP_ERROR})"
        ]
    if source["status"] == "ok" and not (source["summary"] or {}).get("organization"):
        return POINTS_RDAP_NO_ORG, [
            f"RDAP registration names no organization (+{POINTS_RDAP_NO_ORG})"
        ]
    return 0, []


def _score_internetdb(source):
    """Return (points, reasons) for the InternetDB result."""
    if source["status"] == "no_data":
        return POINTS_INTERNETDB_NO_DATA, [
            f"InternetDB has never seen this address (+{POINTS_INTERNETDB_NO_DATA})"
        ]
    if source["status"] == "error":
        return POINTS_INTERNETDB_ERROR, [
            f"InternetDB could not be checked (+{POINTS_INTERNETDB_ERROR})"
        ]
    if source["status"] != "ok":
        return 0, []

    summary = source["summary"] or {}
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


def _score_abuseipdb(source):
    """Return (points, reasons) for the AbuseIPDB result."""
    status = source["status"]
    if status in ("error", "not_configured"):
        return POINTS_ABUSE_MISSING, [
            f"AbuseIPDB gave no answer ({status}), so there is no reputation evidence (+{POINTS_ABUSE_MISSING})"
        ]

    points, reasons = 0, []
    if status == "no_data":
        # Answered, but knows nothing about this IP. Less bad than no answer (+15), and
        # the same size as InternetDB's no_data, since both mean "never seen".
        points += POINTS_ABUSE_NO_DATA
        reasons.append(f"AbuseIPDB has no reports about this address (+{POINTS_ABUSE_NO_DATA})")
    summary = source["summary"] or {}  # None when status is no_data (0 reports)
    score = summary.get("abuse_confidence_score") or 0
    # Graded: points grow in proportion to AbuseIPDB's own number, so 76 and 100 differ.
    # round() makes it a whole number (87 * 0.9 = 78.3 -> 78).
    abuse_points = round(score * ABUSE_SCALE)
    if abuse_points > 0:  # a rule worth 0 points adds no reason line
        points += abuse_points
        # Name the multiplier so a reader can see why 76 becomes +68.
        reasons.append(
            f"AbuseIPDB confidence score is {score}/100, counted at x{ABUSE_SCALE} (+{abuse_points})"
        )
    if summary.get("is_tor"):
        points += POINTS_TOR
        reasons.append(f"AbuseIPDB flags this as a Tor exit node (+{POINTS_TOR})")
    # `raw` is set for both ok and no_data, and a whitelisted IP with 0 reports is no_data,
    # so the whitelist flag is read from raw (the source's own field name).
    if (source["raw"] or {}).get("isWhitelisted"):
        points += POINTS_WHITELISTED  # a negative number: this lowers the score
        reasons.append(f"AbuseIPDB lists this address as whitelisted ({POINTS_WHITELISTED})")
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
    """Return {"level", "score", "summary", "reasons"}. "score" is always a whole number 0-100."""
    # The one early exit: private/reserved addresses were never queried.
    # The score is 0 here, but it means "not judged", not "safe": the level says so.
    if classification["category"] != "global":
        return {
            "level": "not_applicable",
            "score": 0,
            "summary": "Private or reserved address. External sources were not queried.",
            "reasons": [],
        }

    # Scoring: each rule that fires adds points and a reason string.
    # The base is listed as a reason too, so the reason lines always add up to the score.
    score = BASE_SCORE
    reasons = [f"Base rate: even a well-documented IP is occasionally malicious (+{BASE_SCORE})"]
    for name, scorer in (
        ("rdap", _score_rdap),
        ("internetdb", _score_internetdb),
        ("abuseipdb", _score_abuseipdb),
    ):
        source = _find(sources, name)
        if source is None:
            continue
        points, why = scorer(source)
        score += points
        reasons += why

    # Strong signals can stack past 100, and the whitelist rule can push below 0.
    clamped = max(MIN_SCORE, min(score, MAX_SCORE))
    if clamped != score:
        # Show the adjustment as a line (e.g. 143 -> 100 is -43) so the lines still add up.
        reasons.append(f"Score limited to the range {MIN_SCORE} to {MAX_SCORE} ({clamped - score:+d})")
    score = clamped

    if score >= MALICIOUS_AT:
        level, headline = "malicious", "Strong signs of malicious activity."
    elif score >= SUSPICIOUS_AT:
        level, headline = "suspicious", "Some warning signs, or too little is known about this address."
    else:
        # Deliberately not "clean" or "safe": we only know the sources found nothing bad.
        level, headline = "no_known_bad", "No known bad found."

    return {
        "level": level,
        "score": score,
        "summary": f"{headline} {_coverage_text(sources)}",
        "reasons": reasons,
    }
