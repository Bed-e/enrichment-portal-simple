from verdict import score_verdict

GLOBAL = {"category": "global", "explanation": None}


# --- Small helpers that build hand-made source results (no network involved). ---
def make_source(name, display_name, status="ok", summary=None, raw=None):
    return {
        "name": name,
        "display_name": display_name,
        "status": status,
        "summary": summary,
        "raw": raw,
        "error": "boom" if status == "error" else None,
    }


def internetdb(status="ok", tags=(), vulns=()):
    summary = {"tags": list(tags), "vulns": list(vulns)} if status == "ok" else None
    return make_source("internetdb", "Shodan InternetDB", status, summary)


def abuseipdb(status="ok", score=0, is_tor=False, whitelisted=False):
    summary = (
        {"abuse_confidence_score": score, "is_tor": is_tor} if status == "ok" else None
    )
    raw = {"isWhitelisted": whitelisted} if status in ("ok", "no_data") else None
    return make_source("abuseipdb", "AbuseIPDB", status, summary, raw)


def rdap(status="ok", organization="Example Org"):
    summary = {"organization": organization} if status == "ok" else None
    return make_source("rdap", "RDAP (registration)", status, summary)


# A fully documented, clean IP: every source answered and found nothing bad.
def clean_sources():
    return [internetdb(), rdap(), abuseipdb()]


# --- Private addresses and the "never None" rule ---
def test_private_address_is_not_applicable_with_score_zero():
    private = {"category": "private", "explanation": "..."}
    result = score_verdict(private, [internetdb("skipped"), rdap("skipped"), abuseipdb("skipped")])
    assert result["level"] == "not_applicable"
    assert result["score"] == 0  # a number is required; the level says it means "not judged"
    assert result["reasons"] == []


def test_score_is_never_none_for_a_public_address():
    cases = [
        clean_sources(),
        [internetdb("no_data"), rdap("no_data"), abuseipdb("no_data")],
        [internetdb("error"), rdap("ok"), abuseipdb("not_configured")],
    ]
    for sources in cases:
        result = score_verdict(GLOBAL, sources)
        assert isinstance(result["score"], int)
        assert 0 <= result["score"] <= 100


# --- Worked examples from design.md section 3.4 ---
def test_fully_documented_clean_ip_is_2_and_no_known_bad():
    result = score_verdict(GLOBAL, clean_sources())
    assert result["score"] == 2  # just the base
    assert result["level"] == "no_known_bad"
    # Only the base line: rules worth 0 points add no reason line.
    assert len(result["reasons"]) == 1
    assert "Base rate" in result["reasons"][0] and "+2" in result["reasons"][0]


def test_everything_no_data_is_62_and_malicious():
    # No registration (+40), never scanned (+10), no reports (+10), base 2.
    result = score_verdict(GLOBAL, [internetdb("no_data"), rdap("no_data"), abuseipdb("no_data")])
    assert result["score"] == 62
    assert result["level"] == "malicious"


def test_rdap_ok_internetdb_no_data_abuse_not_configured_is_27():
    result = score_verdict(GLOBAL, [internetdb("no_data"), rdap(), abuseipdb("not_configured")])
    assert result["score"] == 27  # 2 + 0 + 10 + 15
    assert result["level"] == "suspicious"


def test_abuseipdb_87_is_80_and_malicious():
    result = score_verdict(GLOBAL, [internetdb(), rdap(), abuseipdb(score=87)])
    assert result["score"] == 80  # base 2 + round(87 * 0.9 = 78.3) = 78
    assert result["level"] == "malicious"
    assert "AbuseIPDB confidence score is 87/100, counted at x0.9 (+78)" in result["reasons"]


# --- Each missing-evidence rule on its own (all other sources documented and clean) ---
def test_rdap_no_data_adds_40():
    result = score_verdict(GLOBAL, [internetdb(), rdap("no_data"), abuseipdb()])
    assert result["score"] == 42
    assert any("no registration record" in r and "+40" in r for r in result["reasons"])


def test_rdap_error_adds_25():
    result = score_verdict(GLOBAL, [internetdb(), rdap("error"), abuseipdb()])
    assert result["score"] == 27
    assert any("+25" in r for r in result["reasons"])


def test_rdap_without_organization_adds_10():
    result = score_verdict(GLOBAL, [internetdb(), rdap(organization=None), abuseipdb()])
    assert result["score"] == 12
    assert any("no organization" in r and "+10" in r for r in result["reasons"])


def test_internetdb_no_data_and_error_each_add_10():
    for status in ("no_data", "error"):
        result = score_verdict(GLOBAL, [internetdb(status), rdap(), abuseipdb()])
        assert result["score"] == 12
        assert any("+10" in r for r in result["reasons"])


def test_abuseipdb_error_and_not_configured_each_add_15():
    for status in ("error", "not_configured"):
        result = score_verdict(GLOBAL, [internetdb(), rdap(), abuseipdb(status)])
        assert result["score"] == 17
        assert any("+15" in r for r in result["reasons"])


def test_abuseipdb_no_data_adds_10():
    result = score_verdict(GLOBAL, [internetdb(), rdap(), abuseipdb("no_data")])
    assert result["score"] == 12
    assert any("no reports" in r and "+10" in r for r in result["reasons"])


# --- Evidence about badness ---
def test_scaling_is_graded():
    # The same rule gives 76 and 100 different points.
    at_76 = score_verdict(GLOBAL, [internetdb(), rdap(), abuseipdb(score=76)])
    at_100 = score_verdict(GLOBAL, [internetdb(), rdap(), abuseipdb(score=100)])
    assert at_76["score"] == 2 + 68  # round(68.4)
    assert at_100["score"] == 2 + 90


def test_internetdb_c2_tag_adds_60():
    result = score_verdict(GLOBAL, [internetdb(tags=["c2"]), rdap(), abuseipdb()])
    assert result["score"] == 62
    assert result["level"] == "malicious"
    assert "InternetDB tag: c2 (+60)" in result["reasons"]


def test_c2_tag_with_abuseipdb_90_is_capped_at_100():
    # 2 + 60 + 81 = 143 before the cap.
    result = score_verdict(GLOBAL, [internetdb(tags=["c2"]), rdap(), abuseipdb(score=90)])
    assert result["score"] == 100
    # base + c2 + AbuseIPDB + the cap line: nothing is hidden, and the lines add up (see below).
    assert len(result["reasons"]) == 4
    assert "Score limited to the range 0 to 100 (-43)" in result["reasons"]


def test_anonymizer_tag_is_10_and_cve_is_5():
    result = score_verdict(GLOBAL, [internetdb(tags=["vpn"], vulns=["CVE-1"]), rdap(), abuseipdb()])
    assert result["score"] == 2 + 10 + 5
    assert result["level"] == "no_known_bad"
    assert "InternetDB tag: vpn (+10)" in result["reasons"]
    assert "1 known CVEs on exposed services (+5)" in result["reasons"]


def test_tor_flag_adds_5_and_a_reason():
    result = score_verdict(GLOBAL, [internetdb(), rdap(), abuseipdb(is_tor=True)])
    assert "AbuseIPDB flags this as a Tor exit node (+5)" in result["reasons"]
    assert result["score"] == 7


# --- Whitelist and the floor ---
def test_whitelisted_subtracts_30_but_never_goes_below_zero():
    # Documented clean + whitelisted: 2 + 10 - 30 = -18, clamped to 0.
    result = score_verdict(GLOBAL, [internetdb(), rdap(), abuseipdb("no_data", whitelisted=True)])
    assert result["score"] == 0
    assert any("whitelisted" in r and "-30" in r for r in result["reasons"])


def test_whitelisted_lowers_an_otherwise_suspicious_score():
    # base 2 + no registration 40 + no reports 10 - whitelist 30 = 22
    result = score_verdict(
        GLOBAL, [internetdb(), rdap("no_data"), abuseipdb("no_data", whitelisted=True)]
    )
    assert result["score"] == 22


# --- Level boundaries (19/20 and 59/60) ---
def test_level_boundaries():
    # (AbuseIPDB number, expected score, expected level). Score = base 2 + round(number * 0.9):
    # 19 -> 2 + 17, 20 -> 2 + 18, 63 -> 2 + 57, 64 -> 2 + 58.
    cases = [
        (19, 19, "no_known_bad"),
        (20, 20, "suspicious"),
        (63, 59, "suspicious"),
        (64, 60, "malicious"),
    ]
    for abuse_number, expected_score, expected_level in cases:
        result = score_verdict(GLOBAL, [internetdb(), rdap(), abuseipdb(score=abuse_number)])
        assert result["score"] == expected_score
        assert result["level"] == expected_level


# --- Summary text ---
def test_not_configured_abuseipdb_is_named_in_the_summary():
    result = score_verdict(GLOBAL, [internetdb(), rdap(), abuseipdb("not_configured")])
    assert "AbuseIPDB" in result["summary"]
    assert "not_configured" in result["summary"]


# --- The reason lines must add up to the score ---
def points_in(reason):
    """Read the number in the last pair of brackets of a reason line, e.g. '... (+10)' -> 10."""
    return int(reason.rsplit("(", 1)[1].rstrip(")"))


def test_reason_points_always_add_up_to_the_score():
    cases = [
        clean_sources(),
        [internetdb("no_data"), rdap("no_data"), abuseipdb("no_data")],
        [internetdb("error"), rdap("error"), abuseipdb("not_configured")],
        [internetdb(tags=["c2"], vulns=["CVE-1"]), rdap(), abuseipdb(score=90, is_tor=True)],  # capped
        [internetdb(), rdap(), abuseipdb("no_data", whitelisted=True)],                        # floored
        [internetdb(tags=["vpn", "tor"]), rdap(organization=None), abuseipdb(score=40)],
    ]
    for sources in cases:
        result = score_verdict(GLOBAL, sources)
        assert sum(points_in(r) for r in result["reasons"]) == result["score"]
