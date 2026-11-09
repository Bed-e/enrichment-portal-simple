from verdict import score_verdict

GLOBAL = {"category": "global", "explanation": None}


# --- Small helpers that build hand-made source results (no network involved). ---
def make_source(name, display_name, status="ok", summary=None):
    return {
        "name": name,
        "display_name": display_name,
        "status": status,
        "summary": summary,
        "raw": None,
        "error": "boom" if status == "error" else None,
    }


def internetdb(status="ok", tags=(), vulns=()):
    summary = {"tags": list(tags), "vulns": list(vulns)} if status == "ok" else None
    return make_source("internetdb", "Shodan InternetDB", status, summary)


def abuseipdb(status="ok", score=0, is_tor=False):
    summary = (
        {"abuse_confidence_score": score, "is_tor": is_tor} if status == "ok" else None
    )
    return make_source("abuseipdb", "AbuseIPDB", status, summary)


def rdap(status="ok"):
    return make_source("rdap", "RDAP (registration)", status, {"name": "x"} if status == "ok" else None)


def test_private_address_is_not_applicable():
    private = {"category": "private", "explanation": "..."}
    result = score_verdict(private, [internetdb("skipped"), rdap("skipped"), abuseipdb("skipped")])
    assert result["level"] == "not_applicable"
    assert result["score"] is None  # no evidence, so None and not 0


def test_all_sources_error_is_unknown():
    result = score_verdict(GLOBAL, [internetdb("error"), rdap("error"), abuseipdb("error")])
    assert result["level"] == "unknown"
    assert result["score"] is None  # None, not 0: 0 would read as "certainly fine"


def test_only_rdap_answered_is_unknown():
    # RDAP cannot flag a bad IP, so on its own it is not enough evidence.
    result = score_verdict(GLOBAL, [internetdb("error"), rdap("ok"), abuseipdb("not_configured")])
    assert result["level"] == "unknown"
    assert result["score"] is None


def test_abuseipdb_87_alone_is_70_and_malicious():
    result = score_verdict(GLOBAL, [internetdb("no_data"), rdap(), abuseipdb(score=87)])
    assert result["score"] == 70  # 87 * 0.8 = 69.6, rounded
    assert result["level"] == "malicious"
    assert "AbuseIPDB confidence score is 87/100 (+70)" in result["reasons"]


def test_abuseipdb_40_and_tor_is_37_and_suspicious():
    result = score_verdict(GLOBAL, [internetdb("no_data"), rdap(), abuseipdb(score=40, is_tor=True)])
    assert result["score"] == 37  # 32 from the score + 5 for Tor
    assert result["level"] == "suspicious"


def test_scaling_is_graded():
    # The old flat rule gave 76 and 100 the same points. Now they differ.
    at_76 = score_verdict(GLOBAL, [internetdb(), rdap(), abuseipdb(score=76)])
    at_100 = score_verdict(GLOBAL, [internetdb(), rdap(), abuseipdb(score=100)])
    assert at_76["score"] == 61
    assert at_100["score"] == 80


def test_internetdb_c2_tag_is_60_and_malicious():
    result = score_verdict(GLOBAL, [internetdb(tags=["c2"]), rdap(), abuseipdb(score=0)])
    assert result["score"] == 60
    assert result["level"] == "malicious"
    assert "InternetDB tag: c2 (+60)" in result["reasons"]


def test_c2_tag_with_abuseipdb_90_is_capped_at_100():
    # 60 + 72 = 132 before the cap.
    result = score_verdict(GLOBAL, [internetdb(tags=["c2"]), rdap(), abuseipdb(score=90)])
    assert result["score"] == 100
    assert len(result["reasons"]) == 2  # the cap hides no reason


def test_level_boundaries():
    # (AbuseIPDB number, expected score, expected level) on each side of 20 and 60.
    cases = [
        (24, 19, "no_known_bad"),
        (25, 20, "suspicious"),
        (74, 59, "suspicious"),
        (75, 60, "malicious"),
    ]
    for abuse_number, expected_score, expected_level in cases:
        result = score_verdict(GLOBAL, [internetdb(), rdap(), abuseipdb(score=abuse_number)])
        assert result["score"] == expected_score
        assert result["level"] == expected_level


def test_both_flagging_sources_clean_is_zero_and_no_known_bad():
    result = score_verdict(GLOBAL, [internetdb(), rdap(), abuseipdb()])
    assert result["level"] == "no_known_bad"
    assert result["score"] == 0  # a real 0: sources looked and found nothing
    assert result["reasons"] == []  # rules worth 0 points add no reason line


def test_not_configured_abuseipdb_still_no_known_bad_but_says_so():
    result = score_verdict(GLOBAL, [internetdb(), rdap(), abuseipdb("not_configured")])
    assert result["level"] == "no_known_bad"
    assert "AbuseIPDB" in result["summary"]
    assert "not_configured" in result["summary"]


def test_lone_anonymizer_tag_and_cve_stay_no_known_bad_but_are_listed():
    result = score_verdict(GLOBAL, [internetdb(tags=["vpn"], vulns=["CVE-1"]), rdap(), abuseipdb()])
    assert result["score"] == 10  # vpn +5, CVEs +5
    assert result["level"] == "no_known_bad"
    assert "InternetDB tag: vpn (+5)" in result["reasons"]
    assert "1 known CVEs on exposed services (+5)" in result["reasons"]


def test_single_cve_alone_is_no_known_bad():
    result = score_verdict(GLOBAL, [internetdb(vulns=["CVE-1"]), rdap(), abuseipdb()])
    assert result["score"] == 5
    assert result["level"] == "no_known_bad"
    assert len(result["reasons"]) == 1


def test_tor_flag_adds_reason():
    result = score_verdict(GLOBAL, [internetdb(), rdap(), abuseipdb(is_tor=True)])
    assert "AbuseIPDB flags this as a Tor exit node (+5)" in result["reasons"]
    assert result["score"] == 5
    assert result["level"] == "no_known_bad"  # 5 alone is below the threshold
