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


def test_all_sources_error_is_unknown():
    result = score_verdict(GLOBAL, [internetdb("error"), rdap("error"), abuseipdb("error")])
    assert result["level"] == "unknown"


def test_only_rdap_answered_is_unknown():
    # RDAP cannot flag a bad IP, so on its own it is not enough evidence.
    result = score_verdict(GLOBAL, [internetdb("error"), rdap("ok"), abuseipdb("not_configured")])
    assert result["level"] == "unknown"


def test_abuseipdb_score_90_is_malicious():
    result = score_verdict(GLOBAL, [internetdb("no_data"), rdap(), abuseipdb(score=90)])
    assert result["level"] == "malicious"
    assert "AbuseIPDB confidence score is 90/100" in result["reasons"]


def test_abuseipdb_score_40_is_suspicious():
    result = score_verdict(GLOBAL, [internetdb("no_data"), rdap(), abuseipdb(score=40)])
    assert result["level"] == "suspicious"


def test_internetdb_c2_tag_is_malicious():
    result = score_verdict(GLOBAL, [internetdb(tags=["c2"]), rdap(), abuseipdb(score=0)])
    assert result["level"] == "malicious"
    assert "InternetDB tag: c2" in result["reasons"]


def test_both_flagging_sources_clean_is_no_known_bad():
    result = score_verdict(GLOBAL, [internetdb(), rdap(), abuseipdb()])
    assert result["level"] == "no_known_bad"
    assert result["score"] == 0


def test_not_configured_abuseipdb_still_no_known_bad_but_says_so():
    result = score_verdict(GLOBAL, [internetdb(), rdap(), abuseipdb("not_configured")])
    assert result["level"] == "no_known_bad"
    assert "AbuseIPDB" in result["summary"]
    assert "not_configured" in result["summary"]


def test_lone_anonymizer_tag_or_cve_stays_no_known_bad_but_is_listed():
    result = score_verdict(GLOBAL, [internetdb(tags=["vpn"], vulns=["CVE-1"]), rdap(), abuseipdb()])
    assert result["score"] == 2  # vpn +1, CVEs +1
    assert result["level"] == "suspicious"
    assert "InternetDB tag: vpn" in result["reasons"]
    assert "1 known CVEs on exposed services" in result["reasons"]


def test_single_cve_alone_is_no_known_bad():
    result = score_verdict(GLOBAL, [internetdb(vulns=["CVE-1"]), rdap(), abuseipdb()])
    assert result["level"] == "no_known_bad"
    assert len(result["reasons"]) == 1


def test_tor_flag_adds_reason():
    result = score_verdict(GLOBAL, [internetdb(), rdap(), abuseipdb(is_tor=True)])
    assert "AbuseIPDB flags this as a Tor exit node" in result["reasons"]
    assert result["level"] == "no_known_bad"  # +1 alone is below the threshold
