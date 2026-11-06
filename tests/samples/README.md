# Recorded samples

Unedited response bodies from the real services, saved by hand with `curl`
(see design.md section 10). The tests replay these files, so no test touches the network.
If a service changes its format, re-record the file and run the tests again.

| File | Address | Recorded | Notes |
|---|---|---|---|
| `internetdb_ok.json` | 8.8.8.8 | 2026-11-06 | HTTP 200 |
| `internetdb_no_data.json` | 1.0.1.4 | 2026-11-06 | HTTP 404 body ("No information available") |
| `rdap_ok.json` | 8.8.8.8 | 2026-11-06 | HTTP 200, after following rdap.org's redirect (`curl -L`) |
| `abuseipdb_ok.json` | 8.8.8.8 | 2026-11-06 | HTTP 200, `totalReports` above 0 |
| `abuseipdb_no_data.json` | 1.0.1.4 | 2026-11-06 | HTTP 200, `totalReports` is 0 |

There is no `rdap_no_data.json`: every real public address is registered to someone,
so RDAP never answered 404 for the addresses I tried. The RDAP 404 case is simulated in
`test_sources.py` instead, and the test says so.

AbuseIPDB needs an API key, sent in a header. The key is never saved in these files
(the response body does not contain it). Check that before committing a new sample.
