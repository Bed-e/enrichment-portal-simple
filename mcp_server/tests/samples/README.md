# Recorded backend answers

Real answers from the portal's backend (`GET /api/ip/<ip>`, design.md section 7), saved unedited.
The MCP server tests replay them, so no test touches the network.

| File | Request | Recorded | How |
| --- | --- | --- | --- |
| `backend_ok.json` | `GET /api/ip/8.8.8.8` (HTTP 200) | 2026-11-06 | Copied unchanged from `frontend/tests/samples/backend_ok.json` (no new source calls) |
| `backend_private.json` | `GET /api/ip/192.168.1.1` (HTTP 200) | 2026-11-09 | `curl.exe -o backend_private.json http://127.0.0.1:5011/api/ip/192.168.1.1` with the backend running |
| `backend_400_invalid.json` | `GET /api/ip/not-an-ip` (HTTP 400) | 2026-11-09 | same, with `not-an-ip` |
| `backend_400_ipv6.json` | `GET /api/ip/2001:4860:4860::8888` (HTTP 400) | 2026-11-09 | same, with the address URL-encoded |

None of the 2026-11-09 requests reached a source: private addresses are skipped and invalid input is
rejected first, so no quota was used.

Checked before committing: no file contains the AbuseIPDB key.
Re-record them if the contract in design.md section 7 changes.
