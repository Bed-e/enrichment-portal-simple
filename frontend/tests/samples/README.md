# Recorded backend answers

Real answers from the backend, saved unedited, which the frontend tests replay.

| File | Request | Recorded | How |
| --- | --- | --- | --- |
| `backend_ok.json` | `GET /api/ip/8.8.8.8` (HTTP 200) | 2026-11-06 | `curl -o backend_ok.json http://127.0.0.1:5001/api/ip/8.8.8.8` with the backend running |

Checked before committing: the file does not contain the AbuseIPDB key.
Re-record it if the contract in design.md section 7 changes.
