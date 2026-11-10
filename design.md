# IP Enrichment Portal (Simple): Design

Owner: Ben. This describes the app as built through M7.

## 1. Goal and scope

**Goal.** A small local web app. An analyst types one IPv4 address and sees, on one page:

1. **A verdict**: a 0 to 100 score and a level (`malicious`, `suspicious`, `no_known_bad` or `not_applicable`), with the reasons listed.
2. **One card per source**: what each source said, with the raw response available on demand.

An *IOC* (indicator of compromise) is a piece of evidence such as an IP, domain or file hash. This version accepts IPv4 addresses only.

**Rule for every decision:** if it can't be explained in a sentence or two, it doesn't go in.

**Requirements.** Python only. A separate backend (API) and frontend. At least three real sources, with no mocks or fake data in the running app. A written API contract. A configurable port. Tests that make no network calls.

**Out of scope**

- IPv6, bulk lookups, and other IOC types (domains, hashes, URLs)
- Database or saved history: every lookup is shown once and forgotten
- Async code, threads or a rate limiter: sources are queried one after another
- Containers and CI: the app runs from a plain virtual environment
- Login and hosting: it runs locally only
- Commercial use: this is a learning project, and some free tiers forbid commercial use
- Writing to any source: the app only reads. It never submits or reports anything to AbuseIPDB or any other service.

## 2. Architecture

```
Browser --> frontend (Flask, port 5000) --HTTP--> backend (Flask, port 5001) --> 3 sources
                                                   ^
Claude Desktop --> MCP server (stdio) --HTTP-------+
```

| Part | Job | Talks to |
|---|---|---|
| **Frontend** (`frontend/app.py`, one HTML template) | Shows the form, verdict banner and source cards. Never calls a source. | Backend only, over HTTP |
| **Backend** (`backend/api.py`) | One endpoint. Runs the lookup and returns JSON. The only part that holds the API key. | The three sources |
| `lookup.py` | Glues the steps: classify, query sources, score. | `ip_tools`, `sources`, `verdict` |
| `ip_tools.py` | Validates the IP. Labels private and reserved addresses. | Standard library `ipaddress` |
| `sources.py` | One function per source. Never raises: every failure becomes a result dict. | `requests` |
| `verdict.py` | Pure function: dicts in, score and level out. | Nothing |
| `cache.py` | In-memory cache per source, so repeat lookups save quota. Lost on restart. | `lookup.py` |
| **MCP server** (`mcp_server/`) | One read-only tool, `lookup_ip`, so Claude Desktop can ask the backend. It is one more caller of the contract. | Backend only |
| **Skill** (`.claude/skills/ioc-triage/`) | Written instructions for triaging a pasted list through `lookup_ip`. | MCP server |

**Data flow.** The frontend sends `GET /api/ip/<ip>` to the backend. The backend classifies the IP. A private or reserved address is **not** sent to any source. A public one goes to each source in turn. The backend scores the answers and returns one JSON object.

Everything passed between steps is a plain Python dict. No classes and no Pydantic.

## 3. API contract

**`GET /api/ip/<ip>`** on the backend, default `http://127.0.0.1:5001`. The backend does all validation.

**Success `200`.** All keys are always present, and a missing value is `null`. `sources` always has three entries, in the order `internetdb`, `rdap`, `abuseipdb`.

```json
{
  "ip": "8.8.8.8",
  "classification": {"category": "global", "explanation": null, "ip": "8.8.8.8"},
  "verdict": {"level": "no_known_bad", "score": 12, "summary": "...", "reasons": ["..."]},
  "sources": [
    {"name": "internetdb", "display_name": "Shodan InternetDB", "status": "ok",
     "summary": {"ports": [53, 443], "tags": [], "vulns": [], "hostnames": [], "cpes": []},
     "raw": {}, "error": null}
  ]
}
```

- `verdict.score` is a whole number from 0 to 100 and is never `null`.
- `verdict.level` comes from the score: 60 to 100 `malicious`, 20 to 59 `suspicious`, 0 to 19 `no_known_bad`. A private or reserved address is `not_applicable` with score `0`, meaning "not judged".
- `sources[].status` is one of `ok`, `no_data` (the source answered but knows nothing), `error`, `not_configured` (no key) or `skipped` (private address).
- `sources[].summary` is `null` unless the status is `ok`. `raw` is the source's own unedited JSON.
- A private or reserved address still returns `200`, with all three sources `skipped`.

**Errors**

| Status | When | Body |
|---|---|---|
| 400 | Not a valid IP | `{"error": "invalid_ip", "message": "..."}` |
| 400 | IPv6 | `{"error": "unsupported_ip_version", "message": "..."}` |
| 503 | Every source we queried returned `error` | `{"error": "sources_unavailable", "message": "..."}` |
| 500 | Anything unexpected | `{"error": "internal_error", "message": "..."}` |

**Rules**

- One source failing is **not** an API error. It stays inside a `200` as that source's `status`.
- Messages are safe to show. Tracebacks go to the backend terminal only.
- The response never contains the API key.
- To change the contract, change this section first, then the backend, frontend and any other caller.

## 4. Data sources: keys, limits and terms

| Source | Request | Key | Limit | Terms and caveats |
|---|---|---|---|---|
| **Shodan InternetDB** | `GET https://internetdb.shodan.io/{ip}` | None | No published limit | Free for non-commercial use only. Data is refreshed weekly, so it can be days old. Tag names (`c2`, `malware`, `tor`, ...) are not formally documented, so treat them as best-effort. |
| **RDAP** (via rdap.org) | `GET https://rdap.org/ip/{ip}` (the redirect to the right registry is followed automatically) | None | About 10 requests per 10 seconds | Says who owns the address block. Some registries (such as ARIN) forbid republishing the data. |
| **AbuseIPDB** | `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90` | Free account key in the `Key` header | 1,000 checks a day on the free tier | Do not republish or resell the data. Check the terms at sign-up. Never report an IP back to AbuseIPDB. |

**Key handling.** The only key is `ABUSEIPDB_API_KEY`, kept in `.env`, which is git-ignored. `.env.example` holds a fake placeholder only. Only the backend reads it. The key travels only in a request header. It is never logged, put in a URL, returned by the API, or saved in a test sample. With no key, AbuseIPDB shows `not_configured` and the other two sources still work.

**Limits are not enforced in code.** One manual lookup at a time stays inside every limit. The cache is what protects the quota on repeats (InternetDB 24 hours, RDAP 7 days, AbuseIPDB 6 hours; "no data" answers are kept for less time; errors are never cached).

**Before changing a source function,** check the provider's current docs for field names, limits and terms.

## 5. Decisions, each with its reason

1. **Flask with plain functions and dicts.** Both are small enough to explain fully. A dict can be printed and read, so no Pydantic or classes.
2. **`requests`, with sources queried one after another.** It is the HTTP library most developers know, and a `for` loop is easy to explain. The cost is a few seconds of waiting (up to about 24 in the worst case), which is fine for one lookup at a time.
3. **Three sources: InternetDB, RDAP, AbuseIPDB.** Two need no account, so the first run is easy. The third teaches key handling once and gives the verdict real reputation evidence. Sources needing extra libraries or tight quotas were dropped.
4. **Separate backend and frontend.** `lookup()` already returned one dict, so it is the natural dividing line. Other programs can then call the backend directly. The cost is two processes to run, and that is accepted.
5. **Only the backend holds the key.** One place to protect, and the frontend can't leak what it never has.
6. **Private and reserved IPs are labelled and never sent out.** They carry no public data, and sending them would leak internal addressing.
7. **Five statuses, with timeouts and rate limits folded into `error`.** The verdict treats them all as missing evidence, so splitting them adds no behaviour. The message says what happened.
8. **The score means "out of 100 IPs with this evidence, how many are malicious".** Callers get one number they can sort. Under that meaning, missing information is not neutral: unregistered or unknown IPs are often malicious, so each gap adds points. The weights are placeholders, kept as named constants at the top of `verdict.py`.
9. **No source answering is a `503`, not a score.** If every source is down, the cause is probably our network, and any number would be made up. 503 covers timeouts, rate limits and a rejected key alike ("try again later").
10. **The app never says "clean" or "safe".** `no_known_bad` means only that nothing bad was found.
11. **A simple in-memory cache.** Analysts repeat lookups and the sources have quotas. A dict inside the backend is the simplest store, and losing it on restart costs one fresh lookup.
12. **MCP server and Skill are extra callers, not changes.** They use the existing contract, so nothing in the backend or frontend changed for them.
13. **Tests replay recorded real responses and make no network calls.** They test the real response shapes without using quota. Failures that can't be recorded on demand (timeouts, a 429, a bad key) are simulated, and the test says so.
14. **Error details go to the terminal, never the web page.** User-facing messages are always safe to show.
15. **The port is set on the command line (`--port N`).** Two programs can't share a port, and two portals can run on one laptop. The frontend finds the backend through `BACKEND_URL`.
