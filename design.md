# IP Enrichment Portal (Simple) — Design

Status: draft v1.2. M1 to M6 are built and merged. M7 (a score that is always 0 to 100, where missing information counts as risk, and a 503 when no source can be reached) is built, in its own pull request. Where M7 changed something from M6, the text says so. Sections 13 and 14 describe the MCP server and the Skill, which M6 touched only in small ways (M6, step 3). This document describes the app as built: a backend and a frontend that talk through the contract in section 7. Sections 2 and 6 still describe the single-program layout as built through M4 where noted; the layout after the split is in M5.
Owner: Ben

---

## 1. Goal

A small local web app. An analyst types one IP address, and the app shows two things on one page:

1. **A verdict**: *Malicious*, *Suspicious*, *No known bad* or *Not applicable* (private or reserved address), with the reasons listed. (*Unknown* was removed in M7: see section 3.4.)
2. **One card per source**: what each source said, in readable form, with the raw response available on demand.

### The rule for every decision in this document

**If I can't explain it in a sentence or two, it doesn't go in.** The previous project failed this test (two programs, async code, Pydantic, protocols, a rate limiter, a database layer). This one is deliberately small.

### Project requirements

- **Python only**, with a separate backend (an API) and frontend. The backend takes an IOC, queries the sources and returns the combined result as JSON. An *IOC* (indicator of compromise) is a piece of evidence such as an IP address, a domain or a file hash. **This version accepts IP addresses only.** The frontend gets all its data from the backend and never calls a source itself, because other programs call the backend directly. The split is milestone M5, and it is required.
- **At most two containers.** Running without containers is fine, and this design uses none (section 9).
- **At least three real sources**, keyless or with a free key: Shodan InternetDB, RDAP and AbuseIPDB. **No mocks or fake data in the running portal.** Fakes exist only inside tests.
- **A documented API contract** (section 7) and **a configurable port** (section 9), because two programs cannot listen on the same port and two portals can run on one laptop.
- **Tests replay recorded real responses and make no network calls** (section 10).
- **A GitHub repository** with a README, design.md, .gitignore and .gitattributes (section 8).
- **Not in this version:** the list in section 4.

### Where the project stands

| Requirement | State |
|---|---|
| Three real sources, no fake data in the app | Done (M2) |
| README, design.md, .gitignore, .gitattributes | Done |
| Tests make no network calls | Done for the tests that exist (pure logic only) |
| Tests replay recorded real responses for the sources | Done (M5) |
| Documented API contract and separate backend and frontend | Contract is written (section 7); the split is built and tested (M5) |
| Configurable port | Works with `--port N` on each program; documented in the README |

### In scope

- Single IPv4 lookup
- Detecting private and reserved addresses, labelling them, explaining them and not sending them to the sources
- Three sources: Shodan InternetDB, RDAP, AbuseIPDB
- A verdict from a simple points score: a certainty of malicious activity from 0 to 100 (graded by what the sources report), plus a level label derived from it (M6)
- A Flask web page with a form and a results section
- Automated tests: the pure logic (built), plus the three source functions replaying recorded real responses (M5)
- (M5) A separate backend and frontend that talk through the written API contract (section 7)

---

## 2. Architecture

One program, one process, plain functions. This is the layout built in M1 to M4. M5 splits it into a backend and a frontend; the layout after the split is in M5.

```
 Browser  --GET /-->            Flask app (app.py)
          --POST /lookup-->       │
                                  ▼
                           lookup(ip_text)              (lookup.py)
                             1. classify_ip()           (ip_tools.py)  uses stdlib `ipaddress`
                             2. for each source: query  (sources.py)   uses `requests`
                             3. score_verdict()         (verdict.py)   plain if-statements
                             4. return one dict
                                  │
                                  ▼
                       render_template("index.html", result=...)
```

The flow is a straight line. Each step is a normal function that takes values and returns values. Nothing is async, and there are no classes.

### Files (as built through M4)

```
enrichment-portal-simple/
├─ app.py              Flask routes (2 routes + the template call)
├─ lookup.py           lookup(ip_text) -> result dict; glues the steps together
├─ ip_tools.py         classify_ip(ip_text) -> dict
├─ sources.py          query_internetdb(ip), query_rdap(ip), query_abuseipdb(ip)
├─ verdict.py          score_verdict(classification, source_results) -> dict
├─ templates/
│   └─ index.html      the form, the verdict banner, the source cards
├─ static/
│   └─ style.css
├─ tests/
│   ├─ test_ip_tools.py
│   └─ test_verdict.py
├─ pytest.ini          lets plain `pytest` find the project's modules
├─ requirements.txt    flask, requests, python-dotenv, pytest
├─ .env.example        ABUSEIPDB_API_KEY=your-key-here
├─ .gitignore          .env, venv/, __pycache__/, .pytest_cache/
├─ .gitattributes      * text=auto
├─ CLAUDE.md           instructions for Claude Code
├─ design.md           this file
└─ README.md           how to install, run and test
```

Still to add in M5: `tests/samples/`, `tests/test_sources.py` and `tests/test_lookup.py`.

Five Python files, each under roughly 150 lines. If a file grows past that, that is a signal to simplify, not to add a framework.

### The shape of the data

Everything passed between steps is a normal Python **dict**. No Pydantic or dataclasses.

**A source result** (what each `query_*` function returns):

```python
{
    "name": "abuseipdb",             # used as a key in code
    "display_name": "AbuseIPDB",     # shown in the card
    "status": "ok",                  # see the status list below
    "summary": {"abuse_confidence_score": 87, "total_reports": 214, ...},   # None unless status == "ok"
    "raw": {...},                    # the source's unmodified JSON, or None
    "error": None,                   # short message when status is "error"
}
```

**Statuses** (only five, all plain strings):

| status | meaning |
|---|---|
| `ok` | data returned |
| `no_data` | the source answered but knows nothing about this IP |
| `error` | timeout, network failure, rate limit (429), bad key or anything else; `error` holds a short message |
| `not_configured` | AbuseIPDB with no key set |
| `skipped` | not queried because the IP is private or reserved |

The old design had separate `timeout` and `rate_limited` statuses. Here they collapse into `error`, and the message says which it was. This is simpler and loses nothing the verdict needs.

**The lookup result** (what `lookup()` returns, and what the contract in section 7 sends as JSON):

```python
{
    "ip": "8.8.8.8",
    "classification": {"category": "global", "explanation": None, "ip": "8.8.8.8"},
    "verdict": {"level": "malicious", "score": 70, "summary": "...", "reasons": ["..."]},
    "sources": [ <source result>, <source result>, <source result> ],
}
```

`verdict.score` is a **whole number from 0 to 100, and is never `None`** (section 3.4). It means: out of 100 IPs that came back with this same evidence, about how many are malicious. `verdict.level` is derived from the score in the backend.

If every source we actually queried fails, `lookup()` does not return a result at all: it raises `SourcesUnavailableError`, and the API answers `503` (section 7).

---

## 3. Components in detail

### 3.1 `ip_tools.classify_ip(ip_text)`

Uses Python's built-in `ipaddress` module:

```python
import ipaddress
ip = ipaddress.ip_address(ip_text.strip())   # raises ValueError if invalid
```

- Invalid text: raises `ValueError("That is not a valid IP address.")`. `app.py` catches it and the page shows the message.
- IPv6: raises `ValueError("IPv6 is not supported yet.")`. No lookup is done.
- Otherwise it returns `{"ip", "category", "explanation"}`. The categories are `global`, `private`, `loopback`, `link_local`, `multicast`, `reserved` and `other_non_global`. The order of the checks matters, because Python counts loopback and link-local as "private" too, so the specific checks run first and `private` comes after them.
- Each non-global category has a short, fixed explanation string stored in a dict at the top of the file. `global` has `None`.

Private and reserved addresses are **labelled and explained, and never sent to the sources**. That avoids leaking internal addressing to third parties, and public sources would have nothing on them anyway. (This is the one place the code already does a little of what the "privacy guard" in section 4 means; see the note there.)

### 3.2 `sources.py`: three functions, one pattern

Each function takes an IP string, makes one `requests.get(..., timeout=8)` call, and returns a source result dict. Each is written in the same order:

1. Make the request (with the 8 second timeout).
2. If the request itself failed, return `status="error"` with a message ("Request timed out" or "Network error: ...").
3. If the HTTP status is 404 (or the "no data" case for that source), return `status="no_data"`.
4. If it is 429, 401 or 403, return `status="error"` with a clear message (for 401/403, "API key rejected", never echoing the key). Any other non-200 gives `status="error"` with "HTTP <code>".
5. Otherwise pick out a few fields from the JSON into `summary`, keep the JSON as `raw`, and return `status="ok"`.

Functions **never raise** to the caller. Every failure becomes a dict, so one broken source can't break the page.

To avoid repeating the try/except three times, there is one small helper `_get_json(url, headers=None)` that does the request and returns `(response, error_message)`. The three source functions use it.

| Source | Request | Key? | No data when |
|---|---|---|---|
| Shodan InternetDB (`internetdb`) | `GET https://internetdb.shodan.io/{ip}` | none | HTTP 404 |
| RDAP (`rdap`, shown as "RDAP (registration)") | `GET https://rdap.org/ip/{ip}` (`requests` follows the redirect to the right registry automatically) | none | HTTP 404 |
| AbuseIPDB (`abuseipdb`) | `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90` with headers `Key` and `Accept: application/json` | free account key | `totalReports` is 0 |

**What `summary` and `raw` hold, as built.** `summary` uses `snake_case` names (words joined by underscores). The full key list per source is in section 7. `raw` is the source's own JSON with its own names, untouched. For InternetDB and RDAP, `raw` is the whole response and is only set when the status is `ok`. For AbuseIPDB, `raw` is the inner `data` object of the response and is also set when the status is `no_data`, because that answer (0 reports) still has useful fields.

**RDAP detail:** the RDAP JSON is nested and awkward (the owning organization sits inside an `entities` list with `vcardArray` data). The function takes the first entity that has an `fn` (formatted name) line in its vCard, and leaves the organization as `None` if the layout isn't what it expects, rather than crashing. This is the most fiddly parsing in the project.

**Before changing a source function:** I check the provider's current docs (field names, limits, terms).

**Limits to remember** (nothing in the code enforces them; I just stay aware):

- InternetDB: no published limit; free for non-commercial use. Data is refreshed weekly, so it can be days old. The tag names (`c2`, `malware`, `compromised`, `tor`, `vpn`) are not formally documented, so I treat them as best-effort.
- RDAP via rdap.org: about 10 requests per 10 seconds. A single manual lookup is fine.
- AbuseIPDB: 1,000 checks a day on the free tier.

### 3.3 API key handling

- The only key is `ABUSEIPDB_API_KEY`.
- `python-dotenv` loads it from a local `.env` file into the environment (`load_dotenv()` in `app.py`), and `sources.py` reads it with `os.environ.get("ABUSEIPDB_API_KEY")`.
- `.env` is in `.gitignore`. `.env.example` shows the variable name with a fake placeholder value only.
- No key means AbuseIPDB returns `not_configured` and the other two sources still work.
- The key goes only in a request header, is never printed or logged, and is never placed in a URL, in the HTML, in a test or in a recorded sample.

### 3.4 `verdict.score_verdict(classification, sources)`

A **pure function**: dicts in, dict out, no network and no Flask. This makes it easy to test and easy to explain.

**What the score means (M7).** `score` is a whole number from 0 to 100, and it is **never `None`**. Read it as: *out of 100 IPs that came back with exactly this evidence, about how many are malicious.* That one sentence drives every weight below. In particular, an IP that sources know little or nothing about is **not** neutral: many IPs with no registration and no history are in fact malicious (perhaps half or more of the unregistered ones), so missing information adds points.

**The one early exit:** if the classification is not `global`, the level is `not_applicable`, the score is `0` and the summary says "Private or reserved address. External sources were not queried." Here `0` means "outside what this tool judges", not "safe": nothing was looked up. The `level` is what tells a caller which meaning applies.

**All sources down is not a verdict.** If every source we actually queried returned `error`, there is nothing to score, so `lookup()` raises `SourcesUnavailableError` before `score_verdict` is called and the API answers `503` (section 7). A source that is `not_configured` or `skipped` was not tried, so it does not count as a failure. If only some sources fail, we still score, and each failed source adds its "missing evidence" points below.

**Flagging sources** (InternetDB and AbuseIPDB) are the ones that can say an IP is *bad*. RDAP says who owns the address, and in M7 it also matters when it has *nothing*: an address with no registration record is the strongest "undocumented" signal we have.

**Scoring** (a running total, starting at the base; each rule that fires adds or subtracts points and appends a reason string). These are the constants at the top of `verdict.py`:

| Signal | Points | Why |
|---|---|---|
| Base | +2 | Even a fully documented, clean IP is occasionally bad, so nothing scores 0 |
| RDAP `no_data` (no registration record) | +40 | Unregistered: the biggest single risk factor |
| RDAP `error` | +25 | Could not confirm registration; missing evidence counts against the IP |
| RDAP `ok` but no organization name | +10 | Registered, but the owner is undocumented |
| InternetDB `no_data` | +10 | Never scanned. Weak, because many legitimate IPs are unscanned too |
| InternetDB `error` | +10 | Could not check |
| AbuseIPDB `no_data` (0 reports) | +10 | It answered but has never seen this IP: undocumented, not vouched for. Less than the +15 for no answer |
| AbuseIPDB `error` or `not_configured` | +15 | No reputation evidence |
| AbuseIPDB `abuse_confidence_score` (0 to 100) | the score × 0.9, rounded | AbuseIPDB's own number, graded; a 100 is nearly always bad. The reason line names the multiplier: "AbuseIPDB confidence score is 76/100, counted at x0.9 (+68)" |
| AbuseIPDB `isWhitelisted` true | -30 | The only real "known good" signal we have |
| AbuseIPDB `is_tor` true | +5 | |
| InternetDB tag in {`c2`, `malware`, `compromised`} | +60 per tag | |
| InternetDB tag in {`tor`, `vpn`, `proxy`} | +10 per tag | Anonymizers are over-represented among malicious IPs |
| InternetDB `vulns` not empty | +5, once | |

A rule that adds 0 points (for example an AbuseIPDB score of 0) adds no reason line. Every other rule adds one reason line that shows its points, for example "RDAP has no registration record for this address (+40)". **The numbers in the reason lines always add up exactly to the score.** That includes the base (it is the first line, "Base rate ... (+2)") and any clamp (below).

**Clamping.** After all the rules have run, the total is clamped to 0 to 100: `score = max(0, min(total, 100))`. The cap is needed when strong signals stack (a `c2` tag and a high AbuseIPDB score pass 100). The floor is needed because the whitelist rule subtracts. When the clamp changes the total, it adds its own reason line with the difference, for example "Score limited to the range 0 to 100 (-43)", so the lines still add up. A test checks this for several combinations of evidence. Private addresses have no reason lines (they are not scored).

**Mapping the score to a level** (the backend does this, so every caller gets the same label):

| Score | Level |
|---|---|
| 60 to 100 | `malicious` |
| 20 to 59 | `suspicious` |
| 0 to 19 | `no_known_bad` |
| (private or reserved address) | `not_applicable` |

`unknown` no longer exists as a level (M7). "Nothing answered" is now the `503` above, and "little is known" is a normal score in the `suspicious` range.

**Worked examples** (check them by hand):

| Evidence | Points | Score | Level |
|---|---|---|---|
| All three `ok`, nothing bad (AbuseIPDB has reports but a score of 0) | 2 | 2 | `no_known_bad` |
| Well-known IP: RDAP ok with owner, InternetDB ok, AbuseIPDB `no_data` (like 8.8.8.8) | 2 + 10 | 12 | `no_known_bad` |
| RDAP, InternetDB and AbuseIPDB all `no_data` | 2 + 40 + 10 + 10 | 62 | `malicious` |
| RDAP ok, InternetDB `no_data`, AbuseIPDB `not_configured` | 2 + 0 + 10 + 15 | 27 | `suspicious` |
| RDAP ok, InternetDB ok, AbuseIPDB 87 | 2 + round(78.3) | 80 | `malicious` |
| InternetDB `c2` tag and AbuseIPDB 90, others documented | 2 + 60 + 81 = 143, capped | 100 | `malicious` |
| All three sources `error` | not scored | no score | the API answers `503` |

**The summary text** is a short headline ("Strong signs of malicious activity.", "Some warning signs, or too little is known about this address." or "No known bad found.") followed by a coverage sentence naming which flagging sources answered and which didn't, for example "Answered: Shodan InternetDB. No answer from: AbuseIPDB (not_configured), so this is weaker evidence."

**Rules about wording (kept from the old design):**

- The app never says "clean" or "safe". `no_known_bad` means the sources found nothing bad and the IP is well documented, not that the IP is safe.
- A source that failed or had no key never makes a verdict look *better*. It adds points.
- Undocumented is treated as suspicious, on purpose (the score meaning above).

**The weights and thresholds are placeholders in one visible place.** They are constants at the top of `verdict.py`, so they are easy to find and change as we learn what real data looks like.

### 3.5 `lookup.lookup(ip_text)`

```python
def lookup(ip_text):
    classification = classify_ip(ip_text)     # may raise ValueError; app.py catches it
    ip = classification["ip"]
    if classification["category"] != "global":
        sources = [_skipped(...), _skipped(...), _skipped(...)]   # never send private addresses out
    else:
        sources = [query_internetdb(ip), query_rdap(ip), query_abuseipdb(ip)]
    if _all_queried_sources_failed(sources):      # M7: nothing answered, so no honest score
        raise SourcesUnavailableError()           # api.py turns this into a 503
    verdict = score_verdict(classification, sources)
    return {"ip": ip, "classification": classification, "verdict": verdict, "sources": sources}
```

Sources are queried one after another in a plain list. With three sources and an 8 second timeout each, the worst case is around 24 seconds, with a typical lookup taking a few seconds. That is accepted for simplicity.

### 3.6 `app.py`: the Flask part

Two routes:

- `GET /` renders `index.html` with just the form.
- `POST /lookup` reads `request.form["ip"]`, calls `lookup()`, and renders `index.html` with `result=...` or `error="..."`.

`ValueError` (invalid IP or IPv6) becomes an inline error message on the page. Any other unexpected exception gets caught once in `POST /lookup`, shows a generic "Something went wrong." message and prints the traceback to the terminal. The page never shows a stack trace.

**Template (`index.html`):** one file. A form at the top, then if `result` exists: a coloured verdict banner (class depends on `verdict.level`) with the level name and, next to it in large type, the 0 to 100 score (hidden for `not_applicable`, where the `0` means "not judged"; M7), the classification label and explanation for non-global addresses, the reasons list, then a loop over `result.sources` that makes a card for each. A card shows the display name, status, the summary as a simple key/value list, and the raw JSON inside an HTML `<details>` element, so it collapses with no JavaScript. Under the cards, a fixed note says how long answers may be reused (section 12). Jinja features used: `{{ }}`, `{% if %}`, `{% for %}`. Nothing else.

---

## 4. Not in this version

These are left out on purpose. Some arrive later in other courses.

- **Database.** No saved history, no export. Every lookup is shown once and forgotten.
- **Caching.** *Now added (section 12):* an in-memory cache per source, so repeat lookups reuse earlier answers. Anything beyond it (a database or a shared cache) is still out.
- **Privacy guard.** Blocking private values is the topic of *Secure Coding with AI*, and nothing beyond what is already built is added here. **Note:** M1 to M3 already include one simple block: private and reserved addresses are labelled and never sent to the sources (section 3.1). It stays as built, because the code and the pull request history already have it. Anything more is later work.
- **Optimization.** No threads, no `asyncio`, no rate limiter. Sources are queried one after another.

Also out of scope:

- IPv6
- Login and hosting
- CI (automatic test runs on GitHub) and containers. Running without containers is fine, and if I ever use them, there are at most two, one per program (section 9)
- Bulk lookups, and other IOC types (domains, hashes, URLs)
- Any upload or report to AbuseIPDB or another service. The app only reads (looks up) data; it never submits anything
- Commercial use. This is a learning project, and some free tiers are non-commercial only

Stretch goals after M5, one at a time, are listed at the end of section 6.

---

## 5. Decisions, each with its reason

**D1 — Flask and Jinja, one program for M1 to M4.** Flask is small enough to explain in full: a route is a function that returns a page. Getting the whole app working first, as one program, means every later change can be checked against a known-good version. The split into two programs is deliberately left to M5 (D16).

**D2 — `requests` and plain functions, sources queried one after another.** `requests` is the HTTP library most Python developers already know. A `for` loop over sources is easy to explain. The cost is a few seconds of waiting, which is acceptable for a one-IP-at-a-time tool. Optimization is not in this version (section 4).

**D3 — Dicts instead of Pydantic models or classes.** I can print a dict and read it. The shapes are documented in section 2 and section 7, and tests check the important keys.

**D4 — Three sources: InternetDB, RDAP, AbuseIPDB.** Two need no account, which keeps the first run easy. The third teaches key handling once, with a real reputation source, which gives the verdict real evidence. Team Cymru was dropped because it needs DNS queries and a separate library. GreyNoise, VirusTotal and ipinfo were dropped for their tight quotas and extra per-source quirks. All three are real: the running portal never uses fake data.

**D5 — No rate limiter; caching added later.** One manual lookup at a time stays well inside every limit, so enforcing limits in code would be machinery for a problem I don't have. Analysts do repeat the same lookups, though, so a simple per-source cache was added afterwards (section 12).

**D6 — Five statuses, with timeouts and rate limits folded into `error`.** The verdict treats all of them the same way (as missing evidence), so splitting them adds no behaviour. The message text says what happened.

**D7 — The verdict is a points score with named constants.** It's about 30 lines of `if` statements. Every verdict lists the reasons that fired, so the result explains itself. The weights are kept in one visible place. From M6 the points are graded (AbuseIPDB's own 0 to 100 number is scaled, the tags stay fixed amounts) and the total is a certainty from 0 to 100 (D36).

**D8 — The verdict never says "clean".** `no_known_bad` states honestly that nothing was found. (M7) `unknown` is gone: when no source answered at all the API answers `503`, and when little is known the score is raised instead (D37).

**D9 — Private and reserved IPs are labelled, explained and not sent out.** They carry no public data, and sending them could leak internal addressing. This is built (M1 to M3) and kept, and section 4 explains how it relates to the brief's "privacy guard" item.

**D10 — IPv4 only.** `ipaddress` handles both versions, so adding IPv6 later would mostly mean removing one check and confirming each source supports it.

**D11 — Local only, no login, no database.** Nothing in v1 needs to be remembered or protected from other users.

**D12 — No JavaScript.** Plain HTML and CSS. The raw response collapses using `<details>`.

**D13 — Tooling: `pip`, a virtual environment, `requirements.txt` and `pytest.ini`.** These are the tools I already know. `pytest.ini` has one line, `pythonpath = .`, so plain `pytest` can import the project's modules. There is no `uv`, `ruff`, CI or Docker in v1.

**D14 — Libraries, and what each is for.** The whole list is short enough to explain:

- `ipaddress` (standard library): validate an IP and tell private from public.
- `os` (standard library): read the API key from the environment.
- `traceback` (standard library): print unexpected errors to the terminal.
- `flask`: the web app and Jinja templates.
- `requests`: calls to the source APIs, and (after M5) from the frontend to the backend.
- `python-dotenv`: loads `.env` into the environment so the key isn't in the code.
- `pytest` (development only): runs the tests.
- Added in M5, tests only: `json` (standard library) to read the recorded sample files, and `unittest.mock` (standard library) to swap `requests.get` for a fake during a test.
- Added with the cache (section 12), both standard library: `time` (when an answer was stored) and `copy` (store and hand out copies, so nobody changes a stored answer by accident).
- Added with the MCP server (section 13), MCP server only: `mcp[cli]` version 2 (the official MCP Python SDK), plus `logging` and `sys` (standard library) to log to stderr. `anyio` (installed with `mcp`) runs the SDK's async client in its tests.

**D15 — Educational and non-commercial.** InternetDB's free tier is for non-commercial use, and AbuseIPDB's terms should be checked at sign-up.

**D16 — Split into backend and frontend as the last milestone (M5), keeping the structure.** `lookup(ip_text)` already returns one dict and the template only reads that dict, so that function is the natural dividing line. The backend keeps `lookup.py`, `ip_tools.py`, `sources.py` and `verdict.py` unchanged. The frontend keeps the Flask routes and the template, and swaps its call to `lookup()` for an HTTP request to the backend. Doing this last means the split can be checked: the same IP should give the same result before and after. The split is required, not optional. The cost is two processes to run and one more thing that can fail (the backend being down), and that is accepted because the contract between two programs is a topic I want to learn.

**D17 — The contract is the existing result dict plus a small error shape, using plain HTTP status codes.** Success is `200` with the result dict from section 2. An invalid IP is `400` with `{"error": ..., "message": ...}`. Source failures are not API errors; they stay inside a `200` as per-source statuses, because the lookup itself worked. The contract is written in section 7, and changing the shape means changing both sides and any other program that calls the backend. There is no `/v1` in the URL and no other versioning, because I control every client.

**D18 — The frontend finds the backend through a `BACKEND_URL` setting.** It is read from `.env` the same way as the AbuseIPDB key (`python-dotenv` and `os.environ.get`), with the default `http://127.0.0.1:5001`. The browser only ever talks to the frontend, so there is no CORS (the browser rule that restricts one site calling another).

**D19 — One shared virtual environment and one `requirements.txt` at the root, even after the split.** It avoids managing two environments. The "keys only in the backend" rule is kept in the code: only the backend reads `ABUSEIPDB_API_KEY`. Nothing in the frontend reads it, forwards it or shows it.

**D20 — Tests of the sources replay recorded real responses, saved by hand (M5).** I fetch each source once and save the unedited answer as a file in `tests/samples/`. Tests swap `requests.get` for a fake that hands back that file. This tests the real response shape without touching the network or using up quotas. Failures that can't be recorded on demand (timeouts, rate limits, a rejected key) are simulated, and the test says so. See section 10.

**D21 — The port is set on the command line, and no containers are used.** `flask run --port N` makes the port configurable with nothing new to learn. Containers are optional (at most two), and I don't use them. See section 9.

**D36 — `verdict.score` becomes the 0 to 100 certainty, and is `null` when there is no evidence (M6). Changed again by D37 (M7): `score` is now never `null`.** Other programs call the backend, so what matters to them is a number they can sort and compare, not a flat value that only means "above or below a line". I reuse the existing `score` field instead of adding a second number, so there is one number to explain and the shape of the contract barely changes. `level` stays in the API, derived from the score in the backend, for two reasons: the thresholds live in one place so every caller gets the same label, and the frontend and template need no change. `score` is `null` for `unknown` and `not_applicable` because a `0` would claim we are sure nothing is wrong, when really we looked at nothing. The cost is that callers must handle `null`, and that is a real change to the contract (section 7). (Numbered D36 because D22 to D35 were added in sections 13 and 14; it stays here because it is a decision about the verdict.)

**D37 — The score is always 0 to 100 and means "out of 100 IPs like this, how many are malicious"; little information is treated as suspicious; no source answering is a `503` (M7).** A caller wants one number it can sort, with no special case for `null`. The honest meaning of that number is a rate: of 100 IPs that came back with this same evidence, how many are malicious. Under that meaning, an IP with no registration record and no history is not neutral, because a large share of such IPs are malicious, so missing information adds points (weights in section 3.4). That is also why `unknown` is gone as a level. But if *every* source we tried is down, the cause is probably our network or the providers, not the IP, and any number would be made up. So the API answers `503 Service Unavailable` (section 7) instead of a score. 503 was chosen over 502 (a bad reply from an upstream server) and 504 (an upstream timeout) because the failures can be timeouts, rate limits or a rejected key, and 503 covers all of them ("try again later"). Private and reserved addresses score `0` with level `not_applicable`: a number is required, nothing was looked up, and `level` says which meaning applies. The costs: the weights are judgement, not measured data; a partial outage raises scores; and callers must handle a new `503` and the loss of the `unknown` level (a second contract change, section 7).

---

## 6. Milestones

Each milestone ends with something I can run and show. Each change reaches `main` through a pull request (see `CLAUDE.md`).

**M1: The skeleton with one source.** *Done (first commit).*
`ip_tools.py`, `sources.py` with only `query_internetdb`, `lookup.py`, and a bare `app.py` and `index.html` that show the raw dict. Tests for `classify_ip`.
*Done when:* I can run `flask run`, look up `8.8.8.8` and see the InternetDB result, and a private IP shows its explanation and an invalid one shows an inline message.

**M2: All three sources.** *Done (pull request #2).*
Add `query_rdap` and `query_abuseipdb`, and the `.env` key handling. Replace the raw display with one card per source, including collapsible raw JSON.
*Done when:* all three cards show for a public IP; with no key, the AbuseIPDB card says "not configured" and the page still works; turning off my network gives readable `error` cards, not a crash.

**M3: The verdict.** *Done (pull request #3).*
Write `verdict.py` and its tests, then add the verdict banner and reasons list.
*Done when:* known-bad, known-good and private IPs each give a sensible verdict with reasons.

**M4: Polish and README.** *Done (pull request #4, then the README in #5 and `pytest.ini` in #6; `CLAUDE.md` came in #1).*
Styling, README with install and run steps, and a final check on a fresh virtual environment that the instructions work. Read through the code once and make sure I can explain every line.
*Done when:* a clean install from the README works, and I can walk through the code top to bottom without hand-waving.

**M5: Close the gaps against the brief, then separate backend and frontend (required).** *Done (pull requests #9, #10 and #11).*
The point of the split is to move code, not rewrite it, so it comes last, after tests protect the sources. Each step below is its own pull request or a small group of them. After each step, tests pass and the page still works.

*New concepts in M5.* Each is explained in plain language when it first appears, and I confirm I understand it before it is used:

- `unittest.mock.patch`: swaps `requests.get` for a fake during one test and puts it back afterwards.
- A small `FakeResponse` class: stands in for a real response in tests (section 10).
- Loading a recorded sample file with `json.load`.
- `jsonify`: a Flask function that turns a Python dict into a JSON response.
- Returning a status code from a route, such as `return jsonify(...), 400`.
- Calling the backend from the frontend with `requests.get(...)` and reading the answer with `.json()` and `.status_code`. This is the same `requests` I already use for the sources.
- Flask's `test_client`: calls a route inside a test with no server running.
- `curl`: a command-line tool that makes a web request and prints the answer, used to call the backend directly and to record samples. A browser can do the same for the keyless endpoints.

*Steps:*

1. *(Done, pull request #9.)* **Recorded samples and source tests.** Record the real responses (section 10), add `tests/test_sources.py` and `tests/test_lookup.py`, and check that `pytest` passes with the network turned off.
2. *(Done, in one pull request with steps 3 and 4, because the page does not run between them.)* **Move the files** into `backend/` and `frontend/` as shown below. Fix any `import` lines that break. The existing tests pass when I run `pytest` from inside `backend/`. (`pytest.ini` moves into `backend/`, and the frontend gets its own.)
3. *(Done.)* **Write the backend endpoint** in `api.py`: it calls `lookup()` and returns the dict with `jsonify`, or a 400 with the error shape from section 7. It also catches unexpected errors once, prints the traceback to the terminal and returns a safe 500. Check it by opening `http://127.0.0.1:5001/api/ip/8.8.8.8` directly in the browser, or with `curl`, where the JSON should appear.
4. *(Done.)* **Change the frontend** so `POST /lookup` calls the backend (timeout 30 seconds, since the backend can take up to about 24 seconds when all three sources are slow) and renders the same template with what comes back. The frontend handles the cases in the table in section 7.
5. *(Done.)* **Add the split's tests** (section 10): `test_client` tests for the endpoint, and frontend tests with `requests.get` faked using a recorded real backend answer.
6. **Update the README** (both programs, ports, tests) and `.env.example` (add `BACKEND_URL`). *(Done early, in the same pull request as steps 2 to 4, so the docs match the code when it merges.)*

*Layout after the split* (files are moved with `git mv` so their history is kept):

```
enrichment-portal-simple/
├─ backend/
│   ├─ api.py              Flask app: one endpoint, GET /api/ip/<ip>
│   ├─ lookup.py           moved unchanged
│   ├─ ip_tools.py         moved unchanged
│   ├─ sources.py          moved unchanged
│   ├─ verdict.py          moved unchanged
│   ├─ pytest.ini          moved
│   └─ tests/
│       ├─ samples/        recorded real responses (from step 1)
│       ├─ test_ip_tools.py   moved unchanged
│       ├─ test_verdict.py    moved unchanged
│       ├─ test_sources.py    moved unchanged
│       ├─ test_lookup.py     moved unchanged
│       └─ test_api.py        new
├─ frontend/
│   ├─ app.py              the routes from before; calls the backend instead of lookup()
│   ├─ pytest.ini
│   ├─ templates/index.html   moved unchanged (or a tiny tweak)
│   ├─ static/style.css       moved unchanged
│   └─ tests/
│       ├─ samples/        a recorded real backend response
│       └─ test_app.py        new
├─ requirements.txt        still one file at the root
├─ .env.example            adds BACKEND_URL=http://127.0.0.1:5001
├─ .gitignore
├─ .gitattributes
├─ CLAUDE.md
├─ design.md
└─ README.md               updated: how to run both programs
```

*Running it* is in section 9.

*Details to settle during M5 and run by me first:*

- How the backend tells its two 400 cases apart (invalid text and IPv6). `classify_ip` raises `ValueError` with a different message for each. Two options are to compare the messages, or to raise two different small error types.
- Whether `load_dotenv()` finds the root `.env` from inside both folders (it searches upward from the file's location, but I check it rather than assume).

*Done when:* the source functions are tested against recorded real responses with the network off; and, with both programs running, I get the same results in the browser as at the end of M4. I can call the backend directly with `curl` and get the JSON from the contract. The frontend shows a readable message when the backend is stopped. I can explain what the contract is, which side owns what, and why the key never reaches the frontend.

**M6: Graded certainty.** *Built, in its own pull request.*
Change the verdict from flat points to a 0 to 100 certainty (section 3.4, D36). No new files, libraries or concepts: one multiplication, `round`, `min`, and `None` for "no evidence". Steps, each on a branch and a pull request:

1. **Update `verdict.py`.** New constants, scaled AbuseIPDB points, the cap, the new level thresholds, `score: None` in both early exits, and reason lines that show the points.
2. **Update `backend/tests/test_verdict.py`** for the new numbers (section 10).
3. **Update the other places that mention the old score:** `README.md`, `frontend/tests/samples/backend_ok.json` (a recorded backend answer with the old `score`; I decide with Claude whether to re-record it with `curl` or edit the one number by hand, and I am told before it is touched), and a check of `backend/lookup.py` and `backend/measure_calls.py` for assumptions about `score`. Also the MCP server and the Skill, which need small edits and no rewrite: (a) the `lookup_ip` description in `mcp_server/server.py` says only "score", so it should say "certainty 0 to 100, `null` when there is no evidence" (`_compact` passes `verdict["score"]` straight through, so the code is unchanged and `None` is fine); (b) `mcp_server/tests/samples/backend_private.json` has `"score": 0`, which becomes `null` (re-recorded or edited by hand, as for the frontend sample, and I am told first); (c) `.claude/skills/ioc-triage/SKILL.md` copies `verdict.score` into its Score column, so it gets one added rule: when `score` is `null` (levels `unknown` and `not_applicable`), write `-`.
4. **Check the frontend.** The template never reads `score`, so it should need no change. I confirm that with the backend running, for a public IP, a private IP and an IP with no answering flagging source.

*Done when:* `pytest` passes in `backend/` and `frontend/` with the network off; `curl http://127.0.0.1:5001/api/ip/8.8.8.8` shows a `score` between 0 and 100; a private address shows `"score": null` and `"level": "not_applicable"`; the page looks and behaves as it did at the end of M5; and I can explain the scoring formula line by line.

**M7: Always-scored verdict.** *Built, in its own pull request.*
Change the score to always be 0 to 100, with missing information adding risk, and answer `503` when no source can be reached (section 3.4, D37). Steps: design.md first (this change), then `verdict.py` and `lookup.py` (a small `SourcesUnavailableError`), then `api.py` (the 503), then tests, then the README, the MCP server, the Skill and the private-address MCP sample (`score` `null` becomes `0`).

*Done when:* `pytest` passes in `backend/`, `frontend/` and `mcp_server/` with the network off; a private address gives `"score": 0` and `not_applicable`; a public address never gives `null`; stopping the network gives a `503` from the backend and the frontend shows its "unavailable" message.

### Stretch goals (only after M5, one at a time)

- Query sources with `ThreadPoolExecutor`, which makes the lookup take as long as the slowest source and fits in about 5 extra lines. (This is optimization, so it is later.)
- Save lookups to a SQLite file using the standard-library `sqlite3`, plus a history page.
- Export a result as JSON or CSV.
- IPv6.
- Add another source (Team Cymru, GreyNoise, VirusTotal or ipinfo).

---

## 7. API contract

This is the agreement between the backend and everyone who calls it. The backend is the only thing that talks to the sources. The frontend never calls a source; it gets everything from the backend. Other programs (scripts, tools, classmates' code) can call the backend directly, so this contract is a promise to them as well. It is built in M5, but the result dict it describes already exists as built in M1 to M4, and the key names below are the ones the code uses today.

### The endpoint

**`GET /api/ip/<ip>`** on the backend. The default address is `http://127.0.0.1:5001`, and the port can be changed (section 9). The IP is given as plain text in the URL, and the backend does all the checking. IP addresses are the only IOC type this version accepts.

Calling it directly:

```bash
curl http://127.0.0.1:5001/api/ip/8.8.8.8
```

### Success: `200`

The body is the lookup result dict from section 2, as JSON. All keys shown are always present. A value that isn't available is `null` rather than missing. `sources` always has exactly three entries in this order: `internetdb`, `rdap`, `abuseipdb`.

```json
{
  "ip": "8.8.8.8",
  "classification": {"category": "global", "explanation": null, "ip": "8.8.8.8"},
  "verdict": {
    "level": "no_known_bad",
    "score": 17,
    "summary": "No known bad found. Answered: Shodan InternetDB. No answer from: AbuseIPDB (not_configured), so this is weaker evidence.",
    "reasons": [
      "Base rate: even a well-documented IP is occasionally malicious (+2)",
      "AbuseIPDB gave no answer (not_configured), so there is no reputation evidence (+15)"
    ]
  },
  "sources": [
    {"name": "internetdb", "display_name": "Shodan InternetDB", "status": "ok",
     "summary": {"ports": [53, 443], "tags": [], "vulns": [], "hostnames": ["dns.google"], "cpes": []},
     "raw": {"...": "the source's unmodified JSON"}, "error": null},
    {"name": "rdap", "display_name": "RDAP (registration)", "status": "ok",
     "summary": {"network_name": "...", "organization": "...", "country": "US",
                 "start_address": "8.8.8.0", "end_address": "8.8.8.255", "registered": "..."},
     "raw": {"...": "..."}, "error": null},
    {"name": "abuseipdb", "display_name": "AbuseIPDB", "status": "not_configured",
     "summary": null, "raw": null, "error": null}
  ]
}
```

(The values above are illustrative; real answers differ. A lookup with evidence would instead show, for example, `"level": "malicious"`, `"score": 80` and a reason line `"AbuseIPDB confidence score is 87/100, counted at x0.9 (+78)"` after the base line.)

**A private or reserved address is also `200`.** Its `classification` carries the category and an explanation, `verdict.level` is `not_applicable`, `verdict.score` is `0` (meaning "not judged"), and all three sources have `status` `skipped` (nothing was sent to them), with `summary`, `raw` and `error` all `null`.

### Field reference

| Field | Type | Meaning |
|---|---|---|
| `ip` | text | the address that was looked up, in standard form |
| `classification.category` | text | `global`, `private`, `loopback`, `link_local`, `multicast`, `reserved` or `other_non_global` |
| `classification.ip` | text | the address in standard form (the same value as the top-level `ip`) |
| `classification.explanation` | text or null | plain-language explanation; `null` when the category is `global` |
| `verdict.level` | text | `malicious` (score 60 to 100), `suspicious` (20 to 59), `no_known_bad` (0 to 19) or `not_applicable` (section 3.4). `unknown` was removed in M7. |
| `verdict.score` | whole number | **0 to 100, never `null`.** Out of 100 IPs that came back with this same evidence, about how many are malicious (section 3.4). Missing information adds points, so an undocumented IP scores in the `suspicious` range. A low score does not mean safe. For `not_applicable` (private or reserved) it is `0`, meaning "not judged". |
| `verdict.summary` | text | one or two sentences, safe to show to a user |
| `verdict.reasons` | list of text | one line per rule that fired; may be empty |
| `sources[].name` | text | `internetdb`, `rdap` or `abuseipdb` |
| `sources[].display_name` | text | the name to show a person |
| `sources[].status` | text | `ok`, `no_data`, `error`, `not_configured` or `skipped` (section 2) |
| `sources[].summary` | object or null | the picked-out fields below; `null` unless `status` is `ok` |
| `sources[].raw` | object or null | the source's own JSON with its own field names. For `internetdb` and `rdap` it is set only when `status` is `ok`. For `abuseipdb` it is the response's inner `data` object and is also set when `status` is `no_data`. Otherwise `null` |
| `sources[].error` | text or null | short message when `status` is `error`; `null` otherwise; never contains the API key |

**`summary` keys per source** (any value may be `null` when the source doesn't give it):

| Source | Keys |
|---|---|
| `internetdb` | `ports` (list of whole numbers), `tags` (list of text), `vulns` (list of text), `hostnames` (list of text), `cpes` (list of text) |
| `rdap` | `network_name`, `organization`, `country`, `start_address`, `end_address`, `registered` (all text) |
| `abuseipdb` | `abuse_confidence_score` (whole number, 0 to 100), `total_reports` (whole number), `last_reported_at` (text), `usage_type` (text), `isp` (text), `is_tor` (true or false), `is_whitelisted` (true or false), `country_code` (text) |

### Errors

| Status | When | Body |
|---|---|---|
| 400 | The text is not a valid IP address | `{"error": "invalid_ip", "message": "That is not a valid IP address."}` |
| 400 | The address is IPv6 | `{"error": "unsupported_ip_version", "message": "IPv6 is not supported yet."}` |
| 503 | Every source we queried returned `error` (timeouts, rate limits, a rejected key, a network failure). `not_configured` and `skipped` sources do not count as failures | `{"error": "sources_unavailable", "message": "No data source could be reached. Try again shortly."}` |
| 500 | Anything unexpected | `{"error": "internal_error", "message": "Something went wrong."}` |

Any other URL gets Flask's default "not found" page. That page is not part of the contract.

### Rules

- A source failing is **not** an API error. The response is still `200`, with that source's `status` set to `error`, `no_data` and so on.
- Error messages are safe to show to a user. Tracebacks and details go to the backend terminal only.
- The response never contains the API key.
- Changing this shape means changing the backend, the frontend, this section and anyone else calling the backend, so changes are made here first.

**Contract change in M6:** `verdict.score` used to be a small points total that was always a whole number (for example 5), and was `0` for `unknown`. From M6 it is a 0 to 100 certainty and is `null` for `unknown` and `not_applicable`. The key is the same, its meaning and scale are different, and a caller that assumed a number must now handle `null`. The frontend does not read `score`, so it is unaffected.

**Contract change in M7 (a second breaking change):** (1) `verdict.score` is never `null` any more. It is `0` for `not_applicable`, and missing information now raises it. (2) The `unknown` level is removed. (3) A new `503` answer with error `sources_unavailable`. A caller that handled `null` or `unknown` can drop that code; a caller that treated every non-200 as "bad input" or "crash" should treat `503` as "retry later". The frontend does not read `score`, and its "unavailable" message already covers a `503`.

### What the frontend does with each outcome

| Backend outcome | The frontend shows |
|---|---|
| `200` | The verdict banner and the source cards, as before |
| `400` | The backend's `message` inline on the page |
| `500`, `503`, no connection, timeout, or an answer that isn't valid JSON | "The lookup service is unavailable. Is the backend running?" (details go to the frontend terminal, never the page) |

---

## 8. Repository and project files

The project lives in a GitHub repository (`Bed-e/enrichment-portal-simple`). Git workflow (branches, pull requests, never committing to `main`) is in `CLAUDE.md`.

Files the repository must have:

| File | State | What it is for |
|---|---|---|
| `README.md` | Done | What the project is, how to install it, how to run both programs, how to change the port, and how to run the tests |
| `design.md` | Done | This document |
| `.gitignore` | Done | Tells Git which files never to save: `.env` (it holds the key), `venv/` (the virtual environment), `__pycache__/` and `.pytest_cache/` (Python's and pytest's temporary files) |
| `.gitattributes` | Done | Tells Git how to treat files. It contains one line, `* text=auto`. Windows ends each line of text with two invisible characters and Mac and Linux with one, and mixing them makes Git show whole files as changed when only the line endings differ. This line makes Git store text with one style and convert it to the local style on each machine, so diffs stay clean. It does not change my Python code at all. |

Also in the repository: `requirements.txt`, `pytest.ini`, `.env.example` (fake placeholder values only), `CLAUDE.md`, and (from M5) the `tests/samples/` files.

**Nothing secret is ever committed:** no `.env`, no API key anywhere. Recorded samples contain only response bodies, and I check them for the key before committing (section 10).

---

## 9. Running it and configuration

**Ports.** Two programs cannot listen on the same port, and two portals can run on one laptop, so the port is never fixed in the code. Flask takes it on the command line with `--port`.

Today (one program):

```bash
flask run --port 5000
```

(`flask run` on its own uses port 5000, which is what the README shows.)

After M5 (two programs, two terminals, the same virtual environment, each started from its own folder):

```bash
# in backend/
flask --app api run --port 5001

# in frontend/
flask --app app run --port 5000
```

Rules:

- The frontend reaches the backend through `BACKEND_URL` in `.env` (D18). If the backend's port changes, `BACKEND_URL` must change with it.
- To run a second portal on the same laptop, give it different ports (for example 5002 and 5003), and point its `BACKEND_URL` at the second backend, for example `http://127.0.0.1:5003`.
- The README shows both commands and explains how to change the numbers (M5).

**Containers.** The requirement is at most two containers, and running without containers is fine. This design runs without any. If I ever add them, it is one container for the backend and one for the frontend. Docker is not built or needed, and I ask before adding it.

**Configuration** is plain environment variables, loaded from `.env` by `python-dotenv`:

| Name | Used by | Meaning |
|---|---|---|
| `ABUSEIPDB_API_KEY` | backend only | free AbuseIPDB key; optional (without it, AbuseIPDB shows `not_configured`) |
| `BACKEND_URL` | frontend only (M5) | where the backend lives; default `http://127.0.0.1:5001` |
| `PORTAL_URL` | MCP server only (section 13) | where the backend lives; default `http://127.0.0.1:5001`. Set in the Claude Desktop config, **not** in `.env`: the MCP server never reads `.env` |

---

## 10. Tests

All tests use `pytest`. **Tests replay recorded real responses and make no network calls.** Nothing in a test talks to a real service.

### What exists today (M1 to M4)

- **`test_ip_tools.py`**: the categories (`8.8.8.8` global, private, loopback, link-local, multicast, reserved), global has no explanation, non-global has one, whitespace is stripped, garbage raises `ValueError`, an IPv6 address is rejected.
- **`test_verdict.py`** (hand-built dicts passed to `score_verdict`): a private address gives `not_applicable`; every source `error` gives `unknown`; only RDAP answering gives `unknown`; AbuseIPDB score 90 gives `malicious` and 40 gives `suspicious`; an InternetDB `c2` tag gives `malicious`; both flagging sources finding nothing gives `no_known_bad`; `not_configured` AbuseIPDB plus a clean InternetDB gives `no_known_bad` and says AbuseIPDB wasn't checked; a lone anonymizer tag or one CVE stays `no_known_bad` but is listed; the Tor flag adds a reason.

These need no samples and no network, because they only pass dicts to pure functions.

**`test_verdict.py` from M6** (same hand-built dicts; the cases above are kept, with their checks changed from points to the exact score):
- AbuseIPDB 87 alone gives score `70` and `malicious`; AbuseIPDB 40 and the Tor flag gives `37` and `suspicious`; a `vpn` tag and CVEs gives `10` and `no_known_bad`.
- Scaling is graded: AbuseIPDB 76 and AbuseIPDB 100 give different scores (61 and 80).
- A `c2` tag with AbuseIPDB 90 is capped at exactly `100`.
- Level boundaries: scores 19 and 20, and 59 and 60, land on the right sides (AbuseIPDB 24 gives 19 and `no_known_bad`; 25 gives 20 and `suspicious`; 74 gives 59 and `suspicious`; 75 gives 60 and `malicious`).
- A private address gives `not_applicable` and a score of `None`; every source `error` gives `unknown` and a score of `None` (not `0`).
- Both flagging sources answering with nothing found gives score `0` and `no_known_bad`.
- A reason line is present for each rule that fired, shows its points, and no reason line appears for a rule worth 0 points.

**`test_verdict.py` from M7** (these replace the M6 checks that assumed `None`, `unknown` or no missing-evidence points):
- Private address: `not_applicable` and score `0`. A public address never gives `None`.
- Fully documented and clean: score `2`, `no_known_bad`. All three `no_data`: `62`, `malicious`. RDAP ok, InternetDB `no_data`, AbuseIPDB `not_configured`: `27`.
- Each missing-evidence rule on its own (RDAP `no_data` +40, RDAP `error` +25, RDAP without organization +10, InternetDB `no_data` or `error` +10, AbuseIPDB `no_data` +10, AbuseIPDB `error` or `not_configured` +15), each with its reason line.
- AbuseIPDB 87 gives `80`; scaling is graded (76 and 100 differ); the `c2` tag with AbuseIPDB 90 is capped at `100`; the whitelist flag subtracts 30 and the score never goes below `0`.
- Level boundaries on each side of 20 and 60 with the new base and 0.9 scale.

**`test_api.py` from M7:** `lookup` raising `SourcesUnavailableError` gives `503` with `sources_unavailable` and no details in the body.

### Added in M5

**Recorded real responses (samples).**

- **Where:** `tests/samples/` (it moves to `backend/tests/samples/` in the split). One file per case, holding the unedited response body, for example `internetdb_ok.json`, `internetdb_no_data.json`, `rdap_ok.json`, `rdap_no_data.json`, `abuseipdb_ok.json` and `abuseipdb_no_data.json`.
- **How I record them, by hand:** I fetch the source once, either in the browser (InternetDB and RDAP need no key) or with `curl`, and save the body as a file without editing it. AbuseIPDB needs the key sent in a header, which a browser can't do, so I use `curl` and read the key from my `.env` without pasting it into chat or into a file.
- **What each case uses:** a well-known address with data (`8.8.8.8`) for the "ok" case, and an address the source knows nothing about for the "no data" case. I look at the real answer first to choose the address. For AbuseIPDB, "no data" is a real answer with `totalReports` 0.
- **A short `tests/samples/README.md`** lists, for each file, the address, the date and how it was recorded, so I can re-record it if a source changes its format.
- **Before committing a sample:** I open it and check that it contains no API key.

**Replaying them with `mock.patch`.** `unittest.mock.patch` swaps `requests.get` for a fake during one test and puts it back afterwards. The fake returns a tiny `FakeResponse` that has the two things my code reads from a real response, a `status_code` and a `.json()` method:

```python
class FakeResponse:
    def __init__(self, status_code, json_data=None):
        self.status_code = status_code
        self._json_data = json_data

    def json(self):
        return self._json_data


def test_internetdb_ok():
    with open("tests/samples/internetdb_ok.json") as f:
        sample = json.load(f)
    with patch("sources.requests.get", return_value=FakeResponse(200, sample)):
        result = query_internetdb("8.8.8.8")
    assert result["status"] == "ok"
```

**Failures that can't be recorded on demand** (a timeout, a 429, a rejected key) are simulated: the fake raises `requests.exceptions.Timeout`, or returns a `FakeResponse` with that status code. Each such test is labelled as simulated in its name or comment, so it's clear which tests use recorded answers and which don't.

**Making sure no test touches the network.** Every test that reaches a source function patches `requests.get`. Nothing in the setup blocks a forgotten patch, so before each pull request I run `pytest` once with my network turned off, and every test must still pass.

**`test_sources.py`** (replaying the recorded samples): for each of the three functions, the "ok" sample gives `ok` with the right `summary` keys and the raw JSON kept; the "no data" sample gives `no_data`. Simulated: a timeout gives `error`; a 429 gives `error`; a 401 gives `error` with "API key rejected" and no key in the message; AbuseIPDB with no key gives `not_configured` and makes no request.

**`test_lookup.py`**: with the three `query_*` functions in `lookup.py` patched to return source results, `lookup("8.8.8.8")` returns the dict shape from section 2; a private address comes back with all three sources `skipped` and none of the `query_*` functions called; garbage raises `ValueError`; (M7) every queried source `error` raises `SourcesUnavailableError`, a mix of `error` and `not_configured` still counts as all failed, and one failed source among others still gives a result.

**With the split:**

- `backend/tests/test_api.py`, using Flask's `test_client` with `lookup` patched: a good IP gives `200` with the contract's keys; an invalid IP gives `400` with `invalid_ip`; an IPv6 address gives `400` with `unsupported_ip_version`; an unexpected error gives `500` with `internal_error` and no traceback in the body.
- `frontend/tests/test_app.py`, with `requests.get` patched to return a recorded real backend answer (`frontend/tests/samples/`, saved with `curl` once the backend works): success renders the verdict and three cards; a `400` shows the backend's message; a connection error, a `500` and a `503` show "The lookup service is unavailable."

---

## 11. Notes for Claude Code

- Work one milestone at a time and stop at the end of each for my review. M1 to M4 are done; do not change their behavior unless I ask.
- Python only, no JavaScript. One Flask program through M4; M5 splits it into a backend and a frontend that talk only through the contract in section 7.
- **Any new concept, library or pattern is run by me before it is used.** The new concepts are listed in M5. Anything beyond those gets asked about first.
- Before adding anything, ask "can Ben explain this in a sentence?" If not, make it simpler or ask me.
- Use only the libraries listed in D14. Ask before adding another.
- Prefer plain functions and dicts. No classes (apart from the tiny `FakeResponse` in tests), `async`, decorators beyond Flask's `@app.route`, or type-heavy patterns unless I ask.
- Comment the *why* in code, and keep comments short.
- **No mocks or fake data in the running portal.** Fakes only inside tests.
- Tests replay recorded real responses and make no network calls. Never record a sample by calling a source without telling me first, and never put a key in a sample.
- Check each source's current docs before changing its function, and update section 3.2 and section 7 if anything differs.
- Never upload or report anything to AbuseIPDB or any other provider. Look-ups only.
- Never log, print or return the API key.
- Keep the "Not in this version" list (section 4) out of the code: no database or optimization (the cache in section 12 is the one exception), and do not extend the private-address block that already exists.
- M7 (the always-scored verdict and the 503) follows M6 in the same way, and D37 explains it. M6 (the graded certainty) is built as described in sections 3.4 and 7 and D36, as its own branch and pull request. Keep the scoring to the formula in section 3.4: no classes, no new libraries. The weights and thresholds are placeholders, kept as constants at the top of `verdict.py`.
- If a requirement here is ambiguous or conflicts with what you find, ask rather than guess.

---

## 12. Caching

Analysts look up the same addresses again and again, and every lookup spends quota at sources with limits. The backend keeps each source's answer for a while and reuses it.

**Where.** A plain Python dict in `backend/cache.py`, inside the running backend. It is empty again after every restart. No file, no database, nothing to gitignore. That is the simplest store, and losing the cache on restart only costs one fresh lookup per address.

**How it fits.** `lookup.py` asks the cache before each source (`_from_cache_or_query`). On a miss it calls the same `query_*` function as before and stores the answer. `sources.py`, `verdict.py` and `api.py` are unchanged.

**The key** is `(source name, address in standard form)`, for example `("rdap", "8.8.8.8")`.
- One address typed differently uses one entry: `classify_ip` strips spaces and `ipaddress` gives one standard form, so `" 8.8.8.8 "` and `"8.8.8.8"` share an entry. (IPv4 has no upper or lower case. A trailing dot is still rejected with `400`, as before, so it never reaches the cache.)
- Two different addresses never share an entry, and neither do two sources.
- The key never contains the API key. The key only travels in a request header.

**Expiry per source.** Checked on each source's own pages on 2026-11-06. None of them ties how long a result may be kept to a `Cache-Control` header, and none rules caching out. AbuseIPDB's terms and ARIN's (where RDAP for many addresses comes from) forbid republishing or reselling the data; a private cache for our own lookups does neither.

| Source | Answer (`ok`) | "Not found" (`no_data`) | Why |
|---|---|---|---|
| Shodan InternetDB | 24 hours | 6 hours | Its data is "updated once a week", so a day-old answer is nearly always the current one. No published limit, but it is a free, non-commercial service. |
| RDAP | 7 days | 1 day | Who owns an address block changes rarely. rdap.org allows about 10 requests per 10 seconds, the tightest per-second limit here. |
| AbuseIPDB | 6 hours | 1 hour | New abuse reports can arrive within hours, and this is the main "is it bad?" signal, so it is kept the shortest. The free plan allows 1,000 checks a day, the tightest daily limit. "0 reports" (`no_data`) can turn wrong fastest, so it gets the shortest time of all. |

"Not found" is a real answer and may be cached, but for less time than a real answer.

**Never cached:** `error` (a timeout, a network failure, a `429`, a `5xx`, a rejected key, a bad response) and `not_configured` (no key). The next lookup asks again. `skipped` (private addresses) never reaches a source or the cache.

**Telling a cached answer from a fresh one: the expiry makes a per-answer flag unnecessary.** The API contract (section 7) does not change, so answers carry no "cached" field. Instead, the expiries keep every reused answer within an age an analyst can accept:
- The "is it bad?" evidence is the freshest. AbuseIPDB's "0 reports" (the cached "clean" answer that could be wrong tomorrow) is at most 1 hour old, and an answer with reports at most 6 hours.
- InternetDB answers are at most 24 hours old, but InternetDB's own data is only updated once a week, so a fresh request would usually return the same thing.
- RDAP answers can be up to 7 days old, but RDAP only says who owns the address and never changes the verdict (section 3.4).
- Anything that went wrong is never reused, so a fresh request always follows an error.
- An analyst who needs a guaranteed-fresh answer can restart the backend, which empties the cache.

So the analyst always knows the worst case, the page shows one fixed note under the results (plain text in `index.html`, not data from the backend): "Answers may be reused for a while to save quota: up to 24 hours for Shodan InternetDB, 7 days for RDAP and 6 hours for AbuseIPDB (1 hour if it found no reports)." If these expiries change, that note changes with them.

**Tests.** `backend/tests/test_cache.py` covers a miss, a hit (with exactly the contract's fields), different spellings, two different addresses, an expired entry, "not found" expiring sooner, an error, a timeout and a missing key not being cached, and the key holding no API key. `backend/tests/conftest.py` empties the cache before every test, so tests can't see each other's answers. All run with the network off.

**Measuring.** `backend/measure_calls.py` runs a fixed list of 26 lookups (repeats, the same address with extra spaces, private addresses, and one address whose InternetDB request always times out) with the network replaced by the recorded samples, and counts requests per source. Run it from `backend/` with `python measure_calls.py`.

---

## 13. MCP server

Our SOC wants to ask Claude about an indicator instead of opening the portal. `mcp_server/server.py` is a small MCP server (MCP, the Model Context Protocol, is the standard way Claude Desktop calls tools). Claude Desktop starts it on the same computer and sends it tool calls; each call becomes one request to the backend's `GET /api/ip/<ip>`.

```
Claude Desktop --stdio--> mcp_server/server.py --HTTP GET /api/ip/<ip>--> backend --> sources
```

**The API contract (section 7) does not change.** The MCP server is one more caller of the backend, like the frontend. Nothing in `backend/`, `frontend/` or section 7 was changed for it.

**Decisions, each with its reason:**

**D22 — One tool, `lookup_ip`.** The portal accepts IPv4 addresses only (section 1; domains, hashes and IPv6 are out of scope in section 4), and there is no endpoint for anything else. A `lookup_domain` or `lookup_hash` tool would have nothing to call. The name is verb + IOC type, and the one argument is called `ip` so it says what it holds.

**D23 — The description tells the model everything it needs to use the answer.** A model only knows a tool by its description (the function's docstring) and its input schema (from the type hint `ip: str`). So the description says: what goes in (one IPv4 address), what comes out (category, verdict level, score, summary, reasons, and each source's status, key fields and error), which sources answer (InternetDB, RDAP, AbuseIPDB, and that RDAP never changes the verdict), what `no_data` means (answered, knows nothing; not proof of safety), that answers may be reused up to the cache times in section 12, and what is refused (IPv6, ranges, hostnames, domains, URLs, hashes, lists) with "do not retry" so the model doesn't try again in a different form.

**D24 — The server checks the input itself, before calling the portal.** It uses `ipaddress.ip_address()`, the same standard-library parser as `ip_tools.py`, after stripping spaces, and rejects IPv6. Checking first gives the model a specific reason ("That is not a valid IPv4 address...") and avoids a pointless request. It also stops text with a `/` in it (a CIDR range or a URL) from changing which backend URL is called. Private and reserved addresses are **not** refused: the portal answers them with `not_applicable`, which is useful to the analyst. The address is sent in its standard form and URL-quoted, as the frontend does.

**D25 — Errors become tool errors; a failing source does not.** Raising `ToolError` makes the SDK return a normal result with `isError: true` and our message, so the model can read it and nothing crashes. The messages are fixed text, kept short and plain on purpose. Following section 7's rule, a failing source stays inside a successful result.

| Input or portal answer | What the tool returns |
|---|---|
| Valid IPv4, `200` | The compact result (below) |
| `200` with a source `error`, `no_data` or `not_configured` | The compact result; that source's status and error are kept |
| Private or reserved IPv4, `200` | The compact result with level `not_applicable` and sources `skipped` |
| Not an IP address (text, empty, a range, a domain, a URL, a hash, a list) | Tool error: "That is not a valid IPv4 address. Give one address like 8.8.8.8; ranges, hostnames, domains, URLs and hashes are not supported." No request is made. |
| IPv6 | Tool error: "IPv6 is not supported by the portal; only IPv4 addresses can be looked up." No request is made. |
| `400` from the portal | Tool error with the portal's own `message` (safe to show, section 7) |
| `500` from the portal | Tool error: "The portal had an internal error. Details are in the portal's terminal." |
| `503` from the portal (M7) | Tool error: "No data source could be reached by the portal. Try again shortly." Not a verdict: the IP was not judged. |
| No connection or a timeout (30 seconds, like the frontend) | Tool error: "Could not reach the portal at <PORTAL_URL>. Is the backend running?" |
| Any other status, or an answer that isn't the contract's JSON | Tool error: "The portal gave an unexpected answer." |

Details (the status code, the exception) go to the log, never into the tool's answer.

**D26 — A compact result.** The tool returns only `ip`, `category`, `explanation`, `verdict` (`level`, `score`, `summary`, `reasons`) and, per source, `name`, `status`, `summary` and `error`. The `raw` JSON is left out because it is large, the model doesn't need it, and the description doesn't promise it. `display_name` is left out because `name` already says which source it is.

**D27 — The portal's address comes from `PORTAL_URL`.** It is an environment variable set in the Claude Desktop config, read on every call with `os.environ.get`, with the default `http://127.0.0.1:5001` (the backend's default). Another portal on the same laptop on another port (section 9) only needs a different `PORTAL_URL`. The MCP server does **not** load `.env` and never sees `ABUSEIPDB_API_KEY`: only the backend reads keys, so there is no key in the server, its config or the Claude Desktop config.

**D28 — stdio, and logging to stderr only.** Claude Desktop starts the server and talks to it over stdin and stdout, so stdout must carry nothing but the protocol. The server has no `print()`; it logs with `logging` to stderr (one line per lookup: address and HTTP status). Claude Desktop keeps stderr in its MCP log file.

**D29 — The tool is marked read-only.** `ToolAnnotations(read_only_hint=True)` tells the client the tool changes nothing, which is true: the backend only reads from the sources (section 4).

**D30 — pip, the existing venv and the root `requirements.txt`.** This follows D13 and D19. The exercise's examples use `uv`, but the project's tool is pip. `mcp[cli]` is pinned to `>=2,<3`, because version 1 has a different API (`FastMCP` instead of `MCPServer`). Checked with version 2.3.0 on Python 3.14.

**D31 — Tests talk to the server through the SDK's own client.** `mcp_server/tests/test_server.py` lists the tools and calls `lookup_ip` exactly as Claude Desktop would, so it checks what a model really sees. `requests.get` is patched to replay recorded backend answers from `mcp_server/tests/samples/` (an 8.8.8.8 answer copied from the frontend's samples, a private address, and the two `400` bodies, recorded with no source calls). The tests cover the tool list (name, input, read-only hint, description), a public and a private address, a failing source, `PORTAL_URL`, every invalid input type (each a tool error with no request made), and the portal's `400`, `500`, being down and answering something unexpected. One test starts `server.py` as a real program over stdio, which fails if anything else is printed to stdout. No test uses the network.

**D32 — An exception to section 11, approved through the pull request.** Section 11 asks for new libraries, decorators other than `@app.route`, and type-heavy code to be run past Ben first. The server needs the `mcp` library, its `@mcp.tool()` decorator and type hints (the SDK builds the input schema from them). They stay inside `mcp_server/`, and the pull request that adds them is where Ben approves or rejects them.

**Running and connecting it** is in the README ("MCP server").

---

## 14. Triage Skill

Analysts triage a list of indicators the same way every time. `.claude/skills/ioc-triage/SKILL.md` is a Skill (a set of written instructions that Claude loads when a request matches its description) that makes Claude follow one procedure: split a pasted list, drop repeats, call `lookup_ip` (section 13) once per value in the user's order, and answer in four fixed sections (Results table, Counts per verdict, Refused values, Lookups).

**Nothing else changes.** It is one Markdown file. The API contract (section 7), the backend, the frontend and the MCP server are untouched, and it uses no library.

**Decisions, each with its reason:**

**D33 — Only `lookup_ip`, and only the values the user gave.** Every verdict, score and piece of evidence comes from the portal, so the answer is the same whoever asks. No web search, no other source, no added, "related" or corrected values.

**D34 — The tool decides what is refused.** Every value goes to `lookup_ip` exactly as given, and the server's own check (D24) refuses domains, hashes, URLs, ranges and IPv6 without making a request. Claude never judges validity itself and never retries a refused value in another form.

**D35 — Fixed output and fixed failure wording.** A failing source stays in its row under "Source problems" (`error`, `not_configured`, `no_data`), as in section 7's rules. If the portal is unreachable, the Skill stops and marks the rest `not_checked`, because every later call would fail the same way.

**Where it loads.** The Code tab finds it in `.claude/skills/`. Claude Desktop chat cannot read the repository, so a user uploads the `ioc-triage` folder as a ZIP there.