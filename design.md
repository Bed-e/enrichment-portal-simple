# IP Enrichment Portal (Simple) — Design

Status: draft v1.0. M1 to M5 are built and merged. This document describes the app as built: a backend and a frontend that talk through the contract in section 7. Sections 2 and 6 still describe the single-program layout as built through M4 where noted; the layout after the split is in M5.
Owner: Ben

---

## 1. Goal

A small local web app. An analyst types one IP address, and the app shows two things on one page:

1. **A verdict**: *Malicious*, *Suspicious*, *No known bad*, *Unknown* or *Not applicable* (private or reserved address), with the reasons listed.
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
- A verdict from a simple points score
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
    "verdict": {"level": "no_known_bad", "score": 0, "summary": "...", "reasons": ["..."]},
    "sources": [ <source result>, <source result>, <source result> ],
}
```

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

**Early exits (before any scoring):**

1. If the classification is not `global`, the level is `not_applicable` and the summary is "Private or reserved address. External sources were not queried."
2. If no *flagging* source answered (see below), the level is `unknown`.

**Flagging sources** are the ones that can actually raise a red flag: **InternetDB and AbuseIPDB**. RDAP only says who owns the address, so it can't say whether the IP is bad. "No red flags" means nothing unless a source that *could* have raised a flag looked and found none. "Answered" means a status of `ok` or `no_data`.

**Scoring** (a running total; each rule that fires adds points and appends a reason string). These are the constants at the top of `verdict.py`:

| Signal | Points | Reason text |
|---|---|---|
| AbuseIPDB `abuse_confidence_score` ≥ 75 | +5 | "AbuseIPDB confidence score is 87/100" |
| AbuseIPDB `abuse_confidence_score` 25–74 | +2 | same wording |
| AbuseIPDB `is_tor` true | +1 | "AbuseIPDB flags this as a Tor exit node" |
| InternetDB tag in {`c2`, `malware`, `compromised`} | +5 | "InternetDB tag: c2" |
| InternetDB tag in {`tor`, `vpn`, `proxy`} | +1 | "InternetDB tag: vpn" |
| InternetDB `vulns` not empty | +1 | "3 known CVEs on exposed services" |

**Mapping the total to a level:**

| Total | Level |
|---|---|
| 5 or more | `malicious` |
| 2 to 4 | `suspicious` |
| 0 or 1 | `no_known_bad` |

(0 or 1 counts as no known bad because a lone Tor/VPN tag or one CVE isn't a bad-IP signal on its own. It does still show up in the reasons list.)

**The summary text** is a short headline ("Strong signs of malicious activity.", "Some warning signs." or "No known bad found.") followed by a coverage sentence naming which flagging sources answered and which didn't, for example "Answered: Shodan InternetDB. No answer from: AbuseIPDB (not_configured), so this is weaker evidence."

**Rules about wording (kept from the old design):**

- The app never says "clean" or "safe". `no_known_bad` means the sources found nothing, not that the IP is safe.
- A source that failed, was missing a key or was skipped never makes a verdict look *better*. It only counts as missing evidence.

**The thresholds and weights are placeholders in one visible place.** They are constants at the top of `verdict.py`, so they are easy to find and change.

### 3.5 `lookup.lookup(ip_text)`

```python
def lookup(ip_text):
    classification = classify_ip(ip_text)     # may raise ValueError; app.py catches it
    ip = classification["ip"]
    if classification["category"] != "global":
        sources = [_skipped(...), _skipped(...), _skipped(...)]   # never send private addresses out
    else:
        sources = [query_internetdb(ip), query_rdap(ip), query_abuseipdb(ip)]
    verdict = score_verdict(classification, sources)
    return {"ip": ip, "classification": classification, "verdict": verdict, "sources": sources}
```

Sources are queried one after another in a plain list. With three sources and an 8 second timeout each, the worst case is around 24 seconds, with a typical lookup taking a few seconds. That is accepted for simplicity.

### 3.6 `app.py`: the Flask part

Two routes:

- `GET /` renders `index.html` with just the form.
- `POST /lookup` reads `request.form["ip"]`, calls `lookup()`, and renders `index.html` with `result=...` or `error="..."`.

`ValueError` (invalid IP or IPv6) becomes an inline error message on the page. Any other unexpected exception gets caught once in `POST /lookup`, shows a generic "Something went wrong." message and prints the traceback to the terminal. The page never shows a stack trace.

**Template (`index.html`):** one file. A form at the top, then if `result` exists: a coloured verdict banner (class depends on `verdict.level`), the classification label and explanation for non-global addresses, the reasons list, then a loop over `result.sources` that makes a card for each. A card shows the display name, status, the summary as a simple key/value list, and the raw JSON inside an HTML `<details>` element, so it collapses with no JavaScript. Under the cards, a fixed note says how long answers may be reused (section 12). Jinja features used: `{{ }}`, `{% if %}`, `{% for %}`. Nothing else.

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

**D7 — The verdict is a points score with named constants.** It's about 30 lines of `if` statements. Every verdict lists the reasons that fired, so the result explains itself. The weights are kept in one visible place.

**D8 — The verdict never says "clean".** `no_known_bad` states honestly that nothing was found. `unknown` is used when no source that could flag the IP gave an answer.

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
    "score": 0,
    "summary": "No known bad found. Answered: Shodan InternetDB. No answer from: AbuseIPDB (not_configured), so this is weaker evidence.",
    "reasons": []
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

(The values above are illustrative; real answers differ.)

**A private or reserved address is also `200`.** Its `classification` carries the category and an explanation, `verdict.level` is `not_applicable`, and all three sources have `status` `skipped` (nothing was sent to them), with `summary`, `raw` and `error` all `null`.

### Field reference

| Field | Type | Meaning |
|---|---|---|
| `ip` | text | the address that was looked up, in standard form |
| `classification.category` | text | `global`, `private`, `loopback`, `link_local`, `multicast`, `reserved` or `other_non_global` |
| `classification.ip` | text | the address in standard form (the same value as the top-level `ip`) |
| `classification.explanation` | text or null | plain-language explanation; `null` when the category is `global` |
| `verdict.level` | text | `malicious`, `suspicious`, `no_known_bad`, `unknown` or `not_applicable` |
| `verdict.score` | whole number | the points total from section 3.4 |
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
| 500 | Anything unexpected | `{"error": "internal_error", "message": "Something went wrong."}` |

Any other URL gets Flask's default "not found" page. That page is not part of the contract.

### Rules

- A source failing is **not** an API error. The response is still `200`, with that source's `status` set to `error`, `no_data` and so on.
- Error messages are safe to show to a user. Tracebacks and details go to the backend terminal only.
- The response never contains the API key.
- Changing this shape means changing the backend, the frontend, this section and anyone else calling the backend, so changes are made here first.

### What the frontend does with each outcome

| Backend outcome | The frontend shows |
|---|---|
| `200` | The verdict banner and the source cards, as before |
| `400` | The backend's `message` inline on the page |
| `500`, no connection, timeout, or an answer that isn't valid JSON | "The lookup service is unavailable. Is the backend running?" (details go to the frontend terminal, never the page) |

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

**`test_lookup.py`**: with the three `query_*` functions in `lookup.py` patched to return source results, `lookup("8.8.8.8")` returns the dict shape from section 2; a private address comes back with all three sources `skipped` and none of the `query_*` functions called; garbage raises `ValueError`.

**With the split:**

- `backend/tests/test_api.py`, using Flask's `test_client` with `lookup` patched: a good IP gives `200` with the contract's keys; an invalid IP gives `400` with `invalid_ip`; an IPv6 address gives `400` with `unsupported_ip_version`; an unexpected error gives `500` with `internal_error` and no traceback in the body.
- `frontend/tests/test_app.py`, with `requests.get` patched to return a recorded real backend answer (`frontend/tests/samples/`, saved with `curl` once the backend works): success renders the verdict and three cards; a `400` shows the backend's message; a connection error and a `500` show "The lookup service is unavailable."

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