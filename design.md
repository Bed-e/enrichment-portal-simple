# IP Enrichment Portal (Simple) — Design

Status: draft v0.1
Owner: Ben

---

## 1. Goal

A small local web app. An analyst types one IP address, and the app shows two things on one page:

1. **A verdict**: *Malicious*, *Suspicious*, *No known bad*, *Unknown* or *Not applicable* (private address), with the reasons listed.
2. **One card per source**: what each source said, in readable form, with the raw response available on demand.

### The rule for every decision in this document

**If I can't explain it in a sentence or two, it doesn't go in.** The previous project failed this test (two programs, async code, Pydantic, protocols, a rate limiter, a database layer). This one is deliberately small.

### In scope

- Single IPv4 lookup
- Detecting private and reserved addresses and explaining them
- Three sources: Shodan InternetDB, RDAP, AbuseIPDB
- A verdict from a simple points score
- A Flask web page with a form and a results section
- A few automated tests for the pure logic

### Out of scope (can be stretch goals later)

- IPv6
- History, database, export
- Login, hosting, Docker, CI
- Caching, rate limiting, concurrency (sources are queried one after another)
- Bulk lookups, other IOC types (domains, hashes, URLs)
- Any upload to AbuseIPDB or another service. The app only reads (looks up) data; it never reports or submits anything
- Commercial use. This is a learning project, and some free tiers are non-commercial only

---

## 2. Architecture

One program, one process, plain functions.

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

The flow is a straight line. Each step is a normal function that takes values and returns values. Nothing is async, and there are no classes unless I find I really want one.

### Files

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
├─ requirements.txt    flask, requests, python-dotenv, pytest
├─ .env.example        ABUSEIPDB_API_KEY=
├─ .gitignore          .env, venv/, __pycache__/
└─ README.md           how to install and run
```

Six Python files, each under roughly 100 lines. If a file grows past that, that is a signal to simplify, not to add a framework.

### The shape of the data

Everything passed between steps is a normal Python **dict**. No Pydantic or dataclasses.

**A source result** (what each `query_*` function returns):

```python
{
    "name": "abuseipdb",             # used as a key in code
    "display_name": "AbuseIPDB",     # shown in the card
    "status": "ok",                  # see the status list below
    "summary": {"abuse_confidence_score": 87, "total_reports": 214, ...},   # None unless status == "ok"
    "raw": {...},                    # the unmodified JSON from the source, or None
    "error": None,                   # short message when status is not "ok"
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

**The lookup result** (what `lookup()` returns to the template):

```python
{
    "ip": "8.8.8.8",
    "classification": {"category": "global", "explanation": None},
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
ip.is_private, ip.is_loopback, ip.is_link_local, ip.is_multicast, ip.is_reserved, ip.is_global
```

- Invalid text: `ValueError` is caught by `lookup()` and the page shows the message "That is not a valid IP address."
- IPv6: if `ip.version == 6`, show "IPv6 is not supported yet." (No lookup is done.)
- Otherwise return a category and an explanation. The categories are `global`, `private`, `loopback`, `link_local`, `multicast`, `reserved` and `other_non_global`. The first match among those checks wins, and `is_global` False with nothing else matching falls into `other_non_global`.
- Each non-global category has a short, fixed explanation string stored in a dict at the top of the file (for example, private: "Not routable on the public internet, so public sources have no data on it. Check internal tools such as DHCP logs and asset inventory.").

Private and reserved addresses are **never sent to the sources**. That avoids leaking internal addressing to third parties, and public sources would have nothing on them anyway.

### 3.2 `sources.py`: three functions, one pattern

Each function takes an IP string, makes one `requests.get(..., timeout=8)` call inside `try/except requests.RequestException`, and returns a source result dict. Each is written in the same order:

1. Make the request (with the 8 second timeout).
2. If the exception was raised, return `status="error"` with a message.
3. If the HTTP status is 404 (or the "no data" case for that source), return `status="no_data"`.
4. If it is 429, 401 or 403, return `status="error"` with a clear message (for 401/403, "API key rejected", never echoing the key).
5. Otherwise pick out a few fields from the JSON into `summary`, keep the full JSON as `raw`, and return `status="ok"`.

Functions **never raise** to the caller. Every failure becomes a dict, so one broken source can't break the page.

To avoid repeating this try/except three times, there is one small helper `_get_json(url, headers=None)` that does the request and returns `(response, error_message)`. The three source functions use it. This is the only helper in the file.

| Source | Request | Key? | Summary fields to pick out | No data when |
|---|---|---|---|---|
| Shodan InternetDB | `GET https://internetdb.shodan.io/{ip}` | none | `ports` (shown as open ports), `tags`, `vulns`, `hostnames`, `cpes` | HTTP 404 |
| RDAP | `GET https://rdap.org/ip/{ip}` (`requests` follows the redirect to the right registry automatically) | none | network name, org name, country, start/end address, registration date | HTTP 404 |
| AbuseIPDB | `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90` with headers `Key` and `Accept: application/json` | free account key | `abuseConfidenceScore`, `totalReports`, `lastReportedAt`, `usageType`, `isp`, `isTor`, `isWhitelisted`, `countryCode` | `totalReports` is 0 |

**RDAP detail to handle:** the RDAP JSON is nested and awkward (the owning organization sits inside an `entities` list with `vcardArray` data). The function pulls out only `name`, `country` (when present), `startAddress`, `endAddress` and the registration event date. For the organization name I look through `entities` for the first one with a `fn` value in its vCard, and if that fails I leave it as `None`. This is the most fiddly parsing in the project, so it gets a clear comment and a saved sample for testing.

**Before writing each function:** I check the provider's current docs (field names, limits, terms) and fix this table if anything differs. The table above comes from the old design and is a starting point, not a guarantee.

**Limits to remember** (nothing in the code enforces them; I just stay aware):

- InternetDB: no published limit; free for non-commercial use. Data is refreshed weekly, so it can be days old. The tag names (`c2`, `malware`, `compromised`, `tor`, `vpn`) are not formally documented, so I treat them as best-effort.
- RDAP via rdap.org: about 10 requests per 10 seconds. A single manual lookup is fine.
- AbuseIPDB: 1,000 checks a day on the free tier.

### 3.3 API key handling

- The only key is `ABUSEIPDB_API_KEY`.
- `python-dotenv` loads it from a local `.env` file into the environment (`load_dotenv()`, one line), and the code reads it with `os.environ.get("ABUSEIPDB_API_KEY")`.
- `.env` is in `.gitignore`. `.env.example` shows the variable name with no value.
- No key means AbuseIPDB returns `not_configured` and the other two sources still work.
- The key goes only in a request header, is never printed or logged, and is never placed in a URL or in the HTML.

### 3.4 `verdict.score_verdict(classification, sources)`

A **pure function**: dicts in, dict out, no network and no Flask. This makes it easy to test and easy to explain.

**Early exits (before any scoring):**

1. If the classification is not `global`, the level is `not_applicable` and the summary is "Private or reserved address. External sources were not queried."
2. If no *flagging* source answered (see below), the level is `unknown`.

**Flagging sources** are the ones that can actually raise a red flag: **InternetDB and AbuseIPDB**. RDAP only says who owns the address, so it can't say whether the IP is bad. "No red flags" means nothing unless a source that *could* have raised a flag looked and found none. "Answered" means a status of `ok` or `no_data`.

**Scoring** (a running total; each rule that fires adds points and appends a reason string):

| Signal | Points | Reason text example |
|---|---|---|
| AbuseIPDB score ≥ 75 | +5 | "AbuseIPDB confidence score is 87/100" |
| AbuseIPDB score 25–74 | +2 | same wording |
| AbuseIPDB `isTor` true | +1 | "AbuseIPDB flags this as a Tor exit node" |
| InternetDB tag in {`c2`, `malware`, `compromised`} | +5 | "InternetDB tag: c2" |
| InternetDB tag in {`tor`, `vpn`, `proxy`} | +1 | "InternetDB tag: vpn" |
| InternetDB lists any CVEs (`vulns` not empty) | +1 | "3 known CVEs on exposed services" |

**Mapping the total to a level:**

| Total | Level |
|---|---|
| 5 or more | `malicious` |
| 2 to 4 | `suspicious` |
| 0 or 1 | `no_known_bad` |

(0 or 1 counts as no known bad because a lone Tor/VPN tag or one CVE isn't a bad-IP signal on its own. It does still show up in the reasons list.)

**The summary text** always names which flagging sources answered and which didn't. For example, "No red flags found by InternetDB. AbuseIPDB was not configured, so this is weak evidence."

**Rules about wording (kept from the old design):**

- The app never says "clean" or "safe". `no_known_bad` means the sources found nothing, not that the IP is safe.
- A source that failed, was missing a key or was skipped never makes a verdict look *better*. It only counts as missing evidence.

**The thresholds and weights are placeholders.** I review and adjust them myself before calling the project finished, then record what I settled on in this section. They are constants at the top of `verdict.py` so they are easy to find and change.

### 3.5 `lookup.lookup(ip_text)`

```python
def lookup(ip_text):
    classification = classify_ip(ip_text)     # may raise ValueError; app.py catches it
    if classification["category"] != "global":
        sources = [skipped(...), skipped(...), skipped(...)]
    else:
        sources = [query_internetdb(ip), query_rdap(ip), query_abuseipdb(ip)]
    verdict = score_verdict(classification, sources)
    return {"ip": ip, "classification": classification, "verdict": verdict, "sources": sources}
```

Sources are queried one after another in a plain list. With three sources and an 8 second timeout each, the worst case is around 24 seconds, with a typical lookup taking a few seconds. That is accepted for simplicity. The template shows a "Looking up…" note on submit using one line of HTML/CSS (no JavaScript), or I skip it.

### 3.6 `app.py`: the Flask part

Two routes:

- `GET /` renders `index.html` with just the form.
- `POST /lookup` reads `request.form["ip"]`, calls `lookup()`, and renders `index.html` with `result=...` or `error="..."`.

`ValueError` (invalid IP) becomes an inline error message on the page. Any other unexpected exception gets caught once in `POST /lookup`, shows a generic "Something went wrong" message and prints the traceback to the terminal. The page never shows a stack trace.

**Template (`index.html`):** one file. A form at the top, then if `result` exists: a coloured verdict banner (class depends on `verdict.level`), the reasons list, then a loop over `result.sources` that makes a card for each. A card shows the display name, status, the summary as a simple key/value list, and the raw JSON inside an HTML `<details>` element, so it collapses with no JavaScript. Jinja features used: `{{ }}`, `{% if %}`, `{% for %}`. Nothing else.

---

## 4. Decisions, each with its reason

**D1 — Flask and Jinja, one program.** Flask is small enough to explain in full: a route is a function that returns a page. A second program, an API boundary and a JSON contract would add concepts without adding anything I want to learn here.

**D2 — `requests` and plain functions, sources queried one after another.** `requests` is the HTTP library most Python developers already know. A `for` loop over sources is easy to explain. The cost is a few seconds of waiting, which is acceptable for a one-IP-at-a-time tool. Threads or `asyncio` are a possible stretch goal later, once the simple version works.

**D3 — Dicts instead of Pydantic models or classes.** I can print a dict and read it. The shapes are documented in section 2, and tests check the important keys.

**D4 — Three sources: InternetDB, RDAP, AbuseIPDB.** Two need no account, which keeps the first run easy. The third teaches key handling once, with a real reputation source, which gives the verdict real evidence. Team Cymru was dropped because it needs DNS queries and a separate library. GreyNoise, VirusTotal and ipinfo were dropped for their tight quotas and extra per-source quirks.

**D5 — No caching, no rate limiter.** Every lookup is live. One manual lookup at a time stays well inside every limit, so enforcing limits in code would be machinery for a problem I don't have.

**D6 — Five statuses, with timeouts and rate limits folded into `error`.** The verdict treats all of them the same way (as missing evidence), so splitting them adds no behaviour. The message text says what happened.

**D7 — The verdict is a points score with named constants.** It's about 30 lines of `if` statements. Every verdict lists the reasons that fired, so the result explains itself. The weights are mine to tune and are kept in one visible place.

**D8 — The verdict never says "clean".** `no_known_bad` states honestly that nothing was found. `unknown` is used when no source that could flag the IP gave an answer.

**D9 — Private and reserved IPs are labelled, explained and not sent out.** They carry no public data, and sending them could leak internal addressing.

**D10 — IPv4 only.** `ipaddress` handles both versions, so adding IPv6 later would mostly mean removing one check and confirming each source supports it.

**D11 — Local only, no login, no database.** Nothing in v1 needs to be remembered or protected from other users. These are listed as stretch goals.

**D12 — No JavaScript.** Plain HTML and CSS. The raw response collapses using `<details>`.

**D13 — Tooling: `pip`, a virtual environment and `requirements.txt`.** These are the tools I already know. There is no `uv`, `ruff`, CI or Docker in v1.

**D14 — Libraries, and what each is for.** The whole list is short enough to explain:

- `ipaddress` (standard library): validate an IP and tell private from public.
- `os` (standard library): read the API key from the environment.
- `flask`: the web app and Jinja templates.
- `requests`: calls to the source APIs.
- `python-dotenv`: loads `.env` into the environment so the key isn't in the code.
- `pytest` (development only): runs the tests.

**D15 — Educational and non-commercial.** InternetDB's free tier is for non-commercial use, and AbuseIPDB's terms should be checked at sign-up.

---

## 5. Tests

Tests cover the pure logic, which is where bugs would be most costly and where tests are cheapest to write. They use `pytest` and make no network calls.

**`test_ip_tools.py`**: `8.8.8.8` is `global`; `10.0.0.5` is `private`; `127.0.0.1` is `loopback`; `169.254.1.1` is `link_local`; `224.0.0.1` is `multicast`; `240.0.0.1` is `reserved`; garbage raises `ValueError`; an IPv6 address is rejected with the "not supported" message.

**`test_verdict.py`** (hand-built dicts passed to `score_verdict`):

- A private classification gives `not_applicable`.
- Every source `error` gives `unknown`.
- Only RDAP answered gives `unknown`.
- AbuseIPDB score 90 gives `malicious`.
- AbuseIPDB score 40 gives `suspicious`.
- InternetDB with a `c2` tag gives `malicious`.
- Both flagging sources `ok` with nothing found gives `no_known_bad`.
- `not_configured` AbuseIPDB plus a clean InternetDB gives `no_known_bad`, with the summary mentioning that AbuseIPDB wasn't checked.
- Reasons are listed for each rule that fired.

**Source functions are not unit tested in v1.** I check them by hand against the real services (look up `8.8.8.8`, an IP with a bad reputation, and an unused address). A later stretch goal is to test them using `unittest.mock.patch` on `requests.get` with saved sample JSON.

---

## 6. Milestones

Each milestone ends with something I can run and show.

**M1: The skeleton with one source.**
`ip_tools.py`, `sources.py` with only `query_internetdb`, `lookup.py`, and a bare `app.py` and `index.html` that show the raw dict. Tests for `classify_ip`.
*Done when:* I can run `flask run`, look up `8.8.8.8` and see the InternetDB result, and a private IP shows its explanation and an invalid one shows an inline message.

**M2: All three sources.**
Add `query_rdap` and `query_abuseipdb`, and the `.env` key handling. Replace the raw display with one card per source, including collapsible raw JSON.
*Done when:* all three cards show for a public IP; with no key, the AbuseIPDB card says "not configured" and the page still works; turning off my network gives readable `error` cards, not a crash.

**M3: The verdict.**
Write `verdict.py` and its tests, then add the verdict banner and reasons list.
*Done when:* known-bad, known-good and private IPs each give a sensible verdict with reasons, and I have reviewed and settled the weights and thresholds.

**M4: Polish and README.**
Styling, README with install and run steps, and a final check on a fresh virtual environment that the instructions work. Read through the code once and make sure I can explain every line.
*Done when:* a clean install from the README works, and I can walk through the code top to bottom without hand-waving.

### Stretch goals (only after M4, one at a time)

- Query sources with `ThreadPoolExecutor`, which makes the lookup take as long as the slowest source and fits in about 5 extra lines.
- Mock-based tests for the source functions.
- Save lookups to a SQLite file using the standard-library `sqlite3`, plus a history page.
- Export a result as JSON or CSV.
- IPv6.
- Add another source (Team Cymru, GreyNoise, VirusTotal or ipinfo).

---

## 7. Notes for Claude Code

- Work one milestone at a time and stop at the end of each for my review.
- Python only, one Flask program, no JavaScript.
- Before adding anything, ask "can Ben explain this in a sentence?" If not, make it simpler or ask me.
- Use only the libraries listed in D14. Ask before adding another.
- Prefer plain functions and dicts. No classes, `async`, decorators beyond Flask's `@app.route`, or type-heavy patterns unless I ask.
- Comment the *why* in code, and keep comments short.
- Check each source's current docs before writing its function, and update section 3.2 if anything differs.
- Never upload or report anything to AbuseIPDB or any other provider. Look-ups only.
- Never log, print or return the API key.
- If a requirement here is ambiguous or conflicts with what you find, ask rather than guess.
