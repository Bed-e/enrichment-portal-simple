# IP Enrichment Portal (Simple)

A small local web app. Type one IPv4 address and it shows:

- a **verdict** (Malicious, Suspicious, No known bad, Unknown, or Not applicable for private
  addresses) with the reasons listed
- one **card per source**, with the raw response available on demand

Sources: Shodan InternetDB, RDAP (registration data) and AbuseIPDB.

The app only **reads** data. It never submits or reports anything to any service. Private and
reserved addresses (like `192.168.1.1`) are never sent to outside services.

For the full design and scope, see [design.md](design.md).

## Requirements

- Python 3 (developed and tested on 3.12; other versions are untested)
- Internet access, because the sources are queried live
- Optional: a free AbuseIPDB API key. Without it the app still works, and the AbuseIPDB card
  says "not configured". Create a free account at https://www.abuseipdb.com to get a key.

## Install

Run these from the project folder.

1. Create a virtual environment. This is a private copy of Python for this project, so its
   packages don't mix with other projects.

   ```
   python -m venv venv
   ```

2. Activate it. Your prompt should then start with `(venv)`.

   - Windows PowerShell: `venv\Scripts\Activate.ps1`
   - Windows cmd: `venv\Scripts\activate.bat`
   - macOS / Linux: `source venv/bin/activate`

3. Install the dependencies:

   ```
   pip install -r requirements.txt
   ```

## Configure (optional)

Settings that must not live in the code, like API keys, go in a `.env` file in the project
folder (the top one, next to this README). It is listed in `.gitignore`, so it is never committed.

1. Copy the template:

   - Windows: `copy .env.example .env`
   - macOS / Linux: `cp .env.example .env`

2. Open `.env` and replace `your-key-here` with your real AbuseIPDB key.

3. `BACKEND_URL` tells the frontend where the backend is. The default already matches the
   commands below, so change it only if you change the backend's port (see "Change the port").

Never share your key or commit `.env`.

## Run

The app is two programs: a **backend** (an API that queries the sources and returns JSON) and a
**frontend** (the web page, which only talks to the backend). Run each in its own terminal, with
the virtual environment active in both.

Terminal 1, the backend (port 5001):

```
cd backend
flask --app api run --port 5001
```

Terminal 2, the frontend (port 5000):

```
cd frontend
flask --app app run --port 5000
```

Then open http://127.0.0.1:5000 in your browser, type an IP address (for example `8.8.8.8`),
and press **Look up**. A lookup queries three sources one after another, so it can take a few
seconds. Stop each server with Ctrl+C. If the backend is stopped, the page says the lookup
service is unavailable.

You can also call the backend directly. A browser or `curl.exe` will do (on Windows PowerShell, plain `curl` is a different command that
prints a confusing summary, so use `curl.exe`; on macOS and Linux, `curl` works):

```
curl.exe http://127.0.0.1:5001/api/ip/8.8.8.8
```

The format of the answer is the API contract in section 7 of [design.md](design.md).

If something goes wrong, details are printed in the terminal of the program that failed. The web
page only shows a short, safe message. Only the backend reads the AbuseIPDB key.

### Change the port

Two programs can't listen on the same port. Change the number after `--port`. If you change the
backend's port, set `BACKEND_URL` in `.env` to match, for example `BACKEND_URL=http://127.0.0.1:5003`.
To run a second copy of the portal on the same computer, give it different ports for both
programs (for example 5003 for the backend and 5002 for the frontend).

## Test

Each program has its own tests. Run `pytest` from inside its folder:

```
cd backend
pytest
```

```
cd frontend
pytest
```

The backend tests cover the pure logic (IP classification and verdict scoring), the source
functions (which replay real responses saved in `backend/tests/samples/`) and the API endpoint.
The frontend tests replay a real backend answer saved in `frontend/tests/samples/`. No test makes
network calls.

To count how many requests a fixed run of 26 lookups sends to each source (no network, no quota
spent), run `python measure_calls.py` from inside `backend/`. The backend keeps each source's
answer for a while and reuses it; the expiry times and reasons are in section 12 of
[design.md](design.md).

## Project layout

| File | What it does |
| --- | --- |
| `backend/api.py` | The backend: one endpoint, `GET /api/ip/<ip>`, that returns JSON |
| `backend/lookup.py` | Runs one lookup: classify the IP, query sources, score the verdict |
| `backend/ip_tools.py` | Checks whether an address is valid, public, private or reserved |
| `backend/sources.py` | One function per source (Shodan InternetDB, RDAP, AbuseIPDB) |
| `backend/verdict.py` | Turns the source results into a verdict using a simple points score |
| `backend/cache.py` | Keeps each source's answer in memory for a while, so repeat lookups reuse it |
| `backend/measure_calls.py` | Counts requests per source for a fixed run of lookups, with no network |
| `backend/tests/` | Automated tests, and the recorded responses they replay |
| `frontend/app.py` | The web page routes: shows the form and calls the backend |
| `frontend/templates/index.html` | The page |
| `frontend/static/style.css` | The styling |
| `frontend/tests/` | Automated tests, and the recorded backend answer they replay |
