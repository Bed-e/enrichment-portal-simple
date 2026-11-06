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

Settings that must not live in the code, like API keys, go in a `.env` file. It is listed in
`.gitignore`, so it is never committed.

1. Copy the template:

   - Windows: `copy .env.example .env`
   - macOS / Linux: `cp .env.example .env`

2. Open `.env` and replace `your-key-here` with your real AbuseIPDB key.

Never share your key or commit `.env`.

## Run

With the virtual environment active, run this from the project folder:

```
flask run
```

Flask finds `app.py` in the current folder on its own. Then open http://127.0.0.1:5000 in your browser, type an IP address (for example `8.8.8.8`),
and press **Look up**. A lookup queries three sources one after another, so it can take a few
seconds. Stop the server with Ctrl+C.

If something goes wrong, details are printed in the terminal where the server is running. The web
page only shows a short, safe message.

## Test

```
pytest
```

The tests cover the pure logic (IP classification and the verdict scoring). They don't make
network calls.

## Project layout

| File | What it does |
| --- | --- |
| `app.py` | Flask routes: the form page and the lookup |
| `lookup.py` | Runs one lookup: classify the IP, query sources, score the verdict |
| `ip_tools.py` | Checks whether an address is valid, public, private or reserved |
| `sources.py` | One function per source (Shodan InternetDB, RDAP, AbuseIPDB) |
| `verdict.py` | Turns the source results into a verdict using a simple points score |
| `templates/index.html` | The page |
| `static/style.css` | The styling |
| `tests/` | Automated tests |
