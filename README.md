# IP Enrichment Portal (Simple)

A small local web app. Type one IPv4 address and it shows a verdict (Malicious, Suspicious, etc.)
with a 0-100 suspicion score, plus one card per source (Shodan InternetDB, RDAP and AbuseIPDB)
with the raw response on demand. How it works: [design.md](design.md).

> Lookups go to outside services, so don't enter addresses you need to keep private.

## Set up

Needs Python 3 (developed on 3.12) and internet access.

```bash
python -m venv venv
venv\Scripts\activate          # macOS / Linux: source venv/bin/activate
pip install -r requirements.txt
```

Optional: AbuseIPDB needs a free API key (https://www.abuseipdb.com). Copy `.env.example` to
`.env` and replace `your-key-here` with your key. `.env` is git-ignored: never commit it.

## Run

Two terminals, both with the virtual environment active:

```bash
cd backend && flask --app api run --port 5001     # terminal 1: the backend
cd frontend && flask --app app run --port 5000    # terminal 2: the frontend
```

Open http://127.0.0.1:5000 and type an IP such as `8.8.8.8`; a lookup can take a few seconds.
If you change the backend's port, set `BACKEND_URL` in `.env` to match. Errors are printed in
the terminal, never on the page.

## Test

Run `pytest` from inside `backend/` and from inside `frontend/`.

Open an issue at https://github.com/Bed-e/enrichment-portal-simple if the tests fail.

## Use it from Claude

The MCP server lets Claude call the backend: setup is in [mcp_server/README.md](mcp_server/README.md).
`.claude/skills/ioc-triage/` is a skill for triaging a pasted list of values; open this folder
in a Claude Code session to use it.
