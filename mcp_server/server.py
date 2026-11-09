"""MCP server for the IP Enrichment Portal.

Claude Desktop starts this program and talks to it over stdio (its stdin and stdout). Each tool
call becomes one request to the portal's backend API, GET /api/ip/<ip> (design.md section 7).
This server never calls a source itself and never reads .env or an API key: only the backend does.

Design and reasons: design.md section 13.
"""

import ipaddress
import logging
import os
import sys
from urllib.parse import quote

import requests
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

# stdout carries the MCP protocol, so anything else written there would corrupt it.
# That is why there is no print() in this file: messages go to stderr through logging.
# This runs before MCPServer() so our settings win (logging.basicConfig only applies once).
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("ioc_portal_mcp")

# The backend's default address (design.md section 7). Override it with the PORTAL_URL
# environment variable, set in the Claude Desktop config, when the backend runs on another port.
DEFAULT_PORTAL_URL = "http://127.0.0.1:5001"

# The backend can take about 24 s when all three sources are slow, so allow 30 s (same as the frontend).
TIMEOUT_SECONDS = 30

mcp = MCPServer("ioc-portal")


def _portal_url():
    # Read on every call (not once at import), so a test or a second portal can change it.
    return os.environ.get("PORTAL_URL", DEFAULT_PORTAL_URL)


def _compact(result):
    """Keep only the fields the tool description promises. Drops `raw` (large) and `display_name`."""
    classification = result["classification"]
    verdict = result["verdict"]
    return {
        "ip": result["ip"],
        "category": classification["category"],
        "explanation": classification["explanation"],
        "verdict": {
            "level": verdict["level"],
            "score": verdict["score"],
            "summary": verdict["summary"],
            "reasons": verdict["reasons"],
        },
        "sources": [
            {
                "name": source["name"],
                "status": source["status"],
                "summary": source["summary"],
                "error": source["error"],
            }
            for source in result["sources"]
        ],
    }


# read_only_hint tells the client this tool only reads data: it changes nothing anywhere.
@mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
def lookup_ip(ip: str) -> dict:
    """Look up one IPv4 address in the IP Enrichment Portal and get its verdict.

    In: ip, a single IPv4 address such as "8.8.8.8".

    Out: the address, its category (global, private, loopback, link_local, multicast, reserved,
    other_non_global), the verdict (level: malicious, suspicious, no_known_bad, unknown or
    not_applicable; score; summary; reasons) and, for each source, its status, key fields
    (summary) and any error message. The score is the certainty of malicious activity from 0 to
    100, or null when there is no evidence (level unknown or not_applicable). A score of 0 does
    not mean safe, only that the sources asked found nothing.

    Sources: Shodan InternetDB (open ports, tags, CVEs), RDAP (who owns the address; never
    changes the verdict) and AbuseIPDB (abuse reports).

    Source status: "no_data" means the source answered but knows nothing about this IP, which is
    not proof it is safe. "error" or "not_configured" means that source gave no evidence.
    Private and reserved addresses are never sent to the sources: level is not_applicable and
    every source is "skipped". The portal may reuse a source's answer for up to 24 hours
    (InternetDB), 7 days (RDAP) or 6 hours (AbuseIPDB; 1 hour when it found no reports).

    Refuses: IPv6, CIDR ranges (1.2.3.0/24), hostnames, domains, URLs, file hashes and lists of
    addresses. The portal only supports single IPv4 addresses, so do not retry those with this tool.
    """
    text = ip.strip()

    # Validate with the same parser the backend uses (backend/ip_tools.py), before any request.
    # A ToolError is sent back to the model as a result with isError: true, not as a crash.
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        raise ToolError(
            "That is not a valid IPv4 address. Give one address like 8.8.8.8; ranges, "
            "hostnames, domains, URLs and hashes are not supported."
        )
    if address.version == 6:
        raise ToolError("IPv6 is not supported by the portal; only IPv4 addresses can be looked up.")

    portal = _portal_url()
    # str(address) is the standard form; quote() keeps it safe inside a URL (as frontend/app.py does).
    url = f"{portal}/api/ip/{quote(str(address), safe='')}"

    try:
        response = requests.get(url, timeout=TIMEOUT_SECONDS)
    except requests.RequestException as e:
        # Covers a refused connection and a timeout. The detail goes to the log, not the model.
        log.warning("lookup %s: could not reach %s (%s)", address, portal, type(e).__name__)
        raise ToolError(f"Could not reach the portal at {portal}. Is the backend running?")
    log.info("lookup %s: HTTP %s", address, response.status_code)

    if response.status_code == 400:
        # The portal's own validation error. Its message is safe to show (design.md section 7).
        try:
            message = response.json()["message"]
        except (ValueError, KeyError, TypeError):
            log.warning("lookup %s: 400 without the contract's error body", address)
            raise ToolError("The portal gave an unexpected answer.")
        raise ToolError(message)

    if response.status_code == 500:
        raise ToolError("The portal had an internal error. Details are in the portal's terminal.")

    if response.status_code != 200:
        log.warning("lookup %s: unexpected HTTP %s", address, response.status_code)
        raise ToolError("The portal gave an unexpected answer.")

    # A failing source is NOT a tool error: it stays inside the 200 answer as status "error".
    try:
        return _compact(response.json())
    except (ValueError, KeyError, TypeError):
        log.exception("lookup %s: answer did not match the API contract", address)
        raise ToolError("The portal gave an unexpected answer.")


if __name__ == "__main__":
    # stdio is the default transport: Claude Desktop starts this file and talks over stdin/stdout.
    mcp.run()
