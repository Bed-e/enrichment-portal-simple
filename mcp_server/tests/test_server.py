"""Tests for the MCP server (design.md section 13).

Each test talks to the server through the MCP SDK's own client, the same way Claude Desktop does,
so they check what a model really sees: the tool list, results and tool errors (is_error).
No test touches the network: requests.get is swapped for a fake that replays a recorded real
backend answer from tests/samples/. Answers that can't be recorded on demand (a 500, a refused
connection, a failing source) are simulated, and the test name or comment says so.

The SDK's client is async, so each test wraps its steps in an `async def` and runs it with
anyio.run() (anyio is installed with the mcp package).
"""

import copy
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import anyio
import requests
from mcp import Client, StdioServerParameters

import server

SAMPLES = Path(__file__).parent / "samples"
SERVER_FILE = Path(__file__).parent.parent / "server.py"


class FakeResponse:
    """Stands in for a requests response: the two things server.py reads from one."""

    def __init__(self, status_code, json_data=None):
        self.status_code = status_code
        self._json_data = json_data

    def json(self):
        if self._json_data is None:
            raise ValueError("not JSON")  # what requests raises for a body that isn't JSON
        return self._json_data


def load(name):
    with open(SAMPLES / name, encoding="utf-8") as f:
        return json.load(f)


def call(arguments):
    """Call lookup_ip through an in-process MCP client and return the CallToolResult."""

    async def run():
        async with Client(server.mcp) as client:
            return await client.call_tool("lookup_ip", arguments)

    return anyio.run(run)


def result_data(result):
    """The answer a model reads from a successful call: one text block holding JSON."""
    assert result.is_error is False
    assert len(result.content) == 1
    return json.loads(result.content[0].text)


def error_text(result):
    """The message a model reads from a tool error."""
    assert result.is_error is True
    return result.content[0].text


# --- The tool list -------------------------------------------------------------------------


def test_lists_exactly_one_read_only_tool_with_an_ip_argument():
    async def run():
        async with Client(server.mcp) as client:
            return (await client.list_tools()).tools

    tools = anyio.run(run)

    assert [t.name for t in tools] == ["lookup_ip"]
    tool = tools[0]
    assert tool.input_schema["required"] == ["ip"]
    assert tool.input_schema["properties"]["ip"]["type"] == "string"
    assert tool.annotations.read_only_hint is True
    # The description must name what comes in, what goes out and every source.
    for words in ["IPv4", "verdict", "Shodan InternetDB", "RDAP", "AbuseIPDB", "no_data", "Refuses"]:
        assert words in tool.description


# --- Valid addresses: the portal answers 200 -----------------------------------------------


def test_public_ip_returns_compact_verdict_and_sources():
    sample = load("backend_ok.json")
    with patch("server.requests.get", return_value=FakeResponse(200, sample)):
        result = call({"ip": "8.8.8.8"})

    data = result_data(result)
    assert data["ip"] == "8.8.8.8"
    assert data["category"] == "global"
    assert data["verdict"]["level"] == sample["verdict"]["level"]
    assert data["verdict"]["reasons"] == sample["verdict"]["reasons"]
    assert [s["name"] for s in data["sources"]] == ["internetdb", "rdap", "abuseipdb"]
    # Compact: only the promised fields, without the large raw JSON or display names.
    assert set(data["sources"][0]) == {"name", "status", "summary", "error"}
    assert "raw" not in json.dumps(data)


def test_spaces_are_stripped_and_the_standard_form_is_sent():
    with patch("server.requests.get", return_value=FakeResponse(200, load("backend_ok.json"))) as fake:
        call({"ip": "  8.8.8.8 "})
    assert fake.call_args.args[0] == "http://127.0.0.1:5001/api/ip/8.8.8.8"


def test_private_ip_is_not_applicable_with_sources_skipped():
    with patch("server.requests.get", return_value=FakeResponse(200, load("backend_private.json"))):
        result = call({"ip": "192.168.1.1"})

    data = result_data(result)
    assert data["category"] == "private"
    assert data["explanation"]
    assert data["verdict"]["level"] == "not_applicable"
    assert data["verdict"]["score"] == 0  # a number, never null; the level says "not judged"
    assert {s["status"] for s in data["sources"]} == {"skipped"}


def test_failing_source_stays_in_the_result_not_a_tool_error():
    # Simulated: the recorded answer with AbuseIPDB changed to a timeout error.
    sample = copy.deepcopy(load("backend_ok.json"))
    sample["sources"][2].update(status="error", summary=None, raw=None, error="Request timed out")
    with patch("server.requests.get", return_value=FakeResponse(200, sample)):
        result = call({"ip": "8.8.8.8"})

    abuse = result_data(result)["sources"][2]
    assert abuse == {"name": "abuseipdb", "status": "error", "summary": None, "error": "Request timed out"}


def test_portal_url_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("PORTAL_URL", "http://127.0.0.1:5003")
    with patch("server.requests.get", return_value=FakeResponse(200, load("backend_ok.json"))) as fake:
        call({"ip": "8.8.8.8"})
    assert fake.call_args.args[0] == "http://127.0.0.1:5003/api/ip/8.8.8.8"


# --- Invalid input: a tool error, and the portal is never called ---------------------------


INVALID = [
    "not-an-ip",
    "",
    "1.2.3.0/24",
    "example.com",
    "https://8.8.8.8/",
    "8.8.8.8, 1.1.1.1",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # a sha256
]


def test_invalid_iocs_give_a_tool_error_without_calling_the_portal():
    with patch("server.requests.get") as fake:
        for text in INVALID:
            message = error_text(call({"ip": text}))
            assert "is not a valid IPv4 address" in message, text
    fake.assert_not_called()


def test_ipv6_gives_a_tool_error_without_calling_the_portal():
    with patch("server.requests.get") as fake:
        message = error_text(call({"ip": "2001:4860:4860::8888"}))
    assert "IPv6 is not supported" in message
    fake.assert_not_called()


# --- The portal answers with an error -------------------------------------------------------


def test_portal_400_passes_on_the_portals_message():
    # Our own check stops bad input first, so this replays the recorded 400 body directly.
    with patch("server.requests.get", return_value=FakeResponse(400, load("backend_400_invalid.json"))):
        message = error_text(call({"ip": "8.8.8.8"}))
    assert "That is not a valid IP address." in message


def test_portal_500_is_a_tool_error():
    # Simulated, using the contract's 500 body (design.md section 7).
    body = {"error": "internal_error", "message": "Something went wrong."}
    with patch("server.requests.get", return_value=FakeResponse(500, body)):
        message = error_text(call({"ip": "8.8.8.8"}))
    assert "internal error" in message


def test_portal_503_is_a_tool_error_saying_the_ip_was_not_judged():
    # Simulated, using the contract's 503 body (design.md section 7): every source failed.
    body = {"error": "sources_unavailable", "message": "No data source could be reached. Try again shortly."}
    with patch("server.requests.get", return_value=FakeResponse(503, body)):
        message = error_text(call({"ip": "8.8.8.8"}))
    assert "not judged" in message


def test_portal_down_is_a_tool_error_naming_the_address():
    # Simulated: the backend is not running.
    with patch("server.requests.get", side_effect=requests.ConnectionError("refused")):
        message = error_text(call({"ip": "8.8.8.8"}))
    assert "Could not reach the portal at http://127.0.0.1:5001" in message


def test_answer_that_is_not_the_contract_is_a_tool_error():
    # Simulated: a 200 whose body is not JSON, and one missing the contract's keys.
    for response in [FakeResponse(200, None), FakeResponse(200, {"unexpected": True})]:
        with patch("server.requests.get", return_value=response):
            message = error_text(call({"ip": "8.8.8.8"}))
        assert "unexpected answer" in message


# --- The real program over stdio ------------------------------------------------------------


def test_real_server_over_stdio_lists_and_calls_the_tool():
    """Start server.py as Claude Desktop does and talk to it over stdin/stdout.

    If anything other than the MCP protocol were printed to stdout, the client could not read
    the answers and this test would fail. PORTAL_URL points at a port where nothing listens on
    this computer, so a valid IP gives the "could not reach" tool error with no network used.
    """
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER_FILE)],
        env={**os.environ, "PORTAL_URL": "http://127.0.0.1:9"},
    )

    async def run():
        async with Client(params) as client:
            tools = (await client.list_tools()).tools
            invalid = await client.call_tool("lookup_ip", {"ip": "example.com"})
            unreachable = await client.call_tool("lookup_ip", {"ip": "8.8.8.8"})
            return tools, invalid, unreachable

    tools, invalid, unreachable = anyio.run(run)

    assert [t.name for t in tools] == ["lookup_ip"]
    assert "is not a valid IPv4 address" in error_text(invalid)
    assert "Could not reach the portal at http://127.0.0.1:9" in error_text(unreachable)
