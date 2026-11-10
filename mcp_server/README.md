## MCP server (ask Claude Desktop about an IP)

`mcp_server/server.py` lets Claude Desktop look up an IP address through the portal. It offers one
tool, `lookup_ip`, that calls the backend's API (it never calls a source itself). The design and
the reasons behind it are in section 13 of [design.md](design.md).

It is installed with everything else by `pip install -r requirements.txt`. The backend must be
running for lookups to work.

Its tests make no network calls. Run them from inside `mcp_server/`:

```
cd mcp_server
pytest
```

**Connect it to Claude Desktop.** First quit Claude Desktop fully (system tray icon, then Quit):
while it is running it can overwrite the config file and drop your change. Then, on Windows, open
`%APPDATA%\Claude\claude_desktop_config.json`. If you installed Claude Desktop from the Microsoft
Store, the file is at `%LOCALAPPDATA%\Claude-Data\claude_<id>\claude_desktop_config.json` instead.
Add the server and save. Replace
`C:\\path\\to` with where this project is, using double backslashes. `PORTAL_URL` is the backend's
address; change the port if you run the backend on another one.

```json
{
  "mcpServers": {
    "ioc-portal": {
      "command": "C:\\path\\to\\enrichment-portal-simple\\venv\\Scripts\\python.exe",
      "args": ["C:\\path\\to\\enrichment-portal-simple\\mcp_server\\server.py"],
      "env": { "PORTAL_URL": "http://127.0.0.1:5001" }
    }
  }
}
```

Start Claude Desktop again, then ask something like "What's the verdict on 8.8.8.8?". No API key goes
in this config: only the backend reads the AbuseIPDB key, from `.env`.