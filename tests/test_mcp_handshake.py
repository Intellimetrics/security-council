"""Live MCP transport handshake — runs only where the `mcp` SDK is installed
(`pip install -e .[mcp]`, e.g. the project .venv); skips elsewhere so the
stdlib-only system-python suite stays green.

Spawns the real server subprocess over stdio and drives initialize ->
list_tools -> call_tool (success + error path). First live-verified
2026-08-22 against mcp 2.0.0 / protocol 2025-11-25.
"""
import asyncio
import json
import os
import pathlib
import sys

import pytest

pytest.importorskip("mcp")

REPO = pathlib.Path(__file__).resolve().parent.parent


async def test_stdio_handshake_lists_and_calls_tools(tmp_path):
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    params = StdioServerParameters(
        command=sys.executable, args=["-m", "security_council.mcp_server"],
        cwd=str(REPO),
        env={**os.environ, "SECURITY_COUNCIL_MCP_ROOT": str(tmp_path)})

    async with asyncio.timeout(60):
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                assert init.server_info.name == "security-council"

                tools = await session.list_tools()
                from security_council.mcp_server import TOOLS
                assert [t.name for t in tools.tools] == [t[0] for t in TOOLS]

                r = await session.call_tool("sc_config", {})
                assert not r.is_error
                cfg = json.loads(r.content[0].text)
                assert cfg["config"]["policy"]["auto_suppress"] is False

                r = await session.call_tool("sc_last_run", {})
                assert not r.is_error and json.loads(r.content[0].text) == {"found": False}

                # handler errors must reach the client as isError with the message
                r = await session.call_tool("sc_config", {"target": "relative"})
                assert r.is_error and "PathMustBeAbsolute" in r.content[0].text
                r = await session.call_tool("sc_nope", {})
                assert r.is_error and "Unknown tool" in r.content[0].text
