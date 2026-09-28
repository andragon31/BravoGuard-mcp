"""Smoke test: server imports and exposes the five Phase 1 tools."""

EXPECTED_TOOLS = {"scan_diff", "scan_repo", "osv_lookup", "owasp_explain", "suggest_fix"}


async def _tool_names() -> set[str]:
    from bravoguard.server import mcp

    if hasattr(mcp, "get_tools"):
        tools = await mcp.get_tools()  # FastMCP <4 fallback
        return set(tools.keys())
    tools = await mcp._list_tools()  # FastMCP 4
    return {t.name for t in tools}


def test_server_exposes_five_tools() -> None:
    import asyncio

    assert asyncio.run(_tool_names()) == EXPECTED_TOOLS


def test_owasp_mapping_corrected_to_2025() -> None:
    from bravoguard.owasp_map import explain_cwe

    # Injection is A05 in 2025, not A03 (2021).
    assert explain_cwe("CWE-79")["owasp_2025"] == "A05"
    assert explain_cwe("cwe-89")["owasp_2025"] == "A05"
    assert explain_cwe("CWE-502")["owasp_2025"] == "A08"
    assert explain_cwe("CWE-798")["owasp_2025"] == "A07"
    assert explain_cwe("CWE-918")["owasp_2025"] == "A01"


def test_llm_table_loads() -> None:
    from bravoguard.owasp_map import explain_llm

    assert explain_llm("LLM01:2026")["title"] == "Prompt Injection"
