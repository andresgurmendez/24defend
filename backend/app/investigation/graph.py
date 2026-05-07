"""LangGraph-based domain investigation agent.

Uses Bedrock Sonnet as the reasoning engine with tools for DNS, SSL,
Levenshtein, Google search, Safe Browsing, and heuristics.

The agent decides which tools to call, interprets results, and returns
a structured verdict: block / warn / allow with reasoning.
"""

import json
import logging
from datetime import datetime, timezone
from time import time
from typing import Annotated

from langchain_aws import ChatBedrock
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from typing_extensions import TypedDict

from app.config import settings
from app.domain_service import put_domain, scan_by_type
from app.investigation.tools import ALL_TOOLS
from app.models import DomainEntry, EntryType, Verdict

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a cybersecurity domain investigation agent for 24Defend, an anti-phishing app protecting users in Latin America.

Your job: determine if a domain is FRAUDULENT (phishing/scam) or LEGITIMATE.

You have tools to investigate. Use them strategically:
1. Always start with `domain_heuristics` and `levenshtein_similarity` — they're instant and free.
2. Use `dns_lookup` to check domain age — new domains (<30 days) impersonating banks are almost always phishing.
3. Use `ssl_certificate_check` to verify the certificate — free CAs on bank-impersonating domains are a red flag.
4. Use `google_search` if you need more context — zero results for a "bank" domain is very suspicious.
5. Use `safe_browsing_check` for a definitive malware/phishing flag.

IMPORTANT CONTEXT:
- The whitelist contains official domains of financial institutions in Uruguay and Latin America.
- Phishing domains in this market typically: impersonate banks (BROU, Itaú, Santander), use similar-looking domains, are very new, and use free SSL certificates.
- False positives are WORSE than false negatives. Only verdict "block" if you are confident. Use "warn" if suspicious but uncertain.

CRITICAL — AD-TECH AND CDN INFRASTRUCTURE:
Many domains you investigate will be ad-tech, tracking, analytics, or CDN infrastructure. These are NOT phishing. Always verdict "allow" for:
- CDN CNAME chains: domains ending in .cdn.cloudflare.net, .cloudfront.net, .akamaiedge.net, .fastly.net, .edgekey.net — these are legitimate CDN endpoints, NOT impersonation.
- Ad/tracking domains: obfuscated or abbreviated names are NORMAL in ad-tech (e.g., ltmsphrcl.net = Lotame, adnxs.com = Xandr/AppNexus, demdex.net = Adobe, omtrdc.net = Adobe, moatads.com = Oracle Moat, adzonestatic.com = ad serving). These look suspicious but serve billions of legitimate page views.
- Google Safe Browsing flags on ad-tech domains are COMMON false positives. Do NOT treat a Safe Browsing hit as definitive for ad/tracking domains.
- If the domain does not impersonate any brand (bank, service, company), it is almost certainly infrastructure. Our app protects against PHISHING, not malware/adware.

RETROACTIVE NOTIFICATION:
The user who visited this domain has already seen the page. If you determine it IS phishing, you can recommend sending them a retroactive warning notification (should_notify=true). This notification tells the user to change their password, so a FALSE notification is extremely damaging to our credibility. Only set should_notify=true when ALL of these are true:
1. You are confident this is phishing (verdict=block, confidence >= 0.85)
2. The domain impersonates a specific, identifiable brand (bank, service, etc.)
3. The evidence is strong: multiple signals like new domain + free SSL + brand impersonation + no legitimate search results
Do NOT notify for: ambiguous cases, domains that could be legitimate regional variants (e.g., santander-mx.com = real Santander Mexico), or domains where the brand match is weak.

After investigation, respond with EXACTLY this JSON format (no other text):
{
    "verdict": "block" | "warn" | "allow",
    "confidence": 0.0 to 1.0,
    "should_notify": true | false,
    "reasoning": "2-3 sentence explanation of your decision"
}
"""


class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    domain: str
    whitelist_domains: list[str]


def _create_llm():
    """Create Bedrock Sonnet LLM with tool binding."""
    llm = ChatBedrock(
        model_id=settings.bedrock_model_id,
        region_name=settings.bedrock_region,
        model_kwargs={"temperature": 0, "max_tokens": 1024},
    )
    return llm.bind_tools(ALL_TOOLS)


def _should_continue(state: AgentState) -> str:
    """Route: if the last message has tool calls, go to tools. Otherwise, end."""
    last_message = state["messages"][-1]
    if isinstance(last_message, AIMessage) and last_message.tool_calls:
        return "tools"
    return END


def _call_model(state: AgentState) -> dict:
    """Call the LLM with the current messages."""
    llm = _create_llm()
    response = llm.invoke(state["messages"])
    return {"messages": [response]}


def build_graph() -> StateGraph:
    """Build the LangGraph investigation agent."""
    graph = StateGraph(AgentState)

    # Nodes
    graph.add_node("agent", _call_model)
    graph.add_node("tools", ToolNode(ALL_TOOLS))

    # Edges
    graph.set_entry_point("agent")
    graph.add_conditional_edges("agent", _should_continue, {"tools": "tools", END: END})
    graph.add_edge("tools", "agent")

    return graph.compile()


# Singleton compiled graph
_graph = None


def _get_graph():
    global _graph
    if _graph is None:
        _graph = build_graph()
    return _graph


async def investigate_domain(domain: str) -> DomainEntry:
    """Run the LangGraph agent to investigate a domain.

    Returns a DomainEntry with verdict, confidence, and reasoning.
    Results are cached in DynamoDB.
    """
    logger.info(f"Starting LangGraph investigation for {domain}")
    start = time()

    # Get whitelist domains for Levenshtein comparison
    whitelist_entries = await scan_by_type(EntryType.whitelist)
    whitelist_domains = list(set(e.domain for e in whitelist_entries))

    # Build the initial message
    user_message = (
        f"Investigate this domain: {domain}\n\n"
        f"Known official (whitelisted) domains to compare against:\n"
        f"{json.dumps(whitelist_domains[:50])}\n\n"
        f"Use your tools to determine if this domain is fraudulent. "
        f"Start with heuristics and levenshtein_similarity."
    )

    initial_state: AgentState = {
        "messages": [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=user_message),
        ],
        "domain": domain,
        "whitelist_domains": whitelist_domains,
    }

    # Run the graph
    graph = _get_graph()
    try:
        final_state = await graph.ainvoke(initial_state)
    except Exception as e:
        logger.error(f"LangGraph agent failed for {domain}: {e}")
        return _fallback_entry(domain, str(e))

    # Parse the final response
    last_message = final_state["messages"][-1]
    elapsed = time() - start
    logger.info(f"Investigation for {domain} completed in {elapsed:.1f}s")

    entry = _parse_verdict(domain, last_message.content)

    # Persist to cache
    await put_domain(entry)

    return entry


def _parse_verdict(domain: str, content: str) -> DomainEntry:
    """Parse the LLM's JSON verdict from its response."""
    try:
        # Extract JSON from the response (may have surrounding text)
        start = content.index("{")
        end = content.rindex("}") + 1
        data = json.loads(content[start:end])

        verdict_str = data.get("verdict", "allow").lower()
        verdict = {"block": Verdict.block, "warn": Verdict.warn}.get(verdict_str, Verdict.allow)

        return DomainEntry(
            domain=domain,
            entry_type=EntryType.cache,
            verdict=verdict,
            confidence=float(data.get("confidence", 0.5)),
            reason=data.get("reasoning", "Agent investigation completed"),
            should_notify=bool(data.get("should_notify", False)),
            checked_at=datetime.now(timezone.utc),
            ttl=int(time()) + 30 * 86400,
        )
    except (ValueError, json.JSONDecodeError, KeyError) as e:
        logger.warning(f"Failed to parse agent verdict for {domain}: {e}. Raw: {content[:200]}")
        return DomainEntry(
            domain=domain,
            entry_type=EntryType.cache,
            verdict=Verdict.warn,
            confidence=0.3,
            reason=f"Agent completed but verdict unclear: {content[:200]}",
            checked_at=datetime.now(timezone.utc),
            ttl=int(time()) + 7 * 86400,  # shorter cache for unclear verdicts
        )


def _fallback_entry(domain: str, error: str) -> DomainEntry:
    """Create a fallback entry when the agent fails entirely."""
    return DomainEntry(
        domain=domain,
        entry_type=EntryType.cache,
        verdict=Verdict.warn,
        confidence=0.1,
        reason=f"Investigation failed: {error}",
        checked_at=datetime.now(timezone.utc),
        ttl=int(time()) + 3600,  # short cache — retry in 1 hour
    )
