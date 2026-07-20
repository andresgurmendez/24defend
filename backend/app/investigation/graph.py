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
from typing import Annotated, Literal

from langchain_aws import ChatBedrock
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel, Field
from typing_extensions import TypedDict

from app.config import settings
from app.domain_service import put_domain, scan_by_type
from app.investigation.tools import ALL_TOOLS
from app.models import DomainEntry, EntryType, Verdict


class AgentVerdict(BaseModel):
    """Final structured verdict from the domain investigation agent."""

    verdict: Literal["block", "warn", "allow"] = Field(
        description="block=confirmed phishing, warn=suspicious but uncertain, allow=safe"
    )
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in the verdict, 0.0 to 1.0")
    should_notify: bool = Field(
        description="Send retroactive user notification. Only true when verdict=block, "
        "confidence>=0.85, and the domain clearly impersonates a specific brand."
    )
    reasoning: str = Field(
        description="1-2 sentence explanation of the decision, WRITTEN IN SPANISH "
        "(Uruguayan / LatAm register). This text is shown directly to end users "
        "in the app's alert log — keep it short, plain-language, and avoid "
        "technical jargon (say 'sitio falso' not 'phishing site', 'no tiene "
        "certificado seguro' not 'no SSL/HTTPS')."
    )

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
- Our app protects against PHISHING (brand impersonation, credential theft), not malware/adware. A domain that doesn't impersonate any brand is less likely to be phishing — weigh other signals carefully before blocking.

RETROACTIVE NOTIFICATION:
The user who visited this domain has already seen the page. If you determine it IS phishing, you can recommend sending them a retroactive warning notification (should_notify=true). This notification tells the user to change their password, so a FALSE notification is extremely damaging to our credibility. Only set should_notify=true when ALL of these are true:
1. You are confident this is phishing (verdict=block, confidence >= 0.85)
2. The domain impersonates a specific, identifiable brand (bank, service, etc.)
3. The evidence is strong: multiple signals like new domain + free SSL + brand impersonation + no legitimate search results
Do NOT notify for: ambiguous cases, domains that could be legitimate regional variants (e.g., santander-mx.com = real Santander Mexico), or domains where the brand match is weak.

After you have gathered enough evidence, briefly summarize what you found. A separate
extraction step will then produce the final structured verdict — do not attempt to
format the verdict as JSON yourself.

OUTPUT LANGUAGE:
The final `reasoning` field in the structured verdict MUST be written in Spanish
(Uruguayan / LatAm register — e.g., "podés", "ingresaste"). This text is shown
directly to end users in the mobile app's alert log, so keep it short (1-2
sentences), plain-language, and avoid technical jargon: prefer "sitio falso" over
"phishing site", "no tiene certificado seguro" over "no SSL", "se hace pasar por
X" over "impersonates X". Your intermediate thinking during tool use can stay in
English for your own clarity — only the final reasoning field must be Spanish.
"""


class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    domain: str
    whitelist_domains: list[str]
    verdict: AgentVerdict | None


def _base_llm() -> ChatBedrock:
    return ChatBedrock(
        model_id=settings.bedrock_model_id,
        region_name=settings.bedrock_region,
        model_kwargs={"temperature": 0, "max_tokens": 1024},
    )


def _create_tool_llm():
    """LLM for the investigation loop — tools bound for iterative reasoning."""
    return _base_llm().bind_tools(ALL_TOOLS)


def _create_verdict_llm():
    """LLM for the final extraction — Bedrock structured output guarantees schema."""
    return _base_llm().with_structured_output(AgentVerdict)


def _should_continue(state: AgentState) -> str:
    """Route: if the last message has tool calls, keep looping. Otherwise, format the verdict."""
    last_message = state["messages"][-1]
    if isinstance(last_message, AIMessage) and last_message.tool_calls:
        return "tools"
    return "format_verdict"


def _call_model(state: AgentState) -> dict:
    """Call the tool-bound LLM with the current messages."""
    llm = _create_tool_llm()
    response = llm.invoke(state["messages"])
    return {"messages": [response]}


def _format_verdict(state: AgentState) -> dict:
    """Extract a validated verdict via Bedrock structured output."""
    llm = _create_verdict_llm()
    prompt = state["messages"] + [
        HumanMessage(
            content=(
                "Based on your investigation above, produce the final verdict.\n\n"
                "The `reasoning` field MUST be written in Spanish (Uruguayan/LatAm "
                "register — 'podés', 'ingresaste', 'se hace pasar por'). It is "
                "displayed directly to end users in the mobile app. Keep it 1-2 "
                "short sentences. Do NOT use technical jargon: say 'sitio falso' "
                "not 'phishing site', 'no tiene certificado seguro' not 'no SSL'.\n\n"
                "Set should_notify=true only when verdict=block AND confidence>=0.85 "
                "AND the domain clearly impersonates a specific brand."
            )
        )
    ]
    verdict: AgentVerdict = llm.invoke(prompt)
    return {"verdict": verdict}


def build_graph() -> StateGraph:
    """Build the LangGraph investigation agent."""
    graph = StateGraph(AgentState)

    graph.add_node("agent", _call_model)
    graph.add_node("tools", ToolNode(ALL_TOOLS))
    graph.add_node("format_verdict", _format_verdict)

    graph.set_entry_point("agent")
    graph.add_conditional_edges(
        "agent",
        _should_continue,
        {"tools": "tools", "format_verdict": "format_verdict"},
    )
    graph.add_edge("tools", "agent")
    graph.add_edge("format_verdict", END)

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
        "verdict": None,
    }

    # Run the graph
    graph = _get_graph()
    try:
        final_state = await graph.ainvoke(initial_state)
    except Exception as e:
        logger.error(f"LangGraph agent failed for {domain}: {e}")
        return _fallback_entry(domain, str(e))

    elapsed = time() - start
    logger.info(f"Investigation for {domain} completed in {elapsed:.1f}s")

    verdict = final_state.get("verdict")
    if verdict is None:
        logger.error(f"Agent finished without producing a structured verdict for {domain}")
        return _fallback_entry(domain, "no structured verdict produced")

    entry = DomainEntry(
        domain=domain,
        entry_type=EntryType.cache,
        verdict={"block": Verdict.block, "warn": Verdict.warn, "allow": Verdict.allow}[verdict.verdict],
        confidence=verdict.confidence,
        reason=verdict.reasoning,
        should_notify=verdict.should_notify,
        checked_at=datetime.now(timezone.utc),
        ttl=int(time()) + 30 * 86400,
    )
    await put_domain(entry)
    return entry


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
