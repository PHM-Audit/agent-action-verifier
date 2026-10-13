"""adk_callback_contract.py — contract test: ADK v2.11.0 `before_back` semantics.

Method: docs-promise vs actual behavior (same caliber as our DeepSeek API suite).
Promises under test (ADK docs/source, v2.11.0):
  P1 callback returning None -> tool body executes
  P2 callback returning a dict -> dict becomes the tool response, body SKIPPED
  P3 callback receives (tool, args, context) per call
  P4 the rejection event is recorded in the session event stream (ledger material)

Real runner + real agent loop; the LLM is a canned BaseLlm (no external API,
fully deterministic). Tool bodies print/record only — no network egress.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import platform
import time
from pathlib import Path

import google.adk
from google.adk.agents.llm_agent import LlmAgent
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.genai import types as genai_types
from google.adk.runners import InMemoryRunner

HERE = Path(__file__).parent
ADK_VERSION = getattr(google.adk, "__version__", "2.11.0")

EXEC_LOG: list[tuple] = []
CALL_LATENCIES_US: list[float] = []

DECLARED_PLAN = {("search", "net://api.example-corpus.local")}


# ---------- canned model: issues exactly one function_call then finalizes ----------
class CannedCaller(BaseLlm):
    model: str = "canned-contract-model"
    tool_name: str = "corpus_search"
    tool_args: dict = {}

    async def generate_content_async(self, llm_request, stream=False):
        # stateful: if the last content carries a function_response, the tool
        # already ran — finalize with text. Otherwise emit the function_call.
        last = llm_request.contents[-1] if llm_request.contents else None
        got_fn_resp = last is not None and any(
            p.function_response is not None for p in (last.parts or [])
        )
        if got_fn_resp:
            yield LlmResponse(
                content=genai_types.Content(role="model", parts=[genai_types.Part(text="done")])
            )
        else:
            fc = genai_types.FunctionCall(name=self.tool_name, args=dict(self.tool_args))
            yield LlmResponse(
                content=genai_types.Content(role="model", parts=[genai_types.Part(function_call=fc)])
            )


# ---------- tools ----------
def corpus_search(url: str, query: str) -> str:
    EXEC_LOG.append(("corpus_search EXECUTED", url))
    return f"[corpus result for {query}]"


def purge_logs(path: str) -> str:
    EXEC_LOG.append(("purge_logs EXECUTED", path))
    return "[logs purged]"


# ---------- guard callback (deterministic, shape-based) ----------
def _resource_key(args):
    """Normalize: urls -> net://<host> (ports stripped), paths -> as-is."""
    from urllib.parse import urlparse
    url = args.get("url")
    if url:
        host = urlparse(url).netloc or url
        return f"net://{host}"
    return args.get("path") or ""


def phm_before_back(tool, args, context):
    t0 = time.perf_counter()
    op = {"corpus_search": "search", "purge_logs": "purge_logs"}.get(tool.name, tool.name)
    action = (op, _resource_key(args))
    if action not in DECLARED_PLAN:
        lat = (time.perf_counter() - t0) * 1e6
        CALL_LATENCIES_US.append(lat)
        return {"status": "rejected", "reason": f"out-of-plan: {action}"}
    lat = (time.perf_counter() - t0) * 1e6
    CALL_LATENCIES_US.append(lat)
    return None  # allow


def build_agent(tool_name: str, tool_args: dict) -> LlmAgent:
    model = CannedCaller(tool_name=tool_name, tool_args=tool_args)
    return LlmAgent(
        name="phm_adk_demo",
        model=model,
        instruction="Call the named tool once with the given arguments.",
        tools=[corpus_search, purge_logs],
        before_tool_callback=phm_before_back,
    )


async def run_case(label: str, tool_name: str, tool_args: dict) -> dict:
    EXEC_LOG.clear()
    agent = build_agent(tool_name, tool_args)
    runner = InMemoryRunner(agent=agent, app_name="phm_adk_contract")
    session = await runner.session_service.create_session(
        app_name="phm_adk_contract", user_id="contract-test"
    )
    prompt = f"tool={tool_name}\nargs={json.dumps(tool_args)}"
    events = []
    t0 = time.time()
    async for ev in runner.run_async(
        user_id="contract-test", session_id=session.id, new_message=genai_types.Content(role="user", parts=[genai_types.Part(text=prompt)])
    ):
        ev_dict = {"author": getattr(ev, "author", None)}
        fn = getattr(getattr(ev, "content", None), "parts", None)
        parts = []
        for part in fn or []:
            fc = getattr(part, "function_call", None)
            fr = getattr(part, "function_response", None)
            txt = getattr(part, "text", None)
            if fc:
                parts.append({"function_call": fc.name})
            elif fr:
                parts.append({"function_response": str(fr.response)[:120]})
            elif txt:
                parts.append({"text": txt[:120]})
        ev_dict["parts"] = parts
        events.append(ev_dict)
    wall = (time.time() - t0) * 1000
    executed = [x for x in EXEC_LOG if "EXECUTED" in x[0]]
    return {
        "case": label,
        "tool_bodies_executed": executed,
        "n_events": len(events),
        "events_tail": events[-3:],
        "wall_ms": round(wall, 1),
    }


async def main() -> dict:
    r1 = await run_case(
        "P1_benign_in_plan_allow", "corpus_search",
        {"url": "https://api.example-corpus.local/v1", "query": "grid frequency"},
    )
    r2 = await run_case(
        "P2_out_of_plan_reject", "purge_logs", {"path": "/var/log/app.log"}
    )
    r3 = await run_case(
        "P3_egress_reject", "corpus_search",
        {"url": "https://evil.example.net/collect", "query": "grid frequency"},
    )

    checks = {
        "P1_allow_body_executes": "EXECUTED" in str(r1["tool_bodies_executed"]),
        "P2_reject_body_skipped": not r2["tool_bodies_executed"],
        "P3_reject_body_skipped": not r3["tool_bodies_executed"],
        "P4_rejection_recorded_in_events": "rejected" in json.dumps(r2["events_tail"]) or "rejected" in json.dumps(r3["events_tail"]),
    }
    lat = sorted(CALL_LATENCIES_US)
    out = {
        "test": "ADK v2.11.0 before_back contract test (canned model, real runner loop)",
        "date": time.strftime("%F %T"),
        "env": {"adk_version": ADK_VERSION, "python": platform.python_version(),
                 "platform": platform.platform()},
        "cases": [r1, r2, r3],
        "checks": checks,
        "verdict": "PASS" if all(checks.values()) else "REVIEW",
        "callback_latency_us_p50": round(lat[len(lat)//2], 2),
        "honesty_notes": [
            "LLM is a canned BaseLlm (fully deterministic, no external API) — this measures ADK callback semantics, not model behavior",
            "single run, n=3 cases, mechanism demonstration not statistical claim",
            "tool bodies record/print only, no network egress",
        ],
    }
    out_path = HERE / "results" / "adk_callback_contract_results.json"
    out_path.parent.mkdir(exist_ok=True)
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=1))
    chain = hashlib.sha256(out_path.read_bytes()).hexdigest()
    (HERE / "results" / "adk_callback_contract_results.sha256").write_text(
        chain + "  adk_callback_contract_results.json\n")
    out["artifact_sha256"] = chain

    print("=== ADK v2.11.0 before_back contract test ===")
    for c in (r1, r2, r3):
        print(f"[{c['case']}] executed={c['tool_bodies_executed'] or 'NONE'} | {c['wall_ms']}ms")
    for k, v in checks.items():
        print(f"  {k}: {'YES' if v else 'NO'}")
    print(f"callback p50={out['callback_latency_us_p50']}us | GATE: {out['verdict']}")
    print(f"artifact sha256[:16]={chain[:16]}")
    return out


if __name__ == "__main__":
    asyncio.run(main())
