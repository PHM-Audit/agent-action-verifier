# ADK evidence: before-tool callback contract test on google-adk v2.11.0

Method: docs-promise vs actual behavior. Promises under test (ADK v2.11.0
`LlmAgent.before_tool_callback`):

- P1 callback returns None -> tool body executes
- P2/P3 callback returns a dict -> dict becomes the tool response, body SKIPPED,
  and the rejection is recorded in the session event stream (ledger material)
- callback receives (tool, args, context) per call; overhead measured

Real Runner + real agent loop (InMemoryRunner, stateful canned LLM — fully
deterministic, no external API, no network egress). Tool bodies record-only.

## Gate result (2026-10-13, single run, n=3 cases — mechanism demonstration)

| Case | Outcome |
|---|---|
| P1 benign in-plan (whitelisted host) | allowed, tool body executed |
| P2 out-of-plan tool | vetoed before body |
| P3 egress breach (non-whitelisted host) | vetoed before body |
| P4 rejection event | recorded in session events |

Guard overhead p50 32.67 µs/call (cloud x86, Python 3.12, includes URL
normalization; not extrapolable to embedded targets).

## Self-caught bug during this gate (kept for honesty)

First run: the benign in-plan call was rejected — root cause was OUR harness:
the declared plan stored a normalized resource key (`net://<host>`) while the
callback compared the raw URL string. Fixed (URL→host normalization) and
re-run; the mismatch class (declared-plan vs runtime-check normalization) is
exactly what this gate exists to catch.

## Files

- `adk_callback_harness.py` — runner + canned LLM + guard (self-contained)
- `results/adk_callback_contract_results.json` — raw run record
- `results/adk_callback_contract_results.sha256` — standalone integrity sidecar

Context issue: google/adk-python #7520. Related discussion: #6099.
