# agent-action-verifier

**Deterministic action-level verification for AI agents.**
A pre-execution enforcement layer that checks every agent action against its declared plan *before* it runs. Pure fixed-constant math in the decision path — no LLM in the judge, no learned parameters, fully seeded and reproducible.

- What it does: plan–execution differential + scope / credential / tool-consent checks on every action (tool call, network egress, file write).
- Verdict per action: `PASS` → execute, `VETO` → block before side effects.
- Cost per action: microsecond-scale fixed math (P99 = 0.13 ms in the 100k stress suite).

This repository publishes the **interface contract, verification harness for released result artifacts, and all result files**. Rule internals are closed. Independent review of methodology and artifacts is explicitly welcome.

---

## Closed-loop results (all artifacts in this repo, SHA-256 chains)

| Layer | Benchmark / suite | Result | Artifact |
|---|---|---|---|
| AgentDojo official, real LLM in the loop | 97 tasks × 2 rounds (v2.2), official injection suite + official `security()` judgment | **ASR = 0**, FP = 0 | `artifact_agentdojo_v2p2.json` |
| AgentDojo fix-cycle history | v2.1 full re-run | ASR = 0, FP = 1 | `artifact_agentdojo_v2p1.json` |
| AgentDojo fix-cycle history | v1.2 full re-run | ASR = 0, FP = 16 | **FP 16 → 1 → 0 across v1.2 → v2.1 → v2.2** (same-source iteration, not independent stability trials) |
| Cross-model spot check | GLM subset, 48 tasks (24 benign + 24 attack) | FP = 0, ASR = 0 | `artifact_agentdojo_glm.json` |
| Synthetic stress layer | 100,000 scenarios, 7 rule families, seeded | FN = 0, FP = 0, interception Wilson-95 lower bound 99.99%+ | `artifact_100k_stress.json` |
| White-box adaptive attacks | 49 cases, 16 adaptive vector families | 43 hard-blocked, 6 documented boundary cases, 0 bypass | see artifacts + report |

**ASR** = official AgentDojo `security()` judgment (attack-success semantics, no audit gate). **FP** = benign rounds blocked. Fix-cycle trajectories are published *including failures* — external review is the scarce resource.

## Scope & honest boundaries

- Synthetic scenarios are abstracted from publicly disclosed incident categories — **not** production traffic.
- AgentDojo numbers are same-source fix-cycle iterations, not independent stability trials.
- GLM subset (24+24) vs DeepSeek full run (97+97) — different models and sample sizes; **not directly comparable**.
- This layer complements monitoring and alignment training; it does not replace them.

## Verify the artifacts yourself

```bash
pip install -r requirements.txt   # none beyond stdlib
python verify_artifacts.py        # recomputes SHA-256 chains + Wilson-95 bounds
```

`verify_artifacts.py` contains **no verifier logic** — it only (1) checks every artifact against `SHA256SUMS.txt`, (2) recomputes the Wilson-95 lower bounds from the raw counts inside each JSON, so you can confirm the published numbers are internally consistent and the confidence math is right.

## Interface contract

See `verifier_interface.pyi`. Integration shape: wrap the agent's action-dispatch point; the verifier receives `(declared plan, pending action)` and returns `PASS` / `VETO` with a rule id. Typical integration is ~10 lines around tool-execution middleware.

## Contact / deeper access

Rule internals are closed. Walk-throughs of methodology (not internals) available on request via GitHub issue or email (see profile).

## ADK evidence (google-adk v2.11.0)

`adk_evidence/` — contract test of `LlmAgent.before_tool_callback` semantics on
google-adk v2.11.0 (real Runner, canned deterministic LLM): gate 4/4
(allow-executes / veto-skips-body ×2 / rejection recorded in session events),
guard p50 32.67 µs/call, single run n=3 mechanism demonstration. Includes one
self-caught harness bug (plan-vs-check resource normalization) kept for
honesty. Context: google/adk-python #7520, #6099.

