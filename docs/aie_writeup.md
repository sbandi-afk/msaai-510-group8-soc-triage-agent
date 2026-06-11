# AIE Component Write-up — SOC Triage Agent

**Author:** Marston Ward (Team Lead / AI Engineer) · **Course:** AAI-510 · Group 8
**Scope:** the agent loop, external API integrations, and evaluation — the AIE
deliverables in the proposal. Runs as **local Python**, **MOCK_MODE by default**.

---

## 1. Architecture

A concrete LangGraph **`StateGraph`** ReAct agent (not just `create_react_agent`),
so State, nodes, tools, and edges are explicit and auditable.

```
START → scope_guard ─(out of scope)→ reject → END
                    └(in scope)────→ reason ⇄ act        (ReAct loop, ≤ 5 iters)
                                         └(no more tools)→ classify_and_ticket → END
```

- **scope_guard** — deterministic rule-based classifier; gracefully rejects
  out-of-scope/irrelevant user queries before any tool call or LLM cost.
- **reason** — the LLM step. A real provider chooses the next tool; the `mock`
  provider follows a fixed tool sequence so the loop still exercises every tool.
  Bounded by `MAX_TOOL_ITERATIONS` (default 5) to prevent runaway loops.
- **act** — executes tool calls, injecting `host_ip`/`indicator` context from
  State (so even empty-arg tool calls resolve), and folds normalized results back
  into State. Tool errors are caught and returned as data, never raised.
- **classify_and_ticket** — LLM-driven MITRE ATT&CK classification with strict
  JSON-schema enforcement; writes an incident row to `gold.incident` when the
  escalation gate is met. The gate is identical in the local package
  (`src/soc_agent/`) and the deployed live agent
  (`databricks_src/03_soc_agent_live.py`): `z_score > 1.5 AND (confidence > 0.7
  OR tactic == MANUAL_REVIEW)` — uncertain classifications on genuinely
  anomalous hosts still produce a ticket for a human, while quiet hosts are
  dismissed. Thresholds are env-configurable. Unparseable LLM output is routed
  to **manual review**, never silently passed.

All logic lives in `src/soc_agent/` and is imported by the notebooks so nothing
is duplicated.

| Module | Responsibility |
|--------|----------------|
| `config.py` | Central env-driven config; LLM provider/model selection; mock fallback; redacted summary |
| `mocks.py` | Fixtures for gold functions, VirusTotal, Shodan, NVD, and calibrated mock LLM completions |
| `api_clients.py` | VirusTotal, Shodan, NVD client wrappers (retries/timeouts/graceful errors) |
| `gold_tools.py` | Wrappers for Sai's gold UC functions + `gold.incident` writes (mock + live) |
| `llm.py` | `get_llm(provider, model)` factory + uniform `LLM` handle + `classify_json` |
| `agent.py` | `AgentState`, nodes, tools, edges, `classify_and_ticket`, `run_triage` |
| `eval_helpers.py` | MLflow tracing, 5-trace harness, same-trace dual-LLM comparison |

---

## 2. Tools

| Tool | Backing | Default | Notes |
|------|---------|---------|-------|
| `score_anomaly()` | Sai's gold TVF | mock | window in **minutes** (shipped reality) |
| `check_ip_reputation()` | VirusTotal v3 | **mock** | no key; `host_ip` is a hostname |
| `lookup_exposed_ports()` | Shodan | **mock** | no key; banners feed CVE lookup |
| `get_cve_context()` | NIST **NVD** (keyless) | **real when online** | mock fallback offline |
| `classify_and_ticket()` | LLM + `gold.incident` | mock LLM | strict JSON; manual-review fallback |

### Signature-drift adaptation (important)
The shipped gold layer **drifted from the proposal's interface contract**. The
wrappers adapt to what actually shipped, not the contract:

| Function | Proposal contract | Shipped reality (adapted) |
|----------|-------------------|----------------------------|
| `score_anomaly` | `(src_ip, window_days)` → `{z_score, baseline_mean, baseline_std}` | **TABLE-VALUED** `score_anomaly(p_host_ip STRING, p_window_min INT)` returning `(host_ip, event_count, baseline_mean, baseline_std, z_score, window_start, computed_at)` — window in **MINUTES**, not days |
| `classify_threat` | (not in contract) | scalar Python UC, JSON→JSON `{tactic, technique_id, confidence}` |
| `get_exposed_assets` | (not in contract) | TABLE-VALUED, no args → `(host_ip, risk_flag, assessed_at)` |

`gold_tools.top_anomaly()` bridges the shipped TVF back to a single
proposal-style `{z_score, ...}` dict the agent reasons over.

### `get_cve_context` ownership
Per the proposal `get_cve_context()` is **officially Sai's (DE)** tool, but it was
**never registered as a Unity Catalog function**. It is implemented here on the
agent side as a keyless NVD Python client and **should be migrated to a UC
SQL/Python function later** so the data layer owns it.

---

## 3. LLM configuration (fully env-driven)

Provider **and** models are selected purely via env vars; a single factory
`get_llm(provider, model)` is used everywhere.

- `LLM_PROVIDER=databricks` (locked default) — Databricks Model Serving via the
  OpenAI-compatible client pointed at `<host>/serving-endpoints`.
- `LLM_PROVIDER=openai` — alternate.
- `LLM_PROVIDER=mock` — canned completions; used automatically when creds are
  absent so everything runs with zero keys.
- Models: `LLM_MODEL` (primary) and `LLM_MODEL_B` (second model for the dual-LLM
  eval). The dual-LLM comparison reads both from config — a grader can point it
  at any two endpoints.

See `docs/SETUP.md` and `.env.example` for the full knob list.

---

## 4. Evaluation methodology

Tracing/eval platform: **MLflow** (local file store under `./mlruns`).

1. **Five traces** (`run_traces`) — 3 in-scope attack events + **2 explicit
   out-of-scope rejections**, each logged as an MLflow run with params (scenario,
   provider, model), tags (decision, tactic), and metrics (latency, iterations,
   confidence, priority, z-score). Each agent run is wrapped in an `mlflow.trace`
   span.
2. **Same-trace 2-LLM comparison** (`dual_llm_table`) — identical inputs through
   **Model A** and **Model B**, comparing tactic, confidence, priority, and
   latency, with an aggregate `comparison_summary` (mean confidence/priority/
   latency per model + tactic agreement rate).

### Human-in-the-loop
Sub-threshold or schema-invalid tickets are routed to **manual review** rather
than auto-closed, so a human analyst remains the final arbiter. Evaluation
measures how much triage the agent can safely automate, not full autonomy.

---

## 5. Results (mock-mode run)

*(Mock numbers are deterministic, calibrated stand-ins; set live env vars for real
endpoint numbers. CSVs in `docs/eval_artifacts/`.)*

- **5/5 traces behaved as expected:** the 3 attack events **escalated** (full
  4-iteration ReAct loop, z-score > 2.5, confidence > 0.7, incident written); the
  2 out-of-scope queries were **rejected in 0 iterations** (no tools, no LLM cost).
- **Dual-LLM:** both models agreed on the MITRE tactic for every scenario
  (`tactic_agreement_rate = 1.0`); they differed on **confidence calibration**
  (Llama-3.1-70B higher mean confidence than DBRX) and latency. The tactic is
  anchored by Sai's deterministic rule classifier, so model choice mainly affects
  confidence and prose — useful when tuning the per-model escalation threshold.

---

## 6. Limitations

- **Mock fixtures, not live telemetry.** VirusTotal/Shodan and the gold functions
  are mocked by default (no keys; `host_ip` is a hostname, not a routable IP).
  Live mode requires real creds and a warm Model Serving endpoint.
- **Simulated dual-LLM offline.** Without creds the two models are calibrated
  stand-ins; comparative numbers are illustrative until pointed at live endpoints.
- **Rule-anchored tactic.** The MITRE tactic leans on `classify_threat`'s rule
  engine, so it inherits that engine's coverage; the LLM adds priority/severity/
  prose and schema discipline rather than independent tactic discovery.
- **Episodic baseline.** The z-score baseline is seeded from aggregated benign
  scenarios (per the proposal), not a live 30-day production stream.
- **`get_cve_context` lives on the agent side** pending migration to a UC function.

---

## 7. Reproducibility

- Env: `requirements.txt` / `team_project/pixi.toml`; kernel `soc-agent`
  (“SOC Agent (Databricks)”).
- Run order: `04_api_clients` → `03_agent_loop` → `05_evaluation` → `00_run_all`.
- Verified headlessly via `nbconvert --execute` in MOCK_MODE with **zero creds**.

## 8. AI-use disclosure
GitHub Copilot / an AI coding assistant was used to scaffold the package, notebook
boilerplate, and documentation. All architecture decisions, the signature-drift
adaptation, the tool design, and the evaluation methodology were directed and
verified by the team; all generated code was reviewed and executed before
inclusion.
