# SOC Triage Agent

**AAI-510 Agentic AI Systems — Final Team Project**
University of San Diego, MS Applied Artificial Intelligence

[Project Proposal (PDF)](proposal_cybersecurity_agent.pdf)

## Team

| Name | Role | Responsibilities |
|------|------|-----------------|
| Marston Ward | Team Lead / AI Engineer | Agent loop, API integrations, evaluation |
| Sai Bandi | Data Engineer | ETL pipeline, Unity Catalog functions |
| Marquise Oliver | Product Manager | Business case, ROI analysis, build-vs-buy |

## Problem

NovaPay Financial is a mid-sized U.S. payments processor whose Security Operations Center (SOC) faces an unsustainable alert workload. Each analyst manually reviews 30–50 alerts per shift, spending 30–45 minutes on repetitive IP lookups, CVE cross-references, and threat classification that a machine could handle in seconds. High-severity threats routinely get buried under routine noise, increasing mean time to detect (MTTD) and mean time to respond (MTTR).

## Solution

An autonomous SOC triage agent that:

1. **Monitors** SIEM event logs stored in Delta Lake for anomalous activity
2. **Scores** each event against a rolling statistical baseline
3. **Enriches** suspicious source IPs with external threat intelligence (VirusTotal, Shodan, NVD)
4. **Classifies** threats using the MITRE ATT&CK framework
5. **Generates** fully labeled incident tickets, ready for human analyst review

The agent follows the **ReAct** (Reasoning + Acting) pattern, interleaving chain-of-thought reasoning with tool calls so every decision is traceable and auditable.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   LangGraph ReAct Agent                 │
│                                                         │
│   Observe ──► Reason ──► Act ──► Observe ──► ...        │
│                          │                              │
│               ┌──────────┴──────────┐                   │
│               ▼                     ▼                   │
│         UC SQL Functions      External APIs             │
│  ┌──────────────────────┐  ┌─────────────────────┐      │
│  │ score_anomaly()      │  │ check_ip_reputation()│     │
│  │ get_cve_context()    │  │ lookup_exposed_ports()│    │
│  │ classify_threat()    │  └─────────────────────┘      │
│  │ get_exposed_assets() │                               │
│  └──────────────────────┘                               │
│               │                                         │
│               ▼                                         │
│      classify_and_ticket()                              │
│      (Python UC + LLM → MITRE-labeled ticket)           │
└─────────────────────────────────────────────────────────┘
```

### Tool Inventory

| Tool | Type | Description |
|------|------|-------------|
| `score_anomaly()` | SQL UC function | Z-score anomaly detection against a rolling baseline |
| `get_cve_context()` | SQL UC function | CVE lookup from NIST NVD data |
| `check_ip_reputation()` | Python / API | IP threat scoring via VirusTotal |
| `lookup_exposed_ports()` | Python / API | Open-port enumeration via Shodan |
| `classify_and_ticket()` | Python UC + LLM | Generates MITRE ATT&CK-labeled incident tickets |

### LLM Comparison

The agent is evaluated with **two LLMs on the same traces**. The provider and both
model names are **fully configurable via environment variables** (`LLM_PROVIDER`,
`LLM_MODEL`, `LLM_MODEL_B`) — no code edits to switch. The locked default is two
**Databricks-served** models (OpenAI-compatible client → Databricks Model Serving):

| Slot | Default model | Provider | Notes |
|------|---------------|----------|-------|
| `LLM_MODEL` (A) | `databricks-meta-llama-3-3-70b-instruct` | Databricks Model Serving | open-weight (Llama 3.3) |
| `LLM_MODEL_B` (B) | `databricks-meta-llama-3-3-70b-instruct` | Databricks Model Serving | same endpoint, temp=0.5 (sampling vs deterministic) |

Set `LLM_PROVIDER=openai` (with `LLM_MODEL=gpt-4o-mini`, `LLM_MODEL_B=gpt-4o`) to
compare against OpenAI instead. With no creds, a built-in `mock` provider runs the
whole comparison offline.

## Data Sources

- **OTRF Security Datasets** — Open Threat Research Forge simulated attack telemetry covering MITRE ATT&CK tactics (execution, persistence, lateral movement, credential access, discovery, privilege escalation, command & control)
- **NIST NVD** — National Vulnerability Database CVE feeds for vulnerability enrichment

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Data Platform | Databricks, Delta Lake, Unity Catalog |
| Orchestration | LangGraph (ReAct pattern) |
| Experiment Tracking | MLflow |
| Data Processing | PySpark |
| External Intelligence | VirusTotal API, Shodan API, NIST NVD |
| LLM Providers | Databricks Model Serving (Llama-3.3-70B @ temp=0.0 vs temp=0.5); OpenAI (GPT-4o-mini) also supported |

## Current Progress

### Data Pipeline (Sai Bandi — DE) ✅ Complete

Medallion architecture ETL pipeline delivering production-ready analytics tables:

- **Bronze → Silver → Gold** transformation pipeline
- Ingests OTRF Security Datasets covering **7 MITRE ATT&CK tactics**
- **51,400 raw events → 40,833 normalized rows** across 10 hosts and 44 user accounts
- Three Gold-layer Unity Catalog functions deployed:
  - `score_anomaly()` — z-score anomaly detection
  - `classify_threat()` — MITRE ATT&CK rule-based classification
  - `get_exposed_assets()` — host-level risk assessment
- Unity Catalog: `soc_intelligence` catalog with `bronze`, `silver`, and `gold` schemas
- Implementation: `soc_etl_pipeline.ipynb`

### Agent Definition (Marston Ward — AIE) ✅ Complete

Runs as **local Python** (`notebooks/` + reusable `src/soc_agent/`), **MOCK_MODE
by default** — executes end-to-end with **zero API keys and zero live Databricks**.

- Concrete LangGraph **`StateGraph`** ReAct agent — explicit State, nodes, tools,
  edges (`notebooks/03_agent_loop.ipynb`, `src/soc_agent/agent.py`)
- API client wrappers for **VirusTotal, Shodan, and NVD/CVE** with MOCK_MODE,
  retries/timeouts, and graceful errors (`notebooks/04_api_clients.ipynb`)
- `classify_and_ticket()` — LLM-driven MITRE ATT&CK labeling that writes a row
  matching the **exact `gold.incident` schema** (escalates when
  `z_score > 2.5 AND confidence > 0.7`; invalid JSON → manual review)
- **Out-of-scope query rejection** with 2 explicit worked examples
- **Fully configurable LLM** provider/models via env (`get_llm()` factory):
  `databricks` (default) / `openai` / `mock`

### Evaluation (Marston Ward — AIE) ✅ Complete

`notebooks/05_evaluation.ipynb` + `src/soc_agent/eval_helpers.py`:

- **5 MLflow traces** (3 in-scope escalations + 2 out-of-scope rejections) with
  params/tags/metrics and `mlflow.trace` spans
- **Same-trace, two-LLM comparison** — both model names read from config so a
  grader can point it at any two Databricks endpoints; side-by-side table +
  summary (mean confidence/priority/latency, tactic agreement)
- Artifacts saved to `docs/eval_artifacts/`

> **Note — `get_cve_context` ownership.** Per the proposal this NVD tool is
> **officially Sai's (DE)** but was never registered as a UC function. It is
> implemented here as a keyless NVD Python tool and **should be migrated to a UC
> function later**.
>
> **Note — `score_anomaly` signature drift.** The shipped gold function is a
> **table-valued** `score_anomaly(p_host_ip, p_window_min INT)` with the window in
> **minutes** (not the dict-keyed-by-days the proposal contract promised). The tool
> wrappers adapt to what actually shipped; `top_anomaly()` normalizes the TVF rows
> to a single `{z_score, ...}` dict for the agent.

### Run locally (mock mode, zero creds)

```bash
python -m pip install -r requirements.txt
python -m ipykernel install --user --name soc-agent --display-name "SOC Agent (Databricks)"
jupyter nbconvert --to notebook --execute --inplace \
  --ExecutePreprocessor.kernel_name=soc-agent notebooks/00_run_all.ipynb
```

Full instructions (env vars, switching to live Databricks, selecting LLM
provider/models) are in **[`docs/SETUP.md`](docs/SETUP.md)**. AIE component
summary: **[`docs/aie_writeup.md`](docs/aie_writeup.md)**.

### Business Case (Marquise Oliver — PM) ⏳ In Progress

- ROI calculation for automated triage vs. manual analyst workflow
- Build-vs-buy justification for NovaPay Financial

## Repository Structure

```
notebooks/
  03_agent_loop.ipynb             ← Marston (AIE)  — StateGraph ReAct agent
  04_api_clients.ipynb            ← Marston (AIE)  — VirusTotal / Shodan / NVD
  05_evaluation.ipynb             ← Marston (AIE)  — MLflow traces + dual-LLM
  00_run_all.ipynb                ← Marston (AIE)  — integration entry point
src/
  soc_agent/                      ← reusable package imported by the notebooks
    config.py                       env-driven config + LLM selection
    mocks.py                        zero-creds fixtures (gold, VT, Shodan, NVD, LLM)
    api_clients.py                  VirusTotal / Shodan / NVD wrappers
    gold_tools.py                   wrappers for Sai's gold UC functions + incidents
    llm.py                          get_llm() factory (databricks/openai/mock)
    agent.py                        AgentState, nodes, tools, edges, classify_and_ticket
    eval_helpers.py                 MLflow tracing + dual-LLM comparison
docs/
  SETUP.md                        ← local env, kernel, mock↔live, LLM config
  aie_writeup.md                  ← AIE component summary for the team report
  eval_artifacts/                 ← trace + comparison CSVs (generated)
  business_case.md                ← Marquise (PM)
soc_etl_pipeline.ipynb            ← Sai (DE) — bronze/silver/gold + UC functions
requirements.txt                  ← local Python deps
.env.example                      ← config template (copy to .env)
proposal_cybersecurity_agent.pdf
README.md
```

> The DE pipeline currently ships as a single `soc_etl_pipeline.ipynb` (catalog/
> schemas, bronze→silver→gold, and the `score_anomaly` / `classify_threat` /
> `get_exposed_assets` UC functions + `gold.incident` table).

## Live Evaluation Results

Evaluation run: **2026-06-02** against Databricks Model Serving (local Python kernel, `soc_agent.ipynb`).

### Model A — `databricks-meta-llama-3-3-70b-instruct`

**Traces 1-3 (in-scope escalation scenarios)**

| Scenario | Expected | Decision | Tactic | Technique | Confidence | Z-Score | Latency (ms) | Incident Written |
|----------|----------|----------|--------|-----------|-----------|---------|--------------|-----------------|
| `credential_access_ws5` | escalate | dismissed | Credential Access | T1003 | 0.20 | 0.0 | 26,199 | No |
| `execution_powershell_ws6` | escalate | dismissed | Execution | T1059 | 0.80 | 0.0 | 7,287 | No |
| `persistence_service_filesrv1` | escalate | dismissed | Defense Evasion | T1059 | 0.80 | 0.0 | 6,150 | No |

**Observations:**
- All three in-scope alerts were classified and returned valid MITRE tactic/technique labels.
- Z-score = 0.0 across all traces indicates `score_anomaly()` returned a baseline z-score below the
  escalation gate (`z_score > 2.5 AND confidence > 0.7`), so no incidents were written.
- Mean latency: **~13.2 s/trace** (dominated by credential_access at 26.2 s; steady-state ~6-7 s).
- Model B (same endpoint, temp=0.5) and OOS rejection traces completed on 2026-06-02. See full results in `soc_agent.ipynb`.

## Team TODO

> Last updated: **2026-06-02**. Owners listed in brackets.

### 🔴 Blocking (must complete before submission)

- [ ] **[Marquise — PM]** Write `docs/business_case.md` — ROI calculation (manual analyst hours vs. automated triage), build-vs-buy justification for NovaPay, cost estimate using Databricks DBU pricing
- [ ] **[Marston — AIE]** Fill in Step 6 commentary table in `soc_agent.ipynb` with actual latency, tactic-match, and confidence numbers from the live run (Model A vs Model B temp=0.5)
- [ ] **[Marston — AIE]** Update `## Live Evaluation Results` in this README with Model B (Traces 4-5) and same-trace comparison numbers once Steps 3-4 output is reviewed
- [ ] **[All]** Record final video walkthrough covering: problem statement, ETL pipeline, agent demo, eval results, business case

### 🟡 Important (high value, do before submission if time allows)

- [ ] **[Sai — DE]** Investigate why `score_anomaly()` returns z_score = 0.0 for all live traces — verify the Gold table has baseline rows covering the test hosts/IPs
- [ ] **[Marston — AIE]** Confirm OOS rejection message quality — review Step 5 refusal text and ensure it clearly explains accepted query types
- [ ] **[Marston — AIE]** Export MLflow traces to `docs/eval_artifacts/` as CSVs for submission artifact

### 🟢 Nice to have (post-submission or if time allows)

- [ ] **[Sai — DE]** Migrate `get_cve_context()` from Python NVD tool to a proper Unity Catalog SQL function (currently in `src/soc_agent/api_clients.py`)
- [ ] **[Marston — AIE]** Add Mermaid architecture diagram to README (was designed, never written)
- [ ] **[All]** Peer-review each section of the final team report for consistency with what actually shipped

### ✅ Completed

- [x] **[Sai — DE]** Bronze → Silver → Gold ETL pipeline (`soc_etl_pipeline.ipynb`)
- [x] **[Sai — DE]** Unity Catalog functions: `score_anomaly()`, `classify_threat()`, `get_exposed_assets()`
- [x] **[Marston — AIE]** LangGraph ReAct agent with `StateGraph`, scope guard, tool nodes, MITRE classification
- [x] **[Marston — AIE]** `src/soc_agent/` reusable package (config, mocks, gold_tools, llm, agent, eval_helpers)
- [x] **[Marston — AIE]** Dual-LLM evaluation harness with MLflow tracing (5 scenarios, same-trace comparison)
- [x] **[Marston — AIE]** Live evaluation run against Databricks Model Serving (all 10 notebook cells passing)
- [x] **[Marston — AIE]** Out-of-scope query rejection tested (2 OOS scenarios, scope_guard node)
- [x] **[Marston — AIE]** API client wrappers: VirusTotal, Shodan, NVD (mock-safe, retries, timeouts)

## References

1. Yao, S., Zhao, J., Yu, D., Du, N., Shafran, I., Narasimhan, K., & Cao, Y. (2022). ReAct: Synergizing Reasoning and Acting in Language Models. *arXiv preprint arXiv:2210.03629*. https://arxiv.org/abs/2210.03629

2. Open Threat Research Forge (OTRF). Security Datasets. https://github.com/OTRF/Security-Datasets

3. National Institute of Standards and Technology (NIST). National Vulnerability Database. https://nvd.nist.gov/

4. MITRE Corporation. MITRE ATT&CK Framework. https://attack.mitre.org/

5. LangGraph Documentation. https://langchain-ai.github.io/langgraph/
