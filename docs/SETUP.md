# SETUP — Local environment, Databricks kernel, and configuration

This is the AIE component (Marston Ward) of the Group 8 SOC Triage Agent. It runs
as **local Python** (notebooks + a reusable `src/soc_agent/` package). It talks to
Databricks via env-configured connections **only when creds are present**, and
**defaults to MOCK_MODE** so a grader can execute everything with **zero API keys
and zero live Databricks connection**.

---

## 1. Create the local environment

You can use either **pixi** (matches the team's pinned stack) or a plain **venv**.

### Option A — pixi (recommended, matches `team_project/pixi.toml`)
```bash
# from the repo root
pixi init . --import requirements.txt   # or copy the team pixi.toml dependencies
pixi install
# the env python is at .pixi/envs/default/bin/python
```

### Option B — venv + pip
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

> Both install the same libraries (LangGraph, LangChain, MLflow, the OpenAI
> client, `databricks-sdk`, pandas, ipykernel, nbformat/nbclient/nbconvert).
> Verified end-to-end on Python 3.12–3.14.

---

## 2. Register the Jupyter kernel

Register an `ipykernel` so the notebooks run on the right interpreter. The
notebooks' `kernelspec` metadata is already set to **`soc-agent`**.

```bash
# run with the SAME python you installed deps into
python -m ipykernel install --user --name soc-agent --display-name "SOC Agent (Databricks)"

# verify
jupyter kernelspec list      # should show: soc-agent
```

Select **“SOC Agent (Databricks)”** as the kernel in Jupyter / VS Code, or execute
headlessly:

```bash
jupyter nbconvert --to notebook --execute --inplace \
  --ExecutePreprocessor.kernel_name=soc-agent \
  notebooks/04_api_clients.ipynb
```

---

## 3. Run in MOCK_MODE (default — zero creds)

Nothing to configure. Run the notebooks in this order:

```
notebooks/04_api_clients.ipynb   →  03_agent_loop.ipynb
                                 →  05_evaluation.ipynb  →  00_run_all.ipynb
```

`00_run_all.ipynb` is the single-click integration demo. In mock mode the gold
UC-function results, VirusTotal, and Shodan are all mocked; NVD still makes real
keyless calls when online and falls back to a fixture offline.

---

## 4. Configure the LLM (provider + models — fully via env)

Provider **and** models are chosen entirely by environment variables — **no code
edits**. A small factory `get_llm(provider, model)` (`src/soc_agent/llm.py`) is
used everywhere, so provider/model is never hardcoded. Copy `.env.example` to
`.env` (auto-loaded) or export the vars.

| Env var | Purpose | Default |
|---------|---------|---------|
| `LLM_PROVIDER` | `databricks` (locked default) \| `openai` \| `mock` | `databricks` |
| `LLM_MODEL` | primary model | `databricks-meta-llama-3-1-70b-instruct` |
| `LLM_MODEL_B` | second model for the dual-LLM eval | `databricks-dbrx-instruct` |
| `LLM_BASE_URL` | OpenAI-compatible base URL (Databricks: `<host>/serving-endpoints`) | derived from `DATABRICKS_HOST` |
| `LLM_API_KEY` | LLM endpoint key (Databricks: falls back to `DATABRICKS_TOKEN`; OpenAI: or `OPENAI_API_KEY`) | — |
| `LLM_TEMPERATURE` / `LLM_MAX_TOKENS` / `LLM_TIMEOUT` | tuning | `0.0` / `1024` / `60` |

**The dual-LLM comparison in `05_evaluation.ipynb` reads both model names from
config**, so point it at any two endpoints:

```bash
export LLM_PROVIDER=databricks
export LLM_MODEL="databricks-meta-llama-3-1-70b-instruct"
export LLM_MODEL_B="databricks-dbrx-instruct"
```

If the configured provider has **no usable creds**, the code transparently falls
back to the `mock` provider so notebooks still execute.

---

## 5. Switch from mock to LIVE Databricks

Set `SOC_MOCK_MODE=0` and supply Databricks creds (never hardcoded). The gold
functions then run against Unity Catalog instead of the mock fixtures.

```bash
export SOC_MOCK_MODE=0
export DATABRICKS_HOST="https://<workspace>.cloud.databricks.com"
export DATABRICKS_TOKEN="dapi..."

# choose ONE way to run SQL against Unity Catalog:
export DATABRICKS_WAREHOUSE_ID="<sql-warehouse-id>"   # via databricks-sdk Statement Execution API
# or
export DATABRICKS_CLUSTER_ID="<cluster-id>"           # via databricks-connect (Spark)

# LLM (Databricks Model Serving):
export LLM_PROVIDER=databricks
export LLM_BASE_URL="$DATABRICKS_HOST/serving-endpoints"
export LLM_MODEL="databricks-meta-llama-3-1-70b-instruct"
export LLM_MODEL_B="databricks-dbrx-instruct"

# optional real threat-intel keys (otherwise these stay mocked):
export VT_API_KEY="..."
export SHODAN_API_KEY="..."
```

You can also use a Databricks CLI profile (`~/.databrickscfg`); the SDK
`WorkspaceClient` honors it when `DATABRICKS_HOST`/`DATABRICKS_TOKEN` are unset.

### Note on `databricks-connect`
`databricks-connect` must match your cluster's DBR version and pins an **older
numpy** that conflicts with `langchain-community`. Install it in a **separate
environment** if you want Spark access, or just use the **SQL warehouse** path
(via `databricks-sdk`, already installed) which has no such conflict. The live
SQL backend tries `databricks-connect` first (if `DATABRICKS_CLUSTER_ID` is set),
then the SDK Statement Execution API (if `DATABRICKS_WAREHOUSE_ID` is set).

---

## 6. Headless verification (what the build was validated with)

```bash
export SOC_MOCK_MODE=1
for nb in 04_api_clients 03_agent_loop 05_evaluation 00_run_all; do
  jupyter nbconvert --to notebook --execute --inplace \
    --ExecutePreprocessor.kernel_name=soc-agent \
    --ExecutePreprocessor.timeout=180 notebooks/$nb.ipynb
done
```

All four execute with **no errors and zero external creds**. MLflow runs are
written under `./mlruns` and comparison CSVs under `docs/eval_artifacts/`.

---

## Quick env-var reference

| Variable | Meaning |
|----------|---------|
| `SOC_MOCK_MODE` | `1` (default) = mock; `0` = live |
| `LLM_PROVIDER` / `LLM_MODEL` / `LLM_MODEL_B` | LLM provider and the two models |
| `LLM_BASE_URL` / `LLM_API_KEY` | OpenAI-compatible endpoint + key |
| `DATABRICKS_HOST` / `DATABRICKS_TOKEN` | workspace auth |
| `DATABRICKS_WAREHOUSE_ID` / `DATABRICKS_CLUSTER_ID` | how to run UC SQL |
| `UC_CATALOG` / `UC_GOLD_SCHEMA` / `UC_SILVER_SCHEMA` | Unity Catalog names |
| `VT_API_KEY` / `SHODAN_API_KEY` / `NVD_API_KEY` | optional threat-intel keys |
| `MLFLOW_TRACKING_URI` / `MLFLOW_EXPERIMENT` | MLflow config |
