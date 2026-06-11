# Databricks notebook source
# MAGIC %md
# MAGIC # Deploy Jobs -- SOC Triage Agent
# MAGIC
# MAGIC **Run this once after checking out the repo via Databricks Git folders.**
# MAGIC Creates (or updates) all 5 jobs and schedules them. Fully idempotent --
# MAGIC re-running updates existing jobs in place rather than duplicating.
# MAGIC
# MAGIC ### How it works
# MAGIC This notebook detects its own location in the repo, so the jobs it creates
# MAGIC point at the notebooks **wherever your team checked out the repo**
# MAGIC (e.g. `/Workspace/Repos/<you>/msaai-510-group8-soc-triage-agent/databricks_src/`).
# MAGIC No hardcoded paths, no local CLI, no tokens -- it uses the notebook's own
# MAGIC workspace context.
# MAGIC
# MAGIC ### Reproduction order for a fresh checkout
# MAGIC 1. Clone repo via **Repos / Git folders** in Databricks
# MAGIC 2. Add API keys to secrets (one-time -- see README):
# MAGIC    `databricks secrets put-secret mcp-keys abuseipdb-key` etc.
# MAGIC 3. Run **`setup_infrastructure`** notebook (catalog, schemas, UC functions, connections)
# MAGIC 4. Run **this notebook** (`deploy_jobs`) -- creates + schedules all jobs
# MAGIC
# MAGIC ### Job inventory created
# MAGIC Staggered hourly cadence (UTC) so each cycle flows inject → ETL → triage → eval:
# MAGIC | Job | Schedule | Notebook |
# MAGIC |-----|----------|----------|
# MAGIC | setup_infrastructure | ON-DEMAND | databricks_src/00_setup_infrastructure |
# MAGIC | mock_event_injector_v2 | hourly at :00 | databricks_src/01_mock_event_injector |
# MAGIC | soc_etl_pipeline_v2 | hourly at :10 | databricks_src/02_soc_etl_pipeline |
# MAGIC | soc_agent_live | hourly at :20 | databricks_src/03_soc_agent_live |
# MAGIC | incident_eval_agent_v2 | hourly at :25:30 | databricks_src/04_incident_eval_agent |

# COMMAND ----------
import json, requests

# -- Auto-auth from the notebook's own workspace context (no token config needed) --
ctx        = dbutils.notebook.entry_point.getDbutils().notebook().getContext()
HOST       = "https://" + spark.conf.get("spark.databricks.workspaceUrl")
TOKEN      = ctx.apiToken().get()
HEADERS    = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

# -- Detect this notebook's folder = the repo's databricks_src/ dir --
# notebookPath() -> e.g. /Workspace/Repos/you/msaai-510-group8-soc-triage-agent/databricks_src/deploy_jobs
THIS_NB    = ctx.notebookPath().get()
NB_FOLDER  = "/".join(THIS_NB.split("/")[:-1])   # the databricks_src/ folder
print(f"Workspace : {HOST}")
print(f"Repo path : {NB_FOLDER}")

ENV_SPEC = [{"environment_key": "default", "spec": {"client": "2"}}]

# -- Single source of truth for all jobs --
# schedule = None  => ON-DEMAND (manual trigger only)
# Staggered hourly (UTC): inject :00 -> ETL :10 -> agent :20 -> eval :25:30.
# These crons MUST match the live job configs -- re-running this deployer
# resets schedules to whatever is listed here.
JOBS = [
    {"name": "setup_infrastructure",     "nb": "00_setup_infrastructure",  "cron": None},
    {"name": "mock_event_injector_v2",   "nb": "01_mock_event_injector",   "cron": "0 0 * * * ?"},
    {"name": "soc_etl_pipeline_v2",      "nb": "02_soc_etl_pipeline",      "cron": "0 10 * * * ?"},
    {"name": "soc_agent_live",           "nb": "03_soc_agent_live",        "cron": "0 20 * * * ?"},
    {"name": "incident_eval_agent_v2",   "nb": "04_incident_eval_agent",   "cron": "30 25 * * * ?"},
]

# COMMAND ----------
def find_job_id(name):
    r = requests.get(f"{HOST}/api/2.1/jobs/list", headers=HEADERS, params={"limit": 100})
    for j in r.json().get("jobs", []):
        if j["settings"]["name"] == name:
            return j["job_id"]
    return None

def build_settings(job):
    s = {
        "name": job["name"],
        "tasks": [{
            "task_key": "run",
            "notebook_task": {"notebook_path": f"{NB_FOLDER}/{job['nb']}", "source": "WORKSPACE"},
            "environment_key": "default",
        }],
        "environments": ENV_SPEC,
        "max_concurrent_runs": 1,
    }
    if job["cron"]:
        s["schedule"] = {
            "quartz_cron_expression": job["cron"],
            "timezone_id": "UTC",
            "pause_status": "UNPAUSED",
        }
    return s

# COMMAND ----------
print("=== Deploying jobs ===\n")
for job in JOBS:
    settings = build_settings(job)
    existing = find_job_id(job["name"])
    trigger  = job["cron"] or "ON-DEMAND"
    if existing:
        # reset replaces the whole settings block (idempotent update)
        requests.post(f"{HOST}/api/2.1/jobs/reset", headers=HEADERS,
                      data=json.dumps({"job_id": existing, "new_settings": settings}))
        print(f"  [updated] {job['name']:<26} {trigger}")
    else:
        r = requests.post(f"{HOST}/api/2.0/jobs/create", headers=HEADERS,
                          data=json.dumps(settings))
        jid = r.json().get("job_id")
        print(f"  [created] {job['name']:<26} {trigger}  (id={jid})")

# COMMAND ----------
print("\n=== Current job inventory ===")
r = requests.get(f"{HOST}/api/2.1/jobs/list", headers=HEADERS, params={"limit": 100})
for j in sorted(r.json().get("jobs", []), key=lambda x: x["settings"]["name"]):
    sched = j["settings"].get("schedule")
    trig  = sched["quartz_cron_expression"] if sched else "ON-DEMAND (manual)"
    print(f"  {j['settings']['name']:<26} {trig}")

print("\nDone. All jobs deployed and scheduled.")
