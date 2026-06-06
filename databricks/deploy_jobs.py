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
# MAGIC (e.g. `/Workspace/Repos/<you>/msaai-510-group8-soc-triage-agent/databricks/`).
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
# MAGIC | Job | Schedule | Notebook |
# MAGIC |-----|----------|----------|
# MAGIC | setup_infrastructure | ON-DEMAND | databricks/setup_infrastructure |
# MAGIC | mock_event_injector_v2 | every 1 min | databricks/mock_event_injector |
# MAGIC | soc_etl_pipeline_v2 | every 2 min | databricks/soc_etl_pipeline |
# MAGIC | soc_agent_live | every 5 min | databricks/soc_agent_live |
# MAGIC | incident_eval_agent_v2 | every 5 min +30s | databricks/incident_eval_agent |

# COMMAND ----------
import json, requests

# -- Auto-auth from the notebook's own workspace context (no token config needed) --
ctx        = dbutils.notebook.entry_point.getDbutils().notebook().getContext()
HOST       = "https://" + spark.conf.get("spark.databricks.workspaceUrl")
TOKEN      = ctx.apiToken().get()
HEADERS    = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

# -- Detect this notebook's folder = the repo's databricks/ dir --
# notebookPath() -> e.g. /Workspace/Repos/you/msaai-510-group8-soc-triage-agent/databricks/deploy_jobs
THIS_NB    = ctx.notebookPath().get()
NB_FOLDER  = "/".join(THIS_NB.split("/")[:-1])   # the databricks/ folder
print(f"Workspace : {HOST}")
print(f"Repo path : {NB_FOLDER}")

ENV_SPEC = [{"environment_key": "default", "spec": {"client": "2"}}]

# -- Single source of truth for all jobs --
# schedule = None  => ON-DEMAND (manual trigger only)
JOBS = [
    {"name": "setup_infrastructure",     "nb": "setup_infrastructure",  "cron": None},
    {"name": "mock_event_injector_v2",   "nb": "mock_event_injector",   "cron": "0 * * * * ?"},
    {"name": "soc_etl_pipeline_v2",      "nb": "soc_etl_pipeline",      "cron": "0 */2 * * * ?"},
    {"name": "soc_agent_live",           "nb": "soc_agent_live",        "cron": "0 */5 * * * ?"},
    {"name": "incident_eval_agent_v2",   "nb": "incident_eval_agent",   "cron": "30 */5 * * * ?"},
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
