# Databricks notebook source
# MAGIC %md
# MAGIC # Incident Quality Eval Agent
# MAGIC
# MAGIC Two complementary evaluation layers run after `soc_agent_live`:
# MAGIC
# MAGIC | Layer | Notebook | What it checks | Storage |
# MAGIC |-------|----------|---------------|---------|
# MAGIC | **Structural** (this notebook) | `incident_eval_agent` | Format validity, MITRE correctness, z_score gate | `gold.incident_eval` Delta table |
# MAGIC | **LLM Reasoning** | `soc_agent_live` (inline) | Decision quality, tactic agreement, latency, dual-LLM comparison | Databricks MLflow experiment |
# MAGIC
# MAGIC Scheduled: every 5 minutes (+30s offset so agent finishes first).

# COMMAND ----------
import json, re, uuid
from datetime import datetime, timezone
from pyspark.sql.types import *

spark.sql("USE CATALOG soc_intelligence")
spark.sql("USE SCHEMA gold")

VALID_TACTICS = {
    "Credential Access","Execution","Persistence","Lateral Movement",
    "Defense Evasion","Discovery","Privilege Escalation",
    "Command and Control","Exfiltration","Impact","Initial Access",
    "Reconnaissance","Resource Development"
}
VALID_SEVERITIES = {"LOW","MEDIUM","HIGH","CRITICAL"}
TECHNIQUE_RE     = re.compile(r"^T\d{4}(\.\d{3})?$")

def grade(score):
    if score >= 0.9: return "A"
    if score >= 0.7: return "B"
    if score >= 0.5: return "C"
    return "F"

def eval_incident(row):
    notes  = []
    checks = {}
    checks["tactic_valid"]     = row["tactic"] in VALID_TACTICS
    checks["technique_valid"]  = bool(TECHNIQUE_RE.match(row["technique_id"] or ""))
    conf = float(row["confidence"] or 0)
    checks["confidence_valid"] = 0.0 <= conf <= 1.0
    checks["severity_valid"]   = (row["severity"] or "").upper() in VALID_SEVERITIES
    z = float(row["z_score"] or 0)
    checks["zscore_valid"]     = z >= 2.5
    if not checks["tactic_valid"]:     notes.append(f"Unknown tactic: {row['tactic']}")
    if not checks["technique_valid"]:  notes.append(f"Invalid technique_id: {row['technique_id']}")
    if not checks["confidence_valid"]: notes.append(f"Confidence out of range: {conf}")
    if not checks["severity_valid"]:   notes.append(f"Invalid severity: {row['severity']}")
    if not checks["zscore_valid"]:     notes.append(f"z_score below threshold: {z:.3f} < 2.5")
    score = sum(checks.values()) / 5.0
    return {**checks, "quality_score": score, "quality_grade": grade(score),
            "notes": json.dumps(notes)}

# COMMAND ----------
# MAGIC %md ## Part 1 -- Structural Quality Check (rule-based)

# COMMAND ----------
now = datetime.now(timezone.utc).replace(tzinfo=None)

recent = spark.sql("""
    SELECT i.*
    FROM soc_intelligence.gold.incident i
    LEFT JOIN soc_intelligence.gold.incident_eval e ON i.incident_id = e.incident_id
    WHERE i.created_at >= DATEADD(MINUTE, -30, CURRENT_TIMESTAMP())
      AND e.incident_id IS NULL
""").collect()

print(f"New incidents to evaluate: {len(recent)}")

if len(recent) > 0:
    eval_rows = []
    for row in recent:
        result = eval_incident(row)
        eval_rows.append({
            "eval_id":         str(uuid.uuid4()),
            "incident_id":     row["incident_id"],
            "evaluated_at":    now,
            "tactic_valid":    result["tactic_valid"],
            "technique_valid": result["technique_valid"],
            "confidence_valid":result["confidence_valid"],
            "severity_valid":  result["severity_valid"],
            "zscore_valid":    result["zscore_valid"],
            "quality_score":   result["quality_score"],
            "quality_grade":   result["quality_grade"],
            "notes":           result["notes"],
        })

    schema = StructType([
        StructField("eval_id",         StringType(),   False),
        StructField("incident_id",     StringType(),   True),
        StructField("evaluated_at",    TimestampType(),True),
        StructField("tactic_valid",    BooleanType(),  True),
        StructField("technique_valid", BooleanType(),  True),
        StructField("confidence_valid",BooleanType(),  True),
        StructField("severity_valid",  BooleanType(),  True),
        StructField("zscore_valid",    BooleanType(),  True),
        StructField("quality_score",   DoubleType(),   True),
        StructField("quality_grade",   StringType(),   True),
        StructField("notes",           StringType(),   True),
    ])
    df_eval = spark.createDataFrame(eval_rows, schema=schema)
    df_eval.write.format("delta").mode("append").saveAsTable("soc_intelligence.gold.incident_eval")

    print("\nStructural eval results:")
    for r in eval_rows:
        print(f"  {r['incident_id'][:8]}  grade={r['quality_grade']}  "
              f"score={r['quality_score']:.2f}  notes={r['notes']}")

# COMMAND ----------
# MAGIC %md ## Part 2 -- MLflow LLM Reasoning Summary
# MAGIC
# MAGIC Reads the latest runs from the `soc_triage_agent` MLflow experiment
# MAGIC logged by `soc_agent_live` and shows dual-LLM comparison metrics.

# COMMAND ----------
import mlflow

try:
    mlflow.set_tracking_uri("databricks")
    exp = mlflow.get_experiment_by_name(
        "/Shared/msaai-510-group8-soc-triage-agent/soc_triage_agent"
    )
    if exp:
        runs_df = mlflow.search_runs(
            experiment_ids=[exp.experiment_id],
            order_by=["start_time DESC"],
            max_results=10,
            output_format="pandas"
        )
        if not runs_df.empty:
            print("\nLatest MLflow runs (LLM reasoning quality):")
            cols = ["tags.host_ip","tags.model_a_decision","tags.model_b_decision",
                    "metrics.z_score","metrics.model_a_confidence","metrics.model_b_confidence",
                    "tags.tactic_agreement","tags.incident_written",
                    "metrics.model_a_latency_ms","metrics.model_b_latency_ms"]
            available = [c for c in cols if c in runs_df.columns]
            print(runs_df[available].to_string(index=False))

            # Summary stats
            if "metrics.model_a_confidence" in runs_df.columns:
                mean_conf_a = runs_df["metrics.model_a_confidence"].mean()
                mean_conf_b = runs_df["metrics.model_b_confidence"].mean() if "metrics.model_b_confidence" in runs_df.columns else 0
                agree_rate  = (runs_df["tags.tactic_agreement"] == "True").mean() if "tags.tactic_agreement" in runs_df.columns else 0
                incidents   = (runs_df["tags.incident_written"] == "true").sum() if "tags.incident_written" in runs_df.columns else 0
                print(f"\nSummary ({len(runs_df)} recent runs):")
                print(f"  Mean confidence  Model A: {mean_conf_a:.3f}  |  Model B: {mean_conf_b:.3f}")
                print(f"  Tactic agreement (A vs B): {agree_rate*100:.0f}%")
                print(f"  Incidents written: {int(incidents)}")
        else:
            print("No MLflow runs found yet -- run soc_agent_live to populate.")
    else:
        print("MLflow experiment not found yet -- will appear after first soc_agent_live run.")
except Exception as e:
    print(f"MLflow query skipped: {e}")

# COMMAND ----------
# MAGIC %md ## Part 3 -- All-Time Quality Summary

# COMMAND ----------
print("\nAll-time structural quality (gold.incident_eval):")
spark.sql("""
    SELECT quality_grade, COUNT(*) AS count,
           ROUND(AVG(quality_score),3) AS avg_score,
           SUM(CASE WHEN zscore_valid     THEN 1 ELSE 0 END) AS zscore_ok,
           SUM(CASE WHEN tactic_valid     THEN 1 ELSE 0 END) AS tactic_ok,
           SUM(CASE WHEN technique_valid  THEN 1 ELSE 0 END) AS technique_ok,
           SUM(CASE WHEN severity_valid   THEN 1 ELSE 0 END) AS severity_ok
    FROM soc_intelligence.gold.incident_eval
    GROUP BY quality_grade ORDER BY quality_grade
""").show()

total_inc  = spark.sql("SELECT COUNT(*) FROM soc_intelligence.gold.incident").collect()[0][0]
total_eval = spark.sql("SELECT COUNT(*) FROM soc_intelligence.gold.incident_eval").collect()[0][0]
print(f"Total incidents: {total_inc}  |  Total evaluated: {total_eval}")