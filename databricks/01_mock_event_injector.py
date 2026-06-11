# Databricks notebook source
# MAGIC %md
# MAGIC # Mock Event Injector
# MAGIC
# MAGIC Injects synthetic SIEM events into **`bronze.siem_raw_event`** (not silver directly).
# MAGIC The ETL pipeline picks them up and normalizes to silver on its next run.
# MAGIC
# MAGIC This fixes Gap 1: the full Bronze -> Silver -> Agent pipeline is exercised.
# MAGIC
# MAGIC Pattern:
# MAGIC - **70% normal run**: 2-3 events across test hosts (builds baseline)
# MAGIC - **30% spike run**: 20-30 events on one host (triggers z_score > 2.5)
# MAGIC
# MAGIC Scheduled: every 1 minute.
# MAGIC After injection, triggers the ETL pipeline job to normalize immediately.

# COMMAND ----------
import random, uuid
from datetime import datetime, timezone
from pyspark.sql import Row
from pyspark.sql.types import (StructType, StructField, StringType,
                                LongType, TimestampType)

TEST_HOSTS = ["WS5", "WS6", "FILESRV1"]

# Bronze schema matches siem_raw_event columns used by ETL normalization
# Key fields: EventID, Hostname, SubjectUserName, ProcessName, CommandLine,
#             @timestamp (as string), Channel, _ingest_ts, _source
SCENARIOS = [
    (4625, "Security",  "",              "",                          "credential_access"),
    (4776, "Security",  "",              "",                          "credential_access"),
    (4688, "Security",  "powershell.exe","powershell.exe -enc <b64>", "execution"),
    (4688, "Security",  "cmd.exe",       "cmd.exe /c whoami",         "execution"),
    (1,    "Microsoft-Windows-Sysmon/Operational","wmic.exe","wmic process call create","execution"),
    (4697, "Security",  "services.exe",  "",                          "persistence"),
    (4720, "Security",  "",              "",                          "persistence"),
    (4624, "Security",  "",              "",                          "lateral_movement"),
    (3,    "Microsoft-Windows-Sysmon/Operational","explorer.exe","",  "lateral_movement"),
    (7,    "Microsoft-Windows-Sysmon/Operational","rundll32.exe","rundll32.exe shell32.dll","defense_evasion"),
    (8,    "Microsoft-Windows-Sysmon/Operational","svchost.exe", "",  "defense_evasion"),
    (11,   "Microsoft-Windows-Sysmon/Operational","cmd.exe","dir /s C:\\","discovery"),
    (13,   "Microsoft-Windows-Sysmon/Operational","regedit.exe","",  "discovery"),
]
USER_IDS = ["jsmith", "aadmin", "svc_backup", "mward", "sbandi", None]

# Bronze table schema -- matches what ETL expects to read
schema = StructType([
    StructField("EventID",          LongType(),      True),
    StructField("Hostname",         StringType(),    True),   # -> host_ip in silver
    StructField("SubjectUserName",  StringType(),    True),   # -> user_id in silver
    StructField("ProcessName",      StringType(),    True),
    StructField("CommandLine",      StringType(),    True),
    StructField("ParentProcessName",StringType(),    True),
    StructField("@timestamp",       StringType(),    True),   # ISO string -> event_ts in silver
    StructField("Channel",          StringType(),    True),   # -> event_type in silver
    StructField("_ingest_ts",       TimestampType(), True),
    StructField("_source",          StringType(),    True),
])

now       = datetime.now(timezone.utc).replace(tzinfo=None)
now_iso   = datetime.now(timezone.utc).isoformat()
is_spike  = random.random() < 0.30
spike_host = random.choice(TEST_HOSTS) if is_spike else None

rows = []

if is_spike:
    n = random.randint(20, 30)
    print(f"SPIKE: {n} events on {spike_host}")
    for _ in range(n):
        eid, chan, proc, cmd, tactic = random.choice(SCENARIOS)
        rows.append(Row(
            EventID=int(eid), Hostname=spike_host,
            SubjectUserName=random.choice(USER_IDS),
            ProcessName=proc or None, CommandLine=cmd or None,
            ParentProcessName=None,
            **{"@timestamp": now_iso},
            Channel=chan, _ingest_ts=now,
            _source="mock/" + tactic + "/spike/" + str(uuid.uuid4())
        ))

# Always add 1-2 normal events on other hosts
for _ in range(random.randint(1, 2)):
    h = random.choice([x for x in TEST_HOSTS if x != spike_host] if is_spike else TEST_HOSTS)
    eid, chan, proc, cmd, tactic = random.choice(SCENARIOS)
    rows.append(Row(
        EventID=int(eid), Hostname=h,
        SubjectUserName=random.choice(USER_IDS),
        ProcessName=proc or None, CommandLine=cmd or None,
        ParentProcessName=None,
        **{"@timestamp": now_iso},
        Channel=chan, _ingest_ts=now,
        _source="mock/" + tactic + "/normal/" + str(uuid.uuid4())
    ))

# Write to BRONZE (not silver) -- ETL pipeline normalizes from here
df = spark.createDataFrame(rows, schema=schema)
df.write.format("delta").mode("append").option("mergeSchema","true") \
    .saveAsTable("soc_intelligence.bronze.siem_raw_event")

run_type = f"SPIKE ({spike_host}, {len(rows)-1} events)" if is_spike else f"NORMAL ({len(rows)} events)"
print(f"Run type : {run_type}")
print(f"Wrote {len(rows)} row(s) to bronze.siem_raw_event")
for r in rows[:3]:
    print(f"  Hostname={r.Hostname}  EventID={r.EventID}  proc={r.ProcessName}")
if len(rows) > 3:
    print(f"  ... and {len(rows)-3} more")

# Bronze row counts
bronze_total  = spark.sql("SELECT COUNT(*) FROM soc_intelligence.bronze.siem_raw_event").collect()[0][0]
bronze_mock   = spark.sql("SELECT COUNT(*) FROM soc_intelligence.bronze.siem_raw_event WHERE _source LIKE 'mock%'").collect()[0][0]
silver_total  = spark.sql("SELECT COUNT(*) FROM soc_intelligence.silver.siem_normalized").collect()[0][0]

print(f"\nbronze.siem_raw_event : {bronze_total:,} total | {bronze_mock} mock events")
print(f"silver.siem_normalized: {silver_total:,} rows (ETL will update on next run)")
print("\nNote: Run soc_etl_pipeline to normalize new bronze rows to silver.")
