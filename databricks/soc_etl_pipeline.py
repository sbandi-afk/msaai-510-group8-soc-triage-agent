# Databricks notebook source
# MAGIC %md
# MAGIC # SOC Intelligence -- ETL Pipeline
# MAGIC
# MAGIC **Scheduled** -- run after `mock_event_injector` or when new OTRF data is added.
# MAGIC Assumes `setup_infrastructure` has already been run once.
# MAGIC
# MAGIC | Step | Action | Mode |
# MAGIC |------|--------|------|
# MAGIC | 1 | Download OTRF ZIPs from GitHub to Volume | Skip if cached |
# MAGIC | 2 | Extract JSON from ZIPs to bronze Delta table | Append only |
# MAGIC | 3 | Normalize new bronze rows to silver tables | Incremental (watermark) |

# COMMAND ----------
# MAGIC %md ## Step 1 -- Download OTRF Datasets from GitHub

# COMMAND ----------
import os, io, zipfile, requests, shutil
from pyspark.sql.functions import col, lit, current_timestamp
from pyspark.sql.types import IntegerType

VOLUME_PATH  = "/Volumes/soc_intelligence/bronze/otrf_raw"
EXTRACT_BASE = "/Volumes/soc_intelligence/bronze/otrf_raw/extracted"
GITHUB_API   = "https://api.github.com/repos/OTRF/Security-Datasets/contents/datasets/atomic/windows"

TACTIC_PATHS = [
    "datasets/atomic/windows/credential_access/host",
    "datasets/atomic/windows/defense_evasion/host",
    "datasets/atomic/windows/execution/host",
    "datasets/atomic/windows/lateral_movement/host",
    "datasets/atomic/windows/persistence/host",
    "datasets/atomic/windows/privilege_escalation/host",
    "datasets/atomic/windows/discovery/host",
]

os.makedirs(VOLUME_PATH,  exist_ok=True)
os.makedirs(EXTRACT_BASE, exist_ok=True)

session = requests.Session()
session.headers.update({"User-Agent": "soc-agent-etl/1.0"})
downloaded, skipped = [], []

for tactic_path in TACTIC_PATHS:
    tactic_name = tactic_path.split("/")[3]
    sub_path    = "/".join(tactic_path.split("/")[3:])
    print(f"\nFetching: {tactic_name}")
    try:
        resp = session.get(f"{GITHUB_API}/{sub_path}", timeout=15)
        resp.raise_for_status()
        files = resp.json()
    except Exception as e:
        print(f"  WARNING: {e}")
        continue
    zips = [f for f in files if isinstance(f, dict) and f.get("name","").endswith(".zip")][:2]
    for z in zips:
        dest = f"{VOLUME_PATH}/{z['name']}"
        if os.path.exists(dest) and os.path.getsize(dest) > 1000:
            print(f"  Cached: {z['name']}")
            skipped.append(z['name'])
            continue
        try:
            r = session.get(z["download_url"], timeout=60)
            r.raise_for_status()
            with open(dest, "wb") as f:
                f.write(r.content)
            print(f"  Downloaded: {z['name']} ({round(os.path.getsize(dest)/1024,1)} KB)")
            downloaded.append(z['name'])
        except Exception as e:
            print(f"  FAILED: {z['name']} -- {e}")

all_zips = [f for f in os.listdir(VOLUME_PATH) if f.endswith(".zip")]
print(f"\nDownloaded: {len(downloaded)} | Cached: {len(skipped)} | Total ZIPs: {len(all_zips)}")

# COMMAND ----------
# MAGIC %md ## Step 2 -- Extract ZIPs and Append to Bronze

# COMMAND ----------
# Clear extract staging for clean run
if os.path.exists(EXTRACT_BASE):
    shutil.rmtree(EXTRACT_BASE)
os.makedirs(EXTRACT_BASE, exist_ok=True)

total_files = 0
for zip_name in all_zips:
    # Skip mock injector ZIPs (they come from Volume root but aren't OTRF ZIPs)
    out_dir = f"{EXTRACT_BASE}/{zip_name.replace('.zip','')}"
    os.makedirs(out_dir, exist_ok=True)
    try:
        with open(f"{VOLUME_PATH}/{zip_name}", "rb") as f:
            zf = zipfile.ZipFile(io.BytesIO(f.read()))
            members = [m for m in zf.namelist() if m.endswith((".json",".jsonl"))]
            for m in members:
                with open(f"{out_dir}/{os.path.basename(m)}", "wb") as out:
                    out.write(zf.read(m))
                total_files += 1
        print(f"  [OK] {zip_name} -- {len(members)} file(s)")
    except Exception as e:
        print(f"  [FAILED] {zip_name}: {e}")

print(f"\nExtracted: {total_files} JSON files")
if total_files == 0:
    raise Exception("No JSON files extracted -- check Volume contents")

# Read extracted OTRF data -- APPEND to bronze (do not overwrite mock events)
df_otrf = (
    spark.read
        .option("recursiveFileLookup", "true")
        .option("inferSchema", "true")
        .option("multiLine", "true")
        .json(EXTRACT_BASE)
        .withColumn("_ingest_ts", current_timestamp())
        .withColumn("_source", col("_metadata.file_path"))
)

otrf_count = df_otrf.count()

# Only append rows not already in bronze (deduplicate by _source path)
try:
    existing_sources = set(
        r["_source"] for r in
        spark.sql("SELECT DISTINCT _source FROM soc_intelligence.bronze.siem_raw_event WHERE _source NOT LIKE 'mock%'").collect()
    )
    df_new_otrf = df_otrf.filter(~col("_source").isin(list(existing_sources))) if existing_sources else df_otrf
    new_count = df_new_otrf.count()
    print(f"OTRF rows: {otrf_count} total, {new_count} new (not yet in bronze)")
except Exception:
    df_new_otrf = df_otrf
    new_count = otrf_count
    print(f"OTRF rows: {new_count} (fresh load)")

if new_count > 0:
    df_new_otrf.write.format("delta").mode("append").option("mergeSchema","true") \
        .saveAsTable("soc_intelligence.bronze.siem_raw_event")
    print(f"[OK] Appended {new_count} OTRF rows to bronze.siem_raw_event")
else:
    print("[OK] No new OTRF rows to append -- bronze is up to date")

# COMMAND ----------
# MAGIC %md ## Step 3 -- Incremental Silver Normalization
# MAGIC
# MAGIC Only processes bronze rows with `_ingest_ts` newer than the latest
# MAGIC timestamp already in silver. This ensures mock injector events written
# MAGIC to bronze are picked up without reprocessing the full OTRF dataset.

# COMMAND ----------
PRIORITY_EVENT_IDS = [4624, 4625, 4688, 4697, 4720, 4776, 1, 3, 7, 8, 10, 11, 13]

# Get watermark -- max _ingest_ts already processed into silver
try:
    wm_row = spark.sql(
        "SELECT MAX(_ingest_ts) AS wm FROM soc_intelligence.silver.siem_normalized"
    ).collect()[0]
    watermark = wm_row["wm"]
except Exception:
    watermark = None

df_bronze = spark.read.table("soc_intelligence.bronze.siem_raw_event")

if watermark:
    df_new_bronze = df_bronze.filter(col("_ingest_ts") > lit(watermark))
    print(f"Incremental: processing bronze rows with _ingest_ts > {watermark}")
else:
    df_new_bronze = df_bronze
    print("Full load: no existing silver data -- processing all bronze rows")

new_bronze_count = df_new_bronze.count()
print(f"New bronze rows to process: {new_bronze_count:,}")

if new_bronze_count == 0:
    print("[OK] Silver is up to date -- nothing to normalize")
else:
    avail = set(df_new_bronze.columns)

    def sc(name, alias, cast=None):
        c = col(f"`{name}`") if name.startswith("@") else col(name)
        if name not in avail:
            c = lit(None).cast("string")
        if cast:
            c = c.cast(cast)
        return c.alias(alias)

    df_norm = (
        df_new_bronze
            .withColumn("EventID_int", col("EventID").cast(IntegerType()))
            .filter(col("EventID_int").isin(PRIORITY_EVENT_IDS))
            .select(
                col("EventID_int").alias("EventID"),
                sc("Hostname",          "host_ip"),
                sc("SubjectUserName",   "user_id"),
                sc("ProcessName",       "ProcessName"),
                sc("CommandLine",       "CommandLine"),
                sc("ParentProcessName", "ParentProcessName"),
                sc("@timestamp",        "event_ts", cast="timestamp"),
                sc("Channel",           "event_type"),
                col("_ingest_ts"),
                col("_source")
            )
    )

    norm_count = df_norm.count()
    df_norm.write.format("delta").mode("append").option("mergeSchema","true") \
        .saveAsTable("soc_intelligence.silver.siem_normalized")
    print(f"[OK] silver.siem_normalized -- appended {norm_count:,} rows")

    # Refresh host and user_account from full silver (these are small dimension tables)
    df_all_norm = spark.read.table("soc_intelligence.silver.siem_normalized")

    df_host = (df_all_norm.select("host_ip").distinct()
        .withColumn("criticality_tier", lit("medium"))
        .withColumn("os", lit("Windows")))
    df_host.write.format("delta").mode("overwrite").saveAsTable("soc_intelligence.silver.host")
    print(f"[OK] silver.host -- {df_host.count()} hosts")

    df_users = (df_all_norm.filter(col("EventID").isin([4624, 4720]))
        .select("user_id","host_ip","event_ts").distinct())
    df_users.write.format("delta").mode("overwrite").saveAsTable("soc_intelligence.silver.user_account")
    print(f"[OK] silver.user_account -- {df_users.count()} identities")

# COMMAND ----------
print("\n" + "=" * 50)
print("  ETL Pipeline Run Complete")
print("=" * 50)
for label, sql in [
    ("bronze.siem_raw_event",  "SELECT COUNT(*) FROM soc_intelligence.bronze.siem_raw_event"),
    ("silver.siem_normalized", "SELECT COUNT(*) FROM soc_intelligence.silver.siem_normalized"),
    ("silver.host",            "SELECT COUNT(*) FROM soc_intelligence.silver.host"),
    ("silver.user_account",    "SELECT COUNT(*) FROM soc_intelligence.silver.user_account"),
]:
    n = spark.sql(sql).collect()[0][0]
    print(f"  {label:<30} {int(n):>8,} rows")
print("=" * 50)