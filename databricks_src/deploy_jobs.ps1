# ==============================================================================
# deploy_jobs.ps1 -- Provision all Databricks jobs for the SOC Triage Agent
# ==============================================================================
# Infrastructure-as-code for the job layer. Idempotent: re-running updates
# existing jobs (matched by name) rather than creating duplicates.
#
# Prerequisites:
#   1. ~/.databrickscfg has a [soc-agent] profile with a valid token
#   2. Notebooks already imported under /Shared/msaai-510-group8-soc-triage-agent/
#   3. setup_infrastructure has been run once (catalog/schemas/UC functions exist)
#
# Usage:
#   pwsh ./deploy_jobs.ps1
#
# To tear down all jobs first:
#   pwsh ./deploy_jobs.ps1 -Recreate
# ==============================================================================

param(
    [switch]$Recreate  # delete existing jobs by name before creating
)

$ErrorActionPreference = "Stop"

# -- Config --
$HostUrl   = "https://dbc-d2cb22c8-c62f.cloud.databricks.com"
$Token     = (Get-Content "C:\Users\$env:USERNAME\.databrickscfg" |
              Select-String "^token" | Select-Object -First 1).ToString().Split("=")[1].Trim().Trim('"')
$Headers   = @{ Authorization = "Bearer $Token"; "Content-Type" = "application/json" }
$NbFolder  = "/Shared/msaai-510-group8-soc-triage-agent"
$EnvSpec   = @(@{ environment_key = "default"; spec = @{ client = "2" } })

# -- Job definitions (single source of truth) --
# schedule = $null means ON-DEMAND (manual trigger only)
$Jobs = @(
    @{
        name     = "setup_infrastructure"
        notebook = "$NbFolder/setup_infrastructure"
        schedule = $null
        desc     = "One-time bootstrap: catalog, schemas, volume, UC functions, HTTP connections, tables"
    },
    @{
        name     = "mock_event_injector_v2"
        notebook = "$NbFolder/mock_event_injector"
        schedule = "0 * * * * ?"        # every 1 min
        desc     = "Generate synthetic SIEM events -> bronze.siem_raw_event"
    },
    @{
        name     = "soc_etl_pipeline_v2"
        notebook = "$NbFolder/soc_etl_pipeline"
        schedule = "0 */2 * * * ?"      # every 2 min
        desc     = "Incremental bronze -> silver normalization (watermark-based)"
    },
    @{
        name     = "soc_agent_live"
        notebook = "$NbFolder/soc_agent_live"
        schedule = "0 */5 * * * ?"      # every 5 min
        desc     = "LangGraph ReAct agent + dual LLM + MLflow + governed AbuseIPDB/Shodan enrichment"
    },
    @{
        name     = "incident_eval_agent_v2"
        notebook = "$NbFolder/incident_eval_agent"
        schedule = "30 */5 * * * ?"     # every 5 min, +30s after agent
        desc     = "Incident quality grading + MLflow reasoning summary -> gold.incident_eval"
    }
)

# -- Helpers --
function Get-JobIdByName($name) {
    $list = Invoke-RestMethod -Method GET -Uri "$HostUrl/api/2.1/jobs/list?limit=100" -Headers $Headers
    $match = $list.jobs | Where-Object { $_.settings.name -eq $name } | Select-Object -First 1
    if ($match) { return $match.job_id } else { return $null }
}

function Build-JobSettings($job) {
    $settings = @{
        name  = $job.name
        tasks = @(@{
            task_key        = "run"
            notebook_task   = @{ notebook_path = $job.notebook; source = "WORKSPACE" }
            environment_key = "default"
        })
        environments        = $EnvSpec
        max_concurrent_runs = 1
    }
    if ($job.schedule) {
        $settings.schedule = @{
            quartz_cron_expression = $job.schedule
            timezone_id            = "UTC"
            pause_status           = "UNPAUSED"
        }
    }
    return $settings
}

# -- Main --
Write-Host "=== Deploying SOC Triage Agent jobs ===" -ForegroundColor Cyan
Write-Host "Workspace: $HostUrl`n"

foreach ($job in $Jobs) {
    $existingId = Get-JobIdByName $job.name

    if ($existingId -and $Recreate) {
        Invoke-RestMethod -Method POST -Uri "$HostUrl/api/2.1/jobs/delete" -Headers $Headers `
            -Body (@{ job_id = $existingId } | ConvertTo-Json) | Out-Null
        Write-Host "  [recreate] deleted old $($job.name) ($existingId)" -ForegroundColor Yellow
        $existingId = $null
    }

    $settings = Build-JobSettings $job

    if ($existingId) {
        # Update in place (reset_settings replaces the whole settings block)
        $body = @{ job_id = $existingId; new_settings = $settings } | ConvertTo-Json -Depth 12
        Invoke-RestMethod -Method POST -Uri "$HostUrl/api/2.1/jobs/reset" -Headers $Headers -Body $body | Out-Null
        $trigger = if ($job.schedule) { $job.schedule } else { "ON-DEMAND" }
        Write-Host "  [updated] $($job.name.PadRight(26)) $trigger" -ForegroundColor Green
    } else {
        $body = $settings | ConvertTo-Json -Depth 12
        $r = Invoke-RestMethod -Method POST -Uri "$HostUrl/api/2.0/jobs/create" -Headers $Headers -Body $body
        $trigger = if ($job.schedule) { $job.schedule } else { "ON-DEMAND" }
        Write-Host "  [created] $($job.name.PadRight(26)) $trigger  (id=$($r.job_id))" -ForegroundColor Green
    }
}

Write-Host "`n=== Done. Current job inventory ===" -ForegroundColor Cyan
$list = Invoke-RestMethod -Method GET -Uri "$HostUrl/api/2.1/jobs/list?limit=100" -Headers $Headers
$list.jobs | Sort-Object { $_.settings.name } | ForEach-Object {
    $trig = if ($_.settings.schedule) { $_.settings.schedule.quartz_cron_expression } else { "ON-DEMAND (manual)" }
    Write-Host ("  {0,-26} {1}" -f $_.settings.name, $trig)
}
