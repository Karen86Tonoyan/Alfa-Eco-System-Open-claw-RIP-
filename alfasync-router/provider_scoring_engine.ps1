#!/usr/bin/env pwsh
# ============================================================
# ALFA Router - Provider Scoring Engine
# ASCII-safe version for Windows PowerShell 5.1
# ============================================================

Set-StrictMode -Version Latest

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------
$script:SCORING_HISTORY_PATH = if ($env:ALFA_HISTORY_PATH) {
    $env:ALFA_HISTORY_PATH
} else {
    Join-Path $PSScriptRoot "history.jsonl"
}

$script:SCORING_MAX_LATENCY_MS = 30000
$script:SCORING_MIN_SAMPLES    = 3
$script:SCORING_DEFAULT_SCORE  = 0.50

$script:PROVIDER_META = @{
    "10" = @{ Name = "LocalCoder"; Tier = "local" }
    "5"  = @{ Name = "Claude";     Tier = "cloud" }
    "6"  = @{ Name = "OpenAI";     Tier = "cloud" }
    "8"  = @{ Name = "Copilot";    Tier = "cloud" }
    "1"  = @{ Name = "Ollama";     Tier = "local" }
    "3"  = @{ Name = "Qwen";       Tier = "local" }
    "4"  = @{ Name = "LMStudio";   Tier = "local" }
}

$script:CASCADE_TEMPLATES = @{
    simple  = @("3", "4", "1", "5", "6", "8")
    medium  = @("5", "10", "3", "4", "1", "6", "8")
    complex = @("10", "5", "6", "8", "3", "4", "1")
}

# ------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------
function _Read-ALFAHistory {
    if (-not (Test-Path $script:SCORING_HISTORY_PATH)) {
        return @()
    }

    $lines = Get-Content -Path $script:SCORING_HISTORY_PATH -Encoding UTF8 -ErrorAction SilentlyContinue
    if (-not $lines) {
        return @()
    }

    $records = foreach ($line in $lines) {
        $line = [string]$line
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        try {
            $line | ConvertFrom-Json -ErrorAction Stop
        } catch {
        }
    }

    return $records
}

function _Aggregate-ProviderMetrics {
    param([object[]]$Records)

    $agg = @{}

    foreach ($r in $Records) {
        $providerProp = $r.PSObject.Properties["provider"]
        if ($null -eq $providerProp) {
            continue
        }

        $id = [string]$providerProp.Value
        if ([string]::IsNullOrWhiteSpace($id)) {
            continue
        }

        if (-not $agg.ContainsKey($id)) {
            $agg[$id] = @{
                total       = 0
                successes   = 0
                failures    = 0
                latency_sum = 0L
                latency_cnt = 0
            }
        }

        $agg[$id].total++

        $typeProp = $r.PSObject.Properties["type"]
        $typeValue = if ($null -ne $typeProp) { [string]$typeProp.Value } else { "" }
        $isSuccess = ($typeValue -eq "response") -or ($typeValue -eq "ok") -or ($typeValue -eq "success")
        if ($isSuccess) {
            $agg[$id].successes++
        } else {
            $agg[$id].failures++
        }

        $latencyProp = $r.PSObject.Properties["latency_ms"]
        if ($null -ne $latencyProp) {
            $latencyValue = $latencyProp.Value
            if ($null -ne $latencyValue -and [int]$latencyValue -gt 0) {
                $agg[$id].latency_sum += [long]$latencyValue
                $agg[$id].latency_cnt++
            }
        }
    }

    return $agg
}

function _Score-Provider {
    param(
        [hashtable]$Stats,
        [int]$MaxLatencyMs = 30000
    )

    if ($Stats.total -lt $script:SCORING_MIN_SAMPLES) {
        return [PSCustomObject]@{
            Score        = $script:SCORING_DEFAULT_SCORE
            Reliability  = $null
            SpeedScore   = $null
            AvgLatencyMs = $null
            Samples      = $Stats.total
            ColdStart    = $true
        }
    }

    $reliability = if ($Stats.total -gt 0) {
        [double]$Stats.successes / [double]$Stats.total
    } else {
        0.0
    }

    $speedScore = $script:SCORING_DEFAULT_SCORE
    $avgLatency = $null
    if ($Stats.latency_cnt -gt 0) {
        $avgLatency = [double]$Stats.latency_sum / [double]$Stats.latency_cnt
        $speedScore = [Math]::Max(0.0, 1.0 - ($avgLatency / $MaxLatencyMs))
    }

    $finalScore = 0.60 * $reliability + 0.40 * $speedScore

    return [PSCustomObject]@{
        Score        = [Math]::Round($finalScore, 4)
        Reliability  = [Math]::Round($reliability, 4)
        SpeedScore   = [Math]::Round($speedScore, 4)
        AvgLatencyMs = if ($null -ne $avgLatency) { [int]$avgLatency } else { $null }
        Samples      = $Stats.total
        ColdStart    = $false
    }
}

# ------------------------------------------------------------
# Public API
# ------------------------------------------------------------
function Get-ProviderScores {
    [CmdletBinding()]
    param(
        [string]$HistoryPath = $script:SCORING_HISTORY_PATH
    )

    $oldPath = $script:SCORING_HISTORY_PATH
    if ($HistoryPath -ne $oldPath) {
        $script:SCORING_HISTORY_PATH = $HistoryPath
    }

    $records = _Read-ALFAHistory
    $agg = _Aggregate-ProviderMetrics -Records $records
    $result = @{}

    foreach ($id in $script:PROVIDER_META.Keys) {
        $meta = $script:PROVIDER_META[$id]
        $stats = if ($agg.ContainsKey($id)) {
            $agg[$id]
        } else {
            @{ total = 0; successes = 0; failures = 0; latency_sum = 0L; latency_cnt = 0 }
        }

        $scored = _Score-Provider -Stats $stats -MaxLatencyMs $script:SCORING_MAX_LATENCY_MS

        $result[$id] = [PSCustomObject]@{
            ProviderId   = $id
            Name         = $meta.Name
            Tier         = $meta.Tier
            Score        = $scored.Score
            Reliability  = $scored.Reliability
            SpeedScore   = $scored.SpeedScore
            AvgLatencyMs = $scored.AvgLatencyMs
            Samples      = $scored.Samples
            ColdStart    = $scored.ColdStart
        }
    }

    $script:SCORING_HISTORY_PATH = $oldPath
    return $result
}

function Select-Provider {
    [CmdletBinding()]
    param(
        [ValidateSet("simple", "medium", "complex")]
        [string]$QueryType = "medium",

        [hashtable]$Scores = $null
    )

    if (-not $Scores) {
        $Scores = Get-ProviderScores
    }

    $template = $script:CASCADE_TEMPLATES[$QueryType]
    $localIds = @($template | Where-Object { $script:PROVIDER_META[$_].Tier -eq "local" })

    $localRank = @{}
    for ($i = 0; $i -lt $localIds.Count; $i++) {
        $localRank[$localIds[$i]] = $i
    }

    $sortedLocal = $localIds | Sort-Object `
        @{ Expression = {
                if ($Scores.ContainsKey($_)) { $Scores[$_].Score } else { $script:SCORING_DEFAULT_SCORE }
            }; Descending = $true },
        @{ Expression = { $localRank[$_] }; Descending = $false }

    $result = [System.Collections.Generic.List[string]]::new()
    $localIdx = 0
    foreach ($id in $template) {
        if ($script:PROVIDER_META[$id].Tier -eq "local") {
            $result.Add($sortedLocal[$localIdx])
            $localIdx++
        } else {
            $result.Add($id)
        }
    }

    return $result.ToArray()
}

function Show-ScoringMatrix {
    [CmdletBinding()]
    param([hashtable]$Scores = $null)

    if (-not $Scores) {
        $Scores = Get-ProviderScores
    }

    $rows = foreach ($id in ($Scores.Keys | Sort-Object)) {
        $s = $Scores[$id]
        [PSCustomObject]@{
            ID          = $id
            Provider    = $s.Name
            Tier        = $s.Tier
            Score       = "{0:F3}" -f $s.Score
            Reliability = if ($null -ne $s.Reliability) { "{0:P0}" -f $s.Reliability } else { "N/A" }
            "Avg ms"    = if ($null -ne $s.AvgLatencyMs) { $s.AvgLatencyMs } else { "N/A" }
            Samples     = $s.Samples
            ColdStart   = if ($s.ColdStart) { "yes" } else { "no" }
        }
    }

    Write-Host ""
    Write-Host "=== ALFA Provider Scoring Matrix ===" -ForegroundColor Cyan
    $rows | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ -NoNewline }
    Write-Host "===================================" -ForegroundColor Cyan
    Write-Host "  Scoring: 60% reliability + 40% speed  |  Min samples: $script:SCORING_MIN_SAMPLES  |  Cold-start score: $script:SCORING_DEFAULT_SCORE" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Recommended cascade order:" -ForegroundColor Yellow
    foreach ($qt in @("simple", "medium", "complex")) {
        $cascade = Select-Provider -QueryType $qt -Scores $Scores
        $names = $cascade | ForEach-Object { $Scores[$_].Name }
        Write-Host ("    {0,-8} -> {1}" -f $qt, ($names -join " -> ")) -ForegroundColor DarkYellow
    }
    Write-Host ""
}

function Reset-ProviderScores {
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$Force)

    if (-not $Force) {
        Write-Warning "Reset-ProviderScores: pass -Force to wipe history.jsonl"
        return
    }

    if (Test-Path $script:SCORING_HISTORY_PATH) {
        Remove-Item -Path $script:SCORING_HISTORY_PATH -Force
        Write-Host "[ScoringEngine] history.jsonl wiped." -ForegroundColor Yellow
    }
}

if ($env:ALFA_SCORING_VERBOSE -eq "1") {
    Write-Host "[ScoringEngine] Loaded. History: $script:SCORING_HISTORY_PATH" -ForegroundColor DarkGray
}
