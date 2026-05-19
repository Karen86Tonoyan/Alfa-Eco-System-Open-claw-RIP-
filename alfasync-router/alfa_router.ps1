#!/usr/bin/env pwsh
# ============================================================
# ALFA ROUTER - PowerShell
# ASCII-safe version for Windows PowerShell 5.1
# ============================================================

Set-StrictMode -Version Latest

# UTF-8 output — fixes Polish characters (a e o s z c n l) in console
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding            = [System.Text.Encoding]::UTF8

# ============================================================
# MEMORY (OneDrive shared sync)
# ============================================================
$ALFA_MEMORY_DIR = "C:\Users\PC\OneDrive\ALFA_MEMORY"
$SESSION_FILE    = Join-Path $ALFA_MEMORY_DIR "session.json"
$HISTORY_FILE    = Join-Path $ALFA_MEMORY_DIR "history.jsonl"
$LOG_FILE        = Join-Path $ALFA_MEMORY_DIR "alfa_router.log"

# Provider Scoring Engine (dot-sourced, same scope)
# $PSScriptRoot is empty when loaded via Invoke-Expression — use fallback
$_scriptRoot     = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $_scriptRoot) { $_scriptRoot = (Get-Location).Path }
$_SCORING_ENGINE = Join-Path $_scriptRoot "provider_scoring_engine.ps1"
if (Test-Path $_SCORING_ENGINE) {
    $env:ALFA_HISTORY_PATH = $HISTORY_FILE
    . $_SCORING_ENGINE
} else {
    Write-Warning "[ALFA] provider_scoring_engine.ps1 not found at $_SCORING_ENGINE - scoring disabled"
}

# ============================================================
# CASCADE
# 10=LocalCoder 5=Claude 6=OpenAI 8=Copilot 1=Ollama 3=Qwen 4=LMStudio
# ============================================================
$cascadeSimple  = @("1", "3")
$cascadeMedium  = @("5", "6", "1")
$cascadeComplex = @("10", "5", "6", "8", "3", "1")

# ============================================================
# PROVIDER MAP
# ============================================================
$_ID_TO_NAME = @{
    "10" = "LocalCoder"
    "5"  = "Claude"
    "6"  = "OpenAI"
    "8"  = "Copilot"
    "1"  = "Ollama"
    "3"  = "Qwen"
    "4"  = "LMStudio"
}

$_LOCAL_FALLBACK_IDS = @("1", "3", "4")

# ============================================================
# LOGGER
# ============================================================
function Write-ALFALog {
    param(
        [string]$Level = "INFO",
        [string]$Message
    )

    $ts = (Get-Date).ToString("s")
    $line = "[$ts] [$Level] $Message"
    Write-Host $line
    Add-Content -Path $LOG_FILE -Value $line
}

function Write-ALFAHistory {
    param(
        [string]$Query,
        [string]$Provider,
        [string]$Type,
        [int]$LatencyMs = 0
    )

    $entry = @{
        ts         = (Get-Date).ToString("s")
        query      = $Query
        provider   = $Provider
        type       = $Type
        latency_ms = $LatencyMs
    } | ConvertTo-Json -Compress

    Add-Content -Path $HISTORY_FILE -Value $entry
}

# ============================================================
# LEGACY PROVIDER STATS
# ============================================================
function Get-ProviderStats {
    if (-not (Test-Path $HISTORY_FILE)) {
        return @{}
    }

    $stats = @{}

    Get-Content -Path $HISTORY_FILE | Where-Object { $_ -and $_.Trim() -ne "" } | ForEach-Object {
        try {
            $e = $_ | ConvertFrom-Json
            $p = [string]$e.provider
            if (-not $p -or $p -eq "FALLBACK" -or $p -eq "NONE") {
                return
            }

            if (-not $stats.ContainsKey($p)) {
                $stats[$p] = @{
                    success  = 0
                    fail     = 0
                    total_ms = 0
                    count_ms = 0
                }
            }

            if ($e.type -eq "response" -or $e.type -eq "ok" -or $e.type -eq "success") {
                $stats[$p].success++
            } else {
                $stats[$p].fail++
            }

            if ($null -ne $e.latency_ms -and [int]$e.latency_ms -gt 0) {
                $stats[$p].total_ms += [int]$e.latency_ms
                $stats[$p].count_ms += 1
            }
        } catch {
        }
    }

    return $stats
}

function Show-ProviderStats {
    $stats = Get-ProviderStats
    if ($stats.Count -eq 0) {
        Write-Host "  No history." -ForegroundColor DarkGray
        return
    }

    Write-Host ""
    Write-Host "  ALFA latency table" -ForegroundColor Cyan
    foreach ($p in ($stats.Keys | Sort-Object)) {
        $s      = $stats[$p]
        $calls  = $s.success + $s.fail
        $avg_ms = if ($s.count_ms -gt 0) { [int]($s.total_ms / $s.count_ms) } else { 0 }
        Write-Host ("  {0,-15} calls={1,4} avg_ms={2,6}" -f $p, $calls, $avg_ms) -ForegroundColor Yellow
    }
    Write-Host ""
}

# ============================================================
# ADAPTIVE CASCADE (legacy latency-based local reorder)
# ============================================================
function Get-AdaptiveCascade {
    param([string[]]$BaseCascade)

    $stats = Get-ProviderStats
    if ($stats.Count -eq 0) {
        return $BaseCascade
    }

    $localInCascade = @($BaseCascade | Where-Object { $_LOCAL_FALLBACK_IDS -contains $_ })
    if ($localInCascade.Count -lt 2) {
        return $BaseCascade
    }

    $localSorted = $localInCascade | Sort-Object -Property {
        $name = $_ID_TO_NAME[$_]
        if ($name -and $stats.ContainsKey($name) -and $stats[$name].count_ms -gt 0) {
            [int]($stats[$name].total_ms / $stats[$name].count_ms)
        } else {
            999999
        }
    }

    $result = [System.Collections.Generic.List[string]]::new()
    $localIdx = 0

    foreach ($id in $BaseCascade) {
        if ($_LOCAL_FALLBACK_IDS -contains $id) {
            $result.Add($localSorted[$localIdx])
            $localIdx++
        } else {
            $result.Add($id)
        }
    }

    return $result.ToArray()
}

# ============================================================
# INIT
# ============================================================
function Initialize-ALFAMemory {
    if (-not (Test-Path $ALFA_MEMORY_DIR)) {
        New-Item -ItemType Directory -Path $ALFA_MEMORY_DIR | Out-Null
        Write-ALFALog "INFO" "Created ALFA_MEMORY dir: $ALFA_MEMORY_DIR"
    }

    if (-not (Test-Path $SESSION_FILE)) {
        '{}' | Set-Content -Path $SESSION_FILE
        Write-ALFALog "INFO" "Created session.json"
    }

    if (-not (Test-Path $HISTORY_FILE)) {
        '' | Set-Content -Path $HISTORY_FILE
        Write-ALFALog "INFO" "Created history.jsonl"
    }

    if (Get-Command Select-Provider -ErrorAction SilentlyContinue) {
        $scores = Get-ProviderScores
        $script:cascadeSimple  = Select-Provider -QueryType "simple"  -Scores $scores
        $script:cascadeMedium  = Select-Provider -QueryType "medium"  -Scores $scores
        $script:cascadeComplex = Select-Provider -QueryType "complex" -Scores $scores
        Write-ALFALog "INFO" "Cascade (scoring engine): SIMPLE=[$($script:cascadeSimple -join '->')] COMPLEX=[$($script:cascadeComplex -join '->')]"
    } else {
        $script:cascadeSimple  = Get-AdaptiveCascade -BaseCascade $cascadeSimple
        $script:cascadeMedium  = Get-AdaptiveCascade -BaseCascade $cascadeMedium
        $script:cascadeComplex = Get-AdaptiveCascade -BaseCascade $cascadeComplex
        Write-ALFALog "INFO" "Cascade (adaptive latency): SIMPLE=[$($script:cascadeSimple -join '->')] COMPLEX=[$($script:cascadeComplex -join '->')]"
    }
}

# ============================================================
# SESSION
# ============================================================
function Get-ALFASession {
    try {
        return Get-Content -Path $SESSION_FILE -Raw | ConvertFrom-Json
    } catch {
        return @{}
    }
}

function Set-ALFASession {
    param([hashtable]$Data)
    $Data | ConvertTo-Json -Depth 5 | Set-Content -Path $SESSION_FILE
}

# ============================================================
# PROVIDER 1 - Ollama
# ============================================================
$OLLAMA_URL   = "http://localhost:11434"
$OLLAMA_MODEL = "llama3.1:latest"

function Test-OllamaAlive {
    try {
        Invoke-RestMethod -Uri "$OLLAMA_URL/" -Method GET -TimeoutSec 2 -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Invoke-OllamaSmall {
    param([string]$Query)

    $body = @{
        model  = $OLLAMA_MODEL
        prompt = $Query
        stream = $false
    } | ConvertTo-Json

    try {
        $resp = Invoke-RestMethod `
            -Uri "$OLLAMA_URL/api/generate" `
            -Method POST `
            -Body $body `
            -ContentType "application/json" `
            -TimeoutSec 60 `
            -ErrorAction Stop

        return $resp.response
    } catch {
        Write-ALFALog "WARN" "Ollama error: $($_.Exception.Message)"
        return $null
    }
}

# ============================================================
# PROVIDER 3 - Qwen via Ollama
# ============================================================
$QWEN_MODEL = "qwen3.5:latest"

function Invoke-QwenProvider {
    param([string]$Query)

    if (-not (Test-OllamaAlive)) {
        Write-ALFALog "WARN" "Qwen: Ollama offline - skipping"
        return $null
    }

    Write-ALFALog "ROUTER" "Routing to Qwen ($QWEN_MODEL)"

    $body = @{
        model  = $QWEN_MODEL
        prompt = $Query
        stream = $false
    } | ConvertTo-Json

    try {
        $resp = Invoke-RestMethod `
            -Uri "$OLLAMA_URL/api/generate" `
            -Method POST `
            -Body $body `
            -ContentType "application/json" `
            -TimeoutSec 120 `
            -ErrorAction Stop

        return $resp.response
    } catch {
        Write-ALFALog "WARN" "Qwen error: $($_.Exception.Message)"
        return $null
    }
}

# ============================================================
# PROVIDER 10 - LocalCoder via Ollama
# ============================================================
$LOCAL_CODER_MODEL   = "qwen3-coder:30b"
$LOCAL_CODER_TIMEOUT = 180

function Invoke-LocalCoderProvider {
    param([string]$Query)

    if (-not (Test-OllamaAlive)) {
        Write-ALFALog "WARN" "LocalCoder: Ollama offline - skipping"
        return $null
    }

    Write-ALFALog "ROUTER" "Routing to LocalCoder ($LOCAL_CODER_MODEL)"

    $body = @{
        model  = $LOCAL_CODER_MODEL
        prompt = $Query
        stream = $false
    } | ConvertTo-Json

    try {
        $resp = Invoke-RestMethod `
            -Uri "$OLLAMA_URL/api/generate" `
            -Method POST `
            -Body $body `
            -ContentType "application/json" `
            -TimeoutSec $LOCAL_CODER_TIMEOUT `
            -ErrorAction Stop

        return $resp.response
    } catch {
        Write-ALFALog "WARN" "LocalCoder error: $($_.Exception.Message)"
        return $null
    }
}

# ============================================================
# PROVIDER 5 - Claude API
# ============================================================
$CLAUDE_MODEL = "claude-haiku-4-5-20251001"

function Invoke-ClaudeProvider {
    param([string]$Query)

    $apiKey = $env:ANTHROPIC_API_KEY
    if (-not $apiKey) {
        Write-ALFALog "WARN" "Claude: missing ANTHROPIC_API_KEY - skipping"
        return $null
    }

    $body = @{
        model      = $CLAUDE_MODEL
        max_tokens = 1024
        messages   = @(
            @{ role = "user"; content = $Query }
        )
    } | ConvertTo-Json -Depth 5

    try {
        $resp = Invoke-RestMethod `
            -Uri "https://api.anthropic.com/v1/messages" `
            -Method POST `
            -Headers @{
                "x-api-key"         = $apiKey
                "anthropic-version" = "2023-06-01"
                "content-type"      = "application/json"
            } `
            -Body $body `
            -TimeoutSec 30 `
            -ErrorAction Stop

        return $resp.content[0].text
    } catch {
        Write-ALFALog "WARN" "Claude error: $($_.Exception.Message)"
        return $null
    }
}

# ============================================================
# PLACEHOLDER PROVIDERS
# ============================================================
function Invoke-OpenAIProvider {
    param([string]$Query)
    Write-ALFALog "WARN" "OpenAI provider not implemented yet - skipping"
    return $null
}

function Invoke-CopilotProvider {
    param([string]$Query)
    Write-ALFALog "WARN" "Copilot provider not implemented yet - skipping"
    return $null
}

function Invoke-LMStudioProvider {
    param([string]$Query)
    Write-ALFALog "WARN" "LMStudio provider not implemented yet - skipping"
    return $null
}

# ============================================================
# DISPATCHER
# ============================================================
function Invoke-Provider {
    param(
        [string]$ID,
        [string]$Query
    )

    switch ($ID) {
        "10" { return Invoke-LocalCoderProvider -Query $Query }
        "5"  { return Invoke-ClaudeProvider -Query $Query }
        "6"  { return Invoke-OpenAIProvider -Query $Query }
        "8"  { return Invoke-CopilotProvider -Query $Query }
        "1"  { return Invoke-OllamaSmall -Query $Query }
        "3"  { return Invoke-QwenProvider -Query $Query }
        "4"  { return Invoke-LMStudioProvider -Query $Query }
        default {
            Write-ALFALog "WARN" "Provider $ID not implemented - skipping"
            return $null
        }
    }
}

# ============================================================
# ROUTER
# ============================================================
function Invoke-ALFARouter {
    param(
        [string]$Query,
        [string]$Type = "COMPLEX"
    )

    $activeCascade = switch ($Type.ToUpper()) {
        "SIMPLE" { $script:cascadeSimple }
        "MEDIUM" { $script:cascadeMedium }
        default  { $script:cascadeComplex }
    }

    Write-ALFALog "ROUTER" "Type=$Type cascade=[$($activeCascade -join '->')]"

    $result     = $null
    $provider   = "NONE"
    $latency_ms = 0

    foreach ($id in $activeCascade) {
        Write-ALFALog "CASCADE" "Trying provider $id"
        $t0 = Get-Date
        $result = Invoke-Provider -ID $id -Query $Query
        $latency_ms = [int]((Get-Date) - $t0).TotalMilliseconds

        if ($result) {
            $provider = if ($_ID_TO_NAME.ContainsKey($id)) { $_ID_TO_NAME[$id] } else { "Provider:$id" }
            Write-ALFALog "ROUTER" "Provider=$provider latency=${latency_ms}ms"
            break
        }
    }

    if (-not $result) {
        $result = "[NO RESPONSE - all providers offline]"
        $provider = "FALLBACK"
        $latency_ms = 0
    }

    Write-ALFAHistory -Query $Query -Provider $provider -Type $Type -LatencyMs $latency_ms
    return $result
}

# ============================================================
# MAIN
# ============================================================
function Start-ALFARouter {
    Initialize-ALFAMemory
    Write-ALFALog "INFO" "ALFA Router started"

    Write-Host ""
    Write-Host "==================================" -ForegroundColor Cyan
    Write-Host "            ALFA ROUTER           " -ForegroundColor Cyan
    Write-Host "==================================" -ForegroundColor Cyan
    Write-Host "  [10] LocalCoder      (qwen3-coder:30b)" -ForegroundColor Yellow
    Write-Host "  [ 5] Claude          (cloud #1)" -ForegroundColor DarkGray
    Write-Host "  [ 6] OpenAI          (cloud #2)" -ForegroundColor DarkGray
    Write-Host "  [ 8] Copilot/GitHub  (cloud #3)" -ForegroundColor DarkGray
    Write-Host "  [ 1] Ollama          (local llama3.1)" -ForegroundColor Green
    Write-Host "  [ 3] Qwen            (local fallback)" -ForegroundColor Green
    Write-Host "  [ 4] LMStudio        (local fallback)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  /s <query>  SIMPLE" -ForegroundColor DarkGray
    Write-Host "  /m <query>  MEDIUM" -ForegroundColor DarkGray
    Write-Host "     <query>  COMPLEX" -ForegroundColor DarkGray
    Write-Host "  /scoring    scoring matrix" -ForegroundColor DarkGray
    Write-Host "  /stats      latency table" -ForegroundColor DarkGray
    Write-Host "  q           exit" -ForegroundColor DarkGray
    Write-Host "  Memory: $ALFA_MEMORY_DIR" -ForegroundColor DarkGray
    Write-Host ""

    while ($true) {
        $query = Read-Host "ALFA>"

        if ($query -eq "q" -or $query -eq "quit" -or $query -eq "exit") {
            Write-ALFALog "INFO" "ALFA Router stopped by user"
            break
        }

        if ([string]::IsNullOrWhiteSpace($query)) {
            continue
        }

        if ($query -eq "/stats") {
            Show-ProviderStats
            continue
        }

        if ($query -eq "/scoring") {
            if (Get-Command Show-ScoringMatrix -ErrorAction SilentlyContinue) {
                Show-ScoringMatrix
            } else {
                Write-Host "  [scoring] provider_scoring_engine.ps1 not loaded." -ForegroundColor Red
            }
            continue
        }

        $type = "COMPLEX"
        if ($query -match "^/s\s+") {
            $type = "SIMPLE"
            $query = $query -replace "^/s\s+", ""
        } elseif ($query -match "^/m\s+") {
            $type = "MEDIUM"
            $query = $query -replace "^/m\s+", ""
        }

        $result = Invoke-ALFARouter -Query $query -Type $type
        Write-Host ""
        Write-Host $result -ForegroundColor Green
        Write-Host ""
    }
}

Start-ALFARouter
