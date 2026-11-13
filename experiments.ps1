# experiments.ps1 - runs the FROST / CGGMP network experiments on two machines.
#
# Run the SAME command on both machines, changing only -Machine (A or B):
#   Machine A:  .\experiments.ps1 -Machine A -IpA 192.168.1.10 -IpB 192.168.1.20 -Label wifi
#   Machine B:  .\experiments.ps1 -Machine B -IpA 192.168.1.10 -IpB 192.168.1.20 -Label wifi
#
# Machine A hosts the coordinator (node 0) and writes the results.
# Placement of the nodes (signers are always on both machines):
#   (2,3): A = nodes 0,2   B = node 1          signers 0,1
#   (3,5): A = nodes 0,2,4 B = nodes 1,3       signers 0,1,2
#
# -Set frostpre runs only FROST with preprocessed commitments (RFC 9591 allows
# round 1 to be done in advance), in the (2,3) and (3,5) configurations.
#
# Optional: -DelayMs 25 adds an emulated one-way delay to every message
# (used to emulate a wide-area network on top of the local network).
param(
    [Parameter(Mandatory = $true)][ValidateSet("A", "B")][string]$Machine,
    [Parameter(Mandatory = $true)][string]$IpA,
    [Parameter(Mandatory = $true)][string]$IpB,
    [string]$Label = "lan",
    [double]$DelayMs = 0,
    [int]$FrostCount = 200,
    [int]$CggmpCount = 20,
    # all = FROST and CGGMP; frostpre = FROST with preprocessed commitments only
    [ValidateSet("all", "frostpre")][string]$Set = "all"
)

$ErrorActionPreference = "Stop"
$exe = Join-Path $PSScriptRoot "target\release\net-bench.exe"
if (-not (Test-Path $exe)) { throw "Build first: cargo build --release" }
New-Item -ItemType Directory -Force -Path (Join-Path $PSScriptRoot "logs") | Out-Null

# experiment list: protocol, t, n  (same order on both machines)
if ($Set -eq "frostpre") {
    $experiments = @( @("frost-pre", 2, 3), @("frost-pre", 3, 5) )
} else {
    $experiments = @(
        @("frost", 2, 3), @("cggmp", 2, 3),
        @("frost", 3, 5), @("cggmp", 3, 5)
    )
}
$placement = @{
    3 = @{ A = @(0, 2);    B = @(1) }
    5 = @{ A = @(0, 2, 4); B = @(1, 3) }
}

$k = 0
foreach ($e in $experiments) {
    $proto = $e[0]; $t = $e[1]; $n = $e[2]
    $base = 7100 + 10 * $k   # a fresh port range for every experiment
    $k++
    # config file
    $cfg = Join-Path $PSScriptRoot "nodes_${Label}_${proto}_t${t}_n${n}.txt"
    $lines = @()
    for ($i = 0; $i -lt $n; $i++) {
        $ip = if ($placement[$n].A -contains $i) { $IpA } else { $IpB }
        $lines += "$i ${ip}:$($base + $i)"
    }
    Set-Content -Path $cfg -Value $lines

    Write-Host ""
    Write-Host "=== experiment $k : $proto ($t,$n) on '$Label' (machine $Machine) ===" -ForegroundColor Cyan
    $mine = $placement[$n][$Machine]
    $count = if ($proto -like "frost*") { $FrostCount } else { $CggmpCount }
    $bg = @()
    foreach ($id in $mine) {
        if ($id -eq 0) { continue }
        $log = Join-Path $PSScriptRoot "logs\${Label}_${proto}_t${t}_n${n}_node$id.log"
        $bg += Start-Process -FilePath $exe -PassThru -NoNewWindow -RedirectStandardOutput $log `
            -WorkingDirectory $PSScriptRoot `
            -ArgumentList "--id $id --config `"$cfg`" --proto $proto --t $t --delay-ms $DelayMs"
    }
    if ($mine -contains 0) {
        & $exe --id 0 --config $cfg --proto $proto --t $t --count $count --label $Label --delay-ms $DelayMs
        if ($LASTEXITCODE -ne 0) { throw "coordinator failed" }
    }
    foreach ($p in $bg) { $p.WaitForExit() }
    Write-Host "experiment $k finished"
}
Write-Host ""
Write-Host "All experiments finished." -ForegroundColor Green
if ($Machine -eq "A") { Write-Host "Results: $(Join-Path $PSScriptRoot 'results\summary.csv')" }
