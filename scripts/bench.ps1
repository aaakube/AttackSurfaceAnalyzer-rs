# Speed comparison: Microsoft Attack Surface Analyzer 2.3.321 vs asa (see docs/comparison.md).
#   bench.ps1 -Scenario files   both tools on C:\Windows only (file collector)
#   bench.ps1 -Scenario full    comparable collectors on the whole system
# Each tool takes two snapshots with the same change in between, then compares them.
# Expects C:\bench\ASA_win_2.3.321, C:\bench\dotnet (.NET 9 + ASP.NET Core 9) and C:\asa\asa.exe.
# Results (wall time, peak memory, database size) go to C:\bench\results-<scenario>.json.
param([Parameter(Mandatory)] [ValidateSet('files', 'full')] [string] $Scenario)

$bench = 'C:\bench'
$out = "$bench\out-$Scenario"
$env:DOTNET_ROOT = "$bench\dotnet"
$dotnet = "$bench\dotnet\dotnet.exe"
$orig = "$bench\ASA_win_2.3.321\Asa.dll"
$asa = 'C:\asa\asa.exe'
$change = 'C:\Windows\AsaBenchChange'
Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $out | Out-Null
Remove-Item $change -Recurse -Force -ErrorAction SilentlyContinue
$results = New-Object System.Collections.ArrayList

# Runs one step; records wall time, peak working set and exit code.
function Step([string] $tool, [string] $what, [string] $exe, [string] $arguments) {
    Write-Host ("{0,-8} {1,-26} ..." -f $tool, $what) -NoNewline -ForegroundColor Cyan
    $label = "$tool-$what" -replace '[^A-Za-z0-9-]', '_'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = Start-Process -FilePath $exe -ArgumentList $arguments -PassThru -NoNewWindow `
        -RedirectStandardOutput "$out\$label.out" -RedirectStandardError "$out\$label.err"
    $null = $p.Handle   # keeps the exit code readable after exit
    $peak = 0
    while (-not $p.HasExited) {
        try { $p.Refresh(); if ($p.PeakWorkingSet64 -gt $peak) { $peak = $p.PeakWorkingSet64 } } catch {}
        Start-Sleep -Milliseconds 200
    }
    $sw.Stop()
    $r = [pscustomobject]@{ tool = $tool; step = $what; seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        peak_mb = [math]::Round($peak / 1MB); exit = $p.ExitCode }
    [void]$results.Add($r)
    Write-Host (" {0,8:N1} s  {1,6} MB peak  exit {2}" -f $r.seconds, $r.peak_mb, $r.exit) -ForegroundColor $(if ($r.exit) { 'Red' } else { 'Green' })
}

function Make-Change([int] $round) {
    Write-Host "--- change between snapshots: 2,000 new files, 200 modified" -ForegroundColor Yellow
    New-Item -ItemType Directory -Force $change | Out-Null
    if ($round -eq 1) {
        1..2000 | ForEach-Object { [IO.File]::WriteAllText("$change\f$_.txt", "asa bench $_") }
    } else {
        1..200 | ForEach-Object { [IO.File]::WriteAllText("$change\f$_.txt", "changed $_") }
    }
}

if ($Scenario -eq 'files') {
    $origCollect = '-f --directories C:\Windows'
    $asaCollect = '--collectors files --path C:\Windows'
} else {
    # Comparable collectors only: the original's event-log and process collectors
    # have no asa equivalent, and asa's tasks/defender/rights/security/wmi none there.
    $origCollect = '-c -C -d -F -f -k -p -r -s -t -u -w'
    $asaCollect = '--collectors files,services,firewall,com,registry,users,certificates,ports,wifi,tpm,keys'
}
$odb = "$out\orig.sqlite"; $adb = "$out\asa.db"

Write-Host "=== scenario: $Scenario (4 CPUs; both programs excluded from Defender scanning; warming the file cache first)" -ForegroundColor Yellow
cmd /c "dir /s /a C:\Windows > NUL 2>&1"
Make-Change 1
Step 'asa' 'snapshot 1' $asa "--db $adb collect --run-id r1 $asaCollect"
Step 'original' 'snapshot 1' $dotnet "$orig collect $origCollect --runid r1 --databasefilename $odb"
Make-Change 2
# Second round in the other order, so neither tool always goes first.
Step 'original' 'snapshot 2' $dotnet "$orig collect $origCollect --runid r2 --databasefilename $odb"
Step 'asa' 'snapshot 2' $asa "--db $adb collect --run-id r2 $asaCollect"
Step 'asa' 'compare (rules applied)' $asa "--db $adb diff r1 r2 --format jsonl --min-severity debug -o $out\asa-diff.jsonl"
Step 'original' 'compare (rules applied)' $dotnet "$orig export-collect --firstrunid r1 --secondrunid r2 --databasefilename $odb --outputpath $out"

$size = { param($pattern) [math]::Round(((Get-ChildItem $pattern -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum) / 1MB, 1) }
[void]$results.Add([pscustomobject]@{ tool = 'asa'; step = 'database size'; mb = (& $size "$out\asa.db*") })
[void]$results.Add([pscustomobject]@{ tool = 'original'; step = 'database size'; mb = (& $size "$out\orig.sqlite*") })
$asaObjects = (cmd /c "$asa --db $adb runs list --json" | ConvertFrom-Json) | ForEach-Object { $_.objects }
[void]$results.Add([pscustomobject]@{ tool = 'asa'; step = 'objects per snapshot'; count = ($asaObjects -join ', ') })
[void]$results.Add([pscustomobject]@{ tool = 'asa'; step = 'changes found'; count = @(Get-Content "$out\asa-diff.jsonl" | Where-Object { $_ -like '{"kind*' -or $_ -like '{"identity*' }).Count })
$results | ConvertTo-Json | Set-Content -Encoding UTF8 "$bench\results-$Scenario.json"
Remove-Item $change -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "=== done; results in $bench\results-$Scenario.json" -ForegroundColor Yellow
