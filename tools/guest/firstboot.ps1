<#
.SYNOPSIS
    First-logon setup chain for a from-scratch CAPEsolo analysis guest. Launched once by the
    autounattend FirstLogonCommands; runs the setup scripts in order and writes C:\setup\done.txt.

.DESCRIPTION
    autounattend.xml stages \setup from the config DVD and runs this wrapper. A single wrapper
    (rather than several FirstLogonCommands) exists because FirstLogonCommands start at the same
    time and do not refresh PATH between them, so a bare 'pip' would miss the just-installed Python
    and nothing would write the done marker. This script instead:
      1. copies its own folder to C:\setup, so the transcript and done marker live on a fixed disk;
      2. runs, in order and each as its own elevated process so one step's exit cannot abort the
         chain: setup_runtime_guest.ps1; setup_nodejs_guest.ps1 (only if node.enabled is staged);
         pip install CAPEsolo (a local CAPEsolo*.whl on the DVD wins over PyPI) plus a Public
         Desktop shortcut to it; and
         setup_quiet_guest.ps1 LAST, because it disables the Store/Delivery Optimization/etc. that
         the earlier downloads rely on;
      3. deletes the answer-file copies Setup caches under C:\Windows\Panther (they hold the
         plaintext password);
      4. writes C:\setup\done.txt with a per-step status and overall=OK|ISSUES, which
         new_guest_vm.ps1 polls for (it checkpoints only on overall=OK).
    PATH is refreshed from the registry after the runtime step so pip resolves the new Python.

.PARAMETER WheelPath
    Explicit CAPEsolo wheel to install instead of PyPI. When omitted, a CAPEsolo*.whl staged in
    C:\setup is used if present, else 'pip install CAPEsolo'.

.NOTES
    Runs elevated: FirstLogonCommands run with the administrator token while UAC is still on (the
    quiet script's EnableLUA=0 only takes effect on the next reboot). Windows PowerShell 5.1
    compatible, pure ASCII.
#>
[CmdletBinding()]
param([string] $WheelPath)

$ErrorActionPreference = 'Stop'

function Write-Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "    [ok] $m" -ForegroundColor Green }
function Write-Note($m) { Write-Host "    [!!] $m" -ForegroundColor Yellow }

$Dest = 'C:\setup'
$src  = $PSScriptRoot

# --- Stage to a fixed disk so the transcript and done marker survive, then work from C:\setup. ---
if ($src -and ($src -ne $Dest)) {
    New-Item -ItemType Directory -Path $Dest -Force | Out-Null
    Copy-Item -Path (Join-Path $src '*') -Destination $Dest -Recurse -Force
}

Start-Transcript -Path (Join-Path $Dest 'firstboot.log') -Append | Out-Null
$status = [ordered]@{}

function Update-Path {
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                [Environment]::GetEnvironmentVariable('Path', 'User')
}
function Invoke-GuestScript($Name, [string[]] $Extra) {
    # Run a staged setup script as its own elevated process and return its exit code (or $null if
    # it was not staged). A separate process keeps a child 'exit' from aborting this chain.
    $path = Join-Path $Dest $Name
    if (-not (Test-Path $path)) { return $null }
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$path`"") + $Extra
    # Keep its output: the chain's own transcript only records the exit code.
    $log = Join-Path $Dest ([IO.Path]::ChangeExtension($Name, '.log'))
    $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $a -Wait -PassThru -RedirectStandardOutput $log
    return $p.ExitCode
}

# 1. Runtime (Python / 7-Zip / VC++).
Write-Step 'Runtime baseline (setup_runtime_guest.ps1)'
$rc = Invoke-GuestScript 'setup_runtime_guest.ps1' @()
$status['runtime'] = if ($null -eq $rc) { 'MISSING' } elseif ($rc -eq 0) { 'OK' } else { "EXIT=$rc" }
Update-Path

# 2. Node.js (optional - only when new_guest_vm.ps1 staged the flag).
if (Test-Path (Join-Path $Dest 'node.enabled')) {
    Write-Step 'Node.js instrumentation (setup_nodejs_guest.ps1)'
    $nc = Invoke-GuestScript 'setup_nodejs_guest.ps1' @()
    $status['node'] = if ($null -eq $nc) { 'MISSING' } elseif ($nc -eq 0) { 'OK' } else { "EXIT=$nc" }
    Update-Path
} else {
    $status['node'] = 'SKIPPED'
}

# 3. CAPEsolo (a local wheel on the DVD wins over PyPI).
Write-Step 'Installing CAPEsolo'
$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) {
    Write-Note 'python not on PATH after the runtime step - cannot pip install CAPEsolo.'
    $status['capesolo'] = 'NO-PYTHON'
} else {
    if (-not $WheelPath) {
        $wheel = Get-ChildItem -Path $Dest -Filter 'CAPEsolo*.whl' -ErrorAction SilentlyContinue |
                 Select-Object -First 1
        if ($wheel) { $WheelPath = $wheel.FullName }
    }
    $target = if ($WheelPath) { $WheelPath } else { 'CAPEsolo' }
    & $py -m pip install --upgrade pip
    & $py -m pip install $target
    $status['capesolo'] = if ($LASTEXITCODE -eq 0) { "OK ($target)" } else { "PIP-EXIT=$LASTEXITCODE" }
    if ($LASTEXITCODE -eq 0) {
        # Desktop shortcut, as README's Quick Start describes: Scripts\CAPEsolo.exe, run as admin, package icon.
        $pyDir = Split-Path $py
        $lnk = 'C:\Users\Public\Desktop\CAPEsolo.lnk'
        $sc = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
        $sc.TargetPath = Join-Path $pyDir 'Scripts\CAPEsolo.exe'
        $sc.IconLocation = Join-Path $pyDir 'Lib\site-packages\CAPEsolo\capesolo.ico'
        $sc.Save()
        $b = [IO.File]::ReadAllBytes($lnk); $b[0x15] = $b[0x15] -bor 0x20; [IO.File]::WriteAllBytes($lnk, $b)  # Run as administrator
        $status['shortcut'] = if (Test-Path $lnk) { 'OK' } else { 'FAILED' }
    }
}

# 4. Quiet LAST.
Write-Step 'Hardening and quieting (setup_quiet_guest.ps1)'
$qc = Invoke-GuestScript 'setup_quiet_guest.ps1' @()
$retried = $false
if ($qc -and $qc -ne 0) {
    # A first-boot race (e.g. Edge's own updater re-arming its tasks mid-run) can leave a transient
    # [!!]; re-run once. Keep the first run's log beside the retry's.
    Write-Host "    quiet exited $qc - re-running once in 30 s" -ForegroundColor Yellow
    Move-Item (Join-Path $Dest 'setup_quiet_guest.log') (Join-Path $Dest 'setup_quiet_guest.first.log') -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 30
    $qc = Invoke-GuestScript 'setup_quiet_guest.ps1' @()
    $retried = $true
}
$status['quiet'] = if ($null -eq $qc) { 'MISSING' } elseif ($qc -eq 0) { if ($retried) { 'OK (retry)' } else { 'OK' } } else { "GAPS/EXIT=$qc" }

# 5. Setup caches the answer file, plaintext password included; remove the cached copies.
Write-Step 'Removing cached unattend.xml copies'
foreach ($f in 'C:\Windows\Panther\unattend.xml', 'C:\Windows\Panther\Unattend\unattend.xml') {
    Remove-Item -Path $f -Force -ErrorAction SilentlyContinue
}
$status['panther'] = if ((Test-Path 'C:\Windows\Panther\unattend.xml') -or
                         (Test-Path 'C:\Windows\Panther\Unattend\unattend.xml')) { 'MISSING-CLEANUP' } else { 'CLEANED' }

# --- done.txt LAST, so new_guest_vm.ps1's poll only succeeds once the chain has finished. ---
$overall = if (@($status.Values) -match 'EXIT|MISSING|NO-PYTHON') { 'ISSUES' } else { 'OK' }
$lines = @("timestamp=$(Get-Date -Format s)", "overall=$overall")
foreach ($k in $status.Keys) { $lines += "$k=$($status[$k])" }
Set-Content -Path (Join-Path $Dest 'done.txt') -Value $lines -Encoding ASCII

Write-Step "First-boot chain complete: $overall"
$status.GetEnumerator() | ForEach-Object { Write-Host ("    {0,-10} {1}" -f $_.Key, $_.Value) }
Write-Host 'Reboot twice, then run setup_quiet_guest.ps1 -AuditOnly to confirm, and snapshot.' -ForegroundColor Cyan
Stop-Transcript | Out-Null
