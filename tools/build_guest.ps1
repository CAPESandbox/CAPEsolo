<#
.SYNOPSIS
    Build a CAPEsolo analysis guest from start to finish on a Hyper-V host: run new_guest_vm.ps1,
    then the post-build checks from docs\guest_install.md section 10, and register the MCP server.

.DESCRIPTION
    Runs on the Hyper-V host. It:
      1. runs new_guest_vm.ps1 (ISO -> VM -> firstboot chain -> 'clean' checkpoint);
      2. audits the guest with C:\setup\setup_quiet_guest.ps1 -AuditOnly over PowerShell Direct;
      3. reboots twice (gracefully, each confirmed by a newer LastBootUpTime plus a running
         explorer) and re-audits; on [!!] it applies the quiet script once, reboots twice and
         re-audits, and stops if gaps remain (Tamper Protection / -DefenderSafeMode need a person);
      4. re-takes 'clean' only if step 3 applied anything;
      5. reverts, jumps the guest clock +25 h, waits, and checks wuauserv is still Disabled with no
         System 7040 event (a revert runs overdue tasks that can re-arm Windows Update);
      6. from a fresh revert, runs a pktmon idle capture and copies the pcap/txt to -OutDir;
      7. registers the guest's MCP endpoint with 'claude mcp add' on the host (an existing entry
         of that name is left alone). CAPEsolo-mcp is NOT started in the guest;
      8. reverts to 'clean' so the capture and clock jumps leave nothing behind.
    Any failure throws and leaves the VM as it is for inspection.

.PARAMETER RevertCheckMinutes  Minutes to wait after the revert + clock jump before checking wuauserv. Default 10.
.PARAMETER IdleMinutes         Length of the pktmon idle capture. Default 15; 0 skips it.
.PARAMETER McpName             Name to register the MCP server under on the host. Default 'capesolo'.
.PARAMETER OutDir              Where the idle capture is copied. Default %TEMP%\capesolo_<Name>_build.
    All other parameters are passed to new_guest_vm.ps1 unchanged; see its help.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\build_guest.ps1 -IsoPath D:\Win11_23H2.iso -Name CAPEsolo-guest -Password 'P@ss'

.NOTES
    Self-elevates like new_guest_vm.ps1 (-Password is forwarded on the command line; run on a
    trusted host). Windows PowerShell 5.1, pure ASCII.
#>
[CmdletBinding()]
param(
    # --- Forwarded to new_guest_vm.ps1; keep in sync with its param block. ---
    [string] $Name = 'CAPEsolo-guest',
    [string] $IsoPath,
    [string] $Switch = 'Default Switch',
    [int]    $MemoryGB = 8,
    [int]    $Cpu = 4,
    [int]    $DiskGB = 80,
    [string] $User = 'analyst',
    [string] $Password = '',
    [ValidateLength(1, 15)] [string] $ComputerName = 'CAPESOLO',
    [string] $ProductKey = 'XGVPP-NMH47-7TTHJ-W3FW7-8HV2C',
    [switch] $NoProductKey,
    [string] $ImageName,
    [int]    $ImageIndex = 0,
    [switch] $IncludeNode,
    [string] $WheelPath,
    [ValidateSet('Standard', 'Production')] [string] $CheckpointType = 'Standard',
    [string] $VhdPath,
    [string] $ConfigIsoPath,
    [int]    $InstallTimeoutMin = 120,
    [switch] $Force,
    # --- This script's own. ---
    [int]    $RevertCheckMinutes = 10,
    [int]    $IdleMinutes = 15,
    [string] $McpName = 'capesolo',
    [string] $OutDir
)

$ErrorActionPreference = 'Stop'

function Write-Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "    [ok] $m" -ForegroundColor Green }
function Write-Note($m) { Write-Host "    [!!] $m" -ForegroundColor Yellow }

if (-not $Password) { throw 'Supply -Password for the guest local administrator account.' }
if (-not $OutDir) { $OutDir = Join-Path $env:TEMP "capesolo_$($Name)_build" }

# --- Self-elevate (same as new_guest_vm.ps1). ---
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
    Write-Note 'Not elevated - relaunching as Administrator...'
    $a = @('-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [System.Management.Automation.SwitchParameter]) {
            if ($kv.Value.IsPresent) { $a += "-$($kv.Key)" }
        } elseif ($kv.Value -is [bool]) {
            if ($kv.Value) { $a += "-$($kv.Key)" }
        } else {
            $a += @("-$($kv.Key)", "`"$($kv.Value)`"")
        }
    }
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $a
    return
}

$cred = New-Object System.Management.Automation.PSCredential(
    $User, (ConvertTo-SecureString $Password -AsPlainText -Force))
$summary = [ordered]@{}

function Invoke-Guest([scriptblock] $Block, [object[]] $Arguments = @()) {
    Invoke-Command -VMName $Name -Credential $cred -ErrorAction Stop -ScriptBlock $Block -ArgumentList $Arguments
}

function Invoke-Quiet([string[]] $Extra) {
    # Run the staged quiet script in the guest; echo its output and return its exit code.
    $r = Invoke-Guest -Arguments (, $Extra) -Block {
        param($x)
        $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\setup\setup_quiet_guest.ps1' @x 2>&1
        [pscustomobject]@{ Out = $out; Code = $LASTEXITCODE }
    }
    $r.Out | ForEach-Object { Write-Host "      $_" }
    return $r.Code
}

function Wait-Desktop($After) {
    # Wait for a running explorer and, after a reboot, a LastBootUpTime newer than $After (the
    # heartbeat can report OK before the guest has gone down).
    $deadline = (Get-Date).AddMinutes(10)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 10
        try {
            $s = Invoke-Guest {
                [pscustomobject]@{
                    Boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
                    Desk = [bool](Get-Process explorer -ErrorAction SilentlyContinue)
                }
            }
            if ($s.Desk -and (-not $After -or $s.Boot -gt $After)) { return }
        } catch { }   # mid-reboot, or the account is not ready yet.
    }
    throw 'the guest did not reach the desktop within 10 min. Check AutoLogon at the VM console (Basic session).'
}

function Restart-Guest {
    $before = Invoke-Guest { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime }
    Restart-VM -Name $Name -Type Reboot -Force   # graceful: a hard Reset re-enabled ScheduledDefrag.
    Wait-Desktop $before
    Write-Ok 'rebooted, desktop up'
}

function Restore-Clean {
    Restore-VMSnapshot -VMName $Name -Name 'clean' -Confirm:$false
    if ((Get-VM -Name $Name).State -ne 'Running') { Start-VM -Name $Name }   # Production checkpoints restore off.
    Wait-Desktop $null
}

function Jump-GuestClock {
    # Mimic reverting the next day; returns the guest time before the jump.
    Invoke-Guest { $t = Get-Date; Set-Date -Adjust (New-TimeSpan -Hours 25) | Out-Null; $t }
}

# 1. Build.
$build = @{ Name = $Name; User = $User; Password = $Password; ComputerName = $ComputerName }
foreach ($k in $PSBoundParameters.Keys) {
    if ($k -notin 'RevertCheckMinutes', 'IdleMinutes', 'McpName', 'OutDir') { $build[$k] = $PSBoundParameters[$k] }
}
& (Join-Path $PSScriptRoot 'new_guest_vm.ps1') @build
$summary['build'] = (Invoke-Guest { Get-Content 'C:\setup\done.txt' }) -join '; '

# 2. Audit as built.
Write-Step 'Audit (as built)'
$rc = Invoke-Quiet @('-AuditOnly')
$state = Invoke-Guest {
    $ed = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
    try { $mp = Get-MpComputerStatus -ErrorAction Stop; $d = "RealTime=$($mp.RealTimeProtectionEnabled) Tamper=$($mp.IsTamperProtected)" }
    catch { $d = 'Defender service off' }
    "edition=$ed; $d"
}
Write-Ok $state
$summary['audit (as built)'] = "exit=$rc; $state"

# 3. Reboot twice, re-audit; apply once on gaps.
Write-Step 'Rebooting twice, then re-auditing'
Restart-Guest; Restart-Guest
$rc = Invoke-Quiet @('-AuditOnly')
$applied = $false
if ($rc -ne 0) {
    Write-Note "audit exit $rc - applying setup_quiet_guest.ps1 once"
    Invoke-Quiet @() | Out-Null
    $applied = $true
    Restart-Guest; Restart-Guest
    $rc = Invoke-Quiet @('-AuditOnly')
    if ($rc -ne 0) {
        throw "audit still reports [!!] after an apply and two reboots. If they are Defender keys, turn off Tamper Protection or use setup_quiet_guest.ps1 -DefenderSafeMode (console logon) - docs\guest_install.md section 5. The 'clean' checkpoint is the original build."
    }
}
Write-Ok 'audit clean (warnings allowed)'
$summary['audit (after reboots)'] = "exit=$rc; applied=$applied"

# 4. Re-take 'clean' only if the guest changed.
if ($applied) {
    Write-Step "Re-taking the 'clean' checkpoint"
    # New one first, so a failed checkpoint never leaves the VM without a 'clean'.
    Checkpoint-VM -Name $Name -SnapshotName 'clean-new'
    Remove-VMSnapshot -VMName $Name -Name 'clean' -Confirm:$false
    Get-VMSnapshot -VMName $Name -Name 'clean-new' | Rename-VMSnapshot -NewName 'clean'
    Write-Ok "checkpoint 'clean' replaced"
}

# 5. Revert-time check: overdue tasks must not re-arm Windows Update.
Write-Step "Revert-time check (+25 h clock jump, $RevertCheckMinutes min wait)"
Restore-Clean
$t0 = Jump-GuestClock
Start-Sleep -Seconds ($RevertCheckMinutes * 60)
$wu = Invoke-Guest -Arguments $t0 -Block {
    param($since)
    $mode = (Get-CimInstance Win32_Service -Filter "Name='wuauserv'").StartMode
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7040; StartTime = $since } -ErrorAction SilentlyContinue |
            Where-Object { $_.Properties[3].Value -eq 'wuauserv' })   # param4 = service key name
    [pscustomobject]@{ Mode = $mode; Events = $ev.Count }
}
if ($wu.Mode -ne 'Disabled' -or $wu.Events -gt 0) {
    throw "wuauserv StartMode=$($wu.Mode), $($wu.Events) System 7040 event(s) after the revert. See docs\guest_install.md section 11 (Windows Update downloads right after a revert). The VM is left in this state for diagnosis."
}
Write-Ok 'wuauserv still Disabled, no 7040 event'
$summary['revert check'] = "wuauserv=$($wu.Mode); 7040 events=0"

# 6. Idle capture.
if ($IdleMinutes -gt 0) {
    Write-Step "Idle capture ($IdleMinutes min, fresh revert, +25 h)"
    Restore-Clean
    Jump-GuestClock | Out-Null
    Invoke-Guest { pktmon start --capture --pkt-size 0 -f C:\idle.etl | Out-Null }
    Start-Sleep -Seconds ($IdleMinutes * 60)
    $dns = Invoke-Guest {
        pktmon stop | Out-Null
        pktmon etl2pcap C:\idle.etl -o C:\idle.pcap | Out-Null
        pktmon etl2txt C:\idle.etl -o C:\idle.txt | Out-Null
        Get-DnsClientCache | Select-Object Entry, Data
    }
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    $s = New-PSSession -VMName $Name -Credential $cred
    try { Copy-Item -Path 'C:\idle.pcap', 'C:\idle.txt' -Destination $OutDir -FromSession $s }
    finally { Remove-PSSession $s }
    Write-Ok "capture copied to $OutDir (idle.pcap, idle.txt)"
    Write-Host '      guest DNS cache:'
    $dns | Format-Table Entry, Data -AutoSize | Out-String | ForEach-Object { Write-Host $_ }
    $summary['idle capture'] = "$OutDir; $(@($dns).Count) DNS cache entries"
}

# 7. Register the MCP endpoint on the host (the server itself is not started).
Write-Step "Registering the MCP server as '$McpName'"
$url = "http://$($ComputerName).mshome.net:8000/mcp"
if ($Switch -ne 'Default Switch') { Write-Note "<name>.mshome.net only resolves on the Default Switch; on '$Switch' re-register with the guest IP." }
if (Get-Command claude -ErrorAction SilentlyContinue) {
    # PS 5.1 turns a native exe's redirected stderr into errors; under 'Stop' a missing entry would throw.
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & claude mcp get $McpName *> $null; $found = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = $eap
    if ($found) {
        Write-Note "an MCP entry named '$McpName' already exists - left as is."
    } else {
        & claude mcp add -s user --transport http $McpName $url
        if ($LASTEXITCODE -ne 0) { throw "claude mcp add failed (exit $LASTEXITCODE)." }
        Write-Ok "registered $McpName -> $url"
    }
} else {
    Write-Note "claude not on PATH - register it yourself: claude mcp add -s user --transport http $McpName $url"
}
Write-Host '      In the guest, start the server with: CAPEsolo-mcp --transport streamable-http --host 0.0.0.0' -ForegroundColor DarkGray
Write-Host '      (binding 0.0.0.0 needs [mcp_server] allowed_hosts in cfg.ini; see mcp_server.md)' -ForegroundColor DarkGray
$summary['mcp'] = $url

# 8. Leave the guest at 'clean'.
Write-Step "Reverting to 'clean'"
Restore-Clean
Write-Ok 'reverted'

Write-Host ''
Write-Host "Done. '$Name' is built, verified and reverted to 'clean'." -ForegroundColor Cyan
foreach ($k in $summary.Keys) { Write-Host ("  {0,-22} {1}" -f $k, $summary[$k]) }
