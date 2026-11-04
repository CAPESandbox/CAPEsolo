<#
.SYNOPSIS
    Harden and quiet a Windows 10/11 CAPEsolo analysis guest: turn off Defender, SmartScreen,
    Smart App Control, Windows Update, Edge update/hardening, and the background services and
    scheduled tasks that generate idle network traffic, so a detonation's PCAP and behavior log
    show the sample's activity and nothing else.

.DESCRIPTION
    The script is table-driven: every setting is one item with a kind (Reg/Svc/Task/Custom) and the
    data needed to test (is it already in the desired state?) and apply it. One driver tests, applies
    and re-tests each item, so -AuditOnly, apply and verify share the same logic. An item whose
    service, key or task is absent on this edition reports [n/a] rather than failing, and
    Windows 11-only items report [n/a] on Windows 10.

    Areas, each with a -Skip switch:
      * Defender     - real-time/behavior/IOAV/script policies, MAPS off, service Start=4, tasks off.
      * Updates      - NoAutoUpdate, Delivery Optimization off, Store auto-download off, services and
                       UpdateOrchestrator/WindowsUpdate/WaaSMedic tasks off, release pinned.
      * Edge         - EdgeUpdate services/tasks off and its folder renamed (Edge ignores its update
                       policies off-domain), Enhanced Security off, new-tab MSN content off,
                       background activity off; typo protection and network prediction off as
                       user-changeable defaults. Edge SmartScreen stays on (domain-only policy).
      * Noise        - telemetry, error reporting, search/Cortana/Widgets/Copilot/Recall, consumer
                       features, background Store apps and silent installs, lock-screen Spotlight,
                       OneDrive, time sync, mid-analysis maintenance tasks, LLMNR/NetBIOS/SSDP/Teredo.
    SmartScreen/MOTW, Smart App Control, VBS/HVCI, BitLocker, analysis conveniences (UAC, sleep,
    System Restore, Explorer, black desktop) and the firewall rule for CAPEsolo-mcp run
    unconditionally.

    [warn] lines never fail the run: they are protected update tasks still enabled after a retry as
    SYSTEM, or user-changeable preferences (background, lock screen) changed since apply.

    Run once on a clean VM, verify, then snapshot the state the sandbox reverts to.

.PARAMETER AuditOnly
    Print [ok]/[!!]/[n/a] per item and change nothing. Exits 1 if any item is [!!], so a caller
    can use the exit code as the pass/fail signal.

.PARAMETER SkipDefender
    Leave Microsoft Defender untouched.

.PARAMETER SkipUpdates
    Leave Windows Update / Delivery Optimization / Store updates untouched.

.PARAMETER SkipEdge
    Leave Microsoft Edge and EdgeUpdate untouched.

.PARAMETER SkipNoise
    Leave the background-network-noise items untouched.

.PARAMETER DefenderSafeMode
    Write the protected Defender service keys from Safe Mode. Defender guards WinDefend/WdFilter/
    Sense while it runs, so a plain admin write can be denied; this reboots into minimal Safe Mode
    via a RunOnce re-entry, writes Start=4, clears the safeboot flag and reboots. Someone must log
    on at the guest console in Safe Mode - PowerShell Direct and the heartbeat are not available
    there. This branch applies ONLY the Defender service keys; re-run without the switch afterwards
    to apply Updates/Edge/Noise.

.PARAMETER DisableFirewall
    Turn the Windows Firewall off on all profiles (CAPEv2's guest guide recommends this). Off by
    default; the firewall is left on with only the CAPEsolo-mcp inbound rule.

.PARAMETER DisableNcsi
    Set NoActiveProbe=1. Off by default: NCSI's connectivity probe is a tradeoff against samples
    that check for Internet before running.

.PARAMETER DisableRootAutoUpdate
    Set DisableRootAutoUpdate=1. Off by default: Authenticode checks on samples depend on the
    root certificate store being current.

.PARAMETER Force
    Run even though this machine's model is not 'Virtual Machine'. The guard exists to protect a
    physical Windows host (e.g. the Hyper-V host itself).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\setup_quiet_guest.ps1 -AuditOnly

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\setup_quiet_guest.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\setup_quiet_guest.ps1 -DefenderSafeMode

.NOTES
    Self-elevates (admin is needed for the policy keys, service Start values and scheduled tasks).
    Refuses to run on a non-VM unless -Force. Windows PowerShell 5.1 compatible.
#>
[CmdletBinding()]
param(
    [switch] $AuditOnly,
    [switch] $SkipDefender,
    [switch] $SkipUpdates,
    [switch] $SkipEdge,
    [switch] $SkipNoise,
    [switch] $DefenderSafeMode,
    [switch] $DisableFirewall,
    [switch] $DisableNcsi,
    [switch] $DisableRootAutoUpdate,
    [switch] $Force,
    [switch] $ServicesOnly   # internal: Safe Mode RunOnce re-entry; not for direct use.
)

$ErrorActionPreference = 'Stop'

function Write-Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "    [ok] $m" -ForegroundColor Green }
function Write-Note($m) { Write-Host "    [!!] $m" -ForegroundColor Yellow }
function Write-Na($m)   { Write-Host "    [n/a] $m" -ForegroundColor DarkGray }
function Write-Warn($m) { Write-Host "    [warn] $m" -ForegroundColor Yellow }

# --- VM guard: refuse on a physical host (protects the Hyper-V host). Runs before elevation so a
#     non-VM is rejected without a UAC prompt. -Force overrides. ---
$model = ''
try { $model = (Get-CimInstance Win32_ComputerSystem).Model } catch { }
if ($model -ne 'Virtual Machine' -and -not $Force) {
    Write-Note "model is '$model', not 'Virtual Machine' - refusing to run on what looks like a physical host. Use -Force to override."
    exit 1
}

# --- Self-elevate: the policy keys, service Start values and scheduled tasks all need admin. ---
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
    # UAC elevation needs an interactive desktop; a remoting/PowerShell Direct session has none, so
    # Start-Process -Verb RunAs would hang. Section 10's agent flow must call this from elevation.
    if ($PSSenderInfo) {
        Write-Note 'Running in a remoting/PowerShell Direct session without admin - cannot UAC-elevate here. Start an elevated session (runas) and re-run.'
        exit 1
    }
    Write-Note 'Not elevated - relaunching as Administrator...'
    # -NoExit keeps the elevated window open so -AuditOnly output survives for an interactive run.
    $a = @('-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    # Forward exactly the switches that were passed (all params here are switches), so an audit
    # relaunch stays an audit and -DefenderSafeMode is never silently dropped.
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [System.Management.Automation.SwitchParameter]) {
            if ($kv.Value.IsPresent) { $a += "-$($kv.Key)" }
        } elseif ($kv.Value -is [bool]) {
            if ($kv.Value) { $a += "-$($kv.Key)" }
        } else {
            $a += @("-$($kv.Key)", "$($kv.Value)")
        }
    }
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $a
    return
}

# --- OS detection. Supported: Win10 10240-19045, or Win11 23H2 (22631). Outside that we warn but
#     continue (unlike new_guest_vm.ps1, which refuses). Win11-only items key off $isWin11. ---
$os        = Get-CimInstance Win32_OperatingSystem
$build     = [int]$os.BuildNumber
$isWin11   = $build -ge 22000
$supported = ($build -ge 10240 -and $build -le 19045) -or ($build -eq 22631)
if (-not $supported) {
    Write-Note "build $build is outside the supported ranges (Win10 10240-19045, Win11 23H2 22631) - continuing anyway."
}

$CV             = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$display        = (Get-ItemProperty $CV -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion
if (-not $display) { $display = (Get-ItemProperty $CV -Name ReleaseId -ErrorAction SilentlyContinue).ReleaseId }
$productVersion = if ($isWin11) { 'Windows 11' } else { 'Windows 10' }

$POL = 'HKLM:\SOFTWARE\Policies\Microsoft'
$DefenderServices = @('WinDefend', 'WdFilter', 'WdNisSvc', 'WdNisDrv', 'WdBoot', 'Sense', 'SecurityHealthService', 'wscsvc')

# ---------------------------------------------------------------------------------------------
#  Primitive Test/Apply helpers. A Test returns $true (satisfied), $false (gap) or $null (n/a:
#  the target does not exist on this edition). Audit the CONFIGURED state (registry/Start values),
#  not the live state, so a fresh apply does not show [!!] until the next reboot.
# ---------------------------------------------------------------------------------------------
function Test-RegValue($Path, $Name, $Value) {
    if (-not (Test-Path $Path)) { return $false }
    $p = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $p) { return $false }
    return ($p.$Name -eq $Value)
}
function Set-RegValue($Path, $Name, $Value, $Type) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}
function Test-SvcStart($Name, $Start) {
    $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if (-not (Test-Path $k)) { return $null }   # service absent on this edition.
    $p = Get-ItemProperty -Path $k -Name Start -ErrorAction SilentlyContinue
    if ($null -eq $p) { return $null }
    return ($p.Start -eq $Start)
}
function Set-SvcStart($Name, $Start) {
    $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if (-not (Test-Path $k)) { return }
    Set-ItemProperty -Path $k -Name Start -Value $Start
}
function Test-TasksDisabled($TaskPath, $TaskName) {
    $t = @(Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue)
    if ($t.Count -eq 0) { return $null }         # no such tasks on this edition.
    return (@($t | Where-Object { $_.State -ne 'Disabled' }).Count -eq 0)
}
function Disable-Tasks($TaskPath, $TaskName) {
    foreach ($t in @(Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue)) {
        # Some protected tasks (parts of UpdateOrchestrator/WaaSMedic) deny even an admin; skip them.
        try { Disable-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -ErrorAction Stop | Out-Null } catch { }
    }
}
function Invoke-AsSystem($Command) {
    # Run a PowerShell command as SYSTEM via a one-shot scheduled task and wait for it (60 s cap).
    # Used for tasks that deny an elevated admin; the caller re-tests afterwards.
    $name = 'CAPEsoloQuietAsSystem'
    $enc  = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
    $act  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc"
    $prin = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $name -Action $act -Principal $prin -Force | Out-Null
    try {
        Start-ScheduledTask -TaskName $name
        $deadline = (Get-Date).AddSeconds(60)
        do { Start-Sleep -Milliseconds 500 } while ((Get-ScheduledTask -TaskName $name).State -eq 'Running' -and (Get-Date) -lt $deadline)
    } finally {
        Unregister-ScheduledTask -TaskName $name -Confirm:$false
    }
}

# --- Item model. Factories store DATA (not closures); the driver dispatches on Kind. Custom items
#     carry plain, unbound scriptblocks that run in this script's scope, so they see the helpers and
#     $display/$POL/$nbtRoot directly. ---
$script:Items = @()
function Add-Item($h) { $script:Items += [pscustomobject]$h }

function RegItem($Area, $Name, $Path, $Key, $Value, $Type = 'DWord', [switch]$Win11Only) {
    Add-Item @{ Area = $Area; Name = $Name; Win11Only = [bool]$Win11Only; Kind = 'Reg'
                Path = $Path; Key = $Key; Value = $Value; Type = $Type }
}
function SvcItem($Area, $Name, $Service, $Start = 4, [switch]$Win11Only) {
    Add-Item @{ Area = $Area; Name = $Name; Win11Only = [bool]$Win11Only; Kind = 'Svc'
                Service = $Service; Start = $Start }
}
# Tasks that deny an elevated admin (e.g. SdbinstMergeDbTask) are retried as SYSTEM. -Protected: any
# still enabled after that are a warning, not a gap. -Advisory: a user-changeable preference; a differing value is a warning,
# so a choice made later in Settings does not fail the audit.
function TaskItem($Area, $Name, $TaskPath, $TaskName = '*', [switch]$Win11Only, [switch]$Protected) {
    Add-Item @{ Area = $Area; Name = $Name; Win11Only = [bool]$Win11Only; Kind = 'Task'
                TaskPath = $TaskPath; TaskName = $TaskName; Protected = [bool]$Protected; Advisory = [bool]$Protected }
}
function CustomItem($Area, $Name, $Test, $Apply, [switch]$Win11Only, [switch]$Advisory) {
    Add-Item @{ Area = $Area; Name = $Name; Win11Only = [bool]$Win11Only; Kind = 'Custom'
                Test = $Test; Apply = $Apply; Advisory = [bool]$Advisory }
}

function Invoke-ItemTest($item) {
    switch ($item.Kind) {
        'Reg'    { return (Test-RegValue $item.Path $item.Key $item.Value) }
        'Svc'    { return (Test-SvcStart $item.Service $item.Start) }
        'Task'   { return (Test-TasksDisabled $item.TaskPath $item.TaskName) }
        'Custom' { return (& $item.Test) }
    }
}
function Invoke-ItemApply($item) {
    switch ($item.Kind) {
        'Reg'    { Set-RegValue $item.Path $item.Key $item.Value $item.Type }
        'Svc'    {
            # Some service keys (SecurityHealthService, wscsvc) grant Administrators only ReadKey but
            # SYSTEM FullControl; retry those as SYSTEM.
            try { Set-SvcStart $item.Service $item.Start } catch { }
            if ((Test-SvcStart $item.Service $item.Start) -eq $false) {
                Invoke-AsSystem ("Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\{0}' -Name Start -Value {1}" -f $item.Service, $item.Start)
            }
        }
        'Task'   {
            Disable-Tasks $item.TaskPath $item.TaskName
            if ((Test-TasksDisabled $item.TaskPath $item.TaskName) -eq $false) {
                Invoke-AsSystem ("Get-ScheduledTask -TaskPath '{0}' -TaskName '{1}' | Disable-ScheduledTask | Out-Null" -f $item.TaskPath, $item.TaskName)
            }
        }
        'Custom' { & $item.Apply }
    }
}

# ---------------------------------------------------------------------------------------------
#  Defender. Tamper Protection must be off first (handled in the apply pre-flight below). The
#  service keys are protected while Defender runs; a denied write is retried as SYSTEM, and one
#  that still stays [!!] needs -DefenderSafeMode. Signature updates: Signature Updates\ScheduleDay=8 (never) stops scheduled
#  checks, and WinDefend Start=4 plus the disabled \Windows Defender\* tasks stop the updater itself.
# ---------------------------------------------------------------------------------------------
# DisableAntiSpyware is ignored by current Defender platforms; it still works on the older Win10
# builds inside the supported range.
RegItem Defender 'anti-spyware off (older platforms)' "$POL\Windows Defender" 'DisableAntiSpyware' 1
$dRtp = "$POL\Windows Defender\Real-Time Protection"
RegItem Defender 'real-time monitoring off'   $dRtp 'DisableRealtimeMonitoring' 1
RegItem Defender 'behavior monitoring off'    $dRtp 'DisableBehaviorMonitoring' 1
RegItem Defender 'on-access protection off'   $dRtp 'DisableOnAccessProtection' 1
RegItem Defender 'IOAV (downloaded files) off' $dRtp 'DisableIOAVProtection' 1
RegItem Defender 'script scanning off'        $dRtp 'DisableScriptScanning' 1
RegItem Defender 'signature update checks never' "$POL\Windows Defender\Signature Updates" 'ScheduleDay' 8
$dSpy = "$POL\Windows Defender\Spynet"
RegItem Defender 'MAPS reporting off'         $dSpy 'SpynetReporting' 0
RegItem Defender 'sample submission off'      $dSpy 'SubmitSamplesConsent' 2
foreach ($s in $DefenderServices) { SvcItem Defender "service $s Start=4" $s 4 }
TaskItem Defender 'Windows Defender tasks off' '\Microsoft\Windows\Windows Defender\*'

# --- Smart App Control (Win11). Once off it cannot be turned back on, which is the point. ---
RegItem SmartScreen 'Smart App Control off' 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState' 0 -Win11Only

# --- SmartScreen / MOTW. ---
RegItem SmartScreen 'Explorer SmartScreen off' "$POL\Windows\System" 'EnableSmartScreen' 0
RegItem SmartScreen 'Store-app SmartScreen off' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost' 'EnableWebContentEvaluation' 0
RegItem SmartScreen 'no MOTW on downloads' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments' 'SaveZoneInformation' 1

# --- Windows Update. ---
RegItem Updates 'auto-update off'          "$POL\Windows\WindowsUpdate\AU" 'NoAutoUpdate' 1
RegItem Updates 'Delivery Optimization off' "$POL\Windows\DeliveryOptimization" 'DODownloadMode' 99
RegItem Updates 'Store auto-download off'  "$POL\WindowsStore" 'AutoDownload' 2
SvcItem Updates 'service wuauserv Start=4' 'wuauserv' 4
SvcItem Updates 'service UsoSvc Start=4'   'UsoSvc' 4
SvcItem Updates 'service WaaSMedicSvc Start=4' 'WaaSMedicSvc' 4   # the Windows Update repair service.
TaskItem Updates 'UpdateOrchestrator tasks off' '\Microsoft\Windows\UpdateOrchestrator\*' -Protected
TaskItem Updates 'WindowsUpdate tasks off'      '\Microsoft\Windows\WindowsUpdate\*'
TaskItem Updates 'WaaSMedic tasks off'          '\Microsoft\Windows\WaaSMedic\*' -Protected
# Pin the installed release so a feature update cannot move it. The TargetReleaseVersion policy
# exists from 1803 (build 17134); older builds -> n/a, the items above still hold the line.
CustomItem Updates 'release pinned (TargetReleaseVersion)' `
    {
        if ($build -lt 17134 -or -not $display) { return $null }
        (Test-RegValue "$POL\Windows\WindowsUpdate" 'TargetReleaseVersion' 1) -and
        (Test-RegValue "$POL\Windows\WindowsUpdate" 'ProductVersion' $productVersion) -and
        (Test-RegValue "$POL\Windows\WindowsUpdate" 'TargetReleaseVersionInfo' $display)
    } `
    {
        Set-RegValue "$POL\Windows\WindowsUpdate" 'TargetReleaseVersion' 1 'DWord'
        Set-RegValue "$POL\Windows\WindowsUpdate" 'ProductVersion' $productVersion 'String'
        Set-RegValue "$POL\Windows\WindowsUpdate" 'TargetReleaseVersionInfo' $display 'String'
    }

# --- Edge. On a standalone guest (not AD/Entra-joined, not MDM-enrolled) Edge ignores its
#     domain-only policies - the EdgeUpdate policies, SmartScreenEnabled/SmartScreenPuaEnabled,
#     NewTabPageLocation - so none of those are relied on. Updates are stopped by the services, the
#     tasks and the EdgeUpdate folder rename. Edge SmartScreen therefore stays on (it only affects
#     pages and downloads opened inside Edge). The EdgeUpdate tasks live at the task-store root with
#     a name prefix, not under their own folder. ---
# EdgeUpdate policies: effective only on domain/MDM devices; kept for guests that are.
RegItem Edge 'EdgeUpdate default off (domain/MDM only)'      "$POL\EdgeUpdate" 'UpdateDefault' 0
RegItem Edge 'EdgeUpdate check period 0 (domain/MDM only)'   "$POL\EdgeUpdate" 'AutoUpdateCheckPeriodMinutes' 0
SvcItem Edge 'service edgeupdate disabled'  'edgeupdate' 4
SvcItem Edge 'service edgeupdatem disabled' 'edgeupdatem' 4
SvcItem Edge 'service MicrosoftEdgeElevationService disabled' 'MicrosoftEdgeElevationService' 4
TaskItem Edge 'MicrosoftEdgeUpdate tasks off' '\' 'MicrosoftEdgeUpdateTask*'
# Durable backstop: with its folder renamed the updater has no exe, so neither the services nor
# the tasks can come back. Edge itself runs from ...\Edge\Application. Undo: rename it back.
$edgeUpdateDir = Join-Path ${env:ProgramFiles(x86)} 'Microsoft\EdgeUpdate'
CustomItem Edge 'EdgeUpdate folder disabled' `
    {
        if (Test-Path "$edgeUpdateDir.disabled") { return $true }
        if (Test-Path $edgeUpdateDir) { return $false }
        return $null
    } `
    {
        Stop-Process -Name MicrosoftEdgeUpdate, msedge -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Rename-Item -Path $edgeUpdateDir -NewName 'EdgeUpdate.disabled'
    }
$edge = "$POL\Edge"
# Obsolete: ignored from Edge 119, where renderer code integrity is always enforced - capemon then
# cannot inject into Edge RENDERER processes (samples launched from Edge are separate processes and
# are hooked normally). Kept because it still applies to Edge 118 and older.
RegItem Edge 'renderer code integrity off (Edge <= 118)' $edge 'RendererCodeIntegrityEnabled' 0
RegItem Edge 'enhanced security mode off'  $edge 'EnhanceSecurityMode' 0
RegItem Edge 'component updates off'       $edge 'ComponentUpdatesEnabled' 0
RegItem Edge 'startup boost off'           $edge 'StartupBoostEnabled' 0
RegItem Edge 'background mode off'         $edge 'BackgroundModeEnabled' 0
RegItem Edge 'diagnostic data off'         $edge 'DiagnosticData' 0
RegItem Edge 'first-run experience hidden' $edge 'HideFirstRunExperience' 1
RegItem Edge 'new-tab MSN content off'     $edge 'NewTabPageContentEnabled' 0
# Recommended policies set the default but leave the user free to change it in edge://settings.
RegItem Edge 'typo protection off (default, user-changeable)'    "$edge\Recommended" 'TyposquattingCheckerEnabled' 0
RegItem Edge 'network prediction off (default, user-changeable)' "$edge\Recommended" 'NetworkPredictionOptions' 2

# --- VBS / HVCI / BitLocker. The keys are written unconditionally and the audit reports the
#     CONFIGURED value; live state (which only changes on reboot) is reported in the summary. ---
RegItem VBS 'HVCI (memory integrity) off' 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled' 0
RegItem VBS 'VBS off' 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'EnableVirtualizationBasedSecurity' 0
RegItem VBS 'device encryption prevented' 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker' 'PreventDeviceEncryption' 1
# An already-encrypted system drive breaks disk conversion and snapshots on other hypervisors.
# Decryption is long and deliberate, so this only reports it.
CustomItem VBS 'system drive not BitLocker-encrypted' `
    {
        if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) { return $null }
        (Get-BitLockerVolume -MountPoint $env:SystemDrive).VolumeStatus -eq 'FullyDecrypted'
    } `
    { throw "decrypt first: manage-bde -off $env:SystemDrive" }

# --- Background network noise. ---
SvcItem Noise 'service DiagTrack disabled'        'DiagTrack' 4
SvcItem Noise 'service dmwappushservice disabled' 'dmwappushservice' 4
RegItem Noise 'telemetry off'   "$POL\Windows\DataCollection" 'AllowTelemetry' 0
RegItem Noise 'error reporting off' "$POL\Windows\Windows Error Reporting" 'Disabled' 1
SvcItem Noise 'service WerSvc disabled' 'WerSvc' 4
TaskItem Noise 'Windows Error Reporting tasks off' '\Microsoft\Windows\Windows Error Reporting\*'
TaskItem Noise 'CEIP tasks off'                '\Microsoft\Windows\Customer Experience Improvement Program\*'
# PcaSvc re-registers (re-enables) PcaPatchDbTask at every boot; disable it so the task stays off.
SvcItem Noise 'service PcaSvc disabled' 'PcaSvc' 4
TaskItem Noise 'Application Experience tasks off' '\Microsoft\Windows\Application Experience\*'
# ReconcileLanguageResources (logon + 2 h) runs as soon as a revert jumps the clock past it and sets
# wuauserv back to demand start, so Windows Update downloads mid-analysis.
TaskItem Noise 'Language Components Installer tasks off' '\Microsoft\Windows\LanguageComponentsInstaller\*'
# The Store's restore/scan/push tasks do the same once a revert jumps the clock hours past their
# last run (AutoDownload=2 does not stop them).
TaskItem Noise 'Store InstallService tasks off' '\Microsoft\Windows\InstallService\*'
TaskItem Noise 'Store PushToInstall tasks off' '\Microsoft\Windows\PushToInstall\*'
# InstallService itself re-enables wuauserv whenever a client starts it (the shell, App Installer
# during maintenance); disabling it stops Store/winget msstore installs in the guest.
SvcItem Noise 'service InstallService disabled' 'InstallService' 4
# Maintenance that would otherwise start mid-analysis and pollute CPU/disk and the behavior log.
# Tasks only: the SysMain and WSearch services stay, so the guest still looks normal.
TaskItem Noise 'scheduled defrag off'            '\Microsoft\Windows\Defrag\' 'ScheduledDefrag'
TaskItem Noise 'component cleanup off'           '\Microsoft\Windows\Servicing\' 'StartComponentCleanup'
TaskItem Noise 'WinSAT benchmark off'            '\Microsoft\Windows\Maintenance\' 'WinSAT'
TaskItem Noise 'indexer maintenance off'         '\Microsoft\Windows\Shell\' 'IndexerAutomaticMaintenance'
$search = "$POL\Windows\Windows Search"
RegItem Noise 'web search off'      $search 'DisableWebSearch' 1
RegItem Noise 'connected search off' $search 'ConnectedSearchUseWeb' 0
RegItem Noise 'Cortana off'         $search 'AllowCortana' 0
RegItem Noise 'Bing in search box off' 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' 'BingSearchEnabled' 0
RegItem Noise 'news feed off (Win10)' "$POL\Windows\Windows Feeds" 'EnableFeeds' 0
RegItem Noise 'Widgets off'         "$POL\Dsh" 'AllowNewsAndInterests' 0 -Win11Only
RegItem Noise 'Copilot off'         "$POL\Windows\WindowsCopilot" 'TurnOffWindowsCopilot' 1 -Win11Only
RegItem Noise 'Recall off'          "$POL\Windows\WindowsAI" 'DisableAIDataAnalysis' 1 -Win11Only
$cloud = "$POL\Windows\CloudContent"
RegItem Noise 'consumer features off' $cloud 'DisableWindowsConsumerFeatures' 1
RegItem Noise 'tips/soft landing off' $cloud 'DisableSoftLanding' 1
# Spotlight uses preference values, not the Spotlight policy (a user policy - ignored at HKLM, and it
# would grey the choice out in Settings). Desktop Spotlight is already deselected by the black
# background below; this turns off the rotating lock screen and its tips.
$cdm = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
$lockScreenPrefs = @('RotatingLockScreenEnabled', 'RotatingLockScreenOverlayEnabled', 'SubscribedContent-338387Enabled')
CustomItem Noise 'lock-screen Spotlight and tips off (user-changeable)' `
    {
        foreach ($v in $lockScreenPrefs) { if (-not (Test-RegValue $cdm $v 0)) { return $false } }
        return $true
    } `
    { foreach ($v in $lockScreenPrefs) { Set-RegValue $cdm $v 0 'DWord' } } -Advisory
RegItem Noise 'silent Store app installs off' $cdm 'SilentInstalledAppsEnabled' 0
RegItem Noise 'background Store apps off'     "$POL\Windows\AppPrivacy" 'LetAppsRunInBackground' 2
RegItem Noise 'OneDrive sync off'   "$POL\Windows\OneDrive" 'DisableFileSyncNGSC' 1
SvcItem Noise 'service w32time disabled' 'w32time' 4
RegItem Noise 'Maps auto-update off' "$POL\Windows\Maps" 'AutoDownloadAndUpdateMapData' 0
SvcItem Noise 'service MapsBroker disabled' 'MapsBroker' 4
RegItem Noise 'font provider off'   "$POL\Windows\System" 'EnableFontProviders' 0
RegItem Noise 'LLMNR off'           "$POL\Windows NT\DNSClient" 'EnableMulticast' 0
SvcItem Noise 'service SSDPSRV disabled' 'SSDPSRV' 4
SvcItem Noise 'service upnphost disabled' 'upnphost' 4
RegItem Noise 'Teredo disabled' "$POL\Windows\TCPIP\v6Transition" 'Teredo_State' 'Disabled' 'String'
# NetBIOS over TCP off on every TCP/IP interface (NetbiosOptions=2).
$nbtRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
CustomItem Noise 'NetBIOS over TCP off (all interfaces)' `
    {
        $ifs = @(Get-ChildItem "$nbtRoot\Tcpip_*" -ErrorAction SilentlyContinue)
        if ($ifs.Count -eq 0) { return $null }
        foreach ($i in $ifs) {
            $v = (Get-ItemProperty $i.PSPath -Name NetbiosOptions -ErrorAction SilentlyContinue).NetbiosOptions
            if ($v -ne 2) { return $false }
        }
        return $true
    } `
    {
        foreach ($i in @(Get-ChildItem "$nbtRoot\Tcpip_*" -ErrorAction SilentlyContinue)) {
            Set-ItemProperty $i.PSPath -Name NetbiosOptions -Value 2
        }
    }

# --- Optional noise items, off by default (tradeoffs documented in the guide). ---
if ($DisableNcsi) {
    RegItem Noise 'NCSI active probe off' "$POL\Windows\NetworkConnectivityStatusIndicator" 'NoActiveProbe' 1
}
if ($DisableRootAutoUpdate) {
    RegItem Noise 'root cert auto-update off' "$POL\SystemCertificates\AuthRoot" 'DisableRootAutoUpdate' 1
}

# --- Analysis conveniences. ---
$uac = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
RegItem Convenience 'UAC off' $uac 'EnableLUA' 0
# The rest of UAC, so nothing prompts or filters even before the EnableLUA reboot (or if it is re-enabled).
RegItem Convenience 'UAC: admins elevate without prompting'        $uac 'ConsentPromptBehaviorAdmin' 0
RegItem Convenience 'UAC: no secure desktop for prompts'           $uac 'PromptOnSecureDesktop' 0
RegItem Convenience 'UAC: built-in Administrator not filtered'     $uac 'FilterAdministratorToken' 0
RegItem Convenience 'UAC: installer detection off'                 $uac 'EnableInstallerDetection' 0
RegItem Convenience 'UAC: file/registry virtualization off'        $uac 'EnableVirtualization' 0
RegItem Convenience 'UAC: remote local-admin logons get full token' $uac 'LocalAccountTokenFilterPolicy' 1
# With UAC off, a member of Administrators runs everything with the full admin token. The guest user
# is the AutoLogon account (or whoever runs this); matched by SID S-1-5-32-544, so localized names work.
$GuestUser = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue).DefaultUserName
if (-not $GuestUser) { $GuestUser = $env:USERNAME }
CustomItem Convenience "guest user '$GuestUser' in Administrators" `
    { [bool](Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.Name -eq "$env:COMPUTERNAME\$GuestUser" }) } `
    { Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $GuestUser }
RegItem Convenience 'Fast Startup off' 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' 0
CustomItem Convenience 'hibernation off' `
    { Test-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabled' 0 } `
    { & "$env:SystemRoot\System32\powercfg.exe" /hibernate off | Out-Null }
CustomItem Convenience 'sleep set to never (AC)' `
    {
        $out = & "$env:SystemRoot\System32\powercfg.exe" /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 2>$null
        [bool]($out | Select-String 'Current AC Power Setting Index:\s+0x00000000')
    } `
    {
        & "$env:SystemRoot\System32\powercfg.exe" -change -standby-timeout-ac 0 | Out-Null
        & "$env:SystemRoot\System32\powercfg.exe" -change -standby-timeout-dc 0 | Out-Null
        & "$env:SystemRoot\System32\powercfg.exe" -change -monitor-timeout-ac 0 | Out-Null
    }
CustomItem Convenience 'System Restore off' `
    { Test-RegValue "$POL\Windows NT\SystemRestore" 'DisableSR' 1 } `
    {
        Set-RegValue "$POL\Windows NT\SystemRestore" 'DisableSR' 1 'DWord'
        try { Disable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction Stop } catch { }
    }
RegItem Convenience 'file extensions shown' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'HideFileExt' 0
RegItem Convenience 'hidden files shown'    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'Hidden' 1
# LocalMachine execution policy (what Set-ExecutionPolicy -Scope LocalMachine writes), for 64- and
# 32-bit Windows PowerShell, so scripts run without -ExecutionPolicy. Not a policy key: still changeable.
RegItem Convenience 'PowerShell execution policy Bypass (x64)' 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' 'ExecutionPolicy' 'Bypass' 'String'
RegItem Convenience 'PowerShell execution policy Bypass (x86)' 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' 'ExecutionPolicy' 'Bypass' 'String'
# Black solid desktop, written as the same preference values Settings writes - never under a
# Policies key, so Personalize > Background stays editable. Advisory: a background picked later in
# Settings is reported as a warning, not a gap.
CustomItem Convenience 'desktop background black (user-changeable)' `
    {
        (Test-RegValue 'HKCU:\Control Panel\Colors' 'Background' '0 0 0') -and
        (Test-RegValue 'HKCU:\Control Panel\Desktop' 'WallPaper' '')
    } `
    {
        Set-RegValue 'HKCU:\Control Panel\Colors' 'Background' '0 0 0' 'String'
        Set-RegValue 'HKCU:\Control Panel\Desktop' 'WallPaper' '' 'String'
        Set-RegValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers' 'BackgroundType' 1 'DWord'
        # Refresh the running desktop so the change shows without signing out.
        if (-not ('CapesoloDesktop' -as [type])) {
            Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class CapesoloDesktop {
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern bool SystemParametersInfo(int uiAction, int uiParam, string pvParam, int fWinIni);
    [DllImport("user32.dll")]
    public static extern bool SetSysColors(int cElements, int[] lpaElements, int[] lpaRgbValues);
}
'@
        }
        [void][CapesoloDesktop]::SystemParametersInfo(0x14, 0, '', 3)   # SPI_SETDESKWALLPAPER, update + broadcast.
        [void][CapesoloDesktop]::SetSysColors(1, @(1), @(0))            # COLOR_BACKGROUND = black.
    } -Advisory

# --- Firewall. Left on with an inbound rule for CAPEsolo-mcp (TCP 8000, mcp_server.md). ---
CustomItem Firewall 'inbound TCP 8000 (CAPEsolo-mcp)' `
    { [bool](Get-NetFirewallRule -DisplayName 'CAPEsolo-mcp (TCP 8000)' -ErrorAction SilentlyContinue) } `
    { New-NetFirewallRule -DisplayName 'CAPEsolo-mcp (TCP 8000)' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8000 -Profile Any | Out-Null }
if ($DisableFirewall) {
    CustomItem Firewall 'firewall off (all profiles)' `
        { (@(Get-NetFirewallProfile | Where-Object { $_.Enabled }).Count -eq 0) } `
        { Set-NetFirewallProfile -All -Enabled False }
}

# ---------------------------------------------------------------------------------------------
#  Safe Mode orchestration for the protected Defender service keys.
# ---------------------------------------------------------------------------------------------
if ($ServicesOnly) {
    # We are the RunOnce re-entry, running in minimal Safe Mode. Clear the safeboot flag FIRST so a
    # later failure cannot leave the guest in a Safe Mode boot loop, then write the keys and reboot.
    Write-Step 'Safe Mode: clearing safeboot and writing Defender service keys'
    & bcdedit /deletevalue '{current}' safeboot | Out-Null
    foreach ($s in $DefenderServices) { Set-SvcStart $s 4 }
    Write-Ok 'Defender services set to Start=4; rebooting to normal mode.'
    Restart-Computer -Force
    return
}
if ($DefenderSafeMode -and -not $AuditOnly -and -not $SkipDefender) {
    Write-Step 'Scheduling a Safe Mode pass to write the protected Defender service keys'
    & bcdedit /set '{current}' safeboot minimal | Out-Null
    # A '*'-prefixed RunOnce entry runs in Safe Mode too.
    Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' '*CAPEsoloQuiet' `
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -ServicesOnly" 'String'
    Write-Note 'Rebooting into Safe Mode. Log on at the guest console (PowerShell Direct and the heartbeat are not available in Safe Mode); the RunOnce writes the keys and reboots back automatically.'
    Write-Note 'After the round-trip, re-run this script WITHOUT -DefenderSafeMode to apply Updates/Edge/Noise.'
    Restart-Computer -Force
    return
}

# ---------------------------------------------------------------------------------------------
#  Tamper Protection pre-flight (apply only). With it on, the Defender writes are denied.
# ---------------------------------------------------------------------------------------------
function Get-TamperProtected {
    # Get-MpComputerStatus throws once WinDefend is disabled; treat that as "Defender already off".
    try { return [bool]((Get-MpComputerStatus -ErrorAction Stop).IsTamperProtected) } catch { return $false }
}
if (-not $AuditOnly -and -not $SkipDefender) {
    if (Get-TamperProtected) {
        Write-Note 'Tamper Protection is ON - the Defender writes would be denied.'
        Write-Note 'Turn it off: Windows Security > Virus & threat protection > Manage settings > Tamper Protection Off, then re-run.'
        Write-Note 'Or re-run with -DefenderSafeMode to write the protected keys from Safe Mode.'
        exit 1
    }
}

# ---------------------------------------------------------------------------------------------
#  Driver. One pass over the table, grouped by area, honouring the -Skip switches.
# ---------------------------------------------------------------------------------------------
$areaSkip = @{ Defender = [bool]$SkipDefender; Updates = [bool]$SkipUpdates; Edge = [bool]$SkipEdge; Noise = [bool]$SkipNoise }
$script:Gaps = 0
$script:Warnings = 0
function Add-Shortfall($item, $detail) {
    # One place decides gap vs warning: advisory/protected items never fail the run.
    if ($item.Advisory) {
        $why = if ($item.Protected) { 'protected, still enabled after SYSTEM retry' } else { 'differs (user-changeable)' }
        Write-Warn "$($item.Name) - $why$detail"; $script:Warnings++
    } else {
        Write-Note "$($item.Name)$detail"; $script:Gaps++
    }
}

if ($AuditOnly -and -not $SkipDefender) {
    Write-Step 'Defender live state (informational)'
    if (Get-TamperProtected) { Write-Note 'Tamper Protection is ON (blocks apply until turned off).' }
    else { Write-Ok 'Tamper Protection is off (or Defender already disabled).' }
}

foreach ($grp in ($script:Items | Group-Object Area)) {
    $area = $grp.Name
    if ($areaSkip.ContainsKey($area) -and $areaSkip[$area]) {
        Write-Step "$area - skipped (-Skip$area)"
        continue
    }
    Write-Step $area
    foreach ($item in $grp.Group) {
        if ($item.Win11Only -and -not $isWin11) { Write-Na "$($item.Name) (Windows 11 only)"; continue }
        try { $state = Invoke-ItemTest $item }
        catch { Write-Note "$($item.Name) - test failed: $($_.Exception.Message)"; $script:Gaps++; continue }
        if ($null -eq $state) { Write-Na $item.Name; continue }
        if (-not $AuditOnly -and -not $state) {
            try { Invoke-ItemApply $item; $state = (Invoke-ItemTest $item) }
            catch { Add-Shortfall $item " - apply failed: $($_.Exception.Message)"; continue }
        }
        if ($state) { Write-Ok $item.Name } else { Add-Shortfall $item '' }
    }
}

# --- Summary ---
Write-Host ''
if ($AuditOnly) {
    Write-Host "Audit complete. $($script:Gaps) item(s) marked [!!] (exit 1 if any). Run without -AuditOnly to apply." -ForegroundColor Cyan
} elseif ($script:Gaps -eq 0) {
    Write-Host 'Done. Every applicable item is satisfied. Reboot twice, re-run with -AuditOnly, then snapshot.' -ForegroundColor Cyan
} else {
    Write-Host "Done, but $($script:Gaps) item(s) remain [!!]. If they are Defender keys, Tamper Protection is likely on - see -DefenderSafeMode." -ForegroundColor Yellow
}
if ($script:Warnings -gt 0) {
    Write-Host "$($script:Warnings) warning(s): protected tasks still enabled, or preferences changed since apply. Warnings do not affect the exit code." -ForegroundColor Yellow
}
Write-Host 'VBS/HVCI live state: Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard (changes only after reboot).' -ForegroundColor DarkGray
Write-Host 'Defender confirmation in the guest: Get-MpComputerStatus (RealTimeProtectionEnabled False) and sc.exe qc WinDefend (START_TYPE DISABLED).' -ForegroundColor DarkGray

if ($script:Gaps -gt 0) { exit 1 }
