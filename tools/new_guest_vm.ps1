<#
.SYNOPSIS
    Provision a CAPEsolo analysis guest on a Hyper-V host from a Windows 10/11 ISO: build a config
    ISO holding the filled autounattend.xml and the setup scripts, create a Gen2 VM with a vTPM,
    run the install unattended to a clean checkpoint.

.DESCRIPTION
    Runs on the Hyper-V host (refuses on a VM). It:
      * fills tools\guest\autounattend.xml with -User/-Password/-ComputerName/-ProductKey and builds
        a config ISO (autounattend.xml at the root; firstboot.ps1 and the three setup_*_guest.ps1
        under \setup) with the built-in IMAPI2FS COM object - no ADK/oscdimg needed;
      * creates a Generation 2 VM with Secure Boot, a local-key-protector vTPM (Windows 11 requires
        one), static memory, automatic checkpoints off and the Guest Service Interface on;
      * attaches two DVD drives - the Windows ISO first in the boot order, the config ISO second -
        spams Space to clear any "press any key to boot from CD" prompt, then waits for the guest's
        heartbeat and for firstboot.ps1 to write C:\setup\done.txt;
      * stops (VM left running for inspection, no checkpoint) unless done.txt says overall=OK;
      * ejects both ISOs and deletes the config ISO (it holds the guest password), turns on
        persistent AutoLogon, reboots so the quiet settings are live, waits for the desktop, and
        takes the 'clean' checkpoint - so a revert lands on a running, logged-on guest.

    -ConfigIsoOnly builds and reports the config ISO and stops, for a no-admin dry run. It keeps the
    ISO and the staging dir for inspection; delete them afterwards.

.PARAMETER Name            VM name. Prompted for when omitted (Enter accepts 'CAPEsolo-guest');
                           pass it explicitly for unattended/agent runs.
.PARAMETER IsoPath         Windows 10/11 installation ISO. Required unless -ConfigIsoOnly.
.PARAMETER Switch          Virtual switch. Default 'Default Switch'.
.PARAMETER MemoryGB        Static startup memory. Default 8.
.PARAMETER Cpu             Virtual processors. Default 4.
.PARAMETER DiskGB          Dynamic VHDX size. Default 80.
.PARAMETER User            Guest local administrator name. Default 'analyst'.
.PARAMETER Password        Its password. Required unless -ConfigIsoOnly.
.PARAMETER ComputerName    Guest computer name, max 15 characters (NetBIOS). Default 'CAPESOLO'.
.PARAMETER ProductKey      Edition-select key. Default the Enterprise generic key (selects, does not activate).
                           Pass your own key to install and activate that edition.
.PARAMETER NoProductKey    Put no key in the answer file, for a pre-activated / single-edition ISO
                           whose own licensing must not be overridden. The edition is then chosen by
                           image: the only image on a single-edition ISO, else -ImageName/-ImageIndex.
.PARAMETER ImageName       With -NoProductKey: install the image with this exact name
                           (e.g. 'Windows 11 Enterprise'), as listed by Get-WindowsImage.
.PARAMETER ImageIndex      With -NoProductKey: install the image with this index.
.PARAMETER IncludeNode     Stage the Node.js step (drops node.enabled for firstboot.ps1).
.PARAMETER WheelPath       A local CAPEsolo wheel to stage under \setup (offline install).
.PARAMETER CheckpointType  'Standard' (revert to a running, logged-on guest - default, best for the
                           revert-before-each-analysis workflow) or 'Production' (restores off).
.PARAMETER VhdPath         VHDX path. Default <VM host VHD path>\<Name>.vhdx.
.PARAMETER ConfigIsoPath   Config ISO path. Default %TEMP%\capesolo_<Name>_config.iso (outside the
                           repo - it contains the guest credentials; deleted after a full build).
.PARAMETER InstallTimeoutMin  Minutes to wait for done.txt. Default 120.
.PARAMETER ConfigIsoOnly   Build and report the config ISO, then stop (no admin, no VM).
.PARAMETER Force           Overwrite an existing VM/VHDX, run on a non-supported ISO build, or run
                           on a host that reports as a VM.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\new_guest_vm.ps1 -ConfigIsoOnly -User analyst -Password 'P@ss' -ComputerName CAPESOLO

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\new_guest_vm.ps1 -IsoPath D:\Win11_23H2.iso -Password 'P@ss'

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\new_guest_vm.ps1 -IsoPath D:\preactivated.iso -Password 'P@ss' -NoProductKey

.NOTES
    Self-elevates for the VM work (Hyper-V cmdlets, Mount-DiskImage). -Password is forwarded to the
    elevated relaunch on the command line; run on a trusted host. Windows PowerShell 5.1, pure ASCII.
#>
[CmdletBinding()]
param(
    [string] $Name,
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
    [switch] $ConfigIsoOnly,
    [switch] $Force
)

$ErrorActionPreference = 'Stop'

function Write-Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "    [ok] $m" -ForegroundColor Green }
function Write-Note($m) { Write-Host "    [!!] $m" -ForegroundColor Yellow }

# --- Resolve the source files this host-side script stages into the config ISO. ---
$Tools    = $PSScriptRoot
$GuestDir = Join-Path $Tools 'guest'
$Template = Join-Path $GuestDir 'autounattend.xml'
$SetupScripts = @(
    (Join-Path $Tools 'setup_runtime_guest.ps1'),
    (Join-Path $Tools 'setup_nodejs_guest.ps1'),
    (Join-Path $Tools 'setup_quiet_guest.ps1'),
    (Join-Path $GuestDir 'firstboot.ps1')
)
foreach ($f in (@($Template) + $SetupScripts)) {
    if (-not (Test-Path $f)) { throw "required source file missing: $f" }
}
if ($WheelPath -and -not (Test-Path $WheelPath)) { throw "wheel not found: $WheelPath" }
if ($NoProductKey -and $PSBoundParameters.ContainsKey('ProductKey')) {
    throw '-NoProductKey and -ProductKey are mutually exclusive.'
}
if (($ImageName -or $ImageIndex) -and -not $NoProductKey) {
    throw '-ImageName/-ImageIndex are only used with -NoProductKey (otherwise the key selects the edition).'
}
if ($ImageName -and $ImageIndex) { throw 'Use -ImageName or -ImageIndex, not both.' }

if (-not $Name) {
    $Name = "$(Read-Host 'VM name [CAPEsolo-guest]')".Trim()
    if (-not $Name) { $Name = 'CAPEsolo-guest' }
    $PSBoundParameters['Name'] = $Name   # so the elevated relaunch receives it instead of prompting again.
}
# The name also becomes the VHDX, config ISO and staging file names.
if ($Name.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
    throw "VM name '$Name' contains characters that are not allowed in a file name."
}

if (-not $Password) {
    if ($ConfigIsoOnly) { $Password = 'DRYRUN-PLACEHOLDER' }
    else { throw 'Supply -Password for the guest local administrator account.' }
}
if (-not $ConfigIsoPath) { $ConfigIsoPath = Join-Path $env:TEMP "capesolo_$($Name)_config.iso" }

# --- Host guard: this runs on the Hyper-V host, not inside a guest. ---
$model = ''
try { $model = (Get-CimInstance Win32_ComputerSystem).Model } catch { }
if ($model -eq 'Virtual Machine' -and -not $Force) {
    throw "this machine reports as a VM ('$model'); new_guest_vm.ps1 runs on the Hyper-V host. Use -Force to override."
}

# --- IMAPI2FS IStream -> file writer (chunked; the config ISO is only a few MB). ---
if (-not ('CapesoloIsoWriter' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public static class CapesoloIsoWriter {
    public static void Write(object imageStream, string path) {
        IStream s = (IStream)imageStream;
        int chunk = 1048576;
        byte[] buf = new byte[chunk];
        IntPtr pRead = Marshal.AllocHGlobal(8);
        try {
            using (FileStream fs = File.Create(path)) {
                while (true) {
                    s.Read(buf, chunk, pRead);
                    int got = Marshal.ReadInt32(pRead);
                    if (got <= 0) break;
                    fs.Write(buf, 0, got);
                }
            }
        } finally { Marshal.FreeHGlobal(pRead); }
    }
}
'@
}

function New-ConfigStaging {
    # Fill the autounattend placeholders and lay out the ISO tree in a temp staging dir; return it.
    $stage = Join-Path $env:TEMP "capesolo_iso_$Name"
    if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
    New-Item -ItemType Directory -Path $stage | Out-Null
    $setup = New-Item -ItemType Directory -Path (Join-Path $stage 'setup')

    $xml = Get-Content $Template -Raw
    $xml = $xml.Replace('__USER__',         [System.Security.SecurityElement]::Escape($User))
    $xml = $xml.Replace('__PASSWORD__',     [System.Security.SecurityElement]::Escape($Password))
    $xml = $xml.Replace('__COMPUTERNAME__', [System.Security.SecurityElement]::Escape($ComputerName))
    $xml = $xml.Replace('__PRODUCTKEY__',   [System.Security.SecurityElement]::Escape($ProductKey))
    if ($NoProductKey) {
        # Key must never be empty, so drop the whole ProductKey block; choose the image instead so
        # Setup still needs no input. By name if given, else by index (1 on a single-edition ISO).
        $xml = [regex]::Replace($xml, '(?s)\s*<ProductKey>.*?</ProductKey>', '')
        $metaKey = if ($ImageName) { '/IMAGE/NAME' } else { '/IMAGE/INDEX' }
        $metaVal = if ($ImageName) { [System.Security.SecurityElement]::Escape($ImageName) } elseif ($ImageIndex) { $ImageIndex } else { 1 }
        $installFrom = "<InstallFrom>`r`n            <MetaData wcm:action=`"add`">`r`n              <Key>$metaKey</Key>`r`n" +
                       "              <Value>$metaVal</Value>`r`n            </MetaData>`r`n          </InstallFrom>`r`n          <InstallTo>"
        $xml = ([regex]'<InstallTo>').Replace($xml, $installFrom, 1)
    }
    Set-Content -Path (Join-Path $stage 'autounattend.xml') -Value $xml -Encoding UTF8

    foreach ($s in $SetupScripts) { Copy-Item $s -Destination $setup.FullName }
    if ($IncludeNode) { Set-Content -Path (Join-Path $setup.FullName 'node.enabled') -Value '1' -Encoding ASCII }
    if ($WheelPath)   { Copy-Item $WheelPath -Destination $setup.FullName }
    return $stage
}

function New-ConfigIso {
    param($StageDir, $OutPath)
    if (Test-Path $OutPath) { Remove-Item $OutPath -Force }
    $fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    $fsi.FileSystemsToCreate = 3   # ISO9660 + Joliet (long names survive).
    $fsi.VolumeName = 'CAPESOLO'
    $fsi.Root.AddTree($StageDir, $false)   # $false: add the contents, not the staging dir itself.
    $result = $fsi.CreateResultImage()
    [CapesoloIsoWriter]::Write($result.ImageStream, $OutPath)
    # IMAPI keeps the staged files open until its COM objects are released; without this the
    # staging cleanup fails on a large file such as a -WheelPath wheel.
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($result)
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($fsi)
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
}

# --- Dry run: build the config ISO and stop. No admin, no VM. ---
if ($ConfigIsoOnly) {
    Write-Step 'Building config ISO (dry run)'
    $stage = New-ConfigStaging
    New-ConfigIso -StageDir $stage -OutPath $ConfigIsoPath
    $size = [math]::Round((Get-Item $ConfigIsoPath).Length / 1KB, 1)
    Write-Ok "config ISO written: $ConfigIsoPath ($size KB)"
    Write-Ok "staging tree: $stage"
    if ($NoProductKey) { Write-Note 'No product key: the image choice is only checked against the ISO in a real build.' }
    Write-Note 'Dry run - no VM was created. The ISO holds the guest credentials; delete it when done.'
    return
}

# --- Self-elevate for the VM work. ---
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

if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
    throw 'the Hyper-V PowerShell module is not available. Enable the Hyper-V role/management tools.'
}
if (-not $IsoPath -or -not (Test-Path $IsoPath)) { throw "Windows ISO not found: $IsoPath" }
if (-not (Get-VMSwitch -Name $Switch -ErrorAction SilentlyContinue)) {
    throw "virtual switch '$Switch' not found. Existing switches: $((Get-VMSwitch).Name -join ', ')"
}

# --- OS enforcement: read the build from the install image (install.wim or install.esd). ---
Write-Step 'Checking the Windows ISO build'
$mount = Mount-DiskImage -ImagePath $IsoPath -PassThru
try {
    $drive = ($mount | Get-Volume).DriveLetter
    $img = "$drive`:\sources\install.wim"
    if (-not (Test-Path $img)) { $img = "$drive`:\sources\install.esd" }
    if (-not (Test-Path $img)) { throw "no sources\install.wim or install.esd on $IsoPath" }
    $useIndex = 1
    if ($NoProductKey) {
        # No key to pick the edition, so resolve the image now and fail before anything is created.
        $images = @(Get-WindowsImage -ImagePath $img)
        $list = ($images | ForEach-Object { "index $($_.ImageIndex): $($_.ImageName)" }) -join '; '
        if ($ImageIndex)    { $sel = $images | Where-Object { $_.ImageIndex -eq $ImageIndex } }
        elseif ($ImageName) { $sel = $images | Where-Object { $_.ImageName -eq $ImageName } }
        elseif ($images.Count -eq 1) { $sel = $images[0]; $ImageIndex = 1 }
        else { throw "-NoProductKey on a multi-edition ISO needs -ImageName or -ImageIndex. Images: $list" }
        if (-not $sel) { throw "no image matches -ImageName/-ImageIndex. Images: $list" }
        $useIndex = $sel.ImageIndex
    }
    $wimInfo = Get-WindowsImage -ImagePath $img -Index $useIndex
    $build = [int]($wimInfo.Version.Split('.')[2])
} finally {
    Dismount-DiskImage -ImagePath $IsoPath | Out-Null
}
Write-Ok "image: $($wimInfo.ImageName) ($($wimInfo.Version))"
$supported = ($build -ge 10240 -and $build -le 19045) -or ($build -eq 22631)
if ($supported) { Write-Ok "build $build supported" }
elseif ($Force) { Write-Note "build $build not supported - continuing (-Force)" }
else { throw "build $build is not supported (Windows 10 10240-19045 or Windows 11 23H2 22631). Use -Force to override." }

# --- Overwrite guards (fail safe; -Force opts in to destroying the old VM/VHDX). ---
if (-not $VhdPath) { $VhdPath = Join-Path (Get-VMHost).VirtualHardDiskPath "$Name.vhdx" }
if (Get-VM -Name $Name -ErrorAction SilentlyContinue) {
    if (-not $Force) { throw "VM '$Name' already exists. Re-run with -Force to remove and recreate it." }
    Write-Note "removing existing VM '$Name' (-Force)"
    Stop-VM -Name $Name -TurnOff -Force -ErrorAction SilentlyContinue
    Remove-VM -Name $Name -Force
}
if (Test-Path $VhdPath) {
    if (-not $Force) { throw "VHDX already exists: $VhdPath. Re-run with -Force to overwrite." }
    Remove-Item $VhdPath -Force
}

# --- Build the config ISO. ---
Write-Step 'Building config ISO'
$stage = New-ConfigStaging
New-ConfigIso -StageDir $stage -OutPath $ConfigIsoPath
Remove-Item $stage -Recurse -Force   # the staging copy holds the filled answer file (password).
Write-Ok "config ISO: $ConfigIsoPath"

# --- Create the Gen2 VM. ---
Write-Step "Creating VM '$Name'"
New-Item -ItemType Directory -Path (Split-Path $VhdPath) -Force | Out-Null
New-VHD -Path $VhdPath -SizeBytes ($DiskGB * 1GB) -Dynamic | Out-Null
New-VM -Name $Name -Generation 2 -MemoryStartupBytes ($MemoryGB * 1GB) `
    -VHDPath $VhdPath -SwitchName $Switch | Out-Null
Set-VMProcessor -VMName $Name -Count $Cpu
Set-VMMemory -VMName $Name -DynamicMemoryEnabled $false
Set-VM -Name $Name -AutomaticCheckpointsEnabled $false -CheckpointType $CheckpointType
Enable-VMIntegrationService -VMName $Name -Name 'Guest Service Interface'

# Secure Boot + a local-key-protector vTPM (Windows 11 requires one).
Set-VMFirmware -VMName $Name -EnableSecureBoot On -SecureBootTemplate 'MicrosoftWindows'
Set-VMKeyProtector -VMName $Name -NewLocalKeyProtector
Enable-VMTPM -VMName $Name

# Two DVD drives: Windows ISO first in the boot order, config ISO second.
$dvdWin = Add-VMDvdDrive -VMName $Name -Path $IsoPath -Passthru
Add-VMDvdDrive -VMName $Name -Path $ConfigIsoPath | Out-Null
Set-VMFirmware -VMName $Name -FirstBootDevice $dvdWin
Write-Ok 'VM created (Gen2, Secure Boot, vTPM, static memory)'

# --- Start and clear any "press any key to boot from CD" prompt by spamming Space (~10s). ---
Write-Step 'Starting the VM'
Start-VM -Name $Name
try {
    $vmcs = Get-CimInstance -Namespace 'root\virtualization\v2' -ClassName Msvm_ComputerSystem -Filter "ElementName='$Name'"
    $kbd  = Get-CimAssociatedInstance -InputObject $vmcs -ResultClassName 'Msvm_Keyboard'
    for ($i = 0; $i -lt 20; $i++) {
        Invoke-CimMethod -InputObject $kbd -MethodName TypeKey -Arguments @{ keyCode = [uint16]0x20 } | Out-Null
        Start-Sleep -Milliseconds 500
    }
    Write-Ok 'sent Space to clear the boot prompt'
} catch {
    Write-Note "could not drive the keyboard ($($_.Exception.Message)); if it is waiting at 'press any key', press one at the VM console."
}

# --- Wait for the guest heartbeat, then for firstboot.ps1 to write done.txt. ---
Write-Step 'Waiting for the install (heartbeat, then C:\setup\done.txt)'
Wait-VM -Name $Name -For Heartbeat -Timeout ($InstallTimeoutMin * 60)
$cred = New-Object System.Management.Automation.PSCredential(
    $User, (ConvertTo-SecureString $Password -AsPlainText -Force))
$deadline = (Get-Date).AddMinutes($InstallTimeoutMin)
$doneLines = $null
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 15
    try {
        $doneLines = Invoke-Command -VMName $Name -Credential $cred -ErrorAction Stop -ScriptBlock {
            if (Test-Path 'C:\setup\done.txt') { Get-Content 'C:\setup\done.txt' }
        }
    } catch { $doneLines = $null }   # account not ready yet, or still installing.
    if ($doneLines) { break }
}
if (-not $doneLines) {
    throw "timed out after $InstallTimeoutMin min waiting for C:\setup\done.txt. The config ISO (holds credentials) is still at $ConfigIsoPath."
}
Write-Ok 'first-boot chain reported:'
$doneLines | ForEach-Object { Write-Host "      $_" }
# Never checkpoint a half-built guest: leave it running so C:\setup\firstboot.log can be read.
if (-not ($doneLines -contains 'overall=OK')) {
    throw "first-boot chain reported issues - no checkpoint taken. Read C:\setup\firstboot.log in the guest. The config ISO (holds credentials) is still at $ConfigIsoPath."
}

# --- Eject and delete the config ISO (it holds the guest password). ---
Write-Step 'Finishing the VM'
Get-VMDvdDrive -VMName $Name | Set-VMDvdDrive -Path $null
Remove-Item $ConfigIsoPath -Force
Write-Ok 'ISOs ejected; config ISO deleted'

# --- Persistent AutoLogon, so the 'clean' checkpoint (and every revert) is a logged-on desktop.
#     The unattend AutoLogon ran once for firstboot.ps1 and is spent; set it for every boot. ---
Invoke-Command -VMName $Name -Credential $cred -ArgumentList $User, $Password, $ComputerName -ScriptBlock {
    param($u, $p, $d)
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Set-ItemProperty -Path $wl -Name AutoAdminLogon -Value '1'
    Set-ItemProperty -Path $wl -Name DefaultUserName -Value $u
    Set-ItemProperty -Path $wl -Name DefaultPassword -Value $p
    Set-ItemProperty -Path $wl -Name DefaultDomainName -Value $d
    Remove-ItemProperty -Path $wl -Name AutoLogonCount -ErrorAction SilentlyContinue
}
Write-Ok 'persistent AutoLogon set'

# --- Reboot so the quiet settings are live, wait for the desktop, then checkpoint. ---
Restart-VM -Name $Name -Type Reboot -Force   # graceful: a hard Reset re-enabled ScheduledDefrag.
Wait-VM -Name $Name -For Heartbeat -Timeout 600
$deadline = (Get-Date).AddMinutes(10)
$loggedOn = $false
while (-not $loggedOn -and (Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 10
    try {
        $loggedOn = Invoke-Command -VMName $Name -Credential $cred -ErrorAction Stop -ScriptBlock {
            [bool](Get-Process explorer -ErrorAction SilentlyContinue)
        }
    } catch { $loggedOn = $false }
}
if (-not $loggedOn) { throw 'the guest did not reach the desktop within 10 min after the reboot - no checkpoint taken. Check AutoLogon at the VM console.' }
Write-Ok 'guest logged on'
Checkpoint-VM -Name $Name -SnapshotName 'clean'
Write-Ok "checkpoint 'clean' taken ($CheckpointType)"

Write-Host ''
Write-Host "Done. '$Name' is installed and quieted; revert to 'clean' before each analysis." -ForegroundColor Cyan
Write-Host 'Golden parent (optional): Export the VHDX read-only and make future guests New-VHD -Differencing clones of it.' -ForegroundColor DarkGray
