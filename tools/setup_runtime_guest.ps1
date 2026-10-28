<#
.SYNOPSIS
    Provision a Windows 10/11 CAPEsolo analysis guest with the common runtime baseline:
    Python 3.13, the latest 7-Zip, and the x64 + x86 Visual C++ 2015-2022 redistributables.

.DESCRIPTION
    Installs, in order:
      * the current winget (App Installer) from its GitHub release, unless the 'winget' source
        already updates - the inbox client (1.2 on 22631) fails 'winget source update' with
        "Cancelled", and setup_quiet_guest.ps1 turns off the Store updates that would replace it;
      * Python 3.13 (all-users, prepended to PATH, 64-bit) - for tooling/scripts run in the guest;
      * the latest 7-Zip - archive extraction;
      * the Visual C++ 2015-2022 redistributables, both x64 and x86 - many native samples and
        analyzer components link against them.

    Each component is installed winget-first with a pinned direct-download fallback, so the script
    works on a guest that has no winget/Store (the fallback URLs are overridable for an air-gapped
    guest that pulls installers from a local host). Re-runs are idempotent: an already-provisioned
    component is detected and skipped.

    Run once on a clean VM, verify, then snapshot the state the sandbox reverts to.

.PARAMETER SkipWinget
    Do not update winget.

.PARAMETER WingetReleaseUrl
    Where DesktopAppInstaller_Dependencies.zip and Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
    are downloaded from. Defaults to the latest winget-cli GitHub release.

.PARAMETER SkipPython
    Do not install Python.

.PARAMETER Skip7Zip
    Do not install 7-Zip.

.PARAMETER SkipVCRedist
    Do not install the Visual C++ redistributables.

.PARAMETER PythonExeUrl
    Explicit Python 3.13 x64 installer URL used by the no-winget fallback (e.g. a locally hosted
    installer for an air-gapped guest). Defaults to a pinned python.org 3.13 amd64 build; winget
    remains the source of the newest 3.13.x patch when available.

.PARAMETER SevenZipExeUrl
    Explicit 7-Zip x64 installer URL used by the no-winget fallback. Defaults to a pinned
    7-zip.org build; winget remains the source of the newest release when available.

.PARAMETER VCRedistX64Url
    x64 VC++ redistributable installer URL used by the no-winget fallback.

.PARAMETER VCRedistX86Url
    x86 VC++ redistributable installer URL used by the no-winget fallback.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\setup_runtime_guest.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\setup_runtime_guest.ps1 -SkipVCRedist

.NOTES
    Self-elevates (admin is needed for all-users installs and machine-scope PATH).
    Requires Internet (or a local installer host) during setup - isolate the guest network
    before detonating samples.
#>
[CmdletBinding()]
param(
    [switch] $SkipWinget,
    [switch] $SkipPython,
    [switch] $Skip7Zip,
    [switch] $SkipVCRedist,
    [string] $PythonExeUrl   = 'https://www.python.org/ftp/python/3.13.1/python-3.13.1-amd64.exe',
    [string] $SevenZipExeUrl = 'https://www.7-zip.org/a/7z2408-x64.exe',
    [string] $VCRedistX64Url = 'https://aka.ms/vs/17/release/vc_redist.x64.exe',
    [string] $VCRedistX86Url = 'https://aka.ms/vs/17/release/vc_redist.x86.exe',
    [string] $WingetReleaseUrl = 'https://github.com/microsoft/winget-cli/releases/latest/download'
)

$ErrorActionPreference = 'Stop'

function Write-Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "    [ok] $m" -ForegroundColor Green }
function Write-Note($m) { Write-Host "    [!!] $m" -ForegroundColor Yellow }

# --- Self-elevate: all-users installs and machine-scope PATH both need admin. ---
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
    Write-Note 'Not elevated - relaunching as Administrator...'
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($SkipWinget)     { $a += '-SkipWinget' }
    if ($SkipPython)     { $a += '-SkipPython' }
    if ($Skip7Zip)       { $a += '-Skip7Zip' }
    if ($SkipVCRedist)   { $a += '-SkipVCRedist' }
    if ($PythonExeUrl)   { $a += @('-PythonExeUrl', $PythonExeUrl) }
    if ($SevenZipExeUrl) { $a += @('-SevenZipExeUrl', $SevenZipExeUrl) }
    if ($VCRedistX64Url) { $a += @('-VCRedistX64Url', $VCRedistX64Url) }
    if ($VCRedistX86Url) { $a += @('-VCRedistX86Url', $VCRedistX86Url) }
    if ($WingetReleaseUrl) { $a += @('-WingetReleaseUrl', $WingetReleaseUrl) }
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $a
    return
}

function Update-SessionPath {
    # winget/installers persist PATH to the registry but not to this process; refresh it.
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                [Environment]::GetEnvironmentVariable('Path', 'User')
}

function Invoke-SilentExe {
    # Run a downloaded installer and wait; throw unless the exit code is an accepted one.
    # okCodes typically includes 3010 (success, reboot required) and 1638 (a newer version present).
    param([string] $Path, [string[]] $Arguments, [int[]] $OkCodes = @(0, 3010))
    $proc = Start-Process -FilePath $Path -ArgumentList $Arguments -Wait -PassThru
    if ($OkCodes -notcontains $proc.ExitCode) {
        throw "installer '$([IO.Path]::GetFileName($Path))' failed (exit $($proc.ExitCode))."
    }
    return $proc.ExitCode
}

function Install-ViaWingetOrExe {
    # winget-first with a pinned direct-download fallback, mirroring Install-NodeMsi in
    # setup_nodejs_guest.ps1. Downloads $Url to %TEMP% and runs it silently when winget is absent.
    param(
        [string]   $Name,
        [string]   $WingetId,
        [string]   $Url,
        [string[]] $SilentArgs,
        [int[]]    $OkCodes = @(0, 3010)
    )
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id $WingetId -e --source winget `
            --accept-package-agreements --accept-source-agreements
        # winget exit 0 = installed; -1978335189 (0x8A15002B) = no applicable upgrade / already installed.
        if ($LASTEXITCODE -eq 0) { Write-Ok "$Name installed via winget"; return }
        if ($LASTEXITCODE -eq -1978335189) { Write-Ok "$Name already up to date (winget)"; return }
        Write-Note "winget install of $Name returned $LASTEXITCODE - falling back to direct download"
    }
    $exe = Join-Path $env:TEMP ([IO.Path]::GetFileName($Url))
    Write-Step "Downloading $([IO.Path]::GetFileName($Url))"
    Invoke-WebRequest -Uri $Url -OutFile $exe -UseBasicParsing
    Write-Step "Installing $Name (silent)"
    [void](Invoke-SilentExe -Path $exe -Arguments $SilentArgs -OkCodes $OkCodes)
    Write-Ok "$Name installed via $Url"
}

# --- winget (App Installer) ---
# Best-effort: on failure the installs below fall back to their direct downloads.
if (-not $SkipWinget) {
    Write-Step 'Updating winget (App Installer)'
    $sourceOk = $false
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget source update --name winget | Out-Null
        $sourceOk = ($LASTEXITCODE -eq 0)
    }
    if ($sourceOk) {
        Write-Ok "winget $(winget --version) already updates its source"
    } else {
        $wg = Join-Path $env:TEMP 'winget'
        $pp = $ProgressPreference
        try {
            New-Item -ItemType Directory -Path $wg -Force | Out-Null
            $ProgressPreference = 'SilentlyContinue'   # PS 5.1's progress bar makes the downloads crawl.
            Invoke-WebRequest -Uri "$WingetReleaseUrl/DesktopAppInstaller_Dependencies.zip" `
                -OutFile "$wg\deps.zip" -UseBasicParsing
            Invoke-WebRequest -Uri "$WingetReleaseUrl/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" `
                -OutFile "$wg\winget.msixbundle" -UseBasicParsing
            Expand-Archive -Path "$wg\deps.zip" -DestinationPath "$wg\deps" -Force
            foreach ($dep in Get-ChildItem "$wg\deps" -Recurse -Filter *.appx | Where-Object FullName -match 'x64') {
                # A dependency already present at a higher version refuses to install; that is fine.
                try { Add-AppxPackage -Path $dep.FullName } catch { Write-Note "$($dep.Name): $($_.Exception.Message)" }
            }
            Add-AppxPackage -Path "$wg\winget.msixbundle"
            winget source update --name winget | Out-Null
            if ($LASTEXITCODE -eq 0) { Write-Ok "winget $(winget --version) installed; source updates" }
            else { Write-Note "winget $(winget --version) installed, but 'winget source update' returned $LASTEXITCODE" }
        } catch {
            Write-Note "winget update failed ($($_.Exception.Message)) - using the direct-download fallbacks."
        } finally {
            $ProgressPreference = $pp
        }
    }
}

# --- Python 3.13 ---
if (-not $SkipPython) {
    Write-Step 'Installing Python 3.13'
    $pyVer = ''
    if (Get-Command python -ErrorAction SilentlyContinue) { $pyVer = (& python --version) 2>&1 }
    $doInstall = $true
    if ($pyVer -match '3\.13\.') {
        Write-Ok "python already present: $pyVer"
        $doInstall = $false
    } elseif ($pyVer -match '^Python ') {
        # An older Python is on PATH. Installing 3.13 adds it side-by-side and prepends it to PATH;
        # it does not remove the existing interpreter. Let the operator decide.
        Write-Note "older Python detected: $pyVer"
        $ans = Read-Host 'Install Python 3.13 alongside it (prepended to PATH)? [y = install / N = leave as is]'
        if ($ans -notmatch '^(y|yes)$') {
            Write-Ok "leaving existing Python as is ($pyVer)"
            $doInstall = $false
        }
    }
    if ($doInstall) {
        Install-ViaWingetOrExe -Name 'Python 3.13' -WingetId 'Python.Python.3.13' `
            -Url $PythonExeUrl `
            -SilentArgs @('/quiet', 'InstallAllUsers=1', 'PrependPath=1', 'Include_test=0')
        Update-SessionPath
    }
}

# --- 7-Zip ---
if (-not $Skip7Zip) {
    Write-Step 'Installing 7-Zip'
    if (Test-Path (Join-Path $env:ProgramFiles '7-Zip\7z.exe')) {
        Write-Ok '7-Zip already present'
    } else {
        Install-ViaWingetOrExe -Name '7-Zip' -WingetId '7zip.7zip' `
            -Url $SevenZipExeUrl -SilentArgs @('/S')
        Update-SessionPath
    }
}

# --- Visual C++ 2015-2022 redistributables (x64 + x86) ---
if (-not $SkipVCRedist) {
    Write-Step 'Installing Visual C++ 2015-2022 redistributables (x64 + x86)'
    # 1638 = a newer version is already installed; accept it alongside 0 and 3010.
    Install-ViaWingetOrExe -Name 'VC++ redist x64' -WingetId 'Microsoft.VCRedist.2015+.x64' `
        -Url $VCRedistX64Url -SilentArgs @('/install', '/quiet', '/norestart') `
        -OkCodes @(0, 3010, 1638)
    Install-ViaWingetOrExe -Name 'VC++ redist x86' -WingetId 'Microsoft.VCRedist.2015+.x86' `
        -Url $VCRedistX86Url -SilentArgs @('/install', '/quiet', '/norestart') `
        -OkCodes @(0, 3010, 1638)
}

# --- Verify ---
Update-SessionPath
Write-Step 'Verifying installed runtime'

if (-not $SkipPython) {
    if ((Get-Command python -ErrorAction SilentlyContinue) -and ((& python --version) 2>&1) -match '3\.13\.') {
        Write-Ok "$((& python --version) 2>&1), $((& python -m pip --version) 2>&1)"
    } else {
        Write-Note 'python 3.13 not resolving on PATH - open a NEW shell (or reboot) and re-check.'
    }
}

if (-not $Skip7Zip) {
    $sevenZip = Join-Path $env:ProgramFiles '7-Zip\7z.exe'
    if (Test-Path $sevenZip) {
        $banner = (& $sevenZip | Select-Object -First 2) -join ' '
        Write-Ok "7-Zip: $banner"
    } else {
        Write-Note "7z.exe not found under $env:ProgramFiles\7-Zip."
    }
}

if (-not $SkipVCRedist) {
    # x64 lives under the native key; x86 under WOW6432Node on 64-bit Windows.
    $vcKeys = @{
        x64 = 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64'
        x86 = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x86'
    }
    foreach ($arch in 'x64', 'x86') {
        $key = $vcKeys[$arch]
        if ((Test-Path $key) -and ((Get-ItemProperty $key).Installed -eq 1)) {
            $v = (Get-ItemProperty $key).Version
            Write-Ok "VC++ redist $arch installed ($v)"
        } else {
            Write-Note "VC++ redist $arch not detected in the registry."
        }
    }
}

Write-Host ''
Write-Host 'Done. Open a NEW shell to confirm `python --version`, `7z`, and the VC++ keys, then snapshot the clean VM.' -ForegroundColor Cyan
