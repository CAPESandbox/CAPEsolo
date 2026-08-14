<#
.SYNOPSIS
    Provision a Windows 10/11 CAPEsolo analysis guest for Node.js sample instrumentation.

.DESCRIPTION
    Installs Node.js (LTS), the npm packages JavaScript malware commonly require()s (including the
    userland 'punycode'), and sets a machine-scope NODE_PATH so those packages resolve for a script
    dropped in any directory (e.g. %TEMP%, where the analyzer runs the sample).

    Why each piece matters - the js_console auxiliary (CAPEsolo/modules/auxiliary/js_console.py)
    instruments every node.exe/bun spawned during an analysis by setting
    NODE_OPTIONS=--require <interceptor> (and BUN_OPTIONS=--preload) at run time, and its interceptor
    replaces the deprecated builtin 'punycode' with the userland package. This script only prepares
    the environment the interceptor and the samples depend on:
      * Node.js on PATH (all users, so a node.exe started by a service or another user sees it);
      * the packages samples import, installed globally;
      * NODE_PATH -> the global node_modules, WITHOUT which require('axios') fails for a sample in
        %TEMP% even though the package is "installed" - this is the easy-to-miss linchpin.
    It does NOT set NODE_OPTIONS: the auxiliary does that per analysis.

    Run once on a clean VM, verify, then snapshot the state the sandbox reverts to.

.PARAMETER Packages
    npm packages to install globally. Default covers the transports the interceptor recognises
    (axios / request / socket.io-client) plus common dependencies, and the userland punycode.

.PARAMETER InstallBun
    Also install Bun (the auxiliary sets BUN_OPTIONS as well).

.PARAMETER SkipNodeInstall
    Node.js is already installed; only do packages + NODE_PATH.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\setup_nodejs_guest.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\setup_nodejs_guest.ps1 -InstallBun -Packages axios,ws,got

.NOTES
    Self-elevates (admin is needed for machine-scope NODE_PATH and an all-users Node install).
    Requires Internet during setup - isolate the guest network before detonating samples.
#>
[CmdletBinding()]
param(
    [string[]] $Packages = @(
        'punycode', 'axios', 'request', 'node-fetch', 'socket.io-client', 'ws', 'form-data'
    ),
    [switch] $InstallBun,
    [switch] $SkipNodeInstall
)

$ErrorActionPreference = 'Stop'

function Write-Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "    [ok] $m" -ForegroundColor Green }
function Write-Note($m) { Write-Host "    [!!] $m" -ForegroundColor Yellow }

# --- Self-elevate: machine-scope NODE_PATH and an all-users Node install both need admin. ---
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
    Write-Note 'Not elevated - relaunching as Administrator...'
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($InstallBun)      { $a += '-InstallBun' }
    if ($SkipNodeInstall) { $a += '-SkipNodeInstall' }
    if ($Packages)        { $a += @('-Packages', ($Packages -join ',')) }
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $a
    return
}

function Update-SessionPath {
    # winget/MSI persist PATH to the registry but not to this process; refresh it.
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                [Environment]::GetEnvironmentVariable('Path', 'User')
}

# --- Node.js ---
if (-not $SkipNodeInstall) {
    Write-Step 'Installing Node.js LTS'
    if (Get-Command node -ErrorAction SilentlyContinue) {
        Write-Ok "node already present: $(node -v)"
    }
    elseif (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id OpenJS.NodeJS.LTS -e --source winget `
            --accept-package-agreements --accept-source-agreements
        Update-SessionPath
        Write-Ok 'Node.js installed via winget'
    }
    else {
        throw ('winget not found and Node.js is not installed. Install the Node.js LTS x64 MSI ' +
               'from https://nodejs.org, then re-run this script with -SkipNodeInstall.')
    }
}

Update-SessionPath
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw 'node is still not on PATH. Open a new shell (or reboot) and re-run with -SkipNodeInstall.'
}
Write-Ok "node $(node -v), npm $(npm -v)"

# --- Bun (optional) ---
if ($InstallBun) {
    Write-Step 'Installing Bun'
    try {
        Invoke-RestMethod https://bun.sh/install.ps1 | Invoke-Expression
        Write-Ok 'Bun installed'
    } catch {
        Write-Note "Bun install failed: $($_.Exception.Message)"
    }
}

# --- npm packages (global). punycode userland is included so the interceptor can use it. ---
Write-Step ("Installing npm packages globally: {0}" -f ($Packages -join ', '))
npm install --global $Packages
if ($LASTEXITCODE -ne 0) { throw "npm install failed (exit $LASTEXITCODE)." }
Write-Ok 'packages installed'

# --- NODE_PATH so require() finds the global packages from any working directory. ---
Write-Step 'Setting machine-scope NODE_PATH'
$nodeRoot = (npm root -g).Trim()
if (-not (Test-Path $nodeRoot)) { throw "npm root -g returned a missing path: $nodeRoot" }
[Environment]::SetEnvironmentVariable('NODE_PATH', $nodeRoot, 'Machine')
$env:NODE_PATH = $nodeRoot
Write-Ok "NODE_PATH = $nodeRoot"

# --- Verify resolution. punycode is a core name (core wins over NODE_PATH), so verify the
#     userland copy is present on disk rather than via require(). ---
Write-Step 'Verifying package resolution'
$userland = $Packages | Where-Object { $_ -ne 'punycode' }
if ($userland) {
    $expr = ($userland | ForEach-Object { "require('$_')" }) -join ';'
    & node -e "$expr; console.log('resolve-ok')"
    if ($LASTEXITCODE -ne 0) {
        Write-Note 'One or more packages failed to resolve - check NODE_PATH in a NEW shell.'
    } else {
        Write-Ok 'all userland packages resolve via NODE_PATH'
    }
}
if ($Packages -contains 'punycode') {
    if (Test-Path (Join-Path $nodeRoot 'punycode')) { Write-Ok 'userland punycode installed' }
    else { Write-Note "userland punycode not found under $nodeRoot" }
}

Write-Host ''
Write-Host 'Done. Open a NEW shell to confirm `node -v` and $env:NODE_PATH, then snapshot the clean VM.' -ForegroundColor Cyan
Write-Host 'NODE_OPTIONS is set per-analysis by the js_console auxiliary - do not set it here.' -ForegroundColor DarkGray
