<#
.SYNOPSIS
    Convert a CAPEsolo guest VHDX to qcow2/vmdk/vdi/raw for KVM, Proxmox, VMware or VirtualBox,
    using qemu-img on the Hyper-V host.

.DESCRIPTION
    Either point at a standalone VHDX with -Source, or give -VMName (and optionally -Checkpoint) to
    export a checkpoint first - exporting merges the AVHDX differencing chain into one standalone
    VHDX, which qemu-img needs because it cannot follow a Hyper-V differencing chain.

    After converting it prints qemu-img info on the result and a short list of target-side notes
    (firmware, TPM, BitLocker, storage/NIC drivers, the new IP). docs\guest_install.md expands them.

    Booting the converted disk on a real KVM/VMware host is yours to test; this script only produces
    the image and verifies it parses as the target format.

.PARAMETER Source         A standalone .vhdx to convert. Mutually exclusive with -VMName.
.PARAMETER VMName         Export this VM's checkpoint and convert the merged VHDX.
.PARAMETER Checkpoint     Checkpoint name to export for -VMName. Default 'clean'.
.PARAMETER Format         Output format: qcow2 (default), vmdk, vdi or raw.
.PARAMETER VmdkSubformat  vmdk only: monolithicSparse (Workstation/Fusion, default) or
                          streamOptimized (ESXi/OVA import).
.PARAMETER OutDir         Output directory. Default: the source's directory.
.PARAMETER QemuImg        Explicit qemu-img.exe path. Default: PATH, then C:\Program Files\qemu.
.PARAMETER KeepExport     Keep the temporary VM export (for -VMName) instead of deleting it.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\convert_guest_disk.ps1 -VMName CAPEsolo-guest -Format qcow2

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\convert_guest_disk.ps1 -Source D:\vm\guest.vhdx -Format vmdk -VmdkSubformat streamOptimized

.NOTES
    Self-elevates only for the -VMName export path (Hyper-V cmdlets need admin). Windows PowerShell
    5.1 compatible, pure ASCII.
#>
[CmdletBinding()]
param(
    [string] $Source,
    [string] $VMName,
    [string] $Checkpoint = 'clean',
    [ValidateSet('qcow2', 'vmdk', 'vdi', 'raw')] [string] $Format = 'qcow2',
    [ValidateSet('monolithicSparse', 'streamOptimized')] [string] $VmdkSubformat = 'monolithicSparse',
    [string] $OutDir,
    [string] $QemuImg,
    [switch] $KeepExport
)

$ErrorActionPreference = 'Stop'

function Write-Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "    [ok] $m" -ForegroundColor Green }
function Write-Note($m) { Write-Host "    [!!] $m" -ForegroundColor Yellow }

if (-not $Source -and -not $VMName) { throw 'Supply -Source <vhdx> or -VMName <vm>.' }
if ($Source -and $VMName)           { throw '-Source and -VMName are mutually exclusive.' }

# --- Self-elevate only for the export path (Hyper-V cmdlets need admin; -Source alone does not). ---
if ($VMName) {
    $isAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltinRole]::Administrator)
    if (-not $isAdmin) {
        Write-Note 'Not elevated - relaunching as Administrator for the VM export...'
        $a = @('-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
        foreach ($kv in $PSBoundParameters.GetEnumerator()) {
            if ($kv.Value -is [System.Management.Automation.SwitchParameter]) {
                if ($kv.Value.IsPresent) { $a += "-$($kv.Key)" }
            } else { $a += @("-$($kv.Key)", "`"$($kv.Value)`"") }
        }
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $a
        return
    }
}

# --- Locate qemu-img. ---
function Resolve-QemuImg {
    if ($QemuImg) {
        if (Test-Path $QemuImg) { return $QemuImg }
        throw "qemu-img not found at -QemuImg path: $QemuImg"
    }
    $cmd = Get-Command qemu-img.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $pf = Join-Path $env:ProgramFiles 'qemu\qemu-img.exe'
    if (Test-Path $pf) { return $pf }
    throw ("qemu-img not found. Install QEMU for Windows (https://qemu.weilnetz.de/w64/) or " +
           "'winget install --id SoftwareFreedomConservancy.QEMU', or pass -QemuImg <path>.")
}
$qemu = Resolve-QemuImg
Write-Ok "qemu-img: $qemu"

# --- Resolve the source VHDX. ---
$exportTmp = $null
if ($VMName) {
    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) { throw 'the Hyper-V PowerShell module is not available.' }
    $snap = Get-VMSnapshot -VMName $VMName -Name $Checkpoint -ErrorAction SilentlyContinue
    if (-not $snap) { throw "checkpoint '$Checkpoint' not found on VM '$VMName'." }
    $exportTmp = Join-Path $env:TEMP "capesolo_export_$VMName"
    if (Test-Path $exportTmp) { Remove-Item $exportTmp -Recurse -Force }
    New-Item -ItemType Directory -Path $exportTmp | Out-Null
    Write-Step "Exporting checkpoint '$Checkpoint' of '$VMName' (merges the differencing chain)"
    $snap | Export-VMSnapshot -Path $exportTmp
    $Source = (Get-ChildItem -Path $exportTmp -Recurse -Filter '*.vhdx' |
               Where-Object { $_.Extension -eq '.vhdx' } | Select-Object -First 1).FullName
    if (-not $Source) { throw "no VHDX found in the export under $exportTmp." }
    Write-Ok "exported VHDX: $Source"
}

if (-not (Test-Path $Source)) { throw "source not found: $Source" }
if ([IO.Path]::GetExtension($Source) -ieq '.avhdx') {
    throw 'source is an AVHDX differencing disk; use -VMName to export a merged VHDX, or point at the parent VHDX.'
}
# Refuse if the source VHDX is attached to a running VM (the file is locked / would be inconsistent).
$attached = Get-VM -ErrorAction SilentlyContinue | Get-VMHardDiskDrive -ErrorAction SilentlyContinue |
            Where-Object { $_.Path -ieq $Source }
if ($attached) {
    $running = $attached | ForEach-Object { Get-VM -Id $_.VMId } | Where-Object { $_.State -ne 'Off' }
    if ($running) { throw "source VHDX is attached to a running VM ($($running.Name -join ', ')); stop it or export a checkpoint instead." }
}

if (-not $OutDir) { $OutDir = Split-Path $Source -Parent }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$ext = @{ qcow2 = 'qcow2'; vmdk = 'vmdk'; vdi = 'vdi'; raw = 'raw' }[$Format]
$out = Join-Path $OutDir ("{0}.{1}" -f [IO.Path]::GetFileNameWithoutExtension($Source), $ext)
if (Test-Path $out) { throw "output already exists: $out. Delete it or choose another -OutDir." }

# --- Convert. ---
Write-Step "Converting to $Format -> $out"
$cargs = @('convert', '-p', '-O', $Format)
if ($Format -eq 'vmdk') { $cargs += @('-o', "subformat=$VmdkSubformat") }
$cargs += @($Source, $out)
& $qemu @cargs
if ($LASTEXITCODE -ne 0) { throw "qemu-img convert failed (exit $LASTEXITCODE)." }
Write-Ok "converted: $out"

Write-Step 'qemu-img info'
& $qemu info $out
if ($LASTEXITCODE -ne 0) { throw "qemu-img info could not read the converted image (exit $LASTEXITCODE)." }

if ($exportTmp -and -not $KeepExport) {
    Remove-Item $exportTmp -Recurse -Force
    Write-Note "removed temporary export $exportTmp (pass -KeepExport to keep it)"
}

# --- Target-side notes (expanded in docs\guest_install.md). ---
Write-Host ''
Write-Host 'Target-side notes (the guest was Gen2 = UEFI in every case):' -ForegroundColor Cyan
Write-Host '  * Firmware: KVM/Proxmox use OVMF (Proxmox: bios: ovmf + an EFI disk); VMware firmware="efi"; VirtualBox: enable EFI.' -ForegroundColor DarkGray
Write-Host '  * TPM: an existing install boots without one. Add where cheap: libvirt swtpm, Proxmox tpmstate, VirtualBox 7 TPM 2.0. VMware vTPM needs VM encryption.' -ForegroundColor DarkGray
Write-Host '  * BitLocker must be OFF before converting (manage-bde -status); the quiet script sets PreventDeviceEncryption.' -ForegroundColor DarkGray
Write-Host '  * Storage/NIC: KVM/Proxmox boot first with SATA/AHCI + e1000e (or install virtio-win first, then virtio-scsi/virtio-net); VMware LSI SAS/NVMe + e1000e; VirtualBox AHCI.' -ForegroundColor DarkGray
Write-Host '  * After first boot the NIC gets a new IP: update the MCP host/IP in the guest cfg.ini and the host client config, re-check the TCP 8000 rule, and take a new clean snapshot.' -ForegroundColor DarkGray
