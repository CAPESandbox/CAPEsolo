# Building a CAPEsolo analysis guest

This guide builds the Windows VM that CAPEsolo detonates samples in: a guest where capemon can
inject and hook unhindered, nothing re-enables itself after a reboot, and an idle system makes
almost no network noise so the PCAP and behavior log show the sample's activity only.

It is written for **Hyper-V**. Section 9 covers converting the finished disk for KVM/Proxmox,
VMware or VirtualBox.

**Supported guest OS:** any Windows 10 (build 10240-19045) or Windows 11 23H2 (build 22631). Other
Windows 11 releases (21H2/22H2, 24H2 and later) are **not** supported here: 24H2 ships a new
`ntdll`/monitor surface this project has not validated, and capemon behaviour on it is unproven.

Windows 10 servicing ended 2025-10-14, and Windows 11 23H2 servicing ended 2025-11-11 for Home/Pro
(Enterprise/Education run to 2026-11-10). That is acceptable here: updates are turned off and the
guest is reverted after every analysis, so it never accumulates state or drifts.

The tooling (all under `tools/`):

| Script | Runs on | Does |
| --- | --- | --- |
| `build_guest.ps1` | host | master: `new_guest_vm.ps1` plus the section 10 checks and MCP registration |
| `new_guest_vm.ps1` | host | ISO to a clean checkpoint, unattended |
| `guest/autounattend.xml` | (in the VM) | unattended-install answer file (a template) |
| `guest/firstboot.ps1` | guest | runs the setup chain at first logon, writes `C:\setup\done.txt` |
| `setup_runtime_guest.ps1` | guest | current winget (the inbox client cannot update its source), Python 3.13, 7-Zip, VC++ redistributables |
| `setup_nodejs_guest.ps1` | guest | Node.js + the npm packages JS samples need (optional) |
| `setup_quiet_guest.ps1` | guest | harden and quiet: Defender, Update, Edge, SmartScreen, noise |
| `convert_guest_disk.ps1` | host | convert the VHDX for another hypervisor |

---

## 1. Requirements

* A Hyper-V host (Windows 10/11 Pro or Windows Server with the Hyper-V role and PowerShell module).
* A Windows 10 (any) or Windows 11 23H2 installation ISO. Check the build before you start:

  ```powershell
  $m = Mount-DiskImage -ImagePath D:\Win11_23H2.iso -PassThru
  $d = ($m | Get-Volume).DriveLetter
  (Get-WindowsImage -ImagePath "$d`:\sources\install.wim" -Index 1).Version   # or install.esd
  Dismount-DiskImage -ImagePath D:\Win11_23H2.iso
  ```

  The third number is the build (e.g. `10.0.22631` -> 22631). `new_guest_vm.ps1` runs this check for
  you and refuses an unsupported build unless you pass `-Force`.
* Suggested sizing: 4 vCPU, 8 GB RAM, 80 GB disk.

---

## 2. Path A - automated (from an ISO)

From an elevated shell on the host:

```powershell
powershell -ExecutionPolicy Bypass -File tools\new_guest_vm.ps1 `
    -IsoPath D:\Win11_23H2.iso -Name CAPEsolo-guest -Password '<local-admin-password>'
```

If you leave out `-Name`, the script asks for the VM name (Enter accepts `CAPEsolo-guest`); pass
`-Name` for unattended or agent-driven runs.

It fills `autounattend.xml`, builds a config ISO (the answer file at the root; `firstboot.ps1` and
the three `setup_*_guest.ps1` under `\setup`), creates a Generation 2 VM with Secure Boot and a
vTPM, boots it, and waits for `C:\setup\done.txt`. After installing CAPEsolo, `firstboot.ps1` puts a
`CAPEsolo` shortcut (run as administrator, `capesolo.ico`) on the Public Desktop. Then:

* If `done.txt` does not say `overall=OK`, it stops **without** a checkpoint and leaves the VM
  running so you can read `C:\setup\firstboot.log`.
* Otherwise it ejects both ISOs, deletes the config ISO, turns on persistent AutoLogon, reboots so
  the quiet settings are live, waits for the desktop, and takes the `clean` checkpoint. A revert
  therefore lands on a running, logged-on guest.

Persistent AutoLogon stores the guest password in the guest's Winlogon registry key (the usual
trade-off for a sandbox guest). The copies Setup caches under `C:\Windows\Panther` are deleted by
`firstboot.ps1`.

**One-shot build.** `build_guest.ps1` takes the same switches, runs `new_guest_vm.ps1`, then steps
3-5 of section 10: audit, two graceful reboots and a re-audit (applying the quiet script once if
anything is `[!!]`, and re-taking `clean` if it did), the revert + 25 h clock-jump wuauserv check,
and a pktmon idle capture copied to `-OutDir`. It registers the MCP endpoint on the host
(`claude mcp add -s user`, `http://<ComputerName>.mshome.net:8000/mcp`; an existing entry of that
name is left alone) but does not start CAPEsolo-mcp in the guest, and finishes reverted to `clean`:

```powershell
powershell -ExecutionPolicy Bypass -File tools\build_guest.ps1 `
    -IsoPath D:\Win11_23H2.iso -Name CAPEsolo-guest -Password '<local-admin-password>'
```

Its own switches: `-RevertCheckMinutes` (default 10), `-IdleMinutes` (default 15, 0 skips the
capture), `-McpName` (default `capesolo`), `-OutDir`.

Useful switches:

* `-IncludeNode` - also install Node.js (stages a `node.enabled` flag that `firstboot.ps1` keys off).
* `-WheelPath C:\path\CAPEsolo-x.y.z-py3-none-any.whl` - install CAPEsolo from a local wheel instead
  of PyPI (staged under `\setup`; `firstboot.ps1` prefers a `CAPEsolo*.whl` there over PyPI).
* `-CheckpointType Standard|Production` - `Standard` (default) reverts to a running, logged-on guest,
  which is what the revert-before-each-analysis workflow wants; `Production` restores powered-off.
* `-MemoryGB`, `-Cpu`, `-DiskGB`, `-Switch` (checked before anything is created), `-User`,
  `-ComputerName` (max 15 characters - the NetBIOS limit), `-ProductKey` / `-NoProductKey`,
  `-ImageName` / `-ImageIndex` (see "Product key and edition"), `-VhdPath`,
  `-ConfigIsoPath`, `-InstallTimeoutMin`.
* `-Force` - overwrite an existing VM/VHDX, or proceed on an unsupported build.
* `-ConfigIsoOnly` - build and report the config ISO, then stop (no admin, no VM) - a dry run.

The config ISO holds the guest credentials and is written outside the repo (default
`%TEMP%\capesolo_<Name>_config.iso`). A successful build deletes it, along with its staging
folder. If a build stops early, the error message gives the ISO's path so you can delete it.
`-ConfigIsoOnly` keeps both for inspection; delete them yourself afterwards.

### Product key and edition

Setup uses the answer file's product key to pick the edition and to skip the key page.

* **Default:** the Enterprise generic key `XGVPP-NMH47-7TTHJ-W3FW7-8HV2C`. It selects Enterprise
  (better policy support) and does **not** activate Windows. Use `-ProductKey
  W269N-WFGWX-YVC9B-4J6C9-T83GX` for Pro, or the IoT Enterprise LTSC key `KBN8V-HFGQ4-MGXVD-347P6-PDQGT`.
* **Your own key:** `-ProductKey <key>` installs that key's edition and activates online during
  setup. It must match an edition on the ISO. Malware in the guest can read the installed key, so
  use one you would not mind losing.
* **`-NoProductKey` (not recommended):** leaves the key out of the answer file and selects the
  image with `-ImageName`/`-ImageIndex` instead. On a multi-edition ISO (Pro + Enterprise, 22631)
  Setup does not accept this: with the `<ProductKey>` block removed it stops at "Windows cannot read
  the `<ProductKey>` setting from the unattend answer file", and with an all-zero placeholder key it
  stops at the "Activate Windows" page. Both need the console, and nothing is installed. It is
  untested on a single-edition ISO. Use the edition's generic key instead: it only selects the
  edition, so a pre-activated ISO's own activation (for example a `sources\$OEM$` SetupComplete
  script) still runs at the end of setup.

The script's build check prints the ISO's first image (`image: Windows 11 Pro` on a Pro + Enterprise
ISO) whatever key you pass; the key decides the edition that is installed. Confirm it in the guest
with `(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID`.

An unactivated guest works normally for analysis, but Settings blocks Personalization (Background,
Colors, Lock screen) until Windows is activated. The black background is still applied by the
script; you just cannot change it in Settings until then.

---

## 3. Path B - manual (build the VM yourself)

Create a Gen2 VM in Hyper-V Manager (or with the cmdlets below), then run the guest scripts in
order. This is the fallback if you would rather not use `new_guest_vm.ps1`.

```powershell
New-VM -Name CAPEsolo-guest -Generation 2 -MemoryStartupBytes 8GB `
    -NewVHDPath D:\vm\CAPEsolo-guest.vhdx -NewVHDSizeBytes 80GB -SwitchName 'Default Switch'
Set-VMProcessor CAPEsolo-guest -Count 4
Set-VMMemory CAPEsolo-guest -DynamicMemoryEnabled $false
Set-VM CAPEsolo-guest -AutomaticCheckpointsEnabled $false -CheckpointType Standard
Set-VMFirmware CAPEsolo-guest -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows
Set-VMKeyProtector CAPEsolo-guest -NewLocalKeyProtector
Enable-VMTPM CAPEsolo-guest
Add-VMDvdDrive CAPEsolo-guest -Path D:\Win11_23H2.iso
```

Install Windows and create a **local administrator** account. If Windows 11 OOBE insists on a
Microsoft account, press Shift+F10, run `oobe\BypassNRO`, and after the reboot choose "I don't have
internet" to get the local-account path. Then from an elevated PowerShell in the guest run the
scripts in this order (the order matters - the quiet script disables the Store,
Delivery Optimization, NCSI and root-cert updates that the earlier downloads rely on, so it is
always last):

```powershell
powershell -ExecutionPolicy Bypass -File setup_runtime_guest.ps1
powershell -ExecutionPolicy Bypass -File setup_nodejs_guest.ps1        # optional
python -m pip install CAPEsolo                                         # or a local wheel
powershell -ExecutionPolicy Bypass -File setup_quiet_guest.ps1
```

Each script self-elevates, is safe to re-run, and ends in a Verify section.

So that a revert lands on a logged-on desktop, turn on persistent AutoLogon (this stores the
password in the guest registry), reboot, and take the `clean` checkpoint once the desktop is up:

```powershell
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty $wl AutoAdminLogon '1'
Set-ItemProperty $wl DefaultUserName '<user>'
Set-ItemProperty $wl DefaultPassword '<password>'
Set-ItemProperty $wl DefaultDomainName $env:COMPUTERNAME
Remove-ItemProperty $wl AutoLogonCount -ErrorAction SilentlyContinue
```

---

## 4. Patching your existing guest

To bring an already-built guest (for example a clean QUEENDRONE snapshot) up to the same baseline
without rebuilding it:

1. Revert the guest to its clean snapshot. Copy `setup_quiet_guest.ps1` in with the script-MCP
   upload or a share - not hand-pasted base64, which corrupts binaries and some scripts.
2. Audit first. Each `[!!]` is a gap in the current snapshot; the list also checks the script
   against a box that already works. The audit exits 1 if anything is `[!!]` and 0 when all is
   `[ok]`. On a build outside the supported ranges it warns but still runs:

   ```powershell
   powershell -ExecutionPolicy Bypass -File setup_quiet_guest.ps1 -AuditOnly
   ```
3. Apply, reboot twice, re-audit, then take a new checkpoint (keep the old one):

   ```powershell
   powershell -ExecutionPolicy Bypass -File setup_quiet_guest.ps1
   ```
4. After a from-scratch build, the same `-AuditOnly` run shows both guests have identical settings.

---

## 5. Defender and Tamper Protection

A policy or a plain admin registry write is **not** enough to turn Defender off on a running guest:
Tamper Protection guards the Defender service keys, and signature/platform updates can re-enable
real-time protection. The script's policies also set `Signature Updates\ScheduleDay=8` (never) so
scheduled signature checks stop. `setup_quiet_guest.ps1` handles the protected keys four ways:

* **Tamper Protection check.** On apply, if Tamper Protection is on the script stops and tells you
  to turn it off: Windows Security > Virus & threat protection > Manage settings > Tamper Protection
  Off. Then re-run.
* **SYSTEM retry.** Some service keys deny an administrator by their ACL rather than through
  Tamper Protection: `SecurityHealthService` and `wscsvc` give `Administrators` only `ReadKey` and
  `SYSTEM` `FullControl`, so a plain write fails with "Requested registry access is not allowed".
  When a service write is denied, the script retries it as SYSTEM through a one-shot scheduled
  task. No Safe Mode or console is needed for these.
* **`-DefenderSafeMode`.** Writes the protected service keys (`WinDefend`, `WdFilter`, `Sense`, ...)
  to `Start=4` durably from Safe Mode: it sets `bcdedit safeboot minimal`, adds a RunOnce that
  re-runs the script in Safe Mode, clears `safeboot` as the first Safe Mode action, writes the keys
  and reboots. Someone must log on at the guest **console** in Safe Mode - PowerShell Direct and the
  heartbeat are not available there. This branch applies only the Defender keys; **re-run without
  `-DefenderSafeMode`** afterwards to apply Updates/Edge/Noise. Use it only for a key that still
  shows `[!!]` after the SYSTEM retry.
* **The specialize pass (from scratch).** `autounattend.xml` sets the Defender service keys to
  `Start=4`, Smart App Control off and `BypassNRO` during the specialize pass, which runs as SYSTEM
  **before** Tamper Protection is active. This is the strongest reason to build from scratch: on
  first boot Defender never starts, so `setup_quiet_guest.ps1` sails past the Tamper Protection
  check with nothing to fight.

Confirm in the guest with `Get-MpComputerStatus` (expect `RealTimeProtectionEnabled False`) and
`sc.exe qc WinDefend` (expect `START_TYPE ... DISABLED`).

---

## 6. What the quiet script changes

`setup_quiet_guest.ps1` is table-driven. `-AuditOnly` reports `[ok]`/`[!!]`/`[n/a]`/`[warn]` per item;
applying runs the same table. Windows 11-only items report `[n/a]` on Windows 10. Each area has a
`-Skip` switch; the convenience, SmartScreen, VBS and firewall items always run.

| Area | Skip with | What, and why |
| --- | --- | --- |
| Defender | `-SkipDefender` | real-time/behavior/on-access/IOAV/script-scan policies off, `DisableAntiSpyware` (older platforms only), MAPS off, `Signature Updates\ScheduleDay=8`, services `Start=4`, `\Windows Defender\*` tasks off - so capemon is not fought and signatures never update. |
| Updates | `-SkipUpdates` | `NoAutoUpdate`, Delivery Optimization off, Store auto-download off, `wuauserv`/`UsoSvc`/`WaaSMedicSvc` (the update repair service) disabled, Update/WaaSMedic tasks off, the installed release pinned - nothing updates or reboots mid-analysis. |
| Edge | `-SkipEdge` | EdgeUpdate services and tasks off and its folder renamed, Enhanced Security off, new-tab MSN content off, startup boost/background mode off; typo protection and network prediction off as defaults you can change. See "Edge on a standalone guest" below. |
| Noise | `-SkipNoise` | telemetry/DiagTrack, error reporting (policy, service and tasks), web search/Bing/Cortana/Widgets/Copilot/Recall, the Win10 news feed, consumer features, background Store apps and silent app installs, lock-screen Spotlight and tips, OneDrive, time sync, Maps (auto-update and MapsBroker), LLMNR/NetBIOS/SSDP/Teredo - idle network chatter. Also the maintenance tasks that would start mid-analysis (scheduled defrag, component cleanup, WinSAT, indexer maintenance); the SysMain and Windows Search services are kept. Application Experience tasks off, and the Program Compatibility Assistant service (`PcaSvc`) disabled, because it re-enables `PcaPatchDbTask` at every boot. Language Components Installer tasks off: `ReconcileLanguageResources` (logon + 2 h) runs as soon as a revert jumps the clock past it and sets `wuauserv` back to demand start. Store `InstallService\*` and `PushToInstall\*` tasks off and the Microsoft Store Install Service (`InstallService`) disabled: whenever it is started (by those tasks once a revert jumps the clock hours past their last run, or by the shell/App Installer during maintenance) it sets `wuauserv` back to demand start. The Store and winget's msstore source cannot install apps in the guest. |
| SmartScreen/MOTW | (always) | Explorer and Store-app SmartScreen off; downloads get no Zone.Identifier. |
| Smart App Control | (always, Win11) | `VerifiedAndReputablePolicyState=0`. Once off it cannot be re-enabled - which is the point. |
| VBS/HVCI/BitLocker | (always) | memory integrity and VBS off, device encryption prevented (24H2 needs it), and a check that the system drive is not already BitLocker-encrypted (reported only - decrypt with `manage-bde -off C:` yourself). |
| Conveniences | (always) | the guest (AutoLogon) user in Administrators; UAC fully off: `EnableLUA=0`, admins elevate without prompting, no secure desktop, the built-in Administrator unfiltered, installer detection and virtualization off, and `LocalAccountTokenFilterPolicy=1` so remote logons by a local admin get the full token; Fast Startup/hibernation/sleep/monitor timeout off, System Restore off, file extensions and hidden files shown, PowerShell execution policy `Bypass` (LocalMachine, 64- and 32-bit), black solid desktop background. |
| Firewall | (always) | left on, with an inbound rule for CAPEsolo-mcp on TCP 8000. |

Optional, off by default (both are tradeoffs):

* `-DisableNcsi` - sets `NoActiveProbe=1`. NCSI's probe is left on so samples that check for Internet
  still see it.
* `-DisableRootAutoUpdate` - sets `DisableRootAutoUpdate=1`. Left on so Authenticode checks on
  samples can fetch root certificates.
* `-DisableFirewall` - turn the firewall off entirely (CAPEv2's guest guide recommends this).

Not changed: system-wide exploit mitigations (CFG and friends). capemon works with the defaults.

### Locked vs changeable settings

Most items are written as Group Policy on purpose, so they cannot be switched back on: Defender,
SmartScreen, download marking, Windows Update, Delivery Optimization, Store updates, telemetry,
error reporting, System Restore, web search, Copilot/Recall, OneDrive, Widgets and the Edge items
that keep it quiet. Settings shows "some settings are managed by your organization" for these;
that is expected.

User-facing preferences are written as ordinary preference values instead, so you can still
change them in Settings:

* desktop background (black, solid color) and lock-screen Spotlight/tips;
* Explorer file extensions and hidden files, sleep/power timeouts;
* Edge typo protection and network prediction (written as "recommended" Edge policies - a default,
  not a lock).

If you change the background or lock screen later, `-AuditOnly` reports it as `[warn]`, not
`[!!]`, and still exits 0.

**Protected items.** Some tasks and service keys refuse even an elevated administrator (for
example `SdbinstMergeDbTask`, `SecurityHealthService`, `wscsvc`, and parts of UpdateOrchestrator and
WaaSMedic). The script retries any denied task or service write as SYSTEM through a one-shot
scheduled task. Only the UpdateOrchestrator/WaaSMedic tasks are reported as `[warn]` if they are
still enabled after that (with `WaaSMedicSvc` disabled, they have nothing to repair); anything else
still enabled stays `[!!]`.

### Edge on a standalone guest

Edge applies some of its policies only on devices joined to Active Directory or Entra ID, or
enrolled in device management. The analysis guest is none of these, so:

* **Edge update policies are ignored.** Updates are stopped instead by the disabled `edgeupdate`
  services and `MicrosoftEdgeUpdateTask*` tasks, and by renaming
  `C:\Program Files (x86)\Microsoft\EdgeUpdate` to `EdgeUpdate.disabled`. Edge itself still runs;
  its About page shows an update error. To undo, rename the folder back.
* **Edge SmartScreen stays on** (`SmartScreenEnabled` is domain-only). It affects only pages and
  downloads opened inside Edge - for example an HTML-smuggling sample. Windows-level SmartScreen
  and download marking are off, and samples normally reach the Desktop by upload. If a sample needs
  it off, toggle it at `edge://settings/privacy` before running it.
* **capemon cannot hook Edge renderer processes on Edge 119 and later.** Edge removed the
  `RendererCodeIntegrityEnabled` policy in 119 and always enforces renderer code integrity, which
  blocks DLLs that are not Microsoft-signed. The script still sets the policy for Edge 118 and
  older. Samples *launched from* Edge are separate processes and are hooked normally.

---

## 7. Verifying the guest

1. **Reboot twice**, then audit - everything should be `[ok]`. Reboot gracefully (from inside the
   guest, or `Restart-VM -Type Reboot` on the host). `Restart-VM -Force` on its own is a hard reset,
   and after hard resets `ScheduledDefrag` was seen enabled again:

   ```powershell
   powershell -ExecutionPolicy Bypass -File setup_quiet_guest.ps1 -AuditOnly
   ```

   `Get-MpComputerStatus` shows real-time protection off; `sc.exe qc WinDefend` shows `DISABLED`.
2. **Idle network.** Capture ~15 minutes of idle traffic and see what talks:

   ```powershell
   pktmon start --capture --pkt-size 0 -f C:\idle.etl
   # wait ~15 minutes
   pktmon stop
   pktmon etl2pcap C:\idle.etl -o C:\idle.pcap
   Get-DnsClientCache | Select-Object Entry, Data
   ```

   Expect close to zero outbound traffic beyond DHCP and anything you deliberately left on (NCSI,
   root-cert/CRL). Capture after a revert with the clock jumped forward (section 10, step 5), since
   that is the state analyses run in. A Windows 11 23H2 Enterprise build measured about 5 MB of
   ETL in 15 minutes that way: certificate checks (CRL/OCSP, `ctldl.windowsupdate.com` root
   lists), device metadata (`go.microsoft.com` fwlink 252669), `settings-win.data.microsoft.com`,
   update configuration lookups (`slscr.update.microsoft.com`, no downloads), the preinstalled
   To Do app (`ecs.office.com`, `to-do.office.com`), push notifications (`wns.windows.com`),
   account sign-in (`login.live.com`) and some Store catalog/licensing. `wuauserv` stayed Disabled.
   A capture that shows tens of MB from `*.delivery.mp.microsoft.com` with a
   `Microsoft-Delivery-Optimization` User-Agent means Windows Update was re-enabled (section 11).
3. **Sanity detonation.** From a fresh revert, detonate one benign sample. The behavior log has API
   calls; `analysis.log` shows no injection or hook errors; a sample launched from Edge is hooked
   (it is a separate process). Edge's own renderer processes are expected to stay unhooked on Edge
   119 and later.

capemon on Windows 11 24H2 is unproven in this project - the sanity detonation is the real gate.
Hyper-V guest artefacts remain detectable by anti-VM samples; that is out of scope here.

---

## 8. Snapshot workflow

* Take the `clean` checkpoint with the guest booted and logged on (autologon), as a **Standard**
  checkpoint, so a revert returns to a ready, running guest.
* **Revert before every analysis.** One sample per revert.
* For many guests, keep the finished VHDX as a read-only golden parent and make each guest a
  differencing clone of it - new guests then appear in seconds:

  ```powershell
  Set-ItemProperty D:\vm\golden.vhdx -Name IsReadOnly -Value $true
  New-VHD -Path D:\vm\guest2.vhdx -ParentPath D:\vm\golden.vhdx -Differencing
  New-VM -Name guest2 -Generation 2 -MemoryStartupBytes 8GB -VHDPath D:\vm\guest2.vhdx -SwitchName 'Default Switch'
  ```

  Never boot or modify the parent - every clone breaks if it changes. Each clone also needs its
  own vTPM and Secure Boot settings (section 3) and its own `clean` checkpoint.

---

## 9. Converting to KVM / Proxmox / VMware / VirtualBox

`convert_guest_disk.ps1` converts the VHDX with `qemu-img`. Export a checkpoint rather than
converting a running disk - exporting merges the differencing (AVHDX) chain into one standalone
VHDX, which `qemu-img` needs. The script refuses an `.avhdx` source, a `-Source` disk attached to
a running VM, and an output file that already exists.

```powershell
# From the VM's clean checkpoint:
powershell -ExecutionPolicy Bypass -File tools\convert_guest_disk.ps1 -VMName CAPEsolo-guest -Format qcow2

# Or from a standalone VHDX, for VMware/ESXi import:
powershell -ExecutionPolicy Bypass -File tools\convert_guest_disk.ps1 `
    -Source D:\vm\guest.vhdx -Format vmdk -VmdkSubformat streamOptimized
```

Switches: `-Format qcow2|vmdk|vdi|raw`, `-VmdkSubformat monolithicSparse|streamOptimized`,
`-Checkpoint` (default `clean`), `-OutDir`, `-QemuImg <path>`, `-KeepExport`. If `qemu-img` is not
on `PATH` or under `C:\Program Files\qemu`, install it
(`winget install --id SoftwareFreedomConservancy.QEMU`) or pass `-QemuImg`.

Dry run to check it end to end without touching a real guest:

```powershell
New-VHD -Path "$env:TEMP\t.vhdx" -SizeBytes 1GB -Dynamic
powershell -ExecutionPolicy Bypass -File tools\convert_guest_disk.ps1 -Source "$env:TEMP\t.vhdx" -Format qcow2 -OutDir $env:TEMP
Remove-Item "$env:TEMP\t.vhdx","$env:TEMP\t.qcow2"
```

Target-side notes (the guest was Gen2, so UEFI in every case):

* **Firmware:** KVM/Proxmox use OVMF (Proxmox: `bios: ovmf` plus an EFI disk); VMware
  `firmware="efi"`; VirtualBox needs EFI enabled.
* **TPM:** Windows 11 checks for a TPM only at install/upgrade, so an existing install boots without
  one. Add one where it is cheap: libvirt swtpm/tpm-crb, Proxmox `tpmstate`, VirtualBox 7 TPM 2.0.
  On VMware a vTPM requires VM encryption, so it is optional there.
* **BitLocker** must be off before converting (`manage-bde -status`), or you get a recovery prompt on
  the new hypervisor. The quiet script sets `PreventDeviceEncryption`.
* **Storage/NIC drivers:** KVM/Proxmox - boot first with SATA/AHCI and an e1000e NIC, or install
  `virtio-win` in the Hyper-V guest before exporting, then switch to virtio-scsi/virtio-net. VMware -
  LSI SAS or NVMe plus e1000e work out of the box; install VMware Tools afterwards. VirtualBox - AHCI.
* **After first boot** the new NIC gets a new IP. Update the MCP host/IP in the guest `cfg.ini` and
  the host client config, re-check the TCP 8000 firewall rule's profile, and take a new clean
  snapshot on the target.

Booting the converted disk on a real KVM/VMware host is yours to test.

---

## 10. Building the guest with an AI agent

The scripts do the work; an agent (for example Claude Code running on the Hyper-V host) can drive
and check them end to end.

**Prerequisites**

* An elevated host shell for the agent, Hyper-V enabled, and the ISO path.
* The guest credentials, given in the prompt and never written to the repo.
* Optionally the capesolo MCP server and the capesolo-detonate skill, for the final sanity
  detonation.

**Paste-ready prompt** - the guardrails are part of it; fill in the placeholders and paste the
whole block:

```
Build a CAPEsolo analysis guest on this Hyper-V host from this elevated shell.
ISO: <iso-path>. VM name: <vm-name>. Guest local admin: <user> / <password>.
CAPEsolo: <PyPI | -WheelPath <wheel-path>>.
Computer name: <computer-name> (max 15 characters).
MCP: register as <mcp-name> (if an entry with that name already exists, ask me before replacing
it), at http://<mcp-host>:8000/mcp, with CAPEsolo-mcp bound to <bind-address>. <mcp-host> is
<computer-name>.mshome.net or the guest IP; <bind-address> is 0.0.0.0 (survives the Default
Switch giving the guest a new IP) or the guest IP.
Edition: Windows 11 Enterprise via the script's default key (XGVPP-NMH47-7TTHJ-W3FW7-8HV2C, the
Enterprise generic key); pass no key option. Do not use -NoProductKey on a multi-edition ISO:
Setup stalls at a ProductKey error or the "Activate Windows" page. An ISO's $OEM$ activation still
runs after the generic key.

Steps:
1.  Validate the ISO build is Windows 10 (10240-19045) or Windows 11 23H2 (22631); stop if not.
    new_guest_vm.ps1 does this check before creating anything; its "image:" line always shows the
    ISO's first image (e.g. Windows 11 Pro), not the edition the key installs.
2.  Run tools\new_guest_vm.ps1 with -IsoPath, -Name, -User, -Password, -ComputerName (and
    -WheelPath if given) in the background (it waits up to 120 min). Always pass -Name so it does not stop at its VM-name
    prompt. About 5 minutes after the VM starts, check that the VHDX has grown past ~1 GB; if not,
    Setup is waiting on a screen - capture a console thumbnail
    (Msvm_VirtualSystemManagementService.GetVirtualSystemThumbnailImage, RGB565) and stop and ask.
    Report the done.txt contents it prints. It takes the 'clean' checkpoint only when done.txt says
    overall=OK (quiet=OK (retry) is fine: firstboot re-runs the quiet script once to ride out a
    first-boot race; the first run's log is setup_quiet_guest.first.log). If it says overall=ISSUES, read C:\setup\setup_quiet_guest.log (each setup script's
    output; firstboot.log has only the chain), fix the gaps, then do the skipped finishing steps by
    hand: eject both ISOs, delete the config ISO, set persistent AutoLogon (section 3), reboot.
    Confirm the edition: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion EditionID = Enterprise
    (ProductName may say "Windows 10 Enterprise"; build 22631 is Windows 11). Confirm CAPEsolo
    imports in the guest (python -c "import CAPEsolo.mcp_server"): capesolo=OK in done.txt only
    means pip succeeded, and a dependency built for another Python version fails here. To install
    a build newer than PyPI, pass -WheelPath <wheel> to new_guest_vm.ps1.
3.  Run setup_quiet_guest.ps1 -AuditOnly inside the guest over PowerShell Direct
    (Invoke-Command -VMName). [warn] lines are acceptable; fix any [!!]. Service keys and tasks
    that deny an admin are already retried as SYSTEM; use -DefenderSafeMode only if a WinDefend/
    WdFilter/Sense key still stays [!!]. Check Get-MpComputerStatus (real-time protection and
    Tamper Protection off).
4.  Reboot twice and re-audit; the audit should exit 0 (warnings allowed). Reboot gracefully
    (Restart-VM -Type Reboot; plain Restart-VM -Force is a hard reset), and confirm each reboot
    by a newer Win32_OperatingSystem LastBootUpTime plus a running explorer - the heartbeat can
    report OK before the guest has gone down.
5.  Revert-time check. A revert resumes the checkpoint and time sync jumps the clock, which runs
    overdue tasks and Automatic Maintenance (4-5 min after the jump). Revert to 'clean', jump the
    guest clock +25 h (Set-Date) to mimic reverting the next day, wait 10 minutes, and confirm
    wuauserv is still Disabled (Win32_Service StartMode, not the registry) with no new System
    7040 "Windows Update service was changed from disabled to demand start". Then, from a fresh
    revert with the same +25 h jump, run a 15-minute pktmon idle capture; report the remote
    endpoints (pktmon etl2txt flows) and the names behind them (HTTP Host/User-Agent and TLS
    server names pulled from the etl2pcap file). Certificate traffic (CRL/OCSP, ctldl
    trusted-root lists) is expected because root auto-update is left on. Revert again afterwards.
6.  MCP. The server refuses to start unless enabled, binds 127.0.0.1 unless given --host, and
    with a 0.0.0.0 bind rejects every request unless allowed_hosts is set. So first write the
    user config C:\Users\Public\CAPEsolo\cfg.ini (per-key merge; pip upgrades leave it alone)
    with only an [mcp_server] section: enabled = true, transport = streamable-http,
    host = <bind-address>, and for 0.0.0.0 allowed_hosts = <mcp-host>:* (add the guest IP as
    <ip>:* if clients may use it). Then start it with
    --transport streamable-http --host <bind-address>, in the logged-on console session
    so it survives PowerShell Direct disconnecting and is in the checkpoint: a one-shot scheduled
    task as <user> with an Interactive logon that runs cmd /c start "" CAPEsolo-mcp ..., then
    unregister the task. Verify from the host (Test-NetConnection <mcp-host> -Port 8000, and an
    MCP initialize POST to http://<mcp-host>:8000/mcp that returns HTTP 200), then
    register it: claude mcp add --transport http <mcp-name> http://<mcp-host>:8000/mcp. With
    <bind-address> set to the guest IP, the server stops answering if the Default Switch hands out
    a new IP after a host reboot; restart it and re-register.
7.  new_guest_vm.ps1 already took the 'clean' checkpoint. Steps 3-6 change the guest, so remove
    it (Remove-VMSnapshot -VMName <vm-name> -Name clean) and take a new Standard 'clean' checkpoint
    with the guest logged on and CAPEsolo-mcp running. Never leave two checkpoints named 'clean'.
    Revert once and confirm the MCP port answers from the host.
8.  Optionally revert and run one benign sanity detonation through the MCP.
9.  Report each step with its evidence, and leave the VM reverted to 'clean'.

Guardrails:
- Never run setup_quiet_guest.ps1 on the host (its VM guard refuses there too).
- Confirm with me before deleting or overwriting an existing VM, VHDX or checkpoint.
- One analysis per revert.
- Stop and ask on any unexpected failure instead of improvising registry or policy changes.
  Diagnose in a throwaway state (after a revert) and revert afterwards: Task Scheduler
  operational log (wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true), process
  creation auditing (4688), Set-Date to reproduce clock-driven triggers, and disable-then-test
  bisection. Bring me the evidence and a proposed fix before changing the scripts.
- Stop and ask me when a step needs the console or a person: Tamper Protection is on, the VM
  waits at "press any key to boot from CD", Setup shows a key or activation page, or
  -DefenderSafeMode needs a Safe Mode logon.
- Do not use -Force to get past an unsupported build or an existing VM without asking me.
- Watch the VM only in a VMConnect Basic session; an enhanced-session logon takes over the console
  session and leaves it locked on disconnect, so do not log on that way before the checkpoint.
- Service Start values written to the registry take effect at the next boot; change a live
  service with sc.exe config. Copy files into the guest with Copy-Item -ToSession (Copy-VMFile
  can be refused for an existing file).
```

**Steps that may still need you** (the prompt tells the agent to stop and ask for these)

* The Tamper Protection toggle, if the specialize-pass route did not take and Defender is live.
* The "press any key to boot from CD" prompt, if the scripted WMI keypress does not register - press
  a key at the VM console.
* The Safe Mode console logon for `-DefenderSafeMode` (no PowerShell Direct in Safe Mode). Only
  needed if a Defender key stays `[!!]` after the SYSTEM retry.
* A Setup screen asking for input (a product-key error or the "Activate Windows" page). That means
  the answer file has no usable key; see "Product key and edition".

---

## 11. Troubleshooting

* **The guest loses Internet on the Default Switch.** The Default Switch is NATed by Internet
  Connection Sharing, not WinNAT; restarting that service restores it on the host:

  ```powershell
  Restart-Service SharedAccess
  ```
  If the guest still has no DHCP lease, bounce its NIC:

  ```powershell
  Disconnect-VMNetworkAdapter -VMName CAPEsolo-guest
  Connect-VMNetworkAdapter -VMName CAPEsolo-guest -SwitchName 'Default Switch'
  ```
* **Getting files into the guest.** Use PowerShell Direct, the Guest Service Interface
  (`new_guest_vm.ps1` enables it), the script-MCP upload, or a shared folder:

  ```powershell
  $s = New-PSSession -VMName CAPEsolo-guest -Credential (Get-Credential)
  Copy-Item .\tools\setup_quiet_guest.ps1 -Destination C:\setup\ -ToSession $s
  Copy-VMFile -Name CAPEsolo-guest -SourcePath .\sample.bin -DestinationPath C:\Users\Public\sample.bin -FileSource Host -CreateFullPath
  ```

  Hand-pasted base64 corrupts binaries (a PE with `FILEALIGN:16` will not load), so avoid it for
  anything but short text.
* **`[warn]` lines in the audit.** They never fail the run. "protected, still enabled after SYSTEM
  retry" is an update task that even SYSTEM could not disable (harmless with `WaaSMedicSvc` off).
  "differs (user-changeable)" means a preference such as the background was changed in Settings.
  Re-run the apply only if you want the script's value back.
* **`[!!]` items come back after a reboot.** Something re-armed them before the policy took hold:
  Tamper Protection was still on, an update/EdgeUpdate task ran first, a service re-registered its
  task at boot (`PcaSvc` does this to `PcaPatchDbTask`; the script now disables `PcaSvc`), or the
  VM was hard-reset instead of rebooted. Enable the Task Scheduler operational log
  (`wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true`) to see who changed a task
  (event 140 "updated", 142 "disabled"). Re-run the apply, and use `-DefenderSafeMode` only for a
  Defender key that stays `[!!]` (section 5). Then reboot twice gracefully and re-audit.
* **Windows Update downloads right after a revert.** A revert resumes the checkpoint and Hyper-V
  time sync jumps the clock, so delayed logon tasks become overdue and run at once. System event
  7040 "Windows Update service was changed from disabled to demand start" marks it. The known causes,
  `LanguageComponentsInstaller\ReconcileLanguageResources` and the Store's `InstallService` (the
  service and its `InstallService\*` / `PushToInstall\*` tasks), are disabled by the quiet script.
  The audit cannot catch this (it passes before the trigger runs): revert, or jump the clock with
  `Set-Date -Adjust (New-TimeSpan -Hours 25)`, wait about 10 minutes (Automatic Maintenance starts
  some 4-5 minutes after the jump), then check `Win32_Service` StartMode for `wuauserv`.
  Note that a direct registry write to a service's `Start` only takes effect after a reboot; use
  `sc.exe config` to change the live value.
* **The install never starts (the VHDX stays at a few tens of MB).** Setup is waiting at a screen.
  Look at the console in a Basic session, or grab a thumbnail from the host with
  `Msvm_VirtualSystemManagementService.GetVirtualSystemThumbnailImage` (RGB565 pixels). A product-key
  error or the "Activate Windows" page means the answer file has no usable key: pass the edition's
  generic key (see "Product key and edition"), not `-NoProductKey`.
* **VMConnect shows a login screen though AutoLogon worked.** An enhanced session is an RDP logon
  and always starts at the login screen; closing it locks the console session. Switch to a Basic
  session (View > Enhanced session off) to see the real console. Check
  `Get-Process explorer` over PowerShell Direct before concluding AutoLogon failed.
* **`done.txt` never appears.** Read `C:\setup\firstboot.log` in the guest (PowerShell Direct) for
  the per-step transcript, and `C:\setup\<script>.log` (for example `setup_quiet_guest.log`) for
  each setup script's own output.
* **`done.txt` says `quiet=OK (retry)`.** The first quiet run left a `[!!]` (seen: Edge's own
  updater re-arming `MicrosoftEdgeUpdateTaskMachineCore` mid-run), so `firstboot.ps1` ran it again
  30 seconds later and it passed. The first run's output is in `C:\setup\setup_quiet_guest.first.log`.
* **The build stopped with `overall=ISSUES`.** `new_guest_vm.ps1` printed `done.txt` and left the
  VM running with no checkpoint. The failing step is the one not marked `OK`; read
  `C:\setup\firstboot.log`, fix it, and re-run that step in the guest. Then eject both ISOs, set
  persistent AutoLogon (the commands in section 3), reboot, and take the `clean` checkpoint once the
  desktop is up. Delete the config ISO whose path the error printed.
* **`new_guest_vm.ps1` refuses the build.** Confirm the ISO is Windows 10 or 11 23H2; `-Force`
  overrides, but capemon on 24H2 is unproven.
