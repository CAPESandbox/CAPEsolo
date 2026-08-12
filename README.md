Python GUI to run capemon in standalone VM. Provides a subset of CAPE (Configuration And Payload Extraction) processing and results.

* Create a Windows 10 VM that's suitable for running malware.
  * Use the CAPEv2 guest guide for configuration details.
  * https://capev2.readthedocs.io/en/latest/installation/guest/index.html
* Install Python in VM, tested on 64-bit Python versions 3.11 and 3.12, and add Python to path.
* Download and install both Microsoft Visual C++ Redistributables:
  * https://aka.ms/vs/17/release/vc_redist.x86.exe
  * https://aka.ms/vs/17/release/vc_redist.x64.exe
* Install CAPEsolo.
  * pip install CAPEsolo
* Snapshot your VM.

Quick Start 
* Open an administrator command window.
* Type capesolo <return> to run.

Alternatively, create a shortcut to CAPEsolo.exe, 
which will be in the Scripts subdirectory of same location as your python.exe file. 
* Under Advanced, check 'Run as administrator'
* An icon file is available in the CAPEsolo install folder under site-packages.

Analysis results are found in C:\Users\Public\CAPEsolo\analysis.
* Can be configured in C:\Users\Public\CAPEsolo\cfg.ini
* Settings there override the packaged defaults in python-path\site-packages\CAPEsolo\cfg.ini,
  and survive `pip install --upgrade CAPEsolo`, which overwrites the packaged copy.
* Only include the keys you want to change; the rest fall back to the packaged defaults.

Revert the VM after each analysis.

View a JSON Report (standalone)
* `tools/report_viewer.py` is a self-contained viewer for a CAPEsolo `report.json` that runs on
  any host with just Python - no CAPEsolo install and no pip dependencies (stdlib tkinter).
  * `python tools/report_viewer.py [path\to\report.json]`
  * With no argument it opens `%USERPROFILE%\Desktop\report.json` (where CAPEsolo writes it);
    use File > Open to pick another.
  * Handles large reports: the file is read with a progress bar, the tree loads lazily (children
    on expand), and the detail pane is bounded, so it stays responsive on hundred-MB/GB reports.
    (A GB report still needs several GB of RAM to parse - inherent to Python's JSON.)
  * Needs tkinter - bundled with the standard Windows/macOS Python; on Linux install `python3-tk`.

Preserve Results From an Unstable VM
* If a sample makes the VM unusable after detonation, click **Zip Results** on the Start panel to
  archive the whole analysis directory to `Desktop\capesolo_analysis_<timestamp>.zip`.
* To restore into a clean/reverted VM, copy that zip to `C:\Users\Public\CAPEsolo\restore.zip`,
  then start CAPEsolo. On startup it extracts the zip into the analysis directory (only when that
  directory has no analysis yet) and renames it `restore.zip.done` so it restores once.
* The result tabs then read the restored artifacts with no re-run - process each tab (Behavior,
  Yara, Configs, Signatures) or use the JSON/HTML Report buttons.

Download Samples by Hash
* The Start panel can fetch a sample by MD5/SHA1/SHA256 from VirusTotal or MalwareBazaar and
  use it as the analysis target. The source is auto-selected (VirusTotal first, then
  MalwareBazaar; MalwareBazaar requires a SHA256), based on which keys are configured.
* Turn it on in `cfg.ini` (or via the Settings button): under `[download]` set `enabled = true`.
  `directory` sets where samples are saved (defaults to the user's Desktop).
* API keys - where to get them:
  * VirusTotal: file downloads require a VirusTotal Enterprise / Intelligence API key. The free
    community key can look up reports but cannot download files.
  * MalwareBazaar: a free abuse.ch Auth-Key (create an account at auth.abuse.ch).
* API keys are stored ENCRYPTED, never in plaintext on the VM. You produce the encrypted blob
  OFF the VM with `tools/encrypt_api_key.py` and paste it into `cfg.ini`.
* `tools/encrypt_api_key.py` ships in the CAPEsolo source repository under `tools/`. Run it on
  a trusted host (NOT the analysis VM); it only needs `pip install cryptography`.
  * `python tools/encrypt_api_key.py`
  * It prompts (hidden) for the API key and a password, and prints an encrypted blob.
  * Encrypt every provider you use with the SAME password, so one prompt unlocks both.
* Install the blob in the guest by either:
  * pasting it into `cfg.ini` as `api_key_enc` under `[virustotal]` and/or `[malwarebazaar]`, or
  * setting the `CAPESOLO_VT_APIKEY_ENC` / `CAPESOLO_MB_APIKEY_ENC` environment variables
    (env vars override `cfg.ini`).
* When downloads are enabled, CAPEsolo prompts once at startup for the password and decrypts the
  key in memory only; the plaintext key never touches the VM's disk. Enter the password, then
  snapshot the VM so it is ready on every revert.

MCP Server
* CAPEsolo includes an MCP server entrypoint for programmatic analysis workflows.
* Start it over stdio with `CAPEsolo-mcp`, or serve it over HTTP to reach it from the host.
* See mcp_server.md for transports, `cfg.ini` configuration, the full tool list, and examples.

Interactive Debugger
* See interactive_debugger.md for the GUI debugger, and mcp_server.md for the MCP equivalent.

Headless Single-Run CLI
* CAPEsolo supports a non-MCP single-run mode that reuses the same backend job runner as the MCP server.
* Run one analysis and exit:
  * `CAPEsolo --headless-analyze "C:\path\sample.exe"`
* Optional flags:
  * `--package <name>`
  * `--options "key=value,key2=value2"`
  * `--timeout <seconds>`
  * `--enforce-timeout`
  * `--headless-json`
  * `--headless-html-report`
