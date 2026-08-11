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
