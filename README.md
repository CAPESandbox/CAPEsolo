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
* Can be configured in python-path\site-packages\CAPEsolo\cfg.ini

Revert the VM after each analysis.

MCP Server
* CAPEsolo includes an MCP server entrypoint for programmatic analysis workflows.
* Install project dependencies (including `mcp`) in your environment.

Run
* Start the server over stdio:
  * `CAPEsolo-mcp`
  * or `python -m CAPEsolo.mcp_server`

Available MCP Tools
* `capesolo_analyze_sample`
  * Submit a sample for analysis.
  * Key args: `sample_path`, `package` (`Auto-detect` by default), `options`, `timeout`, `enforce_timeout`.
* `capesolo_analyze_password_zip`
  * Submit a password-protected ZIP for analysis.
  * Key args: `zip_path`, optional `zip_password` (defaults to `infected`), optional `archive_member_path` (required when ZIP has multiple files), `package`, `options`, `timeout`, `enforce_timeout`.
  * ZIP extraction/decryption is handled by `SFlock2`.
* `capesolo_get_job_status`
  * Get job state (`queued`, `running`, `completed`, `failed`).
* `capesolo_cancel_job`
  * Request termination of a running job (same analyzer termination signal used by GUI Kill).
* `capesolo_get_results`
  * Return CAPEsolo JSON results using existing keys (`target`, `behavior`, `signatures`, `payloads`, `configs`, `detections`).
* `capesolo_get_job_log_tail`
  * Return the last N lines from `analysis.log` for a job.
* `capesolo_render_html_report`
  * Generate an HTML report from completed analysis.
* `capesolo_list_payloads`
  * List payload artifacts from analysis output.
* `capesolo_list_dropped_files`
  * List dropped files under analysis `files` output.
* `capesolo_list_debug_logs`
  * List debugger and analysis log artifacts.
* `capesolo_update_yara`
  * Update CAPE/community YARA rules.

Typical Workflow
1. Call `capesolo_analyze_sample` or `capesolo_analyze_password_zip`.
2. Poll `capesolo_get_job_status` until `completed`.
3. Call `capesolo_get_results` (and optionally `capesolo_render_html_report`).

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

MCP Client Config Examples
* Use these examples to connect CAPEsolo MCP server to common clients.
* Server command is:
  * `CAPEsolo-mcp`
  * or `python -m CAPEsolo.mcp_server`

Claude Desktop
* Add to Claude Desktop MCP config:
```json
{
  "mcpServers": {
    "capesolo": {
      "command": "python",
      "args": ["-m", "CAPEsolo.mcp_server"],
      "cwd": "C:\\Users\\lkuca\\PycharmProjects\\CAPEsolo"
    }
  }
}
```

Cursor
* Add in Cursor MCP servers config:
```json
{
  "mcpServers": {
    "capesolo": {
      "command": "CAPEsolo-mcp",
      "args": []
    }
  }
}
```

OpenCode
* Add in OpenCode MCP config:
```json
{
  "mcpServers": {
    "capesolo": {
      "command": "python",
      "args": ["-m", "CAPEsolo.mcp_server"],
      "cwd": "C:\\Users\\lkuca\\PycharmProjects\\CAPEsolo"
    }
  }
}
```

Codex (Custom Host App)
* If you run Codex through a custom client/app, configure the app's MCP server map with:
```json
{
  "mcpServers": {
    "capesolo": {
      "command": "CAPEsolo-mcp",
      "args": []
    }
  }
}
```
* The host app must support MCP tool calls and pass them through to the Codex model runtime.

PyCharm AI Assistant
* Open:
  * `Settings -> Tools -> AI Assistant -> Model Context Protocol (MCP)`
* Add JSON config:
```json
{
  "mcpServers": {
    "capesolo": {
      "command": "python",
      "args": ["-m", "CAPEsolo.mcp_server"],
      "cwd": "C:\\Users\\lkuca\\PycharmProjects\\CAPEsolo"
    }
  }
}
```

Quick Connection Test
1. Start your MCP-enabled client with the config above.
2. Call `capesolo_get_job_status` with a fake id:
   * `{"job_id":"test"}`
3. Expected response pattern:
   * `{"found": false, "error": "Job not found: test"}`
