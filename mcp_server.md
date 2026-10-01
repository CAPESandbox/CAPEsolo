# MCP Server User Guide

CAPEsolo ships an MCP (Model Context Protocol) server so an assistant or script can drive
analysis programmatically: submit samples, poll jobs, read results, and step a halted
sample under the interactive debugger.

Install project dependencies (including `mcp`) in your environment first.

---

## 1. Running the Server

| Transport | Command | Use when |
|-----------|---------|----------|
| `stdio` (default) | `CAPEsolo-mcp` | The MCP client runs in the same VM and launches the server itself. |
| `streamable-http` | `CAPEsolo-mcp --transport streamable-http --host 192.168.56.10` | CAPEsolo runs in a guest VM and the client is on the host. |

`python -m CAPEsolo.mcp_server` is equivalent to `CAPEsolo-mcp`.

---

## 2. Configuration

Settings resolve in this order, first match wins:

1. **Command line flag** - `--transport`, `--host`, `--port`, `--path`
2. **User `cfg.ini`** - `C:\Users\Public\CAPEsolo\cfg.ini`
3. **Packaged `cfg.ini`** - `python-path\site-packages\CAPEsolo\cfg.ini`
4. **Built-in default**

Put your settings in the **user** file. The packaged copy is replaced on every
`pip install --upgrade CAPEsolo`, which silently reverts anything you changed there; the
user file is never touched. It sits next to the analysis directory, in the CAPEsolo folder
you already have.

Override only the keys you care about - the two files are merged **per key**, so a user file
containing just a `port` line keeps every other value from the packaged defaults and still
picks up new keys added by future versions. Copying the whole packaged file is unnecessary
and makes upgrades staler. A missing user file is simply skipped, so an existing install
behaves exactly as before.

Set `CAPESOLO_CFG` to use a different file entirely, which is handy for keeping the guest
and host on separate configs.

The whole `[mcp_server]` section is optional; if it is absent from both files every value
falls back to its default.

### 2.1. `[mcp_server]` keys

| Key | Default | Description |
|-----|---------|-------------|
| `transport` | `stdio` | `stdio` or `streamable-http`. |
| `host` | `127.0.0.1` | Bind address. For host access, use the guest's host-only adapter IP. |
| `port` | `8000` | Bind port. Ignored for `stdio`. |
| `path` | `/mcp` | HTTP path the endpoint is served on. Ignored for `stdio`. |
| `allowed_hosts` | derived from `host:port` | Comma-separated `Host` headers to accept. A `host:*` entry matches any port. |
| `allowed_origins` | empty | Comma-separated `Origin` headers to accept. Requests without an `Origin` are allowed. |

### 2.2. Token (environment only)

Set `CAPESOLO_MCP_TOKEN` in the guest before starting the server to require
`Authorization: Bearer <token>` on every HTTP request. Leave it unset to run without auth.

**Keep the token in the environment, not in either `cfg.ini`.** The packaged file is tracked
in git, so a token there can be committed by accident. The user file is not in git, but
`C:\Users\Public` is world-readable by default, so a token there is exposed to every account
on the VM.

```
set CAPESOLO_MCP_TOKEN=some-long-random-value
CAPEsolo-mcp --transport streamable-http --host 192.168.56.10
```

---

## 3. Remote Access (guest VM to host)

Point the host client at `http://<guest-ip>:<port>/mcp`. The config form differs by client -
see 3.1 and 3.2 below. Drop the `headers` / `env` block in either if you are not using a token.

### 3.1. Claude Code, Cursor, and other clients with native HTTP support

```json
{
  "mcpServers": {
    "capesolo": {
      "type": "http",
      "url": "http://192.168.56.10:8000/mcp",
      "headers": { "Authorization": "Bearer some-long-random-value" }
    }
  }
}
```

**`type` is required.** A `url` entry without it is read as a stdio server and skipped.
`streamable-http` is accepted as an alias for `http`.

Claude Code can also add it from the command line:

```
claude mcp add --transport http capesolo http://192.168.56.10:8000/mcp \
  --header "Authorization: Bearer some-long-random-value"
```

### 3.2. Claude Desktop - use a connector or the mcp-remote bridge

**Do not put a `url` entry in `claude_desktop_config.json`.** Claude Desktop silently
discards the whole `mcpServers` section on startup when one is present, with no error.
Either add the server under **Settings - Connectors - Add custom connector**, or bridge it
through `mcp-remote` as a stdio server (needs Node.js on the host, not the guest):

```json
{
  "mcpServers": {
    "capesolo": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote@latest",
        "http://192.168.56.10:8000/mcp",
        "--allow-http",
        "--header", "Authorization:${AUTH_HEADER}"
      ],
      "env": { "AUTH_HEADER": "Bearer some-long-random-value" }
    }
  }
}
```

`--allow-http` is required because the server speaks plain HTTP. Write the header as
`Authorization:${AUTH_HEADER}` with **no space after the colon** and keep the value in
`env` - Claude Desktop mishandles arguments containing spaces.

### 3.3. Security

* Use a **host-only or internal** VM network. Never bridge the guest to a real LAN or
  forward this port to the internet: these tools detonate samples, and the debugger tools
  can read and patch process memory.
* Bind the guest's host-only adapter address rather than `0.0.0.0`. Host header validation
  (DNS-rebinding protection) is always enabled and is derived from the bind address, so a
  `0.0.0.0` bind requires setting `allowed_hosts` explicitly or every request is rejected.
* Anything listening inside the guest is also reachable by the malware running there. The
  token and Host validation are hardening; VM isolation remains the real boundary.
* The host client parses data produced inside an infected guest (file names, strings,
  disassembly). That is inherent to remote analysis, but treat that output as untrusted.

---

## 4. Uploading Files

Every analysis tool takes a path **inside the VM**. When the client runs on the host, upload
the bytes first and pass back the returned path.

| Tool | Description |
|------|-------------|
| `capesolo_upload_file` | Write a file into the VM. Args: `filename`, `data_base64`, `destination`, `append`, `sha256`. Returns the guest `path`, `size` and `sha256`. |
| `capesolo_list_uploads` | List both destinations with sizes and SHA-256 hashes. |

### 4.1. Destinations

| `destination` | Directory | Accepts |
|---------------|-----------|---------|
| `desktop` (default) | `%USERPROFILE%\Desktop` | **any** extension, including none |
| `custom` | `%USERPROFILE%\Desktop\custom` | only `.yar`, `.yara`, `.py` |

There is no path argument - the destination is a fixed choice of those two, and the filename
is reduced to a sanitized basename. `Desktop\custom` is created on first use.

`desktop` is deliberately unrestricted because samples are arbitrary by nature: `.exe`,
`.dll`, `.doc`, `.js`, extensionless, or mislabelled on purpose. `custom` is restricted to
the three extensions CAPEsolo actually loads from there.

### 4.2. What `custom` is for

`Desktop\custom` is the same directory the GUI already reads, so uploads and the GUI stay in
step:

* **`.yar` / `.yara`** - merged into the **CAPE** YARA category alongside the built-in rules.
* **`.py`** - a config extractor, loaded **only when its filename matches the name of the YARA
  rule that hit**, exposing either `extract_config(filedata)` or `config(filedata)`.

  The triggering rule can be **any** rule CAPEsolo has, including a bundled one - so a `.py`
  on its own is a valid upload and often the only file you need. `NitrogenLoader.py` pairs
  with the shipped `NitrogenLoader` rule, for example. Upload a `.yar` alongside it only when
  the rule itself is new.

Both are picked up on the **next `capesolo_get_results` call** - no restart, and no reload
tool to call.

> **A `.py` here is executed inside the VM.** CAPEsolo imports and runs the extractor while
> processing results, so uploading one is remote code execution in the guest by design. Keep
> `CAPESOLO_MCP_TOKEN` set and the port on a host-only network (see 3.3).

### 4.3. Size limits and chunking

| Limit | Value |
|-------|-------|
| Request body | 32 MiB, so roughly **24 MiB of file** per call after base64 overhead |
| Total per file | 256 MiB |

For anything larger than one chunk, call repeatedly against the same `filename`:

1. First chunk with `append=false` - creates or truncates the file.
2. Each later chunk with `append=true`.
3. Pass `sha256` of the **whole** file on the final call.

A `sha256` mismatch deletes the file and returns an error, so a truncated or corrupted
upload can never be analyzed by mistake. Chunk state is just the file on disk - an
interrupted upload leaves a short file that the next `append=false` call overwrites.

> **Chunking raises the transport limit, not the practical one.** When an assistant does the
> upload, the base64 passes through its context twice - once reading the file, once re-emitting
> it in the tool call - at about 2.7x the file size. Splitting a file into chunks moves the same
> total through context, so it is not a way around that cost. Past roughly a few hundred KB,
> copy the file into the VM by other means (shared folder, RDP, mapped drive) and pass the
> guest path straight to `capesolo_analyze_sample`; `capesolo_list_uploads` reports the SHA-256
> either way, so verification is identical. Chunking is for scripts driving the endpoint
> directly, where nothing transits a context window.

---

## 5. Analysis Tools

| Tool | Description |
|------|-------------|
| `capesolo_analyze_sample` | Submit a sample. Key args: `sample_path`, `package` (`Auto-detect` by default), `options`, `timeout`, `enforce_timeout`, `interactive_debug`. |
| `capesolo_analyze_password_zip` | Submit a password-protected ZIP. Key args: `zip_path`, `zip_password` (defaults to `infected`), `archive_member_path` (required when the ZIP holds multiple files), plus the args above. Extraction is handled by `SFlock2`. |
| `capesolo_get_job_status` | Job state: `queued`, `running`, `completed`, `failed`. |
| `capesolo_cancel_job` | Request termination of a running job (the same signal as the GUI Kill button). |
| `capesolo_get_results` | CAPEsolo JSON results using existing keys (`target`, `behavior`, `signatures`, `payloads`, `configs`, `detections`). Behaviour analysis, YARA and config extraction all happen here — nothing is analysed at submit time. Computed once per job and cached, so this and `capesolo_render_html_report` do not rescan. `include_strings=False` skips string extraction; `write_file=True` also saves `report.json` the way the GUI's JSON button does. |
| `capesolo_query_calls` | API calls that match a filter, across every process, paged (`offset`, `limit` up to 1000). `api`, `process` (`"<pid> <name>"`) and `argument` (any argument value) are case-insensitive substrings; `tid` is exact; `regex=True` makes each a regular expression; `category` narrows to one behaviour category. These are the same rules as the Behavior tab's filter bar. Each call carries its `cid`, the index signature evidence refers to. |
| `capesolo_process_view` | One process: command line, ancestors and children, call counts by category and top APIs, the files, registry keys and network endpoints its calls touched, and the signatures whose evidence names it. |
| `capesolo_signature_evidence` | Matched signatures with their evidence. Calls a signature marked are resolved to the calls themselves. `name` narrows it to one signature. |
| `capesolo_diff_results` | What differs between a job and `other`: another job from this session, a `report.json` path, or a Zip Results bundle. Compares signatures, detections, yara hits, payload hashes, processes, network domains/hosts/HTTP, mutexes, commands, and written files and keys. |
| `capesolo_get_job_log_tail` | Last N lines of `analysis.log`. |
| `capesolo_render_html_report` | Generate an HTML report from a completed analysis. |
| `capesolo_list_payloads` | Payload artifacts from analysis output. |
| `capesolo_list_dropped_files` | Dropped files under the analysis `files` output. |
| `capesolo_list_debug_logs` | Debugger and analysis log artifacts. |
| `capesolo_update_yara` | Update YARA rules and community signatures. `capesolo` (default true) and `capev2` rebuild the packaged rules, CAPEsolo winning on duplicates; `community` fills the user `yara/community` folder, `community_signatures` the user `signatures/community` folder. |

---

## 6. Interactive Debugger Tools

Available only while a job submitted with `interactive_debug=True` is halted at a
breakpoint. That flag adds `idbg=1` to the options and forces a 4 hour timeout, the same
as the GUI **Interactive Debugger** checkbox. Pair it with breakpoint options such as
`bp0=ep`. See [interactive_debugger.md](interactive_debugger.md) for the GUI equivalent.

**Use the flag, not the option.** Passing `idbg=1` in `options` without
`interactive_debug=True` is rejected: only the flag attaches the debugger session these
tools drive, so the option on its own would leave the sample stopped at its first
breakpoint until the timeout expired. For the same reason interactive debugging is
unavailable in headless mode (`capesolo --headless-analyze`), which has no channel to
drive the debugger and rejects `idbg` outright.

Addresses are hex; the `0x` prefix is optional.

### 6.1. Execution control

| Tool | Description |
|------|-------------|
| `capesolo_dbg_wait_break` | Block until the target halts. Call once after submitting to catch the first break. |
| `capesolo_dbg_step` | Single-step. `mode` is `into`, `over` or `out`. |
| `capesolo_dbg_continue` | Resume until the next breakpoint or the timeout. |
| `capesolo_dbg_run_until` | Resume until a given address. |

These three return the new instruction pointer, the thread that broke (`tid`), the registers,
and a short disassembly window in one response.

| Tool | Description |
|------|-------------|
| `capesolo_dbg_trace` | Single-step the halted thread from the current instruction and return a summary of the path. The monitor steps in-process in one command (TS). It stops at `stop_at`, after `max_steps` (up to 65536), on leaving the allocation it started in (`stop_on_module_change`, which covers images and shellcode), on entering monitor code, or on a user breakpoint. The summary has the stop reason and step count, module transitions, unique blocks and call targets with hit counts, the last `last` instructions, and the halting `tid`. `step_over_calls` runs each CALL through untraced; this needs a free debug register, and a call that never returns leaves the thread running. Very long paths are summarised from the CIPs the monitor fits in its reply (`truncated`). |

### 6.2. Inspection

| Tool | Description |
|------|-------------|
| `capesolo_dbg_status` | Whether a session is active and where it is halted. |
| `capesolo_dbg_get_registers` | Register set, parsed and raw. |
| `capesolo_dbg_get_stack` | Stack window around the stack pointer. |
| `capesolo_dbg_read_memory` | Up to 16384 bytes, returned as hex, in one request. A read that hits unreadable memory reports `bytes_read`. |
| `capesolo_dbg_dump_region` | Save up to 16 MB of the target's memory as a CAPE payload (`CAPE/<sha256>` plus a `files.json` entry, with the target's pid), so the Payloads, Yara and Configs processing examines it. The monitor copies the range in-process in one command (DR) while the thread is halted. Unreadable pages are zero-filled and counted; a wholly unreadable range fails. `type_string` labels the payload. The result reports the guest path, the sha256, and whether the upload has arrived. A report already built for the job is dropped so the next one includes the dump. |
| `capesolo_dbg_disassemble` | Defaults to the current instruction pointer. |
| `capesolo_dbg_list_modules` | Loaded modules with base addresses, sizes and paths. |
| `capesolo_dbg_list_threads` | Threads with start addresses; the current thread is flagged. |
| `capesolo_dbg_list_breakpoints` | Hardware breakpoints with their debug register slots. |

### 6.3. Modification

| Tool | Description |
|------|-------------|
| `capesolo_dbg_set_breakpoint` | `slot` is `next` or a debug register `0`-`3`. |
| `capesolo_dbg_delete_breakpoint` | Delete by debug register number. |
| `capesolo_dbg_set_register` | Decimal or `0x`-prefixed hex value. |
| `capesolo_dbg_set_cip` | Move the instruction pointer; picks EIP or RIP by bitness. |
| `capesolo_dbg_modify_flag` | Set, clear or flip the Zero, Sign or Carry flag. |
| `capesolo_dbg_patch_bytes` | Overwrite memory with a hex byte string. |
| `capesolo_dbg_nop_instruction` | Replace an instruction with NOPs. |

---

## 7. Quick Connection Test

1. Start your MCP-enabled client with the config above.
2. Call `capesolo_get_job_status` with a fake id:
   * `{"job_id":"test"}`
3. Expected response:
   * `{"found": false, "error": "Job not found: test"}`

---

## 8. Examples

### 8.1. Local stdio, no configuration

Nothing in `cfg.ini`. The client launches the server itself:

```json
{
  "mcpServers": {
    "capesolo": {
      "command": "python",
      "args": ["-m", "CAPEsolo.mcp_server"],
      "cwd": "C:\\path\\to\\CAPEsolo"
    }
  }
}
```

Equivalent for a client that resolves entry points: `"command": "CAPEsolo-mcp"`.

### 8.2. Host-only network, no token

Guest adapter is `192.168.56.10`. In the guest:

```ini
[mcp_server]
transport = streamable-http
host = 192.168.56.10
port = 8000
```

Start with `CAPEsolo-mcp`. On the host:

```json
{
  "mcpServers": {
    "capesolo": {
      "type": "http",
      "url": "http://192.168.56.10:8000/mcp"
    }
  }
}
```

`allowed_hosts` is omitted, so it is derived as `192.168.56.10:8000` automatically.

### 8.3. Host-only network with a token, config-free

Leave `cfg.ini` alone and pass everything on the command line. In the guest:

```
set CAPESOLO_MCP_TOKEN=8f3c1d9b0a7e4f26
CAPEsolo-mcp --transport streamable-http --host 192.168.56.10 --port 9000 --path /capesolo
```

On the host:

```json
{
  "mcpServers": {
    "capesolo": {
      "type": "http",
      "url": "http://192.168.56.10:9000/capesolo",
      "headers": { "Authorization": "Bearer 8f3c1d9b0a7e4f26" }
    }
  }
}
```

### 8.4. Binding all interfaces

`0.0.0.0` cannot derive a `Host` header, so `allowed_hosts` must be explicit or every
request is rejected:

```ini
[mcp_server]
transport = streamable-http
host = 0.0.0.0
port = 8000
allowed_hosts = 192.168.56.10:8000, capesolo-vm:*
```

### 8.5. Upload a sample from the host, then analyze it

1. `capesolo_upload_file` with `{"filename": "evil.exe", "data_base64": "<...>", "sha256": "<digest>"}`
   - returns `{"path": "C:\\Users\\analyst\\Desktop\\evil.exe", ...}`
2. `capesolo_analyze_sample` with `{"sample_path": "C:\\Users\\analyst\\Desktop\\evil.exe"}`
3. Poll `capesolo_get_job_status`, then `capesolo_get_results`

For a file over ~24 MiB, step 1 becomes several calls against the same `filename`:
`append=false` for the first, `append=true` for the rest, `sha256` on the last.

A password-protected archive works the same way - upload the `.zip`, then pass the returned
path to `capesolo_analyze_password_zip` instead.

### 8.6. Ship a custom rule and its extractor

1. `capesolo_upload_file` with `{"filename": "MyFamily.yar", "destination": "custom", ...}`
2. `capesolo_upload_file` with `{"filename": "MyFamily.py", "destination": "custom", ...}`
   - the names must match, or the extractor is never invoked
3. `capesolo_list_uploads` to confirm both landed
4. `capesolo_get_results` on an existing job - the new rule and extractor are applied on this
   call, with no restart

### 8.7. Typical analysis run

1. `capesolo_analyze_sample` with `{"sample_path": "C:\\samples\\evil.exe"}`
2. Poll `capesolo_get_job_status` until the state is `completed`
3. `capesolo_get_results` (optionally `capesolo_render_html_report`)

### 8.8. Typical interactive debugger run

1. `capesolo_analyze_sample` with
   `{"sample_path": "C:\\samples\\packed.exe", "options": "bp0=ep", "interactive_debug": true}`
2. `capesolo_dbg_wait_break` to catch the entry-point break
3. `capesolo_dbg_disassemble` and `capesolo_dbg_get_registers` to look around
4. `capesolo_dbg_step` with `{"mode": "over"}`, or `capesolo_dbg_set_breakpoint` then
   `capesolo_dbg_continue`
5. `capesolo_dbg_continue` to run to completion, then `capesolo_get_results`

---

## 9. Talking to the Assistant

Once the server is connected you drive everything in plain language - the assistant picks
the tools. You never type tool names or JSON. These are phrasings that work well.

### 9.1. Getting files into the VM

| Say this | What it runs |
|----------|--------------|
| "Upload `C:\host\evil.exe` to the VM and analyze it." | upload to Desktop, then submit |
| "Send this file over and stop at the entry point." | upload, then submit with `interactive_debug` |
| "Install this YARA rule in the VM." | upload to `custom` |
| "Add this extractor for the MyFamily rule." | upload `MyFamily.py` to `custom` |
| "What custom rules and extractors are installed?" | list uploads |
| "Did the upload finish?" | list uploads, compare size and hash |
| "Re-run the config extraction with the new rule." | get results again (no restart needed) |

The assistant reads the host-side file itself and chunks it if needed - you give it a host
path, not base64.

### 9.2. Running an analysis

| Say this | What it runs |
|----------|--------------|
| "Detonate `C:\samples\evil.exe` and tell me what it does." | submit, poll, read results |
| "Analyze this sample as a DLL instead of an exe." | `package="dll"` |
| "Run it for 5 minutes and force the full timeout." | `timeout=300`, `enforce_timeout=True` |
| "The zip is password protected, the password is `infected`." | the password-ZIP tool |
| "That zip has three files, use `payload.exe`." | `archive_member_path="payload.exe"` |
| "Is it done yet?" | job status |
| "Skip the strings, they're too long." | results with `include_strings=False` |
| "Kill the run, it's hung." | cancel job |
| "Give me the last 50 lines of the log." | log tail |
| "Build me an HTML report." | render HTML report |
| "What did it drop, and what payloads came out?" | dropped files + payloads |
| "Update the YARA rules first." | update YARA |

### 9.3. Starting a debugger session

| Say this | What it runs |
|----------|--------------|
| "Run `packed.exe` under the debugger and stop at the entry point." | submit with `interactive_debug=True`, `options="bp0=ep"`, then wait for the break |
| "Break when it allocates memory." | submit with the matching `bp0=`/`base-on-api` option |
| "Has it hit the breakpoint yet?" | debugger status, or wait for break |
| "Wait up to 10 minutes for the next break." | wait with `timeout_seconds=600` |

Breakpoint placement comes from analyzer **options** at submit time (`bp0=ep`,
`base-on-api=...`); the `capesolo_dbg_*` tools take over once the target is halted.

### 9.4. Driving a halted target

| Say this | What it runs |
|----------|--------------|
| "Where are we?" | status / registers / disassembly |
| "Step into that call." / "Step over it." / "Finish this function." | step `into` / `over` / `out` |
| "Step 10 instructions and describe what changed." | ten steps, diffing registers |
| "Run to `0x401A20`." | run until |
| "Set a breakpoint at `0x401000` and continue." | set breakpoint, continue |
| "Drop the breakpoint in DR1." | delete breakpoint |
| "Keep going." | continue |
| "What breakpoints are set?" | list breakpoints |

### 9.5. Inspecting state

| Say this | What it runs |
|----------|--------------|
| "Show me the registers." | get registers |
| "Disassemble the next 40 instructions." | disassemble with `count=40` |
| "What's the code at `0x401000`?" | disassemble at that address |
| "Dump 256 bytes at RAX." | read memory at the current RAX |
| "Is the string at RDX readable? Decode it." | read memory, decode the hex |
| "What's on the stack right now?" | get stack |
| "Which DLLs are loaded?" | list modules |
| "How many threads, and where did they start?" | list threads |

### 9.6. Changing execution

| Say this | What it runs |
|----------|--------------|
| "NOP out the instruction at `0x401234`." | NOP instruction |
| "Patch those two bytes to `90 90`." | patch bytes |
| "Set RAX to 1 so the check passes." | set register |
| "Flip the zero flag so it takes the other branch." | modify flag |
| "Skip that call, move RIP past it." | set CIP |
| "Force the anti-debug check to fail." | typically flag or register change, then continue |

### 9.7. Longer requests that chain tools

These read like one instruction but drive many calls. They work well because each
execution tool returns the new instruction pointer, registers, and nearby disassembly in a
single response.

* "Run `packed.exe` under the debugger, stop at the entry point, then single-step until
  you reach a call into `VirtualAlloc` and show me the arguments."
* "Step over calls until RIP leaves the packer stub and lands in a different module, then
  tell me which one."
* "Break at the entry point, dump 512 bytes there, and tell me if it looks packed."
* "Set a breakpoint at `0x401000`, continue, and when it hits show me the stack and
  registers."
* "Continue to the next break. If it does not break within two minutes, say so instead of
  waiting."
* "Analyze `evil.exe`, and when it finishes summarize the signatures and configs, but skip
  the strings."

### 9.8. Phrasing that helps

* **Name the address or register** - "dump 64 bytes at RSP" beats "dump the stack area".
* **Give a stopping condition** - "step until the call returns" or "step at most 20 times";
  open-ended stepping burns round trips.
* **Say how long to wait** - "wait up to 5 minutes" maps to `timeout_seconds`. The default
  is 120, and a `continue` that does not break returns `state: running` rather than hanging.
* **Ask for the reasoning** - "step through this and explain what the decryption loop is
  doing" gets you an interpretation, not just a register dump.
* **Hex is assumed** - "401000" and "0x401000" both work.
