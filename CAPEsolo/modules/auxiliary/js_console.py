import logging
import os

from lib.common.abstracts import Auxiliary
from lib.common.constants import OPT_CURDIR
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)
INTERCEPTOR_FILE_NAME = "js_interceptor.js"

INTERCEPTOR_TEMPLATE = """(() => {
  const fs = require("fs");
  const path = require("path");
  const MAX_BODY_CHARS = 4096;

  function loggedInUserTemp() {
    if (process.env.LOCALAPPDATA) return path.join(process.env.LOCALAPPDATA, "Temp");
    if (process.env.USERPROFILE) return path.join(process.env.USERPROFILE, "AppData", "Local", "Temp");
    return process.env.TEMP || "C:\\\\Windows\\\\Temp";
  }

  const logPath = process.env.JS_CONSOLE_LOG_PATH || path.join(loggedInUserTemp(), "js_console.log");

  function safeAppendJson(obj) {
    try {
      fs.mkdirSync(path.dirname(logPath), { recursive: true });
      fs.appendFileSync(logPath, JSON.stringify(obj) + "\\n", "utf8");
    } catch (_) {}
  }

  function nowIso() { return new Date().toISOString(); }

  function safeToString(v) {
    if (typeof v === "string") return v;
    try { return JSON.stringify(v); } catch { return String(v); }
  }

  function truncate(s, limit = MAX_BODY_CHARS) {
    if (typeof s !== "string") s = safeToString(s);
    if (s.length <= limit) return { text: s, truncated: false };
    return { text: s.slice(0, limit), truncated: true };
  }

  function normalizeHeaders(headersLike) {
    try {
      if (!headersLike) return {};
      if (typeof Headers !== "undefined" && headersLike instanceof Headers) return Object.fromEntries(headersLike.entries());
      if (Array.isArray(headersLike)) return Object.fromEntries(headersLike);
      return { ...headersLike };
    } catch {
      return {};
    }
  }

  function normalizeUrl(url) {
    try { return url.toString(); } catch { return String(url); }
  }

  function safeCall(fn, fallback = null) {
    try { return fn(); } catch { return fallback; }
  }

  ["log", "info", "warn", "error", "debug"].forEach((level) => {
    const original = typeof console[level] === "function" ? console[level].bind(console) : null;
    console[level] = (...args) => {
      safeAppendJson({
        ts: nowIso(),
        source: "js_interceptor",
        event: "console",
        level,
        message: args.map(safeToString).join(" "),
      });
      if (original) return original(...args);
    };
  });

  safeAppendJson({
    ts: nowIso(),
    source: "js_interceptor",
    event: "init",
    log_path: logPath,
    pid: safeCall(() => (typeof process !== "undefined" ? process.pid : null), null),
    ppid: safeCall(() => (typeof process !== "undefined" ? process.ppid : null), null),
    cwd: safeCall(() => (typeof process !== "undefined" ? process.cwd() : null), null),
    exec_path: safeCall(() => (typeof process !== "undefined" ? process.execPath : null), null),
    argv: safeCall(() => (typeof process !== "undefined" && Array.isArray(process.argv) ? process.argv : null), null),
    bun_version: safeCall(() => (typeof Bun !== "undefined" ? Bun.version : null), null),
  });

  if (typeof globalThis.fetch !== "function") {
    safeAppendJson({
      ts: nowIso(),
      source: "js_interceptor",
      event: "warning",
      message: "fetch not available on globalThis; fetch interceptor not installed",
    });
    return;
  }

  const originalFetch = globalThis.fetch;
  let seq = 0;

  globalThis.fetch = async (url, options = {}) => {
    const request_id = ++seq;
    const method = options.method || "GET";
    const requestUrl = normalizeUrl(url);
    const reqHeaders = normalizeHeaders(options.headers);

    let reqBody = null;
    if (options.body !== undefined && options.body !== null) {
      const b = truncate(options.body);
      reqBody = { text: b.text, truncated: b.truncated };
    }

    safeAppendJson({
      ts: nowIso(),
      source: "js_interceptor",
      event: "http_request",
      request_id,
      method,
      url: requestUrl,
      headers: reqHeaders,
      body: reqBody,
    });

    const started = Date.now();
    try {
      const response = await originalFetch(url, options);
      const cloned = response.clone();

      const resHeaders = normalizeHeaders(response.headers);
      let resBody = { text: null, truncated: false, unreadable: false };

      try {
        const text = await cloned.text();
        const t = truncate(text);
        resBody = { text: t.text, truncated: t.truncated, unreadable: false };
      } catch {
        resBody = { text: null, truncated: false, unreadable: true };
      }

      safeAppendJson({
        ts: nowIso(),
        source: "js_interceptor",
        event: "http_response",
        request_id,
        status: response.status,
        status_text: response.statusText,
        headers: resHeaders,
        body: resBody,
        elapsed_ms: Date.now() - started,
      });

      return response;
    } catch (err) {
      safeAppendJson({
        ts: nowIso(),
        source: "js_interceptor",
        event: "http_error",
        request_id,
        elapsed_ms: Date.now() - started,
        error: safeToString(err),
      });
      throw err;
    }
  };
})();
"""


def _logged_in_user_temp():
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return os.path.join(local_app_data, "Temp")

    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        return os.path.join(user_profile, "AppData", "Local", "Temp")

    return os.environ.get("TEMP", r"C:\Windows\Temp")


class JsConsole(Auxiliary):
    start_priority = 10
    stop_priority = 10

    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        super().__init__(options, config)

        temp_dir = _logged_in_user_temp()
        file_name = self.options.get("js_console_file", "js_console.log")
        self.log_path = os.path.join(temp_dir, file_name)
        self.interceptor_name = INTERCEPTOR_FILE_NAME
        self.interceptor_path = os.path.join(self._target_directory(), self.interceptor_name)

        # Interceptor should read this path and append console output there.
        os.environ["JS_CONSOLE_LOG_PATH"] = self.log_path
        os.environ["JS_INTERCEPTOR_PATH"] = self.interceptor_path
        self.do_run = True

    def _target_directory(self):
        file_name = getattr(self.config, "file_name", "")
        curdir = self.options.get(OPT_CURDIR) or os.environ.get("TEMP", r"C:\Windows\Temp")
        curdir = os.path.expandvars(curdir)
        if file_name:
            return os.path.dirname(os.path.join(curdir, str(file_name)))
        return curdir

    def start(self):
        if not self.do_run:
            return
        try:
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
            if os.path.exists(self.log_path):
                os.remove(self.log_path)
            os.makedirs(os.path.dirname(self.interceptor_path), exist_ok=True)
            with open(self.interceptor_path, "w", encoding="utf-8") as f:
                f.write(INTERCEPTOR_TEMPLATE)
            log.info("js_console: wrote interceptor script to %s", self.interceptor_path)
        except Exception as e:
            log.warning("js_console: failed to prepare js artifacts: %s", e)

    def stop(self):
        self.do_run = False

    def finish(self):
        try:
            if os.path.exists(self.log_path):
                upload_to_host(self.log_path, "aux/js_console.log", category="aux")
                log.info("js_console: uploaded %s", self.log_path)
            else:
                log.debug("js_console: log file not found at %s", self.log_path)
        except Exception as e:
            log.warning("js_console: upload failed for %s: %s", self.log_path, e)
