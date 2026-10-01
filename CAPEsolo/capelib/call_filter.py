"""Match behaviour calls against a filter.

Kept free of wx so the Behavior tab and the MCP call queries can share one set of rules:

  * api, process and argument match as case-insensitive substrings - process against
    "<pid> <name>", argument against every argument's value (and its pretty value);
  * tid matches exactly;
  * with regex set, every field is a case-insensitive regular expression instead;
  * category matches exactly, "all" meaning any;
  * every field given must match.
"""

import re


class CallFilter:
    FIELDS = ("api", "tid", "process", "argument")

    def __init__(self, api="", tid="", process="", argument="", category="all", regex=False):
        """Raises re.error for an invalid pattern when *regex* is set."""
        self.category = category or "all"
        self.regex = regex
        self.patterns = {}
        for name, text in (("api", api), ("tid", tid), ("process", process), ("argument", argument)):
            text = (text or "").strip()
            if not text:
                continue
            if regex:
                self.patterns[name] = re.compile(text, re.IGNORECASE)
            elif name == "tid":
                self.patterns[name] = re.compile(f"^{re.escape(text)}$")
            else:
                self.patterns[name] = re.compile(re.escape(text), re.IGNORECASE)

    @property
    def active(self):
        """True when anything beyond the category narrows the calls."""
        return bool(self.patterns)

    def MatchesProcess(self, proc):
        pattern = self.patterns.get("process")
        return pattern is None or bool(pattern.search(ProcessLabel(proc)))

    def Matches(self, call):
        if self.category != "all" and call.get("category") != self.category:
            return False
        for name, key in (("api", "api"), ("tid", "thread_id")):
            pattern = self.patterns.get(name)
            if pattern is not None and not pattern.search(str(call.get(key, ""))):
                return False
        pattern = self.patterns.get("argument")
        if pattern is not None:
            for arg in call.get("arguments") or []:
                if pattern.search(str(arg.get("value", ""))) or pattern.search(str(arg.get("pretty_value", ""))):
                    break
            else:
                return False
        return True


def ProcessLabel(proc):
    return f'{proc.get("process_id", "")} {proc.get("process_name", "")}'.strip()


def FilterCalls(processes, callFilter, selected=None):
    """[(process, call)] for the calls that match, in log order.

    With a process pattern, every process whose label matches is searched; otherwise only
    *selected* (the process picked in the tree), or nothing when none is.
    """
    if "process" in callFilter.patterns:
        return FilterAllCalls(processes, callFilter)
    sources = [selected] if selected else []
    return [(proc, call) for proc in sources for call in proc.get("calls") or [] if callFilter.Matches(call)]


def FilterAllCalls(processes, callFilter):
    """[(process, call)] across every process the process pattern allows (all, if none)."""
    return [
        (proc, call)
        for proc in processes or []
        if callFilter.MatchesProcess(proc)
        for call in proc.get("calls") or []
        if callFilter.Matches(call)
    ]
