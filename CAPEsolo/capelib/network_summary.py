"""Build the results["network"] summary CAPEsolo's signatures and reports expect.

Nothing populated this key before, so the 14 network signatures that ship in
signatures/community were loaded and evaluated on every run but could never match, and
neither report had a network section.

Three sources feed it, matching what CAPEv2 merges in modules/processing/network.py
(_merge_behavior_network and _merge_js_log_network alongside the pcap):

  * the behaviour log - capemon records the network and socket API calls, so hosts, DNS
    lookups and HTTP requests are known even with no capture at all;
  * the JS console log - the interceptor reports fetch/XHR requests and DNS lookups that
    never reach a hooked Win32 API;
  * a user-supplied capture, when the Network tab has one.

The key shapes are CAPEv2's, because the signatures read them directly: hosts entries need
"ip", domains "domain", http "uri", dns "request" and "answers" (each with "data"), udp
"dst"/"dport", icmp "dst"/"type", smtp "dst".
"""

import logging
from urllib.parse import urlparse

log = logging.getLogger(__name__)

# Behaviour-log APIs worth reading, grouped by what they tell us. Argument names come from
# logtbl.py, which is what the parsed calls are labelled with.
DNS_APIS = {
    "DnsQuery_A": "Name",
    "DnsQuery_UTF8": "Name",
    "DnsQuery_W": "Name",
    "getaddrinfo": "NodeName",
    "GetAddrInfoW": "NodeName",
    "gethostbyname": "Name",
}

URL_APIS = {
    "URLDownloadToFileW": "URL",
    "URLDownloadToFileA": "URL",
    "InternetOpenUrlA": "URL",
    "InternetOpenUrlW": "URL",
    "WinHttpOpenRequest": "ObjectName",
}

# InternetConnect names the host and port directly, which is the one place the behaviour log
# gives a host/port pair without a URL to parse.
CONNECT_APIS = {
    "InternetConnectA": ("ServerName", "ServerPort"),
    "InternetConnectW": ("ServerName", "ServerPort"),
}

# HttpOpenRequest carries only the path; the host came from the earlier InternetConnect on
# the same handle, which is not tracked here, so these contribute a path-only request.
PATH_APIS = {
    "HttpOpenRequestA": "Path",
    "HttpOpenRequestW": "Path",
}


def _EmptyNetwork():
    return {
        "hosts": [],
        "domains": [],
        "tcp": [],
        "udp": [],
        "icmp": [],
        "http": [],
        "dns": [],
        "smtp": [],
        "irc": [],
        "dead_hosts": [],
        "tls": [],
        "sorted": {"tcp": [], "udp": []},
        # Which sources actually contributed, so a report can say why a section is thin.
        "sources": [],
    }


def _Argument(call, name):
    """Read one argument value from a parsed behaviour call."""
    for argument in call.get("arguments") or ():
        if argument.get("name") == name:
            value = argument.get("value")
            if value is None:
                return ""
            return str(value)

    return ""


def _IsIpv4(value):
    parts = value.split(".")
    if len(parts) != 4:
        return False

    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False

    return True


class _Collector:
    """Accumulates the summary, keeping each list deduplicated as it grows."""

    def __init__(self):
        self.network = _EmptyNetwork()
        self._hosts = set()
        self._domains = set()
        self._requests = set()
        self._dns = {}

    def AddHost(self, ip):
        if not ip or not _IsIpv4(ip) or ip in self._hosts:
            return

        self._hosts.add(ip)
        self.network["hosts"].append({"ip": ip})

    def AddDomain(self, domain, ip=""):
        if not domain or domain in self._domains:
            return

        self._domains.add(domain)
        self.network["domains"].append({"domain": domain, "ip": ip})

    def AddDnsRequest(self, name, answers=None, rtype="A"):
        """One entry per queried name, answers merged into it as they are seen."""
        if not name:
            return

        entry = self._dns.get(name)
        if entry is None:
            entry = {"request": name, "type": rtype, "answers": []}
            self._dns[name] = entry
            self.network["dns"].append(entry)

        seen = {(a["data"], a["type"]) for a in entry["answers"]}
        for address in answers or ():
            if not address or (address, "A") in seen:
                continue
            entry["answers"].append({"data": address, "type": "A"})
            seen.add((address, "A"))
            self.AddHost(address)
            self.AddDomain(name, address)

        if not answers:
            self.AddDomain(name)

    def AddHttp(self, url="", method="GET", host="", path="", data=""):
        """Add an HTTP request, deriving host/uri/path from whichever was supplied."""
        uri = url
        port = 80
        if url:
            try:
                parsed = urlparse(url)
            except ValueError:
                parsed = None

            if parsed and parsed.scheme in ("http", "https"):
                host = host or parsed.hostname or ""
                path = parsed.path or "/"
                if parsed.query:
                    path = f"{path}?{parsed.query}"
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not uri:
            uri = path or "/"

        key = (method, host, uri)
        if key in self._requests:
            return

        self._requests.add(key)
        self.network["http"].append(
            {
                "count": 1,
                "host": host,
                "port": port,
                "method": method,
                "uri": uri,
                "path": path or uri,
                "data": data,
                "body": "",
                "version": "1.1",
                "user-agent": "",
            }
        )
        if host:
            if _IsIpv4(host):
                self.AddHost(host)
            else:
                self.AddDomain(host)

    def AddFlow(self, protocol, src, sport, dst, dport, timestamp=0.0):
        if protocol not in ("tcp", "udp") or not dst:
            return

        entry = {
            "src": src,
            "sport": sport,
            "dst": dst,
            "dport": dport,
            "offset": 0,
            "time": timestamp,
        }
        self.network[protocol].append(entry)
        self.network["sorted"][protocol].append(entry)
        self.AddHost(dst)

    def Source(self, name):
        if name not in self.network["sources"]:
            self.network["sources"].append(name)


def _FromBehavior(collector, behavior):
    """Pull hosts, DNS lookups and HTTP requests out of the monitor's API log."""
    processes = (behavior or {}).get("processes") or []
    found = False
    for process in processes:
        for call in process.get("calls") or ():
            api = call.get("api") or ""
            category = call.get("category") or ""
            if category not in ("network", "socket"):
                continue

            if api in DNS_APIS:
                name = _Argument(call, DNS_APIS[api])
                if name:
                    collector.AddDnsRequest(name)
                    found = True
            elif api in URL_APIS:
                url = _Argument(call, URL_APIS[api])
                if url:
                    collector.AddHttp(url=url)
                    found = True
            elif api in CONNECT_APIS:
                nameArg, portArg = CONNECT_APIS[api]
                host = _Argument(call, nameArg)
                port = _Argument(call, portArg)
                if host:
                    if _IsIpv4(host):
                        collector.AddHost(host)
                    else:
                        collector.AddDomain(host)
                    try:
                        dport = int(port)
                    except (TypeError, ValueError):
                        dport = 0
                    if _IsIpv4(host) and dport:
                        collector.AddFlow("tcp", "", 0, host, dport)
                    found = True
            elif api in PATH_APIS:
                path = _Argument(call, PATH_APIS[api])
                if path:
                    collector.AddHttp(path=path)
                    found = True
            elif api == "bind":
                # A bound listening port is what network_bind looks for.
                found = True

    if found:
        collector.Source("behavior")


def _FromJsLog(collector, jsLog):
    """Pull requests and lookups the JS interceptor saw.

    A script using fetch or XHR goes through the runtime's own stack, so these need not
    appear in the behaviour log at all.
    """
    events = (jsLog or {}).get("events") or []
    found = False
    for event in events:
        name = event.get("event") or ""
        if name == "http_request":
            url = event.get("url") or ""
            if url:
                collector.AddHttp(url=url, method=event.get("method") or "GET")
                found = True
        elif name == "dns_query":
            hostname = event.get("hostname") or ""
            if hostname:
                collector.AddDnsRequest(hostname)
                found = True
        elif name == "dns_result":
            hostname = event.get("hostname") or ""
            addresses = event.get("addresses") or []
            if isinstance(addresses, str):
                addresses = [addresses]
            if hostname:
                collector.AddDnsRequest(hostname, answers=addresses)
                found = True
        elif name == "tcp_connect":
            host = str(event.get("host") or "")
            try:
                port = int(event.get("port") or 0)
            except (TypeError, ValueError):
                port = 0
            if host:
                if _IsIpv4(host):
                    collector.AddFlow("tcp", "", 0, host, port)
                else:
                    collector.AddDomain(host)
                found = True

    if found:
        collector.Source("js_log")


def _FromCapture(collector, capture):
    """Fold in a parsed capture from capelib.network.NetworkData."""
    if not capture:
        return

    for event in capture.get("events") or ():
        kind = event.get("kind")
        if kind == "DNS":
            # The parsed detail is not carried through, so use what the row exposes: the
            # question, plus any answers the resolver returned.
            host = event.get("host") or ""
            if host:
                collector.AddDnsRequest(host)
        elif kind == "HTTP":
            info = event.get("info") or ""
            method = info.split(" ", 1)[0] if info else "GET"
            collector.AddHttp(
                path=info.split(" ")[1] if " " in info else "/",
                method=method,
                host=event.get("host") or event.get("dst") or "",
            )
        elif kind == "TLS":
            host = event.get("host") or ""
            if host:
                collector.AddDomain(host, event.get("dst") or "")
            collector.AddHost(event.get("dst") or "")

    for ip, names in (capture.get("hosts") or {}).items():
        collector.AddHost(ip)
        for name in names:
            collector.AddDomain(name, ip)

    for flow in capture.get("flows") or ():
        info = flow.get("info") or ""
        protocol = "udp" if info.startswith("UDP") else "tcp"
        src, _, sport = str(flow.get("src") or "").rpartition(":")
        dst, _, dport = str(flow.get("dst") or "").rpartition(":")
        try:
            collector.AddFlow(
                protocol, src, int(sport or 0), dst, int(dport or 0), flow.get("time") or 0.0
            )
        except (TypeError, ValueError):
            continue

    collector.Source("pcap")


def NetworkSummary(behavior=None, jsLog=None, capture=None, decrypted=None):
    """Assemble results["network"] from whichever sources are available.

    Every argument is optional: with no capture the summary still covers what the monitor
    and the JS interceptor observed, which is what makes the network signatures work on a
    run where the user never supplied a pcap.
    """
    collector = _Collector()
    try:
        _FromBehavior(collector, behavior)
    except Exception as e:
        log.warning("Could not read network activity from the behaviour log: %s", e)

    try:
        _FromJsLog(collector, jsLog)
    except Exception as e:
        log.warning("Could not read network activity from the JS log: %s", e)

    try:
        _FromCapture(collector, capture)
    except Exception as e:
        log.warning("Could not read network activity from the capture: %s", e)

    network = collector.network

    # Decrypted streams are additive: they carry the plaintext of requests the sources above
    # could only see the metadata of, and they also count as HTTP requests for signatures.
    if decrypted:
        for key in ("http_ex", "https_ex", "smtp_ex"):
            entries = decrypted.get(key) or []
            if entries:
                network[key] = entries

        for entry in (decrypted.get("http_ex") or []) + (decrypted.get("https_ex") or []):
            collector.AddHttp(
                method=entry.get("method") or "GET",
                host=entry.get("host") or "",
                path=entry.get("uri") or "/",
                data=entry.get("request") or "",
            )
            collector.AddHost(entry.get("dst") or "")

        for entry in decrypted.get("smtp_ex") or []:
            network["smtp"].append(
                {
                    "dst": entry.get("dst") or "",
                    "dport": entry.get("dport") or 0,
                    "req": entry.get("req") or {},
                }
            )

        if any(decrypted.get(k) for k in ("http_ex", "https_ex", "smtp_ex")):
            collector.Source("decrypted")

        # Carry the decryption status so a report can explain a thin or empty Plaintext
        # section - a missing dependency, no secrets, or a truncated capture - the way the
        # Network tab does, instead of leaving the reader to guess why it decrypted nothing.
        network["decrypted"] = {
            "available": decrypted.get("available", False),
            "secrets": decrypted.get("secrets", 0),
            "error": decrypted.get("error", ""),
            "counts": {
                key: len(decrypted.get(key) or [])
                for key in ("http_ex", "https_ex", "smtp_ex")
            },
        }

    return network
