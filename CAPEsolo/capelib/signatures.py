import inspect
import logging
import os
import pkgutil
import re
import socket
import sys
from builtins import NotImplementedError
from collections import defaultdict

import dns.resolver
from tldextract import TLDExtract

from CAPEsolo import signatures

from . import cape_compat
from .path_utils import path_exists
from .url_validate import url as url_validator
from .utils import create_folder

log = logging.getLogger(__name__)

myresolver = dns.resolver.Resolver()
myresolver.timeout = 5.0
myresolver.lifetime = 5.0
myresolver.domain = dns.name.Name("google-public-dns-a.google.com")
myresolver.nameserver = ["8.8.8.8"]
_modules = defaultdict(dict)


def load_plugins(module):
    for _, value in inspect.getmembers(module):
        if inspect.isclass(value):
            if issubclass(value, Signature) and value is not Signature:
                register_plugin("signatures", value)


def register_plugin(group, cls):
    global _modules
    group = _modules.setdefault(group, [])
    if cls not in group:
        group.append(cls)


def list_plugins(group=None):
    if group:
        return _modules[group]
    return _modules


def import_plugin(name):
    try:
        module = __import__(name, globals(), locals(), ["dummy"])
    except (ImportError, SyntaxError) as e:
        print(f'Unable to import plugin "{name}": {e}')
        return
    else:
        # ToDo remove for release
        try:
            load_plugins(module)
        except Exception as e:
            print(e, sys.exc_info())


def import_package(package):
    prefix = f"{package.__name__}."
    for _, name, ispkg in pkgutil.iter_modules(package.__path__, prefix):
        if ispkg:
            continue

        import_plugin(name)


class Signature:
    """Base class for Cuckoo signatures."""
    name = ""
    description = ""
    severity = 1
    confidence = 100
    weight = 1
    categories = []
    families = []
    authors = []
    references = []
    alert = False
    enabled = True
    minimum = None
    maximum = None
    ttps = []
    mbcs = []

    # Higher order will be processed later (only for non-evented signatures)
    # this can be used for having meta-signatures that check on other lower-
    # order signatures being matched
    order = 0

    evented = False
    filter_processnames = set()
    filter_apinames = set()
    filter_categories = set()
    filter_analysistypes = set()
    banned_suricata_sids = ()

    def __init__(self, results=None):
        self.data = []
        self.new_data = []
        self.results = results
        self._current_call_cache = None
        self._current_call_dict = None
        self._current_call_raw_cache = None
        self._current_call_raw_dict = None
        self.hostname2ips = {}
        self.matched = False

        # These are set during the iteration of evented signatures
        self.pid = None
        self.cid = None
        self.call = None

    def set_path(self, analysis_path):
        """Set analysis folder path.
        @param analysis_path: analysis folder path.
        """
        self.analysis_path = analysis_path
        self.conf_path = os.path.join(self.analysis_path, "analysis.conf")
        self.file_path = os.path.realpath(os.path.join(self.analysis_path, "binary"))
        self.dropped_path = os.path.join(self.analysis_path, "files")
        self.procdump_path = os.path.join(self.analysis_path, "procdump")
        self.CAPE_path = os.path.join(self.analysis_path, "CAPE")
        self.reports_path = os.path.join(self.analysis_path, "reports")
        self.shots_path = os.path.join(self.analysis_path, "shots")
        self.pcap_path = os.path.join(self.analysis_path, "dump.pcap")
        self.pmemory_path = os.path.join(self.analysis_path, "memory")
        self.self_extracted = os.path.join(self.analysis_path, "selfextracted")
        self.files_metadata = os.path.join(self.analysis_path, "files.json")
        self.logs_path = os.path.join(self.analysis_path, "logs")

        try:
            create_folder(folder=self.reports_path)
        except Exception as e:
            print(e)

    def yara_detected(self, name):

        target = self.results.get("target", {})
        if target.get("category") in ("file", "static") and target.get("file"):
            for keyword in ("cape_yara", "yara"):
                for yara_block in self.results["target"]["file"].get(keyword, []):
                    if re.findall(name, yara_block["name"], re.IGNORECASE):
                        yield "sample", self.results["target"]["file"][
                            "path"
                        ], yara_block, self.results["target"]["file"]

            for block in target["file"].get("extracted_files", []):
                for keyword in ("cape_yara", "yara"):
                    for yara_block in block[keyword]:
                        if re.findall(name, yara_block["name"], re.IGNORECASE):
                            # we can't use here values from set_path
                            yield "sample", block["path"], yara_block, block

        for block in self.results.get("CAPE", {}).get("payloads", []) or []:
            for sub_keyword in ("cape_yara", "yara"):
                for yara_block in block.get(sub_keyword, []):
                    if re.findall(name, yara_block["name"], re.IGNORECASE):
                        yield sub_keyword, block["path"], yara_block, block

            for subblock in block.get("extracted_files", []):
                for keyword in ("cape_yara", "yara"):
                    for yara_block in subblock[keyword]:
                        if re.findall(name, yara_block["name"], re.IGNORECASE):
                            yield "sample", subblock["path"], yara_block, block

        for keyword in ("procdump", "procmemory", "extracted", "dropped"):
            if self.results.get(keyword) is not None:
                for block in self.results.get(keyword, []):
                    if not isinstance(block, dict):
                        continue
                    for sub_keyword in ("cape_yara", "yara"):
                        for yara_block in block.get(sub_keyword, []):
                            if re.findall(name, yara_block["name"], re.IGNORECASE):
                                path = block["path"] if block.get("path", False) else ""
                                yield keyword, path, yara_block, block

                    if keyword == "procmemory":
                        for pe in block.get("extracted_pe", []) or []:
                            for sub_keyword in ("cape_yara", "yara"):
                                for yara_block in pe.get(sub_keyword, []) or []:
                                    if re.findall(name, yara_block["name"], re.IGNORECASE):
                                        yield "extracted_pe", pe[
                                            "path"
                                        ], yara_block, block

                    for subblock in block.get("extracted_files", []):
                        for keyword in ("cape_yara", "yara"):
                            for yara_block in subblock[keyword]:
                                if re.findall(name, yara_block["name"], re.IGNORECASE):
                                    yield "sample", subblock["path"], yara_block, block

        macro_path = os.path.join(self.analysis_path, "macros")
        for macroname in (
            self.results.get("static", {})
            .get("office", {})
            .get("Macro", {})
            .get("info", [])
            or []
        ):
            for yara_block in (
                self.results["static"]["office"]["Macro"]["info"].get("macroname", [])
                or []
            ):
                for sub_block in (
                    self.results["static"]["office"]["Macro"]["info"]["macroname"].get(
                        yara_block, []
                    )
                    or []
                ):
                    if re.findall(name, sub_block["name"], re.IGNORECASE):
                        yield "macro", os.path.join(
                            macro_path, macroname
                        ), sub_block, self.results["static"]["office"]["Macro"]["info"]

        if (
            self.results.get("static", {})
            .get("office", {})
            .get("XLMMacroDeobfuscator", False)
        ):
            for yara_block in (
                self.results["static"]["office"]["XLMMacroDeobfuscator"]
                .get("info", [])
                .get("yara_macro", [])
                or []
            ):
                if re.findall(name, yara_block["name"], re.IGNORECASE):
                    yield "macro", os.path.join(
                        macro_path, "xlm_macro"
                    ), yara_block, self.results["static"]["office"][
                        "XLMMacroDeobfuscator"
                    ][
                        "info"
                    ]

    def signature_matched(self, signame: str) -> bool:
        # Check if signature has matched (useful for ordered signatures)
        matched_signatures = [sig["name"] for sig in self.results.get("signatures", [])]
        return signame in matched_signatures

    def get_signature_data(self, signame: str) -> list[dict[str, str]]:
        # Retrieve data from matched signature (useful for ordered signatures)
        if self.signature_matched(signame):
            signature = next(
                (
                    match
                    for match in self.results.get("signatures", [])
                    if match.get("name") == signame
                ),
                None,
            )

            if signature:
                return signature.get("data", []) + signature.get("new_data", [])
        return []

    def get_pids(self):
        pids = []
        processes = self.results.get("behavior", {}).get("processtree", [])
        if processes:
            for pid in processes:
                pids.append(int(pid.get("pid", "")))
                pids += [
                    int(cpid["pid"])
                    for cpid in pid.get("children", [])
                    if "pid" in cpid
                ]
        # in case if bsons too big
        if path_exists(self.logs_path):
            pids += [
                int(pidb.replace(".bson", ""))
                for pidb in os.listdir(self.logs_path)
                if ".bson" in pidb
            ]

        #  in case if injection not follows
        if self.results.get("procmemory") is not None:
            pids += [int(block["pid"]) for block in self.results["procmemory"]]
        if self.results.get("procdump") is not None:
            pids += [int(block["pid"]) for block in self.results["procdump"]]

        log.debug(list(set(pids)))
        return list(set(pids))

    def advanced_url_parse(self, url):
        EXTRA_SUFFIXES = ("bit",)
        parsed = False
        try:
            parsed = TLDExtract(extra_suffixes=EXTRA_SUFFIXES, suffix_list_urls=None)(
                url
            )
        except Exception as e:
            log.error(e)
        return parsed

    def _get_ip_by_host(self, hostname):
        return next(
            (
                [data.get("ip", "")]
                for data in self.results.get("network", {}).get("hosts", [])
                if data.get("hostname", "") == hostname
            ),
            [],
        )

    def _get_ip_by_host_dns(self, hostname):

        ips = []

        try:
            answers = myresolver.query(hostname, "A")
            for rdata in answers:
                n = dns.reversename.from_address(rdata.address)
                try:
                    answers_inv = myresolver.query(n, "PTR")
                    ips.extend(rdata.address for _ in answers_inv)
                except dns.resolver.NoAnswer:
                    ips.append(rdata.address)
                except dns.resolver.NXDOMAIN:
                    ips.append(rdata.address)
        except dns.name.NeedAbsoluteNameOrOrigin:
            print(
                "An attempt was made to convert a non-absolute name to wire when there was also a non-absolute (or missing) origin"
            )
        except dns.resolver.NoAnswer:
            print("IPs: Impossible to get response")
        except Exception as e:
            log.info(str(e))

        return ips

    def _is_ip(self, ip):
        # is this string an ip?
        try:
            socket.inet_aton(ip)
            return True
        except Exception:
            return False

    def _check_valid_url(self, url, all_checks=False):
        """Checks if url is correct
        @param url: string
        @return: url or None
        """

        try:
            if url_validator(url):
                return url
        except Exception as e:
            print(e)

        if all_checks:
            last = url.rfind("://")
            if url[:last] in ("http", "https"):
                url = url[last + 3 :]

        try:
            if url_validator(f"http://{url}"):
                return f"http://{url}"
        except Exception as e:
            print(e)

    def _check_value(self, pattern, subject, regex=False, all=False, ignorecase=True):
        """Checks a pattern against a given subject.
        @param pattern: string or expression to check for.
        @param subject: target of the check.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @param ignorecase: in non-regex instances, should we ignore case for matches?
                            defaults to true
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        if regex:
            if all:
                retset = set()
            exp = re.compile(pattern, re.IGNORECASE)
            if isinstance(subject, list):
                for item in subject:
                    if exp.match(item):
                        if all:
                            retset.add(item)
                        else:
                            return item
            elif exp.match(subject):
                if all:
                    retset.add(subject)
                else:
                    return subject
            if all and len(retset) > 0:
                return retset
        elif ignorecase:
            lowerpattern = pattern.lower()
            if isinstance(subject, list):
                for item in subject:
                    if item.lower() == lowerpattern:
                        return item
            elif subject.lower() == lowerpattern:
                return subject
        elif isinstance(subject, list):
            for item in subject:
                if item == pattern:
                    return item
        elif subject == pattern:
            return subject

        return None

    def check_process_name(self, pattern, all=False):
        if "behavior" in self.results and "processes" in self.results["behavior"]:
            for process in self.results["behavior"]["processes"]:
                if re.findall(pattern, process["process_name"], re.IGNORECASE):
                    return process if all else True
        return False

    def check_file(self, pattern, regex=False, all=False):
        """Checks for a file being opened.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["files"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_read_file(self, pattern, regex=False, all=False):
        """Checks for a file being read from.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["read_files"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_write_file(self, pattern, regex=False, all=False):
        """Checks for a file being written to.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["write_files"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_delete_file(self, pattern, regex=False, all=False):
        """Checks for a file being deleted.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["delete_files"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_key(self, pattern, regex=False, all=False):
        """Checks for a registry key being opened.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["keys"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_read_key(self, pattern, regex=False, all=False):
        """Checks for a registry key/value being read
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["read_keys"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_write_key(self, pattern, regex=False, all=False):
        """Checks for a registry key/value being modified
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["write_keys"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_delete_key(self, pattern, regex=False, all=False):
        """Checks for a registry key/value being modified or deleted
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["delete_keys"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_mutex(self, pattern, regex=False, all=False):
        """Checks for a mutex being opened.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["mutexes"]
        return self._check_value(
            pattern=pattern, subject=subject, regex=regex, all=all, ignorecase=False
        )

    def check_started_service(self, pattern, regex=False, all=False):
        """Checks for a service being started.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["started_services"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_created_service(self, pattern, regex=False, all=False):
        """Checks for a service being created.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["created_services"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_executed_command(self, pattern, regex=False, all=False, ignorecase=True):
        """Checks for a command being executed.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @param ignorecase: whether the search should be performed case-insensitive
                      or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["executed_commands"]
        return self._check_value(
            pattern=pattern,
            subject=subject,
            regex=regex,
            all=all,
            ignorecase=ignorecase,
        )

    def check_api(self, pattern, process=None, regex=False, all=False):
        """Checks for an API being called.
        @param pattern: string or expression to check for.
        @param process: optional filter for a specific process name.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        # Loop through processes.
        if all:
            retset = set()
        for item in self.results["behavior"]["processes"]:
            # Check if there's a process name filter.
            if process and item["process_name"] != process:
                continue

            # Loop through API calls.
            for call in item["calls"]:
                # Check if the name matches.
                ret = self._check_value(
                    pattern=pattern,
                    subject=call["api"],
                    regex=regex,
                    all=all,
                    ignorecase=False,
                )
                if ret:
                    if all:
                        retset.update(ret)
                    else:
                        return call["api"]

        return retset if all and len(retset) > 0 else None

    def check_argument_call(
        self,
        call,
        pattern,
        name=None,
        api=None,
        category=None,
        regex=False,
        all=False,
        ignorecase=False,
    ):
        """Checks for a specific argument of an invoked API.
        @param call: API call information.
        @param pattern: string or expression to check for.
        @param name: optional filter for the argument name.
        @param api: optional filter for the API function name.
        @param category: optional filter for a category name.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @param ignorecase: boolean representing whether the search is
                    case-insensitive or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        if all:
            retset = set()

        # Check if there's an API name filter.
        if api and call["api"] != api:
            return False

        # Check if there's a category filter.
        if category and call["category"] != category:
            return False

        # Loop through arguments.
        for argument in call["arguments"]:
            # Check if there's an argument name filter.
            if name and argument["name"] != name:
                continue

            # Check if the argument value matches.
            ret = self._check_value(
                pattern=pattern,
                subject=argument["value"],
                regex=regex,
                all=all,
                ignorecase=ignorecase,
            )
            if ret:
                if all:
                    retset.update(ret)
                else:
                    return argument["value"]

        if all and len(retset) > 0:
            return retset

        return False

    def check_argument(
        self,
        pattern,
        name=None,
        api=None,
        category=None,
        process=None,
        regex=False,
        all=False,
        ignorecase=False,
    ):
        """Checks for a specific argument of an invoked API.
        @param pattern: string or expression to check for.
        @param name: optional filter for the argument name.
        @param api: optional filter for the API function name.
        @param category: optional filter for a category name.
        @param process: optional filter for a specific process name.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @param ignorecase: boolean representing whether the search is
                    case-insensitive or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        if all:
            retset = set()

        # Loop through processes.
        for item in self.results["behavior"]["processes"]:
            # Check if there's a process name filter.
            if process and item["process_name"] != process:
                continue

            # Loop through API calls.
            for call in item["calls"]:
                r = self.check_argument_call(
                    call, pattern, name, api, category, regex, all, ignorecase
                )
                if r:
                    if all:
                        retset.update(r)
                    else:
                        return r

        if all and len(retset) > 0:
            return retset

        return None

    def check_ip(self, pattern, regex=False, all=False):
        """Checks for an IP address being contacted.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """

        if all:
            retset = set()

        if "network" not in self.results:
            return None

        hosts = self.results["network"].get("hosts")
        if not hosts:
            return None

        for item in hosts:
            ret = self._check_value(
                pattern=pattern,
                subject=item["ip"],
                regex=regex,
                all=all,
                ignorecase=False,
            )
            if ret:
                if all:
                    retset.update(ret)
                else:
                    return item["ip"]

        if all and len(retset) > 0:
            return retset

        return None

    def check_domain(self, pattern, regex=False, all=False):
        """Checks for a domain being contacted.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """

        if all:
            retset = set()

        if "network" not in self.results:
            return None

        domains = self.results["network"].get("domains")
        if not domains:
            return None

        for item in domains:
            ret = self._check_value(
                pattern=pattern, subject=item["domain"], regex=regex, all=all
            )
            if ret:
                if all:
                    retset.update(ret)
                else:
                    return item["domain"]

        if all and len(retset) > 0:
            return retset

        return None

    def check_url(self, pattern, regex=False, all=False):
        """Checks for a URL being contacted.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """

        if all:
            retset = set()

        if "network" not in self.results:
            return None

        httpitems = self.results["network"].get("http")
        if not httpitems:
            return None
        for item in httpitems:
            ret = self._check_value(
                pattern=pattern,
                subject=item["uri"],
                regex=regex,
                all=all,
                ignorecase=False,
            )
            if ret:
                if all:
                    retset.update(ret)
                else:
                    return item["uri"]

        if all and len(retset) > 0:
            return retset

        return None

    def get_initial_process(self):
        """Obtains the initial process information
        @return: dict containing initial process information or None
        """

        if (
            "behavior" not in self.results
            or "processes" not in self.results["behavior"]
            or not len(self.results["behavior"]["processes"])
        ):
            return None

        return self.results["behavior"]["processes"][0]

    def get_environ_entry(self, proc, env_name):
        """Obtains environment entry from process
        @param proc: Process to inspect
        @param env_name: Name of environment entry
        @return: value of environment entry or None
        """
        if not proc or env_name not in proc.get("environ", {}):
            return None

        return proc["environ"][env_name]

    def get_argument(self, call, name):
        """Retrieves the value of a specific argument from an API call.
        @param call: API call object.
        @param name: name of the argument to retrieve.
        @return: value of the required argument.
        """
        # Check if the call passed to it was cached already.
        # If not, we can start caching it and store a copy converted to a dict.
        if call is not self._current_call_cache:
            self._current_call_cache = call
            self._current_call_dict = {
                argument["name"]: argument["value"] for argument in call["arguments"]
            }

        # Return the required argument.
        if name in self._current_call_dict:
            return self._current_call_dict[name]

        return None

    def get_name_from_pid(self, pid):
        """Retrieve a process name from a supplied pid
        @param pid: a Process PID observed in the analysis
        @return: basestring name of the process or None
        """
        if pid:
            if isinstance(pid, str) and pid.isdigit():
                pid = int(pid)
            if self.results.get("behavior", {}).get("processes", []):
                for proc in self.results["behavior"]["processes"]:
                    if proc["process_id"] == pid:
                        return proc["process_name"]

        return None

    def get_raw_argument(self, call, name):
        """Retrieves the raw value of a specific argument from an API call.
        @param call: API call object.
        @param name: name of the argument to retrieve.
        @return: value of the requried argument.
        """
        # Check if the call passed to it was cached already.
        # If not, we can start caching it and store a copy converted to a dict.
        if call is not self._current_call_raw_cache:
            self._current_call_raw_cache = call
            self._current_call_raw_dict = {
                argument["name"]: argument["raw_value"]
                for argument in call["arguments"]
                if "raw_value" in argument
            }

        # Return the required argument.
        if name in self._current_call_raw_dict:
            return self._current_call_raw_dict[name]

        return None

    def check_suricata_alerts(self, pattern, blacklist=None):
        """Check for pattern in Suricata alert signature
        @param pattern: string or expression to check for.
        @return: True/False
        """
        if blacklist is None:
            blacklist = []
        res = False
        if isinstance(self.results.get("suricata", {}), dict):
            for alert in self.results.get("suricata", {}).get("alerts", []):
                sid = alert.get("sid", 0)
                if (
                    sid not in self.banned_suricata_sids and sid not in blacklist
                ) and re.findall(pattern, alert.get("signature", ""), re.IGNORECASE):
                    res = True
                    break
        return res

    def mark_call(self, *args, **kwargs):
        """Mark the current call as explanation as to why this signature matched."""

        mark = {
            "type": "call",
            "pid": self.pid,
            "cid": self.cid,
        }

        if args or kwargs:
            log.warning(
                "You have provided extra arguments to the mark_call() method which does not support doing so."
            )

        self.data.append(mark)

    def add_match(self, process, type, match):
        """Adds a match to the signature data.
        @param process: The process triggering the match.
        @param type: The type of matching data (ex: 'api', 'mutex', 'file', etc.)
        @param match: Value or array of values triggering the match.
        """
        signs = []
        if isinstance(match, list):
            signs.extend({"type": type, "value": item} for item in match)
        else:
            signs.append({"type": type, "value": match})

        process_summary = None
        if process:
            process_summary = {
                "process_name": process["process_name"],
                "process_id": process["process_id"],
            }

        self.new_data.append({"process": process_summary, "signs": signs})

    def has_matches(self) -> bool:
        """Returns true if there is matches (data is not empty)
        @return: boolean indicating if there is any match registered
        """
        return len(self.new_data) > 0 or len(self.data) > 0

    def on_call(self, call, process):
        """Notify signature about API call. Return value determines
        if this signature is done or could still match.
        @param call: logged API call.
        @param process: process doing API call.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def on_complete(self):
        """Evented signature is notified when all API calls are done.
        @return: Match state.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def run(self):
        """Start signature processing.
        @param results: analysis results.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def as_result(self):
        """Properties as a dict (for results).
        @return: result dictionary.
        """
        return dict(
            name=self.name,
            description=self.description,
            categories=self.categories,
            severity=self.severity,
            weight=self.weight,
            confidence=self.confidence,
            references=self.references,
            data=self.data,
            new_data=self.new_data,
            alert=self.alert,
            families=self.families,
        )


class RunSignatures:
    """Run Signatures."""

    def __init__(self, results, analysis_path):
        self.results = results
        self.ttps = []
        self.mbcs = {}
        self.analysis_path = analysis_path

        import_package(signatures)
        # Community (CAPEv2) signatures are not shipped: the user's own folder beside cfg.ini.
        # One there replaces a shipped signature of the same name, so a copy of upstream's set
        # does not report every shared match twice; likewise the user's own files beat the
        # community subfolder Update fills.
        userClasses = cape_compat.load_user_signatures()
        userNames = {cls.name for cls in userClasses}
        ownNames = {cls.name for cls in userClasses if not cls.__module__.startswith(cape_compat.COMMUNITY_PACKAGE)}

        # Gather all enabled & up-to-date Signatures.
        self.signatures = []
        # Under the view too: CAPEv2 signatures read results["info"] and the like in __init__.
        with cape_compat.SignatureView(self.results, self.analysis_path):
            for signature in list_plugins(group="signatures"):
                if signature.name in userNames and not signature.__module__.startswith(cape_compat.USER_PACKAGE + "."):
                    continue
                if signature.name in ownNames and signature.__module__.startswith(cape_compat.COMMUNITY_PACKAGE):
                    continue
                if self._should_load_signature(signature):
                    # Initialize them all. One at a time: a user signature that raises here
                    # must not take the whole pass down with it.
                    try:
                        self.signatures.append(signature(self.results))
                    except Exception as e:
                        log.warning("Skipping signature %s: failed to initialise: %s", signature.name, e)

        self.evented_list = []
        self.non_evented_list = []
        try:
            for sig in self.signatures:
                if sig.evented:
                    # This is to confirm that the evented signature has its own on_call function, which is required
                    # https://capev2.readthedocs.io/en/latest/customization/signatures.html#evented-signatures
                    if sig.on_call.__module__ != Signature.on_call.__module__:
                        if (
                            not sig.filter_analysistypes
                            or self.results.get("target", {}).get("category")
                            in sig.filter_analysistypes
                        ):
                            self.evented_list.append(sig)

                if sig not in self.evented_list:
                    self.non_evented_list.append(sig)
        except Exception as e:
            print(e)

        # Cache of signatures to call per (process name, API name, category).
        self.api_sigs = {}

        # Prebuild a list of signatures that *may* be interested
        self.call_always = set()
        self.call_for_api = defaultdict(set)
        self.call_for_cat = defaultdict(set)
        self.call_for_processname = defaultdict(set)
        for sig in self.evented_list:
            if (
                not sig.filter_apinames
                and not sig.filter_categories
                and not sig.filter_processnames
            ):
                self.call_always.add(sig)
                continue
            for api in sig.filter_apinames:
                self.call_for_api[api].add(sig)
            for cat in sig.filter_categories:
                self.call_for_cat[cat].add(sig)
            for proc in sig.filter_processnames:
                self.call_for_processname[proc].add(sig)
            if not sig.filter_apinames:
                self.call_for_api["any"].add(sig)
            if not sig.filter_categories:
                self.call_for_cat["any"].add(sig)
            if not sig.filter_processnames:
                self.call_for_processname["any"].add(sig)

    def _should_load_signature(self, signature):
        """Should the given signature be enabled for this analysis?"""
        if not signature.enabled or signature.name is None:
            return False

        return True

    def process(self, signature):
        """Run a signature.
        @param signature: signature to run.
        @return: matched signature.
        """
        # Skip signature processing if there are no results.
        if not self.results:
            return

        # Give it path to the analysis results.
        signature.set_path(self.analysis_path)
        log.debug('Running signature "%s"', signature.name)

        try:
            # Run the signature and if it gets matched, extract key information
            # from it and append it to the results container.
            data = signature.run()

            if data:
                log.debug('Analysis matched signature "%s"', signature.name)
                # Return information on the matched signature.
                return signature.as_result()
        except KeyError as e:
            log.error('Failed to run signature "%s": %s', signature.name, e)
        except NotImplementedError:
            return None
        except Exception as e:
            log.exception('Failed to run signature "%s": %s', signature.name, e)

        return None

    def run(self, test_signature: str = False):
        # CAPEv2's result shapes for the pass only; see cape_compat.SignatureView.
        with cape_compat.SignatureView(self.results, self.analysis_path):
            return self._run(test_signature)

    def _run(self, test_signature: str = False):
        """Run evented signatures.
        test_signature: signature name, Ex: cape_detected_threat, to test unique signature
        """
        # This will contain all the matched signatures.
        matched = []
        stats = {}

        if test_signature:
            self.evented_list = next(
                (sig for sig in self.evented_list if sig.name == test_signature), []
            )
            self.non_evented_list = next(
                (sig for sig in self.non_evented_list if sig.name == test_signature), []
            )
            if not isinstance(self.evented_list, list):
                self.evented_list = [self.evented_list]
            if not isinstance(self.non_evented_list, list):
                self.non_evented_list = [self.non_evented_list]

        if self.evented_list and "behavior" in self.results:
            log.debug("Running %d evented signatures", len(self.evented_list))
            for sig in self.evented_list:
                stats[sig.name] = 0
                if sig == self.evented_list[-1]:
                    log.debug("\t `-- %s", sig.name)
                else:
                    log.debug("\t |-- %s", sig.name)

            # Iterate calls and tell interested signatures about them.
            evented_set = set(self.evented_list)
            always = evented_set.intersection(self.call_always)
            for proc in self.results["behavior"]["processes"]:
                process_name = proc["process_name"]
                process_id = proc["process_id"]
                calls = proc.get("calls", [])
                sigs = evented_set.intersection(
                    self.call_for_processname.get("any", set()).union(
                        self.call_for_processname.get(process_name, set())
                    )
                )

                for idx, call in enumerate(calls):
                    api = call.get("api")
                    # Build interested signatures
                    cat = call.get("category")
                    # The set only depends on these three, so it is built once per combination
                    # rather than once per call; nothing below mutates it.
                    key = (process_name, api, cat)
                    call_sigs = self.api_sigs.get(key)
                    if call_sigs is None:
                        call_sigs = sigs.intersection(
                            self.call_for_api.get(api, set()).union(
                                self.call_for_api.get("any", set())
                            )
                        )
                        call_sigs = call_sigs.intersection(
                            self.call_for_cat.get(cat, set()).union(
                                self.call_for_cat.get("any", set())
                            )
                        )
                        call_sigs.update(always)
                        self.api_sigs[key] = call_sigs

                    for sig in call_sigs:
                        # Setting signature attributes per call
                        sig.cid = idx
                        sig.call = call
                        sig.pid = process_id

                        if sig.matched:
                            continue
                        try:
                            result = sig.on_call(call, proc)
                        except NotImplementedError:
                            result = False
                        except Exception as e:
                            log.exception("Failed to run signature %s: %s", sig.name, e)
                            result = False

                        if result:
                            sig.matched = True

            # Call the stop method on all remaining instances.
            for sig in self.evented_list:
                if sig.matched:
                    continue
                try:
                    result = sig.on_complete()
                except NotImplementedError:
                    continue
                except Exception as e:
                    log.exception(
                        'Failed run on_complete() method for signature "%s": %s',
                        sig.name,
                        e,
                    )
                    continue
                else:
                    if result and not sig.matched:
                        matched.append(sig.as_result())
                        if hasattr(sig, "ttps"):
                            [
                                self.ttps.append({"ttp": ttp, "signature": sig.name})
                                for ttp in sig.ttps
                                if {"ttp": ttp, "signature": sig.name} not in self.ttps
                            ]
                        if hasattr(sig, "mbcs"):
                            self.mbcs[sig.name] = sig.mbcs

        # Link this into the results already at this point, so non-evented signatures can use it
        self.results["signatures"] = matched

        # Compat loop for old-style (non evented) signatures.
        if self.non_evented_list:
            if hasattr(self.non_evented_list, "sort"):
                self.non_evented_list.sort(key=lambda sig: sig.order)
            else:
                # for testing single signature with process.py
                self.non_evented_list = [self.non_evented_list]
            log.debug("Running non-evented signatures")

            for signature in self.non_evented_list:
                if (
                    not signature.filter_analysistypes
                    or self.results.get("target", {}).get("category")
                    in signature.filter_analysistypes
                ):
                    match = self.process(signature)
                    # If the signature is matched, add it to the list.
                    if match and not signature.matched:
                        if hasattr(signature, "ttps"):
                            [
                                self.ttps.append(
                                    {"ttp": ttp, "signature": signature.name}
                                )
                                for ttp in signature.ttps
                                if {"ttp": ttp, "signature": signature.name}
                                not in self.ttps
                            ]
                        if hasattr(signature, "mbcs"):
                            self.mbcs[signature.name] = signature.mbcs
                        signature.matched = True

        for signature in self.signatures:
            if not signature.matched:
                continue
            log.debug('Analysis matched signature "%s"', signature.name)
            signature.matched = True
            matched.append(signature.as_result())

        # Sort the matched signatures by their severity level.
        matched.sort(key=lambda key: key["severity"])
