import binascii
import logging
import os

import yara

from .config_paths import user_config_path
from .path_utils import path_exists

log = logging.getLogger(__name__)

# The last compiled CAPE ruleset, shared by every YaraProcessor; see init_yara.
_compiled = {}


class YaraProcessor(object):
    yara_error = {
        "1": "ERROR_INSUFFICIENT_MEMORY",
        "2": "ERROR_COULD_NOT_ATTACH_TO_PROCESS",
        "3": "ERROR_COULD_NOT_OPEN_FILE",
        "4": "ERROR_COULD_NOT_MAP_FILE",
        "6": "ERROR_INVALID_FILE",
        "7": "ERROR_CORRUPT_FILE",
        "8": "ERROR_UNSUPPORTED_FILE_VERSION",
        "9": "ERROR_INVALID_REGULAR_EXPRESSION",
        "10": "ERROR_INVALID_HEX_STRING",
        "11": "ERROR_SYNTAX_ERROR",
        "12": "ERROR_LOOP_NESTING_LIMIT_EXCEEDED",
        "13": "ERROR_DUPLICATED_LOOP_IDENTIFIER",
        "14": "ERROR_DUPLICATED_IDENTIFIER",
        "15": "ERROR_DUPLICATED_TAG_IDENTIFIER",
        "16": "ERROR_DUPLICATED_META_IDENTIFIER",
        "17": "ERROR_DUPLICATED_STRING_IDENTIFIER",
        "18": "ERROR_UNREFERENCED_STRING",
        "19": "ERROR_UNDEFINED_STRING",
        "20": "ERROR_UNDEFINED_IDENTIFIER",
        "21": "ERROR_MISPLACED_ANONYMOUS_STRING",
        "22": "ERROR_INCLUDES_CIRCULAR_REFERENCE",
        "23": "ERROR_INCLUDE_DEPTH_EXCEEDED",
        "24": "ERROR_WRONG_TYPE",
        "25": "ERROR_EXEC_STACK_OVERFLOW",
        "26": "ERROR_SCAN_TIMEOUT",
        "27": "ERROR_TOO_MANY_SCAN_THREADS",
        "28": "ERROR_CALLBACK_ERROR",
        "29": "ERROR_INVALID_ARGUMENT",
        "30": "ERROR_TOO_MANY_MATCHES",
        "31": "ERROR_INTERNAL_FATAL_ERROR",
        "32": "ERROR_NESTED_FOR_OF_LOOP",
        "33": "ERROR_INVALID_FIELD_NAME",
        "34": "ERROR_UNKNOWN_MODULE",
        "35": "ERROR_NOT_A_STRUCTURE",
        "36": "ERROR_NOT_INDEXABLE",
        "37": "ERROR_NOT_A_FUNCTION",
        "38": "ERROR_INVALID_FORMAT",
        "39": "ERROR_TOO_MANY_ARGUMENTS",
        "40": "ERROR_WRONG_ARGUMENTS",
        "41": "ERROR_WRONG_RETURN_TYPE",
        "42": "ERROR_DUPLICATED_STRUCTURE_MEMBER",
        "43": "ERROR_EMPTY_STRING",
        "44": "ERROR_DIVISION_BY_ZERO",
        "45": "ERROR_REGULAR_EXPRESSION_TOO_LARGE",
        "46": "ERROR_TOO_MANY_RE_FIBERS",
        "47": "ERROR_COULD_NOT_READ_PROCESS_MEMORY",
        "48": "ERROR_INVALID_EXTERNAL_VARIABLE_TYPE",
        "49": "ERROR_REGULAR_EXPRESSION_TOO_COMPLEX",
    }

    def __init__(self, yara_root="yara", yara_custom="custom"):
        self.yara_root = yara_root
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        self.yara_custom = os.path.join(desktop, yara_custom)
        self.yara_rules = {}
        self.init_yara()

    def _yara_encode_string(self, yara_string):
        # Beware, spaghetti code ahead.
        if not isinstance(yara_string, bytes):
            return yara_string

        def as_hex(raw):
            # yara_string = binascii.hexlify(yara_string.lstrip("uU")).upper()
            raw = binascii.hexlify(raw).upper()
            raw = b" ".join(raw[i : i + 2] for i in range(0, len(raw), 2))
            return f"{{ {raw.decode()} }}"

        try:
            new = yara_string.decode()
        except UnicodeDecodeError:
            return as_hex(yara_string)

        if "\x00" not in new:
            return new

        # A `wide` match hands back UTF-16LE, and for ASCII text every one of those bytes is
        # below 0x80, so the UTF-8 decode above *succeeds* and yields embedded NULs instead
        # of raising. Those NULs terminate the native text control the results are shown in,
        # silently truncating the rest of the report, so they must never reach a caller.
        try:
            wide = yara_string.decode("utf-16-le")
        except UnicodeDecodeError:
            return as_hex(yara_string)

        # Not actually UTF-16LE text, just binary that happened to decode - keep it as hex.
        return wide if "\x00" not in wide else as_hex(yara_string)

    def add_rules(self, directory, category):
        """
        Scan a single `directory` for .yar/.yara files and return:
        - rules: dict mapping 'rule_{category}_{n}' to file paths
        - indexed: list of filenames loaded (for logging)
        """
        rules = {}
        indexed = []
        if os.path.isdir(directory):
            for filename in os.listdir(directory):
                if not filename.endswith((".yar", ".yara")):
                    continue

                filepath = os.path.join(directory, filename)
                key = f"rule_{category}_{len(rules)}"
                rules[key] = filepath
                indexed.append(filename)

        return rules, indexed

    def init_yara(self):
        log.debug("Initializing Yara...")
        # Only the CAPE category is ever scanned (get_yara), so it is the only one compiled.
        # Community rules are not shipped: the user's own folder beside cfg.ini joins the CAPE
        # rules, as CAPEv2 installs community rules into the same directory. A file name already
        # taken is skipped, the way a copy into one directory would replace it: Desktop\custom
        # beats the user folder beats its community subfolder beats the packaged rules. Each source gets its own key prefix,
        # since add_rules numbers from 0 and a shared prefix let the custom rules overwrite the
        # first CAPE ones.
        category = "CAPE"
        category_root = os.path.join(self.yara_root, category)
        if not path_exists(category_root):
            log.warning("Missing Yara directory: %s?", category_root)

        rules, indexed = {}, []
        for directory, prefix in (
            (self.yara_custom, "custom"),
            (str(user_config_path().parent / "yara"), "user"),
            # Where Update Yara puts the community rules, replaced as a unit; the user's own
            # files one level up are never touched by it and win over it.
            (str(user_config_path().parent / "yara" / "community"), "community"),
            (category_root, category),
        ):
            found, _ = self.add_rules(directory, prefix)
            for key, filepath in found.items():
                if os.path.basename(filepath) not in indexed:
                    rules[key] = filepath
                    indexed.append(os.path.basename(filepath))

        # Compiling takes seconds and every ProcessYara/GetResults used to repeat it; the rule
        # files and their mtimes key the cache, so a rule staged or updated mid-session still
        # triggers a recompile.
        cacheKey = tuple(sorted((path, os.path.getmtime(path)) for path in rules.values()))
        if cacheKey in _compiled:
            self.yara_rules[category] = _compiled[cacheKey]
            return

        # Need to define each external variable that will be used in the
        # future. Otherwise, Yara will complain.
        externals = {"filename": ""}

        while True:
            try:
                self.yara_rules[category] = yara.compile(
                    filepaths=rules, externals=externals
                )
                _compiled.clear()
                _compiled[cacheKey] = self.yara_rules[category]
                break
            except yara.Error as e:
                # A SyntaxError names its file. Anything else does not - a file antivirus will
                # not let us read (EINVAL, as a flagged Macoute.yar did on a Defender host), a
                # missing module - and used to end here with no CAPE rules at all. Either way,
                # drop what fails and compile the rest rather than lose every rule to one file.
                bad_rule = f"{str(e).split('.yar', 1)[0]}.yar" if isinstance(e, yara.SyntaxError) else ""
                failing = [k for k, v in rules.items() if v == bad_rule] or self._failing_rules(rules, externals)
                if not failing:
                    log.error("There was an error in one or more Yara rules: %s", e)
                    break
                for key in failing:
                    log.error(
                        "Can't compile YARA rule: %s. Maybe is bad yara but can be missing YARA's module.",
                        rules[key],
                    )
                    indexed.remove(os.path.basename(rules[key]))
                    del rules[key]

        indexed = sorted(indexed)
        for entry in indexed:
            if entry == indexed[-1]:
                log.debug("\t `-- %s %s", category, entry)
            else:
                log.debug("\t |-- %s %s", category, entry)

    def _failing_rules(self, rules, externals):
        """Keys of the rule files that do not compile on their own."""
        failing = []
        for key, path in rules.items():
            try:
                yara.compile(filepath=path, externals=externals)
            except yara.Error as e:
                log.debug("YARA rule %s does not compile: %s", path, e)
                failing.append(key)
        return failing

    def get_yara(self, file_path, category="CAPE", externals=None):
        """Get Yara signatures matches.
        @return: matched Yara signatures.
        """
        file_path_ansii = (
            file_path if isinstance(file_path, str) else file_path.decode()
        )
        results = []
        if not os.path.getsize(file_path):
            return results

        try:
            results, rule = [], self.yara_rules[category]
            for match in rule.match(file_path_ansii, externals=externals):
                strings = []
                addresses = {}
                for yara_string in match.strings:
                    for x in yara_string.instances:
                        y_string = self._yara_encode_string(x.matched_data)
                        if y_string not in strings:
                            strings.append(y_string)
                        addresses.update({yara_string.identifier.strip("$"): x.offset})
                results.append(
                    {
                        "name": match.rule,
                        "meta": match.meta,
                        "strings": strings,
                        "addresses": addresses,
                    }
                )
        except Exception as e:
            errcode = str(e).rsplit(maxsplit=1)[-1]
            if errcode in self.yara_error:
                log.exception(
                    "Unable to match Yara signatures for %s: %s",
                    file_path,
                    self.yara_error[errcode],
                )

            else:
                log.exception(
                    "Unable to match Yara signatures for %s: unknown code %s",
                    file_path,
                    errcode,
                )

        return results
