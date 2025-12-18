import codecs
import os
from contextlib import suppress
from pathlib import Path

from CAPEsolo.capelib.path_utils import path_exists, path_glob, path_is_file
from CAPEsolo.capelib.utils import (
    datefmt,
    dict2list,
    get_detection_by_pid,
    getkey,
    malware_config,
    parentfixup,
    proctreetolist,
    str2list,
)

try:
    from jinja2 import TemplateAssertionError, TemplateNotFound, TemplateSyntaxError, UndefinedError
    from jinja2.environment import Environment
    from jinja2.loaders import FileSystemLoader

    HAVE_JINJA2 = True
except ImportError:
    HAVE_JINJA2 = False


class ReportHTML:
    """Stores report in HTML format."""

    def run(self, analysisDir, soloRoot, results):
        """Writes report.
        @param results: CAPE results dict.
        """
        if not HAVE_JINJA2:
            return False, "Failed to generate HTML report: Jinja2 Python library is not installed"

        desktop = Path(os.path.expanduser("~/Desktop"))
        rootDir = Path(soloRoot)
        filepath = desktop / "report.html"
        debuggerPath = Path(analysisDir) / "debugger"
        htmlPath = rootDir / "capelib/html"
        debugger = {}
        if path_exists(str(debuggerPath)):
            with suppress(FileNotFoundError, OSError, PermissionError):
                for logPath in sorted(path_glob(str(debuggerPath), "*.log")):
                    if not path_is_file(str(logPath)):
                        continue

                    pid = logPath.stem
                    with open(logPath, "r", encoding="utf-8", errors="replace") as f:
                        debugger[pid] = f.read()

        env = Environment(loader=FileSystemLoader(str(htmlPath)), autoescape=True)
        env.globals["get_detection_by_pid"] = get_detection_by_pid
        env.filters.update(
            {
                "getkey": getkey,
                "str2list": str2list,
                "dict2list": dict2list,
                "parentfixup": parentfixup,
                "malware_config": malware_config,
                "datefmt": datefmt,
                "proctreetolist": proctreetolist,
            }
        )
        try:
            tpl = env.get_template("report.html")
            html = tpl.render(results=results, summary_report=False, debugger=debugger)
        except UndefinedError as e:
            return False, e
        except TemplateNotFound as e:
            return False, e
        except (TemplateSyntaxError, TemplateAssertionError) as e:
            return False, e

        try:
            with codecs.open(filepath, "w", encoding="utf-8", errors="replace") as report:
                report.write(html)
                return True, None
        except OSError as e:
            return False, e
