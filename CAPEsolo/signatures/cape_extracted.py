# Copyright (C) 2019 Kevin Ross
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os

from CAPEsolo.capelib.signatures import Signature


class CAPEExtractedContent(Signature):
    name = "cape_extracted_content"
    description = "CAPE extracted potentially suspicious content"
    severity = 2
    categories = ["generic"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        ret = False
        for cape in self.results.get("CAPE", {}).get("payloads", []) or []:
            process = cape.get("process_name", "")
            yara = ", ".join([block["name"] for block in cape.get("cape_yara", [])])
            if yara and process:
                self.data.append({process.replace(".", "_"): yara})
                ret = True

        return ret


class CAPEExtractedConfig(Signature):
    name = "cape_extracted_config"
    description = "CAPE has extracted a malware configuration"
    severity = 3
    categories = ["malware"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        # Upstream reads CAPE["cape_config"], a list keyed by malware name. CAPEsolo keys its
        # configs by the file they came out of (json_report.Configs -> [{path: cfg}]) and
        # keeps the families it matched in results["detections"], so the family name comes
        # from there rather than from the dict key.
        configs = self.results.get("CAPE", {}).get("configs", []) or []
        if not configs:
            return False

        families = self.results.get("detections") or []
        if not families:
            families = sorted({
                os.path.basename(str(path))
                for entry in configs if isinstance(entry, dict)
                for path in entry
            })

        for family in families:
            self.data.append({"extracted_config": family})

        return bool(families)
