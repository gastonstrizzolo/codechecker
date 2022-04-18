# -------------------------------------------------------------------------
#
#  Part of the CodeChecker project, under the Apache License v2.0 with
#  LLVM Exceptions. See LICENSE for license information.
#  SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# -------------------------------------------------------------------------

import json
import logging
import os

from typing import Dict, List


from codechecker_report_converter.report import File, get_or_create_file, \
    Report

from ..analyzer_result import AnalyzerResultBase


LOG = logging.getLogger('report-converter')


class Sarif(AnalyzerResultBase):
    """ Transform analyzer result of the ESLint analyzer. """

    def get_reports_sarif(self, file_path: str) -> List[Report]:
        """ Get reports from the given analyzer result. """
        reports: List[Report] = []

        if not os.path.exists(file_path):
            LOG.error("Report file does not exist: %s", file_path)
            return reports

        try:
            with open(file_path, 'r', encoding="utf-8", errors="ignore") as f:
                diagnostics = json.load(f)
        except (IOError, json.decoder.JSONDecodeError):
            LOG.error("Failed to parse the given analyzer result '%s'. Please "
                      "give a valid json file generated by ESLint.",
                      file_path)
            return reports

        file_cache: Dict[str, File] = {}

        if len(diagnostics["runs"]) == 0:
            LOG.error("diagnostics['runs'] == 0")

        diag = diagnostics["runs"][-1]["results"] # -1 = the last run

        for bug in diag:
            for occurrences in range(0, len(bug['locations'])):    
                result_path = os.path.join(
                    os.path.dirname(file_path), bug['locations'][occurrences]['physicalLocation']['artifactLocation']['uri'])

                if not os.path.exists(result_path):
                    LOG.warning("Source file does not exists: %s", result_path)
                    continue

                reports.append(Report(
                    get_or_create_file(
                        os.path.abspath(result_path), file_cache),
                    int(bug["locations"][occurrences]["physicalLocation"]["region"]["startLine"]),
                    int(bug["locations"][occurrences]["physicalLocation"]["region"]["startColumn"]),
                    bug['message']['text'],
                    bug['ruleId']))

        return reports