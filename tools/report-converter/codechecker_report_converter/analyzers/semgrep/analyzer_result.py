# -------------------------------------------------------------------------
#
#  Part of the CodeChecker project, under the Apache License v2.0 with
#  LLVM Exceptions. See LICENSE for license information.
#  SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# -------------------------------------------------------------------------

import logging

from typing import Dict, List

from codechecker_report_converter.report import Report

from ..analyzer_result import AnalyzerResultBase

from codechecker_report_converter.report.parser import sarif

LOG = logging.getLogger('report-converter')


class AnalyzerResult(AnalyzerResultBase):
    """ Transform analyzer result of the Semgrep analyzer. """

    TOOL_NAME = 'semgrep'
    NAME = 'Semgrep'
    URL = 'https://semgrep.dev/'

    def get_reports(self, file_path: str) -> List[Report]:
        """ Get reports from the given analyzer result. """
        reports: List[Report] = []
        reports = sarif.get_reports_sarif(self, file_path)
        return reports