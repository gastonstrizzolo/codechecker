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

from .sarif import *

LOG = logging.getLogger('report-converter')


class AnalyzerResult(AnalyzerResultBase):
    """ Transform analyzer result of the ESLint analyzer. """

    TOOL_NAME = 'eslint'
    NAME = 'ESLint'
    URL = 'https://eslint.org/'

    def get_reports(self, file_path: str) -> List[Report]:
        """ Get reports from the given analyzer result. """
        reports: List[Report] = []
        reports = Sarif.get_reports_sarif(self, file_path)
        return reports
