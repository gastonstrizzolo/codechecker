import os
import unittest

from codechecker_report_converter.report import BugPathEvent, \
    BugPathPosition, File, Range, Report, report_file
from codechecker_report_converter.report.reports import \
    get_mentioned_original_files


gen_sarif_dir_path = os.path.join(
    os.path.dirname(__file__), 'sarif_test_files' ,'gen_sarif')

class SarifParserTestCaseNose(unittest.TestCase):
    """Test the parsing of the sarif generated by multiple semgrep
    and shellcheck reports."""

    @classmethod
    def setup_class(cls):
        """Initialize test source file."""
        # Bugs found by these checkers in the test source files.
        cls.__shellcheck_found_checker_names = [2034, 1066]
        cls.__semgrep_found_checker_names = [
            "python.lang.correctness.common-mistakes.string-concat-in-list. \
            string-concat-in-list",
            "python.lang.maintainability.return.code-after-unconditional-return"
        ]

        # Already generated plist files for the tests.
        cls.__this_dir = os.path.dirname(__file__)
        cls.__sarif_test_files = os.path.join(
            cls.__this_dir, 'sarif_test_files')

    def test_empty_file(self):
        """Plist file is empty."""
        empty_plist = os.path.join(self.__sarif_test_files, 'empty_file')
        reports = report_file.get_reports(empty_plist)
        self.assertEqual(reports, [])
