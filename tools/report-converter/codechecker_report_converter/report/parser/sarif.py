# -------------------------------------------------------------------------
#
#  Part of the CodeChecker project, under the Apache License v2.0 with
#  LLVM Exceptions. See LICENSE for license information.
#  SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# -------------------------------------------------------------------------
"""
Parse the sarif output of an analyzer
"""

import json
import logging
from pathlib import Path

from urllib.parse import urlparse
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

from codechecker_report_converter import util
from codechecker_report_converter.report import BugPathEvent, \
    BugPathPosition, File, get_or_create_file, Range, Report
from codechecker_report_converter.report.hash import get_report_hash, HashType
from codechecker_report_converter.report.parser.base import AnalyzerInfo, \
    BaseParser


LOG = logging.getLogger('report-converter')


EXTENSION = 'sarif'


class Location(NamedTuple):
    """
    Location of a bug.
    """
    file: File
    range: Range
    message: Optional[str] = ""


class ThreadFlowInfo(NamedTuple):
    bug_path_events: List[BugPathEvent] = []
    notes: List[BugPathEvent] = []
    macro_expansions: List[BugPathEvent] = []


class Parser(BaseParser):
    EXTENSION = 'sarif'

    def get_reports(
        self,
        analyzer_result_file_path: str
    ) -> List[Report]:

        """ Get reports from the given analyzer result file. """
        data = util.load_json_or_empty(analyzer_result_file_path, {})

        reports: List[Report] = []

        for run in data.get("runs", []):
            rules = self._get_rules(run)

            for result in run.get("results", []):
                rule_id = result["ruleId"]

                message = self._process_message(
                    result["message"], rule_id, rules)  # §3.11
                severity = self.get_severity_from_level(rule_id, rules)
                analyzer_name = run["tool"]["driver"]["name"]
                for location in result.get("locations", []):
                    thread_flow_info = self._process_code_flows(
                        result, rule_id, rules)
                    file, rng = self._process_physical_location(location)
                    if not (file and rng):
                        continue
                    bug_path_positions = [BugPathPosition(file, rng)]
                    bug_path_events = thread_flow_info.bug_path_events or None

                    report = Report(
                        file,
                        rng.start_line,
                        rng.start_col,
                        message,
                        rule_id,
                        severity,
                        analyzer_name=analyzer_name,
                        analyzer_result_file_path=analyzer_result_file_path,
                        bug_path_events=bug_path_events,
                        bug_path_positions=bug_path_positions,
                        notes=thread_flow_info.notes,
                        macro_expansions=thread_flow_info.macro_expansions)

                    if report.report_hash is None:
                        report.report_hash = get_report_hash(
                            report, HashType.PATH_SENSITIVE)

                    reports.append(report)

        return reports

    def _get_rules(self, data: Dict) -> Dict[str, Dict]:
        """ """
        rules: Dict[str, Dict] = {}
        tool = data["tool"]
        driver = tool["driver"]
        for rule in driver.get("rules", []):
            rules[rule["id"]] = rule

        return rules

    def _process_code_flows(
        self,
        result: Dict,
        rule_id: str,
        rules: Dict[str, Dict]
    ) -> Tuple[List[BugPathEvent], List[BugPathEvent], List[BugPathEvent]]:
        """ """
        thread_flow_info = ThreadFlowInfo()

        for code_flow in result.get("codeFlows", []):
            for thread_flow in code_flow.get("threadFlows", []):  # §3.36.3
                for raw_location in thread_flow["locations"]:
                    location = self._process_location(
                        raw_location, rule_id, rules)

                    # TODO: check the importance field.
                    mybugpathevent = BugPathEvent(
                            location.message,
                            location.file,
                            location.range.start_line,
                            location.range.start_col,
                            location.range
                        )
                    thread_flow_info.bug_path_events.append(mybugpathevent)
        return thread_flow_info

    def _process_location(
        self,
        location: Dict,
        rule_id: str,
        rules: Dict[str, Dict]
    ) -> Optional[Tuple[str, Optional[File], Optional[Range]]]:
        message = "<Unknown message>"
        if "message" in location:
            message = self._process_message(
                location["message"], rule_id, rules)

        file, rng = self._process_physical_location(location)

        return Location(message=message, file=file, range=rng)

    def _process_physical_location(
        self,
        location: Dict,
    ) -> Tuple[Optional[File], Optional[Range]]:
        """ """
        physical_loc = location.get("physicalLocation")
        # Physical loc is required, must always be present.
        if physical_loc:
            file = self._get_file(physical_loc)
            rng = self._get_range(physical_loc)
            return file, rng

        return None, None

    def _get_range(self, physical_loc: Dict) -> Optional[Range]:
        """ Get range from a physical location. """
        region = physical_loc.get("region", {})
        start_line = region.get("startLine")
        if start_line is None:
            return None

        start_col = region.get("startColumn", 1)
        end_line = region.get("endLine", start_line)
        end_col = region.get("endColumn", start_col)

        return Range(start_line, start_col, end_line, end_col)

    def _get_file(
        self,
        physical_loc: Dict
    ) -> Optional[File]:
        """ Get file path. """
        artifact_loc = physical_loc.get("artifactLocation")
        if not artifact_loc:
            return None
        file_path = artifact_loc.get("uri")
        if file_path.startswith("file://"):
            uri = urlparse(artifact_loc.get("uri"))
            if uri is None:
                return None
            file_path = Path(uri.netloc, uri.path).as_posix()
        return get_or_create_file(file_path, self._file_cache)

    def _process_message(
        self,
        msg: Dict,
        rule_id: str,
        rules: Dict[str, Dict]
    ) -> str:
        """ Get message string. """
        if "text" in msg:
            return msg["text"]

        args = msg.get("arguments", [])

        rule = rules[rule_id]
        message_strings = rule.get("messageStrings", {})
        return message_strings[msg["id"]]["text"].format(*args)

    def convert(
        self,
        reports: List[Report],
        analyzer_info: Optional[AnalyzerInfo] = None
    ):
        """ Converts the given reports to sarif format. """

        # TODO self._get_tool_info()
        tool_name = 'tool_name'
        tool_version = 'tool_Version'
        rules = {}
        results = []
        for report in reports:
            if report.checker_name not in rules:
                rules[report.checker_name] = {
                    "id": report.checker_name,
                    "fullDescription": {
                        "text": report.message
                    }
                }

            results.append(self._create_result(report))
        schema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec \
        /master/Schemata/sarif-schema-2.1.0.json"

        return {
            "vesion": "2.1.0",
            "$schema": schema,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "rules": list(rules.values())
                    }
                },
                "results": results
            }]
        }

    def _create_result(self, report: Report) -> Dict:
        """ Create result dictionary from the given report. """
        result = {
            "ruleId": report.checker_name,
            "message": {
                "text": report.message
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": report.file.original_path
                    },
                    "region": {
                        "startLine": report.line,
                        "startColumn": report.column
                    }
                }
            }]
        }

        locations = []

        if report.bug_path_events:
            for event in report.bug_path_events:
                locations.append(self._create_location_from_bug_path_event(
                    event, "important"))

        if report.notes:
            for note in report.notes:
                locations.append(self._create_location_from_bug_path_event(
                    note, "essential"))

        if report.macro_expansions:
            for macro_expansion in report.macro_expansion:
                locations.append(self._create_location_from_bug_path_event(
                    macro_expansion, "essential"))

        if report.bug_path_positions:
            for bug_path_position in report.bug_path_positions:
                locations.append(self._create_location(bug_path_position))

        if locations:
            result["codeFlows"] = [{
                "threadFlows": [{"locations": locations}]
            }]

        return result

    def _create_location_from_bug_path_event(
        self,
        event: BugPathEvent,
        importance: str
    ) -> Dict[str, Any]:
        """ Create location from bug path event. """
        location = self._create_location(event, event.line, event.column)

        location["importance"] = importance
        location["location"]["message"] = {"text": event.message}

        return location

    def _create_location(
        self,
        pos: BugPathPosition,
        line: Optional[int] = -1,
        column: Optional[int] = -1
    ) -> Dict[str, Any]:
        """ Create location from bug path position. """
        if pos.range:
            rng = pos.range
            region = {
                "startLine": rng.start_line,
                "startColumn": rng.start_col,
                "endLine": rng.end_line,
                "endColumn": rng.end_col,
            }
        else:
            region = {
                "startLine": line,
                "startColumn": column,
            }

        return {
            "location": {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": pos.file.original_path
                    },
                    "region": region
                }
            }
        }

    def write(self, data: Any, output_file_path: str):
        """ Creates an analyzer output file from the given data. """
        try:
            with open(output_file_path, 'w',
                      encoding="utf-8", errors="ignore") as f:
                json.dump(data, f)
        except TypeError as err:
            LOG.error('Failed to write sarif file: %s', output_file_path)
            LOG.error(err)
            import traceback
            traceback.print_exc()

    def replace_report_hash(
        self,
        analyzer_result_file_path: str,
        hash_type=HashType.CONTEXT_FREE
    ):
        """
        Override hash in the given file by using the given version hash.
        """
        pass

    # INFO     -> LOW
    # WARNING  -> MEDIUM
    # ERROR    -> HIGH
    def get_severity_from_level(self, rule_id: str, rules: Dict[str, Dict]):
        severity = 'UNDEFINED'
        try:
            current_rule = rules[rule_id]
            level = current_rule["defaultConfiguration"]["level"]
            if level == 'info':
                severity = 'low'
            if level == 'warning':
                severity = 'MEDIUM'
            if level == 'error':
                severity = 'HIGH'
        except KeyError:
            return severity
        except IndexError:
            return severity
        return severity
