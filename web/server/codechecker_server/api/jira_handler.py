# -------------------------------------------------------------------------
#
#  Part of the CodeChecker project, under the Apache License v2.0 with
#  LLVM Exceptions. See LICENSE for license information.
#  SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# -------------------------------------------------------------------------
"""
Handle Thrift requests for server info.
"""
import os
from dotenv import load_dotenv

from jira import JIRA

from codechecker_common.logger import get_logger
from codechecker_api.Jira_v6 import ttypes
from codechecker_server.profiler import timeit

load_dotenv()
JIRA_LOGIN = os.getenv('JIRA_LOGIN')
JIRA_TOKEN = os.getenv('JIRA_TOKEN')
JIRA_SERVER = os.getenv('JIRA_SERVER')
JIRA_PATH_TICKET = os.getenv('JIRA_PATH_TICKET')
JIRA_ISSUE_TYPE = os.getenv('JIRA_ISSUE_TYPE')
JIRA_FIELD_CODECHECKER_ID = os.getenv('JIRA_FIELD_CODECHECKER_ID')
ECL_SERVER = os.getenv('ECL_SERVER')
LOG = get_logger('server')


class ThriftJiraHandler:
    @timeit
    def getJiraProjects(self):
        try:
            jira = JIRA(server=JIRA_SERVER,
                        basic_auth=(JIRA_LOGIN, JIRA_TOKEN))
            jira_projects = jira.projects()
            projects_keys = []
            for project in jira_projects:
                projects_keys.append(project.key)
            return projects_keys
        except:
            LOG.error('Jira get projects error')
            return []

    @timeit
    def createJiraTicket(self, cleanup_plan_id, cleanup_plan_url, project_name, name):
        try:
            jira = JIRA(server=JIRA_SERVER,
                        basic_auth=(JIRA_LOGIN, JIRA_TOKEN))
        except:
            return [ttypes.Jira(isError=True,
                                msg="jira credentials are incorrect")]
        issue_dict = {
            'project': project_name,
            'summary': f'{name}',
            'description': f'Link: [{ECL_SERVER}{cleanup_plan_url}]',
            'issuetype': {'name': JIRA_ISSUE_TYPE},
            JIRA_FIELD_CODECHECKER_ID: cleanup_plan_id
        }

        issues_in_proj = jira.search_issues(f'reporter = currentUser() AND CodeCheckerId = "{cleanup_plan_id}"')

        if len(issues_in_proj) > 0:
            return [ttypes.Jira(isError=True,
                                msg=f"Ticket \"{name}\" already exists",
                                link=f"{ECL_SERVER}{JIRA_PATH_TICKET}{issues_in_proj[0]}")]
        try:
            ticket_name = jira.create_issue(fields=issue_dict)
            return [ttypes.Jira(isError=False,
                                msg=f"Ticket \"{name}\" successfully created",
                                link=f"{ECL_SERVER}{JIRA_PATH_TICKET}{ticket_name}")]
        except:
            return [ttypes.Jira(isError=True,
                                msg="Jira error")]
