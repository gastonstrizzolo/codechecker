// -------------------------------------------------------------------------
//  Part of the CodeChecker project, under the Apache License v2.0 with
//  LLVM Exceptions. See LICENSE for license information.
//  SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// -------------------------------------------------------------------------
include "codechecker_api_shared.thrift"

namespace py Jira_v6
namespace js codeCheckerJira_v6

struct Jira {
  1: bool             isError,
  2: string           msg,
  3: string           link
}
typedef list<Jira> JiraList

service jiraService {
  JiraList createJiraTicket(1: i64 id,
                     2: string url,
                     3: string projectName,
                     4: string name)
                     throws (1: codechecker_api_shared.RequestFailed requestError),
  list<string> getJiraProjects() throws(1: codechecker_api_shared.RequestFailed requestError);

}
