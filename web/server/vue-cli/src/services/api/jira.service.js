import ServiceClient from "@cc/jira";
import { BaseService } from "./_base.service";

class JiraService extends BaseService {
  constructor() {
    super("Jira", ServiceClient);
  }
}

const jiraService = new JiraService();

export default jiraService;
