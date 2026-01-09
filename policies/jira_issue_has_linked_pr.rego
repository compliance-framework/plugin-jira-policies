package compliance_framework.jira_issue_has_linked_pr

import future.keywords.if
import future.keywords.in

title := "Change requests must have linked pull requests"
description := "All change request issues must have at least one linked pull request before deployment."

violation[{"remarks": remarks}] if {
	project := input.projects[_]
	count(project.issues) > 0
	issue := project.issues[_]
	is_change_request(issue)
	not has_linked_pr(issue)
	remarks := sprintf("Issue %s does not have any linked pull requests.", [issue.key])
}

change_request_types := ["change request", "change", "cr", "request a change"]

is_change_request(issue) if {
	issue_type := lower(object.get(issue.fields, "issuetype", {}).name)
	issue_type in change_request_types
}

is_change_request(issue) if {
	issue_type := lower(object.get(issue.fields, "issuetype", ""))
	issue_type in change_request_types
}

has_linked_pr(issue) if {
	issue.dev_info != null
	count(issue.dev_info.pull_requests) > 0
}
