package compliance_framework.jira_issue_has_changelog

import future.keywords.if
import future.keywords.in

title := "Change requests must have audit trail"
description := "All change request issues must have at least one changelog entry to ensure proper audit trail."

violation[{"remarks": remarks}] if {
	project := input.projects[_]
	issue := project.issues[_]
	is_change_request(issue)
	not has_changelog(issue)
	remarks := sprintf("Issue %s does not have any changelog entries.", [issue.key])
}

is_change_request(issue) if {
	issue_type := lower(object.get(issue.fields, "issuetype", {}).name)
	issue_type in ["change request", "change", "cr", "request a change"]
}

is_change_request(issue) if {
	issue_type := lower(object.get(issue.fields, "issuetype", ""))
	issue_type in ["change request", "change", "cr", "request a change"]
}

has_changelog(issue) if {
	issue.changelog != null
	count(issue.changelog.histories) > 0
}
