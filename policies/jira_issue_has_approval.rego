package compliance_framework.jira_issue_has_approval

import future.keywords.if
import future.keywords.in

title := "Change requests must have approved approvals"
description := "All change request issues must have at least one approval with status 'approved' before being considered complete."

violation[{"remarks": remarks}] if {
	project := input.projects[_]
	issue := project.issues[_]
	is_change_request(issue)
	not has_approved_approval(issue)
	remarks := sprintf("Issue %s does not have an approved approval.", [issue.key])
}

is_change_request(issue) if {
	issue_type := lower(object.get(issue.fields, "issuetype", {}).name)
	issue_type in ["change request", "change", "cr", "request a change"]
}

is_change_request(issue) if {
	issue_type := lower(object.get(issue.fields, "issuetype", ""))
	issue_type in ["change request", "change", "cr", "request a change"]
}

has_approved_approval(issue) if {
	approval := issue.approvals[_]
	lower(approval.finalDecision) == "approved"
}
