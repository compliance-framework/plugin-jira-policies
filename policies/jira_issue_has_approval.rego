package compliance_framework.jira_issue_has_approval

import future.keywords.if
import future.keywords.in

title := "Change requests must have approved approvals"
description := "All change request issues must have at least one approval with status 'approved' before being considered complete. A 2-week grace period is allowed from issue creation."

grace_period_seconds := 1209600

violation[{"remarks": remarks}] if {
	project := input.projects[_]
	issue := project.issues[_]
	is_change_request(issue)
	not has_approved_approval(issue)
	is_past_grace_period(issue)
	remarks := sprintf("Issue %s does not have an approved approval (created more than 2 weeks ago).", [issue.key])
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

is_past_grace_period(issue) if {
	created := object.get(issue.fields, "created", "")
	created != ""
	created_time := time.parse_rfc3339_ns(created)
	current_time := time.now_ns()
	elapsed_seconds := (current_time - created_time) / 1000000000
	elapsed_seconds > grace_period_seconds
}

is_past_grace_period(issue) if {
	not object.get(issue.fields, "created", null)
}
