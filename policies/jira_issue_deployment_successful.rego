package compliance_framework.jira_issue_deployment_successful

import future.keywords.if
import future.keywords.in

title := "Deployments must be in successful state"
description := "All issue deployments must have a successful status to ensure proper change management."

failed_statuses := ["failed", "failure", "error", "cancelled", "canceled"]

violation[{"remarks": remarks}] if {
	project := input.projects[_]
	issue := project.issues[_]
	deployment := issue.deployments[_]
	lower(deployment.status) in failed_statuses
	remarks := sprintf("Issue %s has a failed deployment (ID: %s, Environment: %s, Status: %s)", [issue.key, deployment.id, deployment.environment, deployment.status])
}

violation[{"remarks": remarks}] if {
	project := input.projects[_]
	count(project.issues) > 0
	issue := project.issues[_]
	is_change_request(issue)
	not has_deployments(issue)
	remarks := sprintf("Issue %s has no deployment information available.", [issue.key])
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

has_deployments(issue) if {
	issue.deployments != null
	count(issue.deployments) > 0
}
