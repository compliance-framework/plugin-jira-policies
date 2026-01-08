package compliance_framework.jira_issue_has_required_fields

import future.keywords.if
import future.keywords.in

title := "Change requests must have required fields populated"
description := "All change request issues must have summary, description, and priority fields populated."

required_fields := ["summary", "description", "priority"]

violation[{"remarks": remarks}] if {
	project := input.projects[_]
	issue := project.issues[_]
	is_change_request(issue)
	field := required_fields[_]
	not has_field(issue, field)
	remarks := sprintf("Issue %s is missing required field: %s", [issue.key, field])
}

is_change_request(issue) if {
	issue_type := lower(object.get(issue.fields, "issuetype", {}).name)
	issue_type in ["change request", "change", "cr", "request a change"]
}

is_change_request(issue) if {
	issue_type := lower(object.get(issue.fields, "issuetype", ""))
	issue_type in ["change request", "change", "cr", "request a change"]
}

has_field(issue, field) if {
	value := issue.fields[field]
	value != null
	value != ""
}

has_field(issue, field) if {
	field == "priority"
	value := issue.fields[field]
	value != null
	is_object(value)
	value.name != ""
}
