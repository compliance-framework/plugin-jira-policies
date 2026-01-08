package compliance_framework.jira_issue_approval_not_self

import future.keywords.if
import future.keywords.in

title := "Change requests must not be self-approved"
description := "The author of a change request cannot approve their own change. Separation of duties is required."

violation[{"remarks": remarks}] if {
	project := input.projects[_]
	issue := project.issues[_]
	is_change_request(issue)
	approval := issue.approvals[_]
	approver_item := approval.approvers[_]
	author := get_author(issue)
	author != ""
	lower(approver_item.approver.displayName) == lower(author)
	remarks := sprintf("Issue %s has reporter %s configured as approver. Separation of duties violation.", [issue.key, author])
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

get_author(issue) := author if {
	reporter := object.get(issue.fields, "reporter", {})
	display_name := object.get(reporter, "displayName", "")
	display_name != ""
	author := display_name
}

get_author(issue) := author if {
	reporter := object.get(issue.fields, "reporter", {})
	display_name := object.get(reporter, "displayName", "")
	display_name == ""
	name := object.get(reporter, "name", "")
	name != ""
	author := name
}

get_author(issue) := author if {
	not issue.fields.reporter
	creator := object.get(issue.fields, "creator", {})
	author := object.get(creator, "displayName", "")
}
