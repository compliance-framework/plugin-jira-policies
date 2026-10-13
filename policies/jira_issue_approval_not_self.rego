package compliance_framework.jira_issue_approval_not_self

import future.keywords.if
import future.keywords.in

title := "Change requests must not be self-approved"
description := "The author of a change request cannot approve their own change. Separation of duties is required."

risk_templates := [{
	"name": "Change request author is also the approver",
	"title": "Self-Approval of Change Requests Violates Separation of Duties",
	"statement": "When the author of a change request is also listed as its approver, the separation of duties control is bypassed. This allows a single person to both propose and authorize a change without independent review, increasing the risk that unauthorized, erroneous, or malicious changes are approved and deployed. This is a direct violation of change management controls required by frameworks such as SOC 2, ISO 27001, and ITIL.",
	"likelihood_hint": "moderate",
	"impact_hint": "high",
	"threat_refs": [
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-284",
			"title": "Improper Access Control",
			"url": "https://cwe.mitre.org/data/definitions/284.html",
		},
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-269",
			"title": "Improper Privilege Management",
			"url": "https://cwe.mitre.org/data/definitions/269.html",
		},
	],
	"remediation": {
		"title": "Enforce separation of duties in Jira change request approval workflows",
		"description": "Configure Jira workflows and approval schemes to prevent the issue reporter or creator from being listed as an approver. Require a distinct, independent approver for all change requests.",
		"tasks": [
			{"title": "Review and remediate all change requests where the reporter is listed as an approver"},
			{"title": "Configure Jira approval schemes to exclude the issue reporter from the approver list"},
			{"title": "Assign a dedicated change advisory board (CAB) or approval group for change requests"},
			{"title": "Add a workflow validator or automation rule that blocks self-approval transitions"},
			{"title": "Audit existing merged/closed change requests for historical self-approval violations"},
		],
	},
}]

violation[{"id": "self_approval", "remarks": remarks}] if {
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
