package compliance_framework.jira_issue_has_changelog

import future.keywords.if
import future.keywords.in

title := "Change requests must have audit trail"
description := "All change request issues must have at least one changelog entry to ensure proper audit trail."

risk_templates := [{
	"name": "Change request has no changelog entries",
	"title": "Missing Changelog Breaks Audit Trail for Change Requests",
	"statement": "A change request without any changelog entries has no auditable history of modifications, status transitions, or decisions. This means there is no evidence of when the change was approved, who made modifications, or what the original scope was. Change management compliance frameworks require a complete audit trail for all change requests to support post-incident investigation and regulatory audit.",
	"likelihood_hint": "moderate",
	"impact_hint": "moderate",
	"threat_refs": [
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-778",
			"title": "Insufficient Logging",
			"url": "https://cwe.mitre.org/data/definitions/778.html",
		},
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-1059",
			"title": "Incomplete Documentation",
			"url": "https://cwe.mitre.org/data/definitions/1059.html",
		},
	],
	"remediation": {
		"title": "Ensure all change requests accumulate changelog entries",
		"description": "Verify that Jira changelog tracking is enabled and that all change request workflow transitions generate changelog entries. Review any CRs lacking changelogs for possible data integrity issues.",
		"tasks": [
			{"title": "Confirm Jira issue history (changelog) tracking is enabled at the project level"},
			{"title": "Review change requests with no changelog to determine if data was deleted or if the issue was created non-interactively"},
			{"title": "Add at least one status transition or comment to generate a changelog entry for affected CRs"},
			{"title": "Configure Jira automation to log a comment or field update when a CR is created, recording initial state"},
			{"title": "Restrict deletion of issue history to Jira administrators and audit such actions"},
		],
	},
}]

violation[{"id": "no_changelog", "remarks": remarks}] if {
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
