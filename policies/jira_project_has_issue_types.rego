package compliance_framework.jira_project_has_issue_types

import future.keywords.if

title := "Projects must have issue types configured"
description := "All Jira projects must have at least one issue type configured to enable proper issue creation."

risk_templates := [{
	"name": "Jira project has no issue types configured",
	"title": "Missing Issue Types Prevents Structured Work Tracking and Compliance Classification",
	"statement": "A Jira project without configured issue types cannot categorize work items such as bugs, change requests, tasks, or security findings. This prevents the application of type-specific workflows, SLAs, and compliance policies. Without issue types, change management, security tracking, and audit controls cannot be applied consistently, creating gaps in governance coverage.",
	"likelihood_hint": "low",
	"impact_hint": "moderate",
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-1059",
		"title": "Incomplete Documentation",
		"url": "https://cwe.mitre.org/data/definitions/1059.html",
	}],
	"remediation": {
		"title": "Configure required issue types for the Jira project",
		"description": "Add the necessary issue types to the project's issue type scheme, including at minimum: Task, Bug, Change Request, and any other types required by the team's workflow and compliance obligations.",
		"tasks": [
			{"title": "Navigate to Project Settings > Issue Types and assign an appropriate issue type scheme"},
			{"title": "Ensure the scheme includes at minimum: Task, Bug, and Change Request issue types"},
			{"title": "Associate the correct workflows with each issue type"},
			{"title": "Verify SLA configurations are applied to security and change request issue types"},
			{"title": "Update existing issues that lack a type to the most appropriate available type"},
		],
	},
}]

violation[{"id": "no_issue_types", "remarks": remarks}] if {
	project_data := input.projects[_]
	not has_issue_types(project_data)
	remarks := sprintf("Project %q (%s) has no issue types configured.", [project_data.project.name, project_data.project.key])
}

has_issue_types(project_data) if {
	count(project_data.issue_types) > 0
}
