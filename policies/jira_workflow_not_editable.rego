package compliance_framework.jira_workflow_not_editable

import future.keywords.if

title := "Production workflows should not be editable"
description := "Workflows in production scope should be locked to prevent unauthorized changes."

risk_templates := [{
	"name": "Production Jira workflow is editable",
	"title": "Editable Production Workflows Allow Unauthorized Process Tampering",
	"statement": "A production-scoped Jira workflow that remains editable can be modified by administrators or users with workflow management permissions without going through a change control process. This allows the approval, status transition, or validation rules governing change requests and security issues to be altered silently, bypassing compliance controls and potentially eliminating mandatory approval gates.",
	"likelihood_hint": "low",
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
			"external_id": "CWE-693",
			"title": "Protection Mechanism Failure",
			"url": "https://cwe.mitre.org/data/definitions/693.html",
		},
	],
	"remediation": {
		"title": "Lock production Jira workflows to prevent unauthorized modification",
		"description": "Mark production workflows as inactive/locked so they cannot be edited without first being explicitly duplicated and going through a change control process.",
		"tasks": [
			{"title": "Review the listed production workflow(s) and confirm they should be locked"},
			{"title": "In Jira Administration > Issues > Workflows, set the workflow status to 'Inactive' to prevent editing"},
			{"title": "Restrict workflow edit permissions to the Jira administrator role only"},
			{"title": "Implement a change control process for workflow modifications: duplicate, modify copy, test, then publish"},
			{"title": "Enable audit logging to track any future changes to workflow configuration"},
		],
	},
}]

violation[{"id": "production_workflow_editable", "remarks": remarks}] if {
	project := input.projects[_]
	workflow := project.workflows[_]
	is_production_scope(workflow)
	workflow.isEditable == true
	remarks := sprintf("Workflow %q is editable but should be locked for production use.", [workflow.name])
}

is_production_scope(workflow) if {
	workflow.scope.type == "global"
}

is_production_scope(workflow) if {
	contains(lower(workflow.name), "production")
}

is_production_scope(workflow) if {
	contains(lower(workflow.name), "prod")
}
