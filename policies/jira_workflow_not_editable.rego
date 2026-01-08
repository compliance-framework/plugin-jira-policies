package compliance_framework.jira_workflow_not_editable

import future.keywords.if

title := "Production workflows should not be editable"
description := "Workflows in production scope should be locked to prevent unauthorized changes."

violation[{"remarks": remarks}] if {
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
