package compliance_framework.jira_workflow_not_editable_test

import data.compliance_framework.jira_workflow_not_editable as policy

test_violation_when_global_workflow_is_editable if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "workflows": [{
		"id": "wf-1",
		"name": "Standard Workflow",
		"scope": {"type": "global"},
		"isEditable": true,
		"transitions": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_production_named_workflow_is_editable if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "workflows": [{
		"id": "wf-1",
		"name": "Production Change Workflow",
		"scope": {"type": "project"},
		"isEditable": true,
		"transitions": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_prod_named_workflow_is_editable if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "workflows": [{
		"id": "wf-1",
		"name": "Prod Release Workflow",
		"scope": {"type": "project"},
		"isEditable": true,
		"transitions": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_pass_when_global_workflow_is_not_editable if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "workflows": [{
		"id": "wf-1",
		"name": "Standard Workflow",
		"scope": {"type": "global"},
		"isEditable": false,
		"transitions": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_project_workflow_is_editable if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "workflows": [{
		"id": "wf-1",
		"name": "Development Workflow",
		"scope": {"type": "project"},
		"isEditable": true,
		"transitions": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_production_workflow_is_not_editable if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "workflows": [{
		"id": "wf-1",
		"name": "Production Workflow",
		"scope": {"type": "project"},
		"isEditable": false,
		"transitions": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}
