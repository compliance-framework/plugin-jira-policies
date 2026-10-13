package compliance_framework.jira_project_has_lead_test

import data.compliance_framework.jira_project_has_lead as policy

test_violation_when_project_has_no_lead if {
	inp := {"projects": [{"project": {
		"id": "10001",
		"key": "PROJ",
		"name": "Test Project",
		"lead": null,
	}}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_project_lead_inactive if {
	inp := {"projects": [{"project": {
		"id": "10001",
		"key": "PROJ",
		"name": "Test Project",
		"lead": {
			"accountId": "user-123",
			"displayName": "John Doe",
			"active": false,
		},
	}}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_pass_when_project_has_active_lead if {
	inp := {"projects": [{"project": {
		"id": "10001",
		"key": "PROJ",
		"name": "Test Project",
		"lead": {
			"accountId": "user-123",
			"displayName": "John Doe",
			"active": true,
		},
	}}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_violation_multiple_projects_without_leads if {
	inp := {"projects": [
		{"project": {
			"id": "10001",
			"key": "PROJ1",
			"name": "Project One",
			"lead": null,
		}},
		{"project": {
			"id": "10002",
			"key": "PROJ2",
			"name": "Project Two",
			"lead": {
				"accountId": "user-123",
				"displayName": "John Doe",
				"active": false,
			},
		}},
	]}

	violations := policy.violation with input as inp
	count(violations) == 2
}
