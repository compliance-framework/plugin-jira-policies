package compliance_framework.jira_audit_records_exist_test

import data.compliance_framework.jira_audit_records_exist as policy

test_violation_when_no_audit_records if {
	inp := {"audit_records": []}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_audit_records_missing if {
	inp := {"projects": []}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_pass_when_audit_records_exist if {
	inp := {"audit_records": [{
		"id": 1,
		"summary": "User logged in",
		"created": "2024-01-01T10:00:00Z",
		"authorName": "admin",
		"category": "user management",
	}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_multiple_audit_records_exist if {
	inp := {"audit_records": [
		{
			"id": 1,
			"summary": "User logged in",
			"created": "2024-01-01T10:00:00Z",
			"authorName": "admin",
			"category": "user management",
		},
		{
			"id": 2,
			"summary": "Project created",
			"created": "2024-01-01T11:00:00Z",
			"authorName": "admin",
			"category": "projects",
		},
	]}

	violations := policy.violation with input as inp
	count(violations) == 0
}
