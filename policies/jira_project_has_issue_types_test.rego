package compliance_framework.jira_project_has_issue_types_test

import data.compliance_framework.jira_project_has_issue_types as policy

test_violation_when_no_issue_types if {
	inp := {"projects": [{
		"project": {"id": "10001", "key": "PROJ", "name": "Test Project"},
		"issue_types": [],
	}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_issue_types_missing if {
	inp := {"projects": [{"project": {"id": "10001", "key": "PROJ", "name": "Test Project"}}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_pass_when_has_issue_types if {
	inp := {"projects": [{
		"project": {"id": "10001", "key": "PROJ", "name": "Test Project"},
		"issue_types": [
			{"id": "1", "name": "Bug"},
			{"id": "2", "name": "Task"},
		],
	}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}
