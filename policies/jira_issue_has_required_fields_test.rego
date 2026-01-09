package compliance_framework.jira_issue_has_required_fields_test

import data.compliance_framework.jira_issue_has_required_fields as policy

test_violation_when_missing_summary if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"description": "Test description",
			"priority": {"name": "High"},
		},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_missing_description if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"summary": "Test summary",
			"priority": {"name": "High"},
		},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_missing_multiple_fields if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
		},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 3
}

test_pass_when_all_fields_present if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"summary": "Test summary",
			"description": "Test description",
			"priority": {"name": "High"},
		},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_non_change_request if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "BUG-123",
		"fields": {
			"issuetype": {"name": "Bug"},
		},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}
