package compliance_framework.jira_issue_has_changelog_test

import data.compliance_framework.jira_issue_has_changelog as policy

test_violation_when_change_request_has_no_changelog if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {"issuetype": {"name": "Change Request"}},
		"changelog": {"histories": [], "startAt": 0, "maxResults": 0, "total": 0},
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_pass_when_change_request_has_changelog if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {"issuetype": {"name": "Change Request"}},
		"changelog": {"histories": [{
			"author": {"displayName": "user1"},
			"created": "2024-01-01T10:00:00Z",
			"items": [{
				"field": "status",
				"fromString": "Open",
				"toString": "In Progress",
			}],
		}], "startAt": 0, "maxResults": 1, "total": 1},
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_non_change_request_has_no_changelog if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "BUG-123",
		"fields": {"issuetype": {"name": "Bug"}},
		"changelog": {"histories": [], "startAt": 0, "maxResults": 0, "total": 0},
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_violation_when_cr_type_has_no_changelog if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-456",
		"fields": {"issuetype": {"name": "CR"}},
		"changelog": {"histories": [], "startAt": 0, "maxResults": 0, "total": 0},
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_changelog_is_null if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-789",
		"fields": {"issuetype": {"name": "Change Request"}},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}
