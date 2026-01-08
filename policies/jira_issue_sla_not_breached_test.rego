package compliance_framework.jira_issue_sla_not_breached_test

import data.compliance_framework.jira_issue_sla_not_breached as policy

test_violation_when_sla_breached_by_state if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "ISSUE-123",
		"fields": {},
		"changelog": null,
		"approvals": [],
		"slas": [{
			"id": "1",
			"name": "Time to Resolution",
			"state": "BREACHED",
		}],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_sla_breached_by_ongoing_cycle if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "ISSUE-123",
		"fields": {},
		"changelog": null,
		"approvals": [],
		"slas": [{
			"id": "1",
			"name": "Time to Resolution",
			"state": "",
			"ongoingCycle": {"breached": true},
		}],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_sla_breached_by_completed_cycle if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "ISSUE-123",
		"fields": {},
		"changelog": null,
		"approvals": [],
		"slas": [{
			"id": "1",
			"name": "Time to Resolution",
			"state": "",
			"completedCycles": [{"breached": true}],
		}],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_multiple_slas_breached if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "ISSUE-123",
		"fields": {},
		"changelog": null,
		"approvals": [],
		"slas": [
			{"id": "1", "name": "Time to First Response", "state": "BREACHED"},
			{"id": "2", "name": "Time to Resolution", "state": "BREACHED"},
		],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 2
}

test_pass_when_sla_not_breached if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "ISSUE-123",
		"fields": {},
		"changelog": null,
		"approvals": [],
		"slas": [{
			"id": "1",
			"name": "Time to Resolution",
			"state": "MET",
			"ongoingCycle": {"breached": false},
		}],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_no_slas if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "ISSUE-123",
		"fields": {},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}
