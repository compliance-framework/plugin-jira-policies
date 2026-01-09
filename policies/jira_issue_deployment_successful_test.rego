package compliance_framework.jira_issue_deployment_successful_test

import data.compliance_framework.jira_issue_deployment_successful as policy

test_violation_when_deployment_failed if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "ISSUE-123",
		"fields": {},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [{
			"id": "dep-1",
			"environment": "production",
			"status": "failed",
		}],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_deployment_error if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "ISSUE-123",
		"fields": {},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [{
			"id": "dep-1",
			"environment": "staging",
			"status": "error",
		}],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_deployment_cancelled if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "ISSUE-123",
		"fields": {},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [{
			"id": "dep-1",
			"environment": "production",
			"status": "cancelled",
		}],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_pass_when_deployment_successful if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "ISSUE-123",
		"fields": {},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [{
			"id": "dep-1",
			"environment": "production",
			"status": "successful",
		}],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_no_deployments if {
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

test_violation_multiple_failed_deployments if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "ISSUE-123",
		"fields": {},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [
			{
				"id": "dep-1",
				"environment": "staging",
				"status": "failed",
			},
			{
				"id": "dep-2",
				"environment": "production",
				"status": "failure",
			},
		],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 2
}

test_violation_when_no_deployments_for_change_request if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "TSTCHG-1",
		"fields": {"issuetype": {"name": "Request a change"}},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": null,
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_empty_deployments_for_change_request if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {"issuetype": {"name": "Change Request"}},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_pass_when_no_deployments_for_non_change_request if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "BUG-123",
		"fields": {"issuetype": {"name": "Bug"}},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": null,
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}
