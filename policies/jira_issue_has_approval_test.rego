package compliance_framework.jira_issue_has_approval_test

import data.compliance_framework.jira_issue_has_approval as policy

test_violation_when_change_request_has_no_approvals if {
	old_date := time.format(time.add_date(time.now_ns(), 0, 0, -30))
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"created": old_date,
		},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_change_request_has_pending_approval if {
	old_date := time.format(time.add_date(time.now_ns(), 0, 0, -30))
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Request a change"},
			"created": old_date,
		},
		"changelog": null,
		"approvals": [{
			"id": "1",
			"finalDecision": "pending",
			"approvers": [{"approver": {"displayName": "user1"}, "approverDecision": "pending"}],
		}],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_pass_when_change_request_has_approved_approval if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {"issuetype": {"name":  "Request a change"}},
		"changelog": null,
		"approvals": [{
			"id": "1",
			"finalDecision": "approved",
			"approvers": [{"approver": {"displayName": "user1"}, "approverDecision": "approved"}],
		}],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_non_change_request_has_no_approvals if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "BUG-123",
		"fields": {"issuetype": {"name": "Bug"}},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_cr_type_has_approved_approval if {
	old_date := time.format(time.add_date(time.now_ns(), 0, 0, -30))
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-456",
		"fields": {
			"issuetype": {"name": "CR"},
			"created": old_date,
		},
		"changelog": null,
		"approvals": [{
			"id": "1",
			"finalDecision": "Approved",
			"approvers": [{"approver": {"displayName": "user1"}, "approverDecision": "approved"}],
		}],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_change_request_within_grace_period if {
	recent_date := time.format(time.add_date(time.now_ns(), 0, 0, -5))
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-789",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"created": recent_date,
		},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}
