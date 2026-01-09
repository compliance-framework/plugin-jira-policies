package compliance_framework.jira_issue_approval_not_self_test

import data.compliance_framework.jira_issue_approval_not_self as policy

test_violation_when_reporter_is_approver if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"reporter": {"displayName": "John Doe"},
		},
		"changelog": null,
		"approvals": [{
			"id": "1",
			"finalDecision": "pending",
			"approvers": [{"approver": {"displayName": "John Doe"}, "approverDecision": "pending"}],
		}],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_reporter_in_approvers_list_with_others if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "TSTCHG-1",
		"fields": {
			"issuetype": {"name": "Request a change"},
			"reporter": {"displayName": "Ian Miell"},
		},
		"changelog": null,
		"approvals": [{
			"id": "805",
			"name": "Waiting for CAB approval",
			"finalDecision": "pending",
			"approvers": [
				{"approver": {"displayName": "Ian Miell"}, "approverDecision": "pending"},
				{"approver": {"displayName": "Someone Else"}, "approverDecision": "approved"},
			],
		}],
		"slas": [],
		"deployments": null,
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_pass_when_approved_by_different_user if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"reporter": {"displayName": "John Doe"},
		},
		"changelog": null,
		"approvals": [{
			"id": "1",
			"finalDecision": "approved",
			"approvers": [{"approver": {"displayName": "Jane Smith"}, "approverDecision": "approved"}],
		}],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_no_approvals if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"reporter": {"displayName": "John Doe"},
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
			"reporter": {"displayName": "John Doe"},
		},
		"changelog": null,
		"approvals": [{
			"id": "1",
			"finalDecision": "approved",
			"approvers": [{"approver": {"displayName": "John Doe"}, "approverDecision": "approved"}],
		}],
		"slas": [],
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}
