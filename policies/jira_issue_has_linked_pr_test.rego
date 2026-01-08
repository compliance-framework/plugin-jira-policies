package compliance_framework.jira_issue_has_linked_pr_test

import data.compliance_framework.jira_issue_has_linked_pr as policy

test_violation_when_change_request_has_no_pr if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {"issuetype": {"name": "Change Request"}},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"dev_info": null,
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_change_request_has_empty_pr_list if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {"issuetype": {"name": "Change Request"}},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"dev_info": {"pull_requests": []},
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_pass_when_change_request_has_linked_pr if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {"issuetype": {"name": "Change Request"}},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"dev_info": {
			"pull_requests": [{
				"id": "1",
				"status": "merged",
				"url": "https://github.com/org/repo/pull/1",
			}],
		},
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_pass_when_non_change_request_has_no_pr if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "BUG-123",
		"fields": {"issuetype": {"name": "Bug"}},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"dev_info": null,
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_violation_when_change_type_has_no_pr if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CHG-123",
		"fields": {"issuetype": {"name": "Change"}},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"dev_info": null,
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_request_a_change_has_no_pr if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "TSTCHG-1",
		"fields": {"issuetype": {"name": "Request a change"}},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"dev_info": null,
		"deployments": null,
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}
