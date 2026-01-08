package compliance_framework.jira_issue_pr_merged_before_done_test

import data.compliance_framework.jira_issue_pr_merged_before_done as policy

test_violation_when_done_with_unmerged_pr if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"status": {"name": "Done"},
		},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"dev_info": {
			"pull_requests": [{
				"id": "1",
				"status": "open",
				"url": "https://github.com/org/repo/pull/1",
			}],
		},
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_pass_when_done_with_merged_pr if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"status": {"name": "Done"},
		},
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

test_pass_when_not_done if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"status": {"name": "In Progress"},
		},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"dev_info": {
			"pull_requests": [{
				"id": "1",
				"status": "open",
				"url": "https://github.com/org/repo/pull/1",
			}],
		},
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_violation_when_done_without_dev_info if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"status": {"name": "Done"},
		},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"dev_info": null,
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_pass_when_done_with_empty_prs if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "CR-123",
		"fields": {
			"issuetype": {"name": "Change Request"},
			"status": {"name": "Done"},
		},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"dev_info": {"pull_requests": []},
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
			"status": {"name": "Done"},
		},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"dev_info": {
			"pull_requests": [{
				"id": "1",
				"status": "open",
				"url": "https://github.com/org/repo/pull/1",
			}],
		},
		"deployments": [],
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_violation_when_no_dev_info if {
	inp := {"projects": [{"project": {"id": "1", "key": "TEST", "name": "Test"}, "issues": [{
		"key": "TSTCHG-1",
		"fields": {
			"issuetype": {"name": "Request a change"},
			"status": {"name": "Waiting for CAB approval"},
		},
		"changelog": null,
		"approvals": [],
		"slas": [],
		"dev_info": null,
		"deployments": null,
	}]}]}

	violations := policy.violation with input as inp
	count(violations) == 1
}
