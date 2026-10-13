package compliance_framework.jira_live_data_test

import data.compliance_framework.jira_issue_approval_not_self as approval_not_self
import data.compliance_framework.jira_issue_sla_not_breached as sla

live_data := {"projects": [{
	"project": {
		"id": "10256",
		"key": "TSTCHG",
		"name": "Test Change Management",
		"lead": {
			"accountId": "user-123",
			"displayName": "John Doe",
			"emailAddress": "someone@someplace.com",
			"active": true,
		},
	},
	"issue_types": [
		{"id": "10496", "name": "Service Request with Approvals"},
		{"id": "10497", "name": "Service Request"},
		{"id": "10700", "name": "Request a change"},
	],
	"workflows": [],
	"issues": [{
		"key": "TSTCHG-1",
		"fields": {
			"issuetype": {"name": "Request a change"},
			"status": {"name": "Waiting for CAB approval"},
			"created": "2026-01-09T10:00:00.000Z",
			"reporter": {
				"accountId": "user-456",
				"displayName": "My Good friend",
				"emailAddress": "friend@someplace.com",
				"active": true,
			},
			"summary": "Test change request",
			"description": "Testing the change management workflow",
			"priority": {"name": "Medium"},
		},
		"fields_with_metadata": [],
		"changelog": {
			"histories": [{
				"author": {"displayName": "Someone Else"},
				"created": "2026-01-07T14:29:44+01:00",
				"items": [{"field": "CAB Approvers", "fromString": "", "toString": "[My Friend]"}],
			}],
			"startAt": 0,
			"maxResults": 3,
			"total": 3,
		},
		"approvals": [{
			"id": "805",
			"name": "Waiting for CAB approval",
			"finalDecision": "pending",
			"approvers": [
				{
					"approver": {
						"accountId": "user-456",
						"displayName": "My Good Friend",
						"emailAddress": "friend@someplace.com",
						"active": true,
					},
					"approverDecision": "pending",
				},
				{
					"approver": {
						"accountId": "user-789",
						"displayName": "Someone Else",
						"emailAddress": "someone.else@someplace.com",
						"active": true,
					},
					"approverDecision": "approved",
				},
			],
		}],
		"slas": [
			{
				"id": "17",
				"name": "Time to done",
				"state": "",
				"ongoingCycle": {"breached": false},
			},
			{
				"id": "18",
				"name": "Time to first response",
				"state": "",
				"ongoingCycle": {"breached": true},
			},
		],
		"dev_info": null,
		"deployments": null,
	}],
}]}

test_approval_not_self_detects_reporter_as_approver if {
	violations := approval_not_self.violation with input as live_data
	count(violations) == 1
}

test_sla_detects_breached_sla if {
	violations := sla.violation with input as live_data
	count(violations) == 1
}
