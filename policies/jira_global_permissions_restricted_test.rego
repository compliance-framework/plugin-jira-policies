package compliance_framework.jira_global_permissions_restricted_test

import data.compliance_framework.jira_global_permissions_restricted as policy

test_violation_when_administer_permission_enabled if {
	inp := {
		"global_permissions": [{
			"id": "1",
			"key": "ADMINISTER",
			"name": "Jira Administrators",
		}],
	}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_system_admin_permission_enabled if {
	inp := {
		"global_permissions": [{
			"id": "2",
			"key": "SYSTEM_ADMIN",
			"name": "System Administrators",
		}],
	}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_pass_when_non_sensitive_permission if {
	inp := {
		"global_permissions": [{
			"id": "3",
			"key": "BROWSE_USERS",
			"name": "Browse Users",
		}],
	}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_violation_multiple_sensitive_permissions if {
	inp := {
		"global_permissions": [
			{
				"id": "1",
				"key": "ADMINISTER",
				"name": "Jira Administrators",
			},
			{
				"id": "2",
				"key": "BULK_CHANGE",
				"name": "Bulk Change",
			},
		],
	}

	violations := policy.violation with input as inp
	count(violations) == 2
}
