package compliance_framework.jira_global_permissions_restricted

import future.keywords.if
import future.keywords.in

title := "Sensitive global permissions must be restricted"
description := "Global permissions that can affect system security must be properly controlled."

sensitive_permissions := [
	"administer",
	"system_admin",
	"manage_group_filter_subscriptions",
	"bulk_change",
	"create_shared_objects",
]

violation[{"remarks": remarks}] if {
	permission := input.global_permissions[_]
	lower(permission.key) in sensitive_permissions
	remarks := sprintf("Sensitive global permission %q (%s) is enabled. Ensure this is intentional and properly restricted.", [permission.name, permission.key])
}
