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

risk_templates := [{
  "name": "Sensitive Jira global permissions are unrestricted",
  "title": "Overly Broad Global Permissions Enable Unauthorized System Administration",
  "statement": "Global permissions such as 'administer', 'system_admin', or 'bulk_change' grant users the ability to modify system-wide configuration, override project-level controls, or perform mass data changes. If these permissions are granted to broad groups or unintended users, attackers or insiders can alter audit settings, bypass workflow controls, or exfiltrate bulk data without detection.",
  "likelihood_hint": "moderate",
  "impact_hint": "high",
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-732",
      "title": "Incorrect Permission Assignment for Critical Resource",
      "url": "https://cwe.mitre.org/data/definitions/732.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-284",
      "title": "Improper Access Control",
      "url": "https://cwe.mitre.org/data/definitions/284.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-269",
      "title": "Improper Privilege Management",
      "url": "https://cwe.mitre.org/data/definitions/269.html"
    }
  ],
  "remediation": {
    "title": "Review and restrict sensitive global Jira permissions",
    "description": "Audit all groups and users assigned sensitive global permissions and reduce them to the minimum necessary, applying the principle of least privilege.",
    "tasks": [
      { "title": "Review all groups assigned each sensitive global permission in Jira Administration > System > Global Permissions" },
      { "title": "Remove any groups or users that do not require the sensitive permission for their role" },
      { "title": "Restrict 'administer' and 'system_admin' permissions to a named, minimal administrator group" },
      { "title": "Restrict 'bulk_change' to project managers or team leads only" },
      { "title": "Schedule a quarterly review of global permission assignments" },
      { "title": "Enable audit logging to track changes to global permissions" }
    ]
  }
}]

violation[{"id": "sensitive_global_permission_unrestricted", "remarks": remarks}] if {
	permission := input.global_permissions[_]
	lower(permission.key) in sensitive_permissions
	remarks := sprintf("Sensitive global permission %q (%s) is enabled. Ensure this is intentional and properly restricted.", [permission.name, permission.key])
}
