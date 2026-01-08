package compliance_framework.jira_audit_records_exist

import future.keywords.if

title := "Audit records must exist for compliance"
description := "The Jira instance must have audit records enabled and populated to ensure compliance tracking."

violation[{"remarks": remarks}] if {
	not has_audit_records
	remarks := "No audit records found. Audit logging must be enabled for compliance."
}

has_audit_records if {
	count(input.audit_records) > 0
}
