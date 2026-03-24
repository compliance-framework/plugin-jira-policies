package compliance_framework.jira_audit_records_exist

import future.keywords.if

title := "Audit records must exist for compliance"
description := "The Jira instance must have audit records enabled and populated to ensure compliance tracking."

risk_templates := [{
  "name": "Jira audit logging is absent",
  "title": "Absence of Audit Records Prevents Detection of Unauthorized Actions",
  "statement": "Without audit records, there is no trail to detect or investigate unauthorized configuration changes, privilege escalations, or data access events in Jira. Regulatory frameworks (SOC 2, ISO 27001, PCI-DSS) require audit logging as a mandatory control. The absence of audit records means incidents may go undetected and unattributed.",
  "likelihood_hint": "moderate",
  "impact_hint": "high",
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-778",
      "title": "Insufficient Logging",
      "url": "https://cwe.mitre.org/data/definitions/778.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-223",
      "title": "Omission of Security-relevant Information",
      "url": "https://cwe.mitre.org/data/definitions/223.html"
    }
  ],
  "remediation": {
    "title": "Enable and verify Jira audit logging",
    "description": "Enable audit logging in Jira administration and confirm that audit records are being generated and retained according to the organization's retention policy.",
    "tasks": [
      { "title": "Enable audit logging in Jira Administration > System > Audit log" },
      { "title": "Set the audit log retention period to meet compliance requirements (e.g., 12 months)" },
      { "title": "Verify audit records are being written by performing a test action and checking the log" },
      { "title": "Export or forward audit logs to a SIEM for centralized monitoring and alerting" },
      { "title": "Restrict access to audit log settings to Jira administrators only" }
    ]
  }
}]

violation[{"id": "no_audit_records", "remarks": remarks}] if {
	not has_audit_records
	remarks := "No audit records found. Audit logging must be enabled for compliance."
}

has_audit_records if {
	count(input.audit_records) > 0
}
