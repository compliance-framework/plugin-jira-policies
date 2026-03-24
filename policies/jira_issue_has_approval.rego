package compliance_framework.jira_issue_has_approval

import future.keywords.if
import future.keywords.in

title := "Change requests must have approved approvals"
description := "All change request issues must have at least one approval with status 'approved' before being considered complete. A 2-week grace period is allowed from issue creation."

grace_period_seconds := 1209600

risk_templates := [{
  "name": "Change request lacks formal approval",
  "title": "Unapproved Change Requests Bypass Change Management Controls",
  "statement": "Change requests that have not received a formal approval decision allow changes to proceed without authorization. This defeats the purpose of the change management process, increases the risk of unplanned or harmful changes reaching production, and creates compliance gaps under frameworks such as SOC 2 CC6, ISO 27001 A.12.1.2, and ITIL change enablement. A two-week grace period is allowed after creation before this becomes a violation.",
  "likelihood_hint": "moderate",
  "impact_hint": "high",
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-693",
      "title": "Protection Mechanism Failure",
      "url": "https://cwe.mitre.org/data/definitions/693.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-284",
      "title": "Improper Access Control",
      "url": "https://cwe.mitre.org/data/definitions/284.html"
    }
  ],
  "remediation": {
    "title": "Obtain formal approval for all open change requests",
    "description": "Ensure all change requests past the grace period have received an explicit approval decision. Configure Jira workflows to require approval before allowing transition to implementation stages.",
    "tasks": [
      { "title": "Identify all change requests older than 2 weeks without an approved decision" },
      { "title": "Assign the appropriate approver (CAB, manager, or designated owner) to each outstanding CR" },
      { "title": "Configure Jira workflow transitions to require approved status before moving to 'In Progress' or 'Done'" },
      { "title": "Set up automated reminders for approvers when CRs have been pending approval for more than 5 business days" },
      { "title": "Review and close or reject stale CRs that are no longer applicable" }
    ]
  }
}]

violation[{"id": "change_request_unapproved", "remarks": remarks}] if {
	project := input.projects[_]
	issue := project.issues[_]
	is_change_request(issue)
	not has_approved_approval(issue)
	is_past_grace_period(issue)
	remarks := sprintf("Issue %s does not have an approved approval (created more than 2 weeks ago).", [issue.key])
}

is_change_request(issue) if {
	issue_type := lower(object.get(issue.fields, "issuetype", {}).name)
	issue_type in ["change request", "change", "cr", "request a change"]
}

is_change_request(issue) if {
	issue_type := lower(object.get(issue.fields, "issuetype", ""))
	issue_type in ["change request", "change", "cr", "request a change"]
}

has_approved_approval(issue) if {
	approval := issue.approvals[_]
	lower(approval.finalDecision) == "approved"
}

is_past_grace_period(issue) if {
	created := object.get(issue.fields, "created", "")
	created != ""
	created_time := time.parse_rfc3339_ns(created)
	current_time := time.now_ns()
	elapsed_seconds := (current_time - created_time) / 1000000000
	elapsed_seconds > grace_period_seconds
}

is_past_grace_period(issue) if {
	not object.get(issue.fields, "created", null)
}
