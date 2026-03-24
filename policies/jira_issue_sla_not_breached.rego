package compliance_framework.jira_issue_sla_not_breached

import future.keywords.if

title := "Issues must not breach SLA targets"
description := "All issues with SLA tracking must not have any breached SLAs."

risk_templates := [{
  "name": "Jira issue has breached SLA target",
  "title": "SLA Breach Indicates Failure to Meet Committed Service Response Obligations",
  "statement": "A breached SLA means the team has failed to respond to, resolve, or progress an issue within the agreed time commitment. Persistent SLA breaches indicate inadequate capacity, triage processes, or escalation procedures. For security issues, SLA breaches can leave known vulnerabilities unaddressed beyond acceptable risk windows, increasing exposure. For change requests, breaches may indicate stalled approvals or blocked changes that delay compliance remediation.",
  "likelihood_hint": "moderate",
  "impact_hint": "moderate",
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-693",
      "title": "Protection Mechanism Failure",
      "url": "https://cwe.mitre.org/data/definitions/693.html"
    }
  ],
  "remediation": {
    "title": "Address SLA-breached issues and improve SLA compliance processes",
    "description": "Triage all SLA-breached issues immediately and update their status. Review the root cause of the breach and improve team processes to prevent recurrence.",
    "tasks": [
      { "title": "Immediately triage all SLA-breached issues and assign to the responsible owner" },
      { "title": "Update issue status and add progress comments to acknowledge the breach" },
      { "title": "Perform a root cause analysis on why the SLA was breached (capacity, process, escalation failure)" },
      { "title": "Configure Jira SLA breach notifications to alert the team lead before the SLA deadline" },
      { "title": "Review and adjust SLA targets if they are systematically unachievable given current capacity" },
      { "title": "Track SLA breach rates as a KPI and review in regular team retrospectives" }
    ]
  }
}]

violation[{"id": "sla_breached", "remarks": remarks}] if {
	project := input.projects[_]
	issue := project.issues[_]
	sla := issue.slas[_]
	is_sla_breached(sla)
	remarks := sprintf("Issue %s has breached SLA: %s", [issue.key, sla.name])
}

is_sla_breached(sla) if {
	upper(sla.state) == "BREACHED"
}

is_sla_breached(sla) if {
	sla.ongoingCycle != null
	sla.ongoingCycle.breached == true
}

is_sla_breached(sla) if {
	cycle := sla.completedCycles[_]
	cycle.breached == true
}
