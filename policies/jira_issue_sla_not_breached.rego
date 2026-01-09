package compliance_framework.jira_issue_sla_not_breached

import future.keywords.if

title := "Issues must not breach SLA targets"
description := "All issues with SLA tracking must not have any breached SLAs."

violation[{"remarks": remarks}] if {
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
