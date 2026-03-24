package compliance_framework.jira_project_has_lead

import future.keywords.if

title := "Projects must have an assigned lead"
description := "All Jira projects must have a designated project lead for accountability."

risk_templates := [{
  "name": "Jira project has no assigned active lead",
  "title": "Unowned Project Lacks Accountability for Compliance and Governance",
  "statement": "A Jira project without an assigned, active project lead has no designated owner responsible for its compliance posture, workflow configuration, permission scheme, or issue hygiene. This creates an accountability gap where compliance violations go unaddressed, access permissions accumulate unchecked, and there is no point of contact for audit or incident response purposes.",
  "likelihood_hint": "moderate",
  "impact_hint": "moderate",
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-284",
      "title": "Improper Access Control",
      "url": "https://cwe.mitre.org/data/definitions/284.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-1059",
      "title": "Incomplete Documentation",
      "url": "https://cwe.mitre.org/data/definitions/1059.html"
    }
  ],
  "remediation": {
    "title": "Assign an active project lead to all Jira projects",
    "description": "Assign an active, named user as project lead for every Jira project. The project lead is accountable for governance, access reviews, and compliance of the project.",
    "tasks": [
      { "title": "Navigate to Project Settings > Details and assign an active user as project lead" },
      { "title": "Ensure the assigned lead has an active Jira account (not deactivated or suspended)" },
      { "title": "Define project lead responsibilities including periodic access reviews and SLA monitoring" },
      { "title": "Schedule quarterly reviews to verify project leads remain active and appropriate" },
      { "title": "For inactive or deprecated projects, either assign a lead or archive/close the project" }
    ]
  }
}]

violation[{"id": "no_active_project_lead", "remarks": remarks}] if {
	project_data := input.projects[_]
	not has_active_lead(project_data.project)
	remarks := sprintf("Project %q (%s) does not have an assigned active lead.", [project_data.project.name, project_data.project.key])
}

has_active_lead(project) if {
	project.lead != null
	project.lead.active == true
}
