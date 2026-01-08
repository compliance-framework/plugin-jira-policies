package compliance_framework.jira_project_has_lead

import future.keywords.if

title := "Projects must have an assigned lead"
description := "All Jira projects must have a designated project lead for accountability."

violation[{"remarks": remarks}] if {
	project_data := input.projects[_]
	not has_active_lead(project_data.project)
	remarks := sprintf("Project %q (%s) does not have an assigned active lead.", [project_data.project.name, project_data.project.key])
}

has_active_lead(project) if {
	project.lead != null
	project.lead.active == true
}
