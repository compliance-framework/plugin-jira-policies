package compliance_framework.jira_project_has_issue_types

import future.keywords.if

title := "Projects must have issue types configured"
description := "All Jira projects must have at least one issue type configured to enable proper issue creation."

violation[{"remarks": remarks}] if {
	project_data := input.projects[_]
	not has_issue_types(project_data)
	remarks := sprintf("Project %q (%s) has no issue types configured.", [project_data.project.name, project_data.project.key])
}

has_issue_types(project_data) if {
	count(project_data.issue_types) > 0
}
