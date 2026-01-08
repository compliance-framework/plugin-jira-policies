package compliance_framework.jira_issue_pr_merged_before_done

import future.keywords.if
import future.keywords.in

title := "Pull requests must be merged before issue completion"
description := "Change request issues with linked PRs must have at least one PR merged before the issue can be considered complete."

done_statuses := ["done", "closed", "resolved", "complete", "completed"]

violation[{"remarks": remarks}] if {
	project := input.projects[_]
	issue := project.issues[_]
	is_change_request(issue)
	is_done(issue)
	has_prs(issue)
	not has_merged_pr(issue)
	remarks := sprintf("Issue %s is done but has no merged pull requests.", [issue.key])
}

violation[{"remarks": remarks}] if {
	project := input.projects[_]
	count(project.issues) > 0
	issue := project.issues[_]
	is_change_request(issue)
	not has_dev_info(issue)
	remarks := sprintf("Issue %s has no development information available.", [issue.key])
}

change_request_types := ["change request", "change", "cr", "request a change"]

is_change_request(issue) if {
	issue_type := lower(object.get(issue.fields, "issuetype", {}).name)
	issue_type in change_request_types
}

is_change_request(issue) if {
	issue_type := lower(object.get(issue.fields, "issuetype", ""))
	issue_type in change_request_types
}

has_dev_info(issue) if {
	issue.dev_info != null
}

is_done(issue) if {
	status := lower(object.get(issue.fields, "status", {}).name)
	status in done_statuses
}

is_done(issue) if {
	status := lower(object.get(issue.fields, "status", ""))
	status in done_statuses
}

has_prs(issue) if {
	issue.dev_info != null
	count(issue.dev_info.pull_requests) > 0
}

has_merged_pr(issue) if {
	pr := issue.dev_info.pull_requests[_]
	lower(pr.status) == "merged"
}
