# Jira Policies

Compliance policies for evaluating Jira projects and issues in the Continuous Compliance Framework.

## Overview

These policies evaluate various aspects of Jira project governance, including:
- Project configuration and leadership
- Change request workflows and approvals
- Development and deployment practices
- SLA compliance
- Audit trail requirements

## Supported Issue Types

The policies recognize the following change request types:
- `Change Request`
- `Change`
- `CR`
- `Request a change`

## Available Policies

### Project-Level Policies
- **jira_project_has_lead** - Ensures projects have an active project lead
- **jira_project_has_issue_types** - Validates project has required issue types configured

### Issue-Level Policies
- **jira_issue_has_approval** - Requires change requests to have at least one approved approval
- **jira_issue_approval_not_self** - Prevents self-approval (separation of duties)
- **jira_issue_has_changelog** - Ensures issues have audit trail entries
- **jira_issue_has_required_fields** - Validates required fields are populated
- **jira_issue_has_linked_pr** - Requires change requests to have linked pull requests
- **jira_issue_pr_merged_before_done** - Ensures PRs are merged before issues are marked done
- **jira_issue_deployment_successful** - Validates deployments are in successful state
- **jira_issue_sla_not_breached** - Checks SLA compliance

## Data Model

Policies expect a project-centric data structure:

```json
{
  "projects": [
    {
      "project": {
        "id": "123",
        "key": "PROJ",
        "name": "Project Name",
        "lead": {
          "accountId": "user-123",
          "displayName": "John Doe",
          "active": true
        }
      },
      "issues": [
        {
          "key": "PROJ-123",
          "fields": {
            "issuetype": {"name": "Change Request"},
            "status": {"name": "In Progress"},
            "reporter": {"displayName": "Jane Smith"}
          },
          "approvals": [...],
          "dev_info": {...},
          "deployments": [...],
          "slas": [...],
          "changelog": {...}
        }
      ],
      "workflows": [...],
      "issue_types": [...]
    }
  ]
}
```

## Testing

Run all tests:

```shell
opa test policies/
```

Run tests with verbose output:

```shell
opa test policies/ -v
```

Run specific test file:

```shell
opa test policies/jira_project_has_lead_test.rego
```

## Building

Policies are built into a bundle for distribution:

```shell
make build
```

This creates a `bundle.tar.gz` file containing all policies.

## Writing New Policies

Policies are written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) language.

### Policy Structure

Each policy file should:
1. Define `title` and `description` fields
2. Implement a `violation` rule that returns violation details
3. Include helper functions for clarity
4. Have a corresponding test file

### Example Policy

```rego
package compliance_framework.example_policy

import future.keywords.if

title := "Example Policy"
description := "Description of what this policy checks"

violation[{"remarks": remarks}] if {
    project := input.projects[_]
    issue := project.issues[_]
    # Policy logic here
    remarks := sprintf("Issue %s violates policy", [issue.key])
}
```

### Testing

Create a test file with `_test.rego` suffix:

```rego
test_example_violation if {
    inp := {"projects": [...]}  # Test data
    violations := policy.violation with input as inp
    count(violations) == 1
}
```

## Special Considerations

- Empty issues arrays are treated as "no issues to check" (no violations)
- Missing `dev_info` or `deployments` for change requests triggers violations
- Self-approval is flagged when reporter appears in approvers list, regardless of decision
- SLA breaches are detected via `sla.ongoingCycle.breached` field
