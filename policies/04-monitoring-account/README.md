# Guardrail #04 - Enterprise Monitoring Accounts

Create role-based account to enable enterprise monitoring and visibility.

**Key Considerations:**

- [ ] Assign roles to approved GC stakeholders to enable enterprise visibility. Roles include billing reader, policy contributor/reader, security reader, and global reader.
- [ ] Ensure that multi-factor authentication mechanism for enterprise monitoring accounts is enabled.

## Policies

- [04-monitoring-account.rego](./04-monitoring-account.rego)

## 04-monitoring-account.rego

Ensure the appropriate IAM roles are assigned to a Google Cloud Group.

The roles that are being looked for are:

- roles/resourcemanager.organizationViewer

- roles/billing.admin

### Policy Flow Diagram

![04-monitoring-account](../policy_diagrams/04-monitoring-account.png "04-monitoring-account")

### Compliant

In order to mark this policy as `COMPLIANT`, the following must be true:

- In the IAM policy for the Organization there must exist two (2) bindings for the appropriate member being looked for
- One binding must exist for the IAM role `roles/resourcemanager.organizationViewer`
- One binding must exist for the IAM role `roles/billing.admin`

### Non-Compliant

If the policy is marked as `NON-COMPLIANT` then the message returned will indicate which IAM role is missing for the member.
