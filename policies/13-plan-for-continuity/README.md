# Guardrail #01: Protect Root / Global Admins Account

Protect root or master account used to establish the cloud service.

**Key Considerations:**

- [ ] Implement tconsmulti-factor authentication (MFA) mechanism for root/master account.
- [ ] Document a break glass emergency account management procedure. Including names of users with root or master account access.
- [ ] Obtain signature from Departmental Chief Information Officer (CIO) and Chief Security Officer (CSO) to confirm acknowledgment and approval of the break glass emergency account management procedures.
- [ ] Implement a mechanism for enforcing access authorizations.
- [ ] Configure appropriate alerts on root/master accounts to detect a potential compromise, in accordance with the GC Event Logging Guidance

## Policies

- [01-protect-accounts.rego](./01-protect-accounts.rego)
- [01-file-check.rego](./01-file-check.rego)

## 01-protect-accounts.rego

In the Admin console, you can share data from your Google Workspace, Cloud Identity, or Essentials account with services in your organization’s Google Cloud account. You can access the shared data through the Google Cloud audit logs.

The following log events data is shared with Google Cloud:

Groups Enterprise log events:

- Admin log events
- User log events

If you have Enterprise, Education Standard or Education Plus, Voice Premier, or Cloud Identity Premium edition, the following log events data is also shared with Google Cloud:

- OAuth log events
- SAML log events
- Access Transparency log events (Enterprise and Education editions only)

### Policy Flow Diagram

![01-protect-accounts](../policy_diagrams/01-protect-accounts.png "01-protect-accounts")

### Compliant

To ensure the policy is `COMPLIANT` you can enable sharing data by following the steps below:

1. In the Admin console, go to `Menu` > `Account` > `Account settings` > `Legal and compliance`
2. Click `Sharing options`
3. To share data, click `Enabled`
4. Click `Save`

### Warn

If this policy is found to be `WARN` please ensure the steps for enabling data sharing (found under `Compliant`) have been followed.

If the steps have been followed, then you may need to generate logs by interacting with the Google Workspace Admin Console (logging in at admin.google.com should be good enough). This is due to logs only being pulled for the last 7 days, so could just be a period of inactivity.

## 01-file-check.rego

Check for the presence of two (2) files in the `guardrail-01` Google Cloud Storage Bucket:

- Break Glass account Procedure
- MFA Policy Enforcement

### Policy Flow Diagram

![01-file-check](../policy_diagrams/01-file-check.png "01-file-check.rego")

### Compliant

To ensure the policy is `COMPLIANT` you should ensure that the two (2) files required are present in the `guardrail-01` Google Cloud Storage Bucket:

- Break Glass account Procedure
- MFA Policy Enforcement

> NOTE: Due to not being able to guarantee what name the file(s) will be, this policy will only check that the number of files present exceeds the minimum number required (including the default instructions.txt file).

### Non-Compliant

If this policy is found to be `NON-COMPLIANT` you should ensure that the two (2) files required are present in the `guardrail-01` Google Cloud Storage Bucket:

- Break Glass account Procedure
- MFA Policy Enforcement

You may also want to ensure that the default instructions.txt file is still present as well.

Finally, you may need to alter the `required_file_count` value inside `01-file-check.rego` to set what the minimum required number of files should be (including the default instructions.txt).
