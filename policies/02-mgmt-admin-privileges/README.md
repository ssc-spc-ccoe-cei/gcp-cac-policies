# Guardrail #02 - Management of Administrative Privileges

Establish access control policies and procedures for management of administrative privileges.

**Key Considerations:**

- [ ] Document a process for managing accounts, access privileges, and access credentials for organizational users, non-organizational users (if required), and processes based on the principles of separation of duties and least privilege (for example, operational procedures and active directory).
- [ ] Implement a mechanism for enforcing access authorizations.
- [ ] Implement a mechanism for uniquely identifying and authenticating organizational users, non-organizational users (if applicable), and processes (for example, username and password).
- [ ] Implement a multi-factor authentication mechanism for privileged accounts (for example, username, password and one-time password) and for external facing interfaces.
- [ ] Change default passwords.
- [ ] Ensure that no custom subscription owner roles are created.
- [ ] Configure password policy in accordance with GC Password Guidance.
- [ ] Minimize number of guest users; add only if needed.
- [ ] Determine access restrictions and configuration requirements for GC-issued endpoint devices, including those of non-privileged and privileged users, and configure access restrictions for endpoint devices accordingly. Note: Some service providers may offer configuration options to restrict endpoint device access. Alternatively, organizational policy and procedural instruments can be implemented to restrict access.

## Policies

- [02-access-policy.rego](./02-access-policy.rego)
- [02-file-check.rego](./02-file-check.rego)

## 02-access-policy.rego

This policy checks for the existence of a `VPC Service Controls Perimeter` and an `Access Context Manager Access Level`.

More information about VPC Service Controls Perimeters can be found [here](https://cloud.google.com/vpc-service-controls/docs/service-perimeters).

More information about Access Context Manager Access Levels can be found [here](https://cloud.google.com/access-context-manager/docs/overview#access-levels).

It should be noted that due to the complex nature of VPC Service Controls and Access Context Manager, and the fact that no requirements currently exist, this policy only checks for the existence of either a Service Perimeter or an Access Level. It does not verify any of the contents or the validity of the actual setup.

### Policy Flow Diagram

![02-access-policy](../policy_diagrams/02-access-policy.png "02-access-policy")

### Compliant

To ensure the policy is `COMPLIANT` you should have a `VPC Service Controls Perimeter` and an `Access Context Manager Access Level` configured at the Organization level.

As mentioned in the `Overview` section, the actual configuration of either resource will not be verified - only the actual existence of either.

Instructions on setting up a VPC Service Controls Perimeter can be found [here](https://cloud.google.com/vpc-service-controls/docs/create-service-perimeters).

Instructions on setting up an Access Context Manager Access Level can be found [here](https://cloud.google.com/access-context-manager/docs/create-basic-access-level).

### Warn

If this policy is found to be `WARN` please ensure you have a `VPC Service Controls Perimeter` and an `Access Context Manager Access Level` configured at the Organization level∑ß.

## 02-file-check.rego

Check for the presence of three (3) files in the `guardrail-02` Google Cloud Storage Bucket:

- Privileged Account Management Plan
- GC Password Guidance Doc.
- MFA Policy Enforcement

### Policy Flow Diagram

![02-file-check](../policy_diagrams/02-file-check.png "02-file-check")

### Compliant

To ensure the policy is `COMPLIANT` you should ensure that the three (3) files required are present in the `guardrail-02` Google Cloud Storage Bucket:

- Privileged Account Management Plan
- GC Password Guidance Doc.
- MFA Policy Enforcement

>NOTE: Due to not being able to guarantee what name the file(s) will be, this policy will only check that the number of files present exceeds the minimum number required (including the default instructions.txt file).

### Non-Compliant

If this policy is found to be `NON-COMPLIANT` you should ensure that the two (2) files required are present in the `guardrail-02` Google Cloud Storage Bucket:

- Privileged Account Management Plan
- GC Password Guidance Doc.
- MFA Policy Enforcement

You may also want to ensure that the default instructions.txt file is still present as well.

Finally, you may need to alter the `required_file_count` value inside `02-file-check.rego` to set what the minimum required number of files should be (including the default instructions.txt).
