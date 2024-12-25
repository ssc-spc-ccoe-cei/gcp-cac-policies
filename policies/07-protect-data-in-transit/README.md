# Guardrail #07 - Protection of Data-in-Transit

Protect data transiting networks through the use of appropriate encryption and network safeguards.

**Key Considerations:**

- [ ] Implement an encryption mechanism to protect the confidentiality and integrity of data when data are in transit to and from your solution.
- [ ] Use CSE-approved cryptographic algorithms and protocols.
- [ ] Encryption of data in transit by default (e.g. TLS v1.2, etc.) for all publicly accessible sites and external communications as per the direction on Implementing HTTPS for Secure Web Connections (ITPIN 2018-01).
- [ ] Encryption for all access to cloud services (e.g. Cloud storage, Key Management systems, etc.).
- [ ] Consider encryption for internal zone communication in the cloud based on risk profile and as per the direction in CCCS network security zoning guidance in ITSG-22 and ITSG-38.
- [ ] Implement key management procedures.

## Policies

- [07-minimum-tls-version.rego](./07-minimum-tls-version.rego)

## 07-minimum-tls-version.rego

Google Cloud allows you to define SSL policies for SSL and TLS protocols. To define an SSL policy, you specify a minimum TLS version and a profile. The profile selects a set of SSL features to enable in the load balancer. When creating a load balancer you can set which SSL policy it will use.

Three pre-configured Google-managed profiles let you specify the level of compatibility appropriate for your application.

For optimal security, the policy will ensure any SSL policies that exist are using TLS/SSL Version 1.2 at a minimum.

It will also ensure that the same policies are set with any of the following profiles:

- `RESTRICTED` - Supports a reduced set of SSL features, intended to meet stricter compliance requirements.
- `MODERN` - Supports a wide set of SSL features, allowing modern clients to negotiate SSL.

The policy will also ensure that any load balancers that exist are using any of the approved SSL policies. Load balancers will also be divided between external and internal - as external ones have mandatory requirements to meet.

A default SSL policy that's managed by Google also exists. This policy does not meet the requirements that have been set, and there is no way for this default policy to be removed. Therefore, the policy will also check for any load balancers that are using this default SSL policy and will alert accordingly.

More information about SSL policies can be found here: [link](https://cloud.google.com/load-balancing/docs/ssl-policies-concepts).

### Policy Flow Diagram

![07-minimum-tls-version](../policy_diagrams/07-minimum-tls-version.png "07-minimum-tls-version")

### Compliant

To ensure the policy is `COMPLIANT` you should have all Global/Regional SSL policies configured with the following settings:

- `Minimum TLS version:` TLS 1.2
- `Profile:` Modern OR Restricted

All SSL policies with both of those settings set correctly will be considered valid and will be kept inside a variable.

Load balancer assets will be sorted through and split up depending on if they're internal or external. Both sets of load balancers will then have their attached target proxies looked up (this is where the SSL policy is set). These target proxies will then have their attached SSL policy looked up and will check for its presence inside the variable storing all valid SSL policies.

If the attached SSL policy is found then the policy will be marked as compliant.

### Non-Compliant

If this policy is found to be `NON-COMPLIANT` then please ensure the following have been completed:

- ALL SSL policies are configured with the appropriate settings (found above under Compliant section).
- The default SSL policy managed by Google (called "GCP default") is not in us by any External HTTPS load balancers. The default SSL policy is configured with settings that are deemed non-compliant.
- All External HTTPS load balancers are using a compliant SSL policy.

### Warn

If this policy is found to be `WARN` then please ensure the following have been completed:

- The default SSL policy managed by Google (called "GCP default") is not in us by any Internal HTTPS load balancers. The default SSL policy is configured with settings that are deemed non-compliant.
- All Internal HTTPS load balancers are using a compliant SSL policy.
