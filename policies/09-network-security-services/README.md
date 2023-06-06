# Guardrail #09 - Network Security Services

Establish external and internal network perimeters and monitor network traffic.

**Key Considerations:**

- [ ] Ensure that egress/ingress points to and from GC cloud-based environments are managed and monitored. Use centrally provisioned network security services where available.
- [ ] Implement network boundary protection mechanisms for all external facing interfaces that enforce a deny-all or allow-by-exception policy.
- [ ] Perimeter security services such as boundary protection, intrusion prevention services, proxy services, TLS traffic inspection, etc. must be enabled based on risk profile, in alignment with GC Secure Connectivity Requirements and ITSG-22 and ITSG-38..
- [ ] Ensure that access to cloud storage services is protected and restricted to authorized users and services.

## Policies

- [09-check-firewall-rules.rego](./09-check-firewall-rules.rego)
- [09-cloud-sql-ext-ip-org-policy.rego](./09-cloud-sql-ext-ip-org-policy.rego)
- [09-default-network-org-policy.rego](./09-default-network-org-policy.rego)
- [09-gcs-public-bucket-org-policy.rego](./09-gcs-public-bucket-org-policy.rego)
- [09-vm-ext-ip-org-policy.rego](./09-vm-ext-ip-org-policy.rego)
- [09-access-policy.rego](./09-access-policy.rego)

## 09-check-firewall-rules.rego

Best practice dictates that when configuring firewall rules you should avoid the use of too wide/broad a range of ports. This can be considered `0.0.0.0/0`, which is essentially ALL. This policy will check for any ingress firewall rules that are set to allow and have a source range that matches `0.0.0.0/0`.

It's also worth discussing that if all other Guardrail #09 policies are compliant then there shouldn't be any public facing resources in Google Cloud. Therefore any rules that are configured with `0.0.0.0/0` would only be permitting private traffic between Google Cloud subnets.

Still, the best practice for Google Cloud firewalls dictates that you should use network tags or service accounts when configuring firewall rules. If that's not possible, then specific networks should be called out (e.g `10.0.0.0/24`) instead of using the `0.0.0.0/0` range.

More information about best practices for firewall rules can be found here: [link](https://cloud.google.com/vpc/docs/firewalls#best_practices_for_firewall_rules).

### Policy Flow Diagram

![09-check-firewall-rules](../policy_diagrams/09-check-firewall-rules.png "09-check-firewall-rules")

### Compliant

To ensure the policy is `COMPLIANT` you should have all ingress firewall rules that are set to allow traffic use source ranges other than `0.0.0.0/0`.

### Warn

If this policy is found to be `WARN` then please ensure all ingress firewall rules that are set to allow traffic use source ranges other than `0.0.0.0/0`.

Recommendations for other sources to use:

- Network tags
- Service account
- More narrow ranges (10.0.0.0/24, 192.168.0.10/28)

## 09-cloud-sql-ext-ip-org-policy.rego

Google Cloud provides an organization policy that allows you to restrict configuring a Public IP on Cloud SQL instances.

If the policy is enforced it'll ensure that all Cloud SQL instances are only accessible using their private IP addresses.

The organization policy is called `Restrict Public IP access on Cloud SQL instances` (ID: `constraints/sql.restrictPublicIp`).

### Policy Flow Diagram

![09-cloud-sql-ext-ip-org-policy](../policy_diagrams/09-cloud-sql-ext-ip-org-policy.png "09-cloud-sql-ext-ip-org-policy")

### Compliant

To mark this policy as `COMPLIANT`, the Organization Policy `Restrict Public IP access on Cloud SQL instances` (ID: `constraints/sql.restrictPublicIp`) should be set at the Organization level and have a rule configured with `Enforcement` set to `on`.

### Warn

If the policy is marked as `WARN` then the Organization Policy `Restrict Public IP access on Cloud SQL instances` (ID: `constraints/sql.restrictPublicIp`):

- Has not been configured at the Organization level
- Has been configured at the Organization level with a value other than `Enforcement` set to `on`
- Has been configured at the Project level with a value other than `Enforcement` set to `on`, while also being set at the Organization level with a rule configured with `Enforcement` set to `on`
- Has been set at a Project level with a rule configured with `Enforcement` set to `on`

The second last point would be considered an override whereby the project level organization policy is overriding the organization level policy for the project it's alerting on.

For additional context to the last point, although the policy is configured with the appropriate rule, organization policies should be set solely at the Organization level to ensure they're inherited throughout the entire Google Cloud organization.

>NOTE: A WARN can exist alongside a COMPLIANT to ensure that the project level policy is brought to attention and addressed as necessary.

## 09-default-network-org-policy.rego

Google Cloud provides an organization policy that skips the creation of the default network and related resources during Project creation. The default network VPC has a predefined network configuration that is good for getting started quickly, however, it doesn't follow some best practices that should be followed. Namely, the firewall rules that get automatically created are over-permissive, insecure, and are not included in audit logging.

Therefore, the organization policy should be configured and enforced to ensure that VPCs are configured as needed and are following best practices.

The organization policy is called `Skip default network creation` (ID: `constraints/compute.skipDefaultNetworkCreation`).

### Policy Flow Diagram

![09-default-network-org-policy](../policy_diagrams/09-default-network-org-policy.png "09-default-network-org-policy")

### Compliant

In order to mark this policy as `COMPLIANT`, the Organization Policy `Skip default network creation` (ID: `constraints/compute.skipDefaultNetworkCreation`) should be set at the Organization level and have a rule configured with `Enforcement` set to `on`.

### Non-Compliant

If the policy is marked as `NON-COMPLIANT` then the Organization Policy `Skip default network creation` (ID: `constraints/compute.skipDefaultNetworkCreation`):

- Has not been configured at the Organization level
- Has been configured at the Organization level with a value other than `Enforcement` set to `on`
- Has been configured at the Project level with a value other than `Enforcement` set to `on`, while also being set at the Organization level with a rule configured with `Enforcement` set to `on`

The last point would be considered an override whereby the project level organization policy is overriding the organization level policy for the project it's alerting on.

### Warn

If the policy is marked as `WARN` then the Organization Policy `Skip default network creation` (ID: `constraints/compute.skipDefaultNetworkCreation`):

- Has been set at a Project level with a rule configured with `Enforcement` set to `on`

Although the policy is configured with the appropriate rule, organization policies should be set solely at the Organization level to ensure they're inherited throughout the entire Google Cloud organization.

>NOTE: A WARN can exist alongside a COMPLIANT to ensure that the project level policy is brought to attention and addressed as necessary.

## 09-gcs-public-bucket-org-policy.rego

Google Cloud provides an organization policy that enforces public access prevention on any Cloud Storage data/buckets. It accomplishes this by disabling and blocking ACLs and IAM permissions that grant access to allUsers and allAuthenticatedUsers on any Cloud Storage resources. This ensures that no data is accidentally or intentionally made public inside Cloud Storage.

The organization policy is called `Enforce Public Access Prevention` (ID: `constraints/storage.publicAccessPrevention`).

### Policy Flow Diagram

![09-gcs-public-bucket-org-policy](../policy_diagrams/09-gcs-public-bucket-org-policy.png "09-gcs-public-bucket-org-policy")

### Compliant

In order to mark this policy as `COMPLIANT`, the Organization Policy `Enforce Public Access Prevention` (ID: `constraints/storage.publicAccessPrevention`) should be set at the Organization level and have a rule configured with `Enforcement` set to `on`.

### Warn

If the policy is marked as `WARN` then the Organization Policy `Enforce Public Access Prevention` (ID: `constraints/storage.publicAccessPrevention`):

- Has not been configured at the Organization level
- Has been configured at the Organization level with a value other than `Enforcement` set to `on`
- Has been configured at the Project level with a value other than `Enforcement` set to `on`, while also being set at the Organization level with a rule configured with `Enforcement` set to `on`
- Has been set at a Project level with a rule configured with `Enforcement` set to `on`

The second last point would be considered an override whereby the project level organization policy is overriding the organization level policy for the project it's alerting on.

For additional context to the last point, although the policy is configured with the appropriate rule, organization policies should be set solely at the Organization level to ensure they're inherited throughout the entire Google Cloud organization.

>NOTE: A WARN can exist alongside a COMPLIANT to ensure that the project level policy is brought to attention and addressed as necessary.

## 09-vm-ext-ip-org-policy.rego

Google Cloud provides an organization policy that allows you to define the set of Compute Engine VM instances that are allowed to use external IP addresses. You can specify individual VM instances using their name.

The policy can also be set to `Deny All`, whereby no Compute Engine VM instances will be allowed to use external IP addresses. This ensures that all VMs will be put behind a load balancer should they need to be accessed externally and that they use Cloud NAT should they require external access.

The organization policy is called `Define allowed external IPs for VM instances` (ID: `constraints/compute.vmExternalIpAccess`).

### Policy Flow Diagram

![09-vm-ext-ip-org-policy](../policy_diagrams/09-vm-ext-ip-org-policy.png "09-vm-ext-ip-org-policy")

### Compliant

In order to mark this policy as `COMPLIANT`, the Organization Policy `Define allowed external IPs for VM instances` (ID: `constraints/compute.vmExternalIpAccess`) should be set at the Organization level and have a rule configured with `Polic values` set to `Deny All`.

### Warn

If the policy is marked as `WARN` then the Organization Policy `Define allowed external IPs for VM instances` (ID: `constraints/compute.vmExternalIpAccess`):

- Has not been configured at the Organization level
- Has been configured at the Organization level with a value other than `Enforcement` set to `on`
- Has been configured at the Project level with a value other than `Enforcement` set to `on`, while also being set at the Organization level with a rule configured with `Enforcement` set to `on`
- Has been set at a Project level with a rule configured with `Enforcement` set to `on`

The second last point would be considered an override whereby the project level organization policy is overriding the organization level policy for the project it's alerting on.

For additional context to the last point, although the policy is configured with the appropriate rule, organization policies should be set solely at the Organization level to ensure they're inherited throughout the entire Google Cloud organization.

>NOTE: A WARN can exist alongside a COMPLIANT to ensure that the project level policy is brought to attention and addressed as necessary.

## 09-access-policy.rego

This policy checks for the existence of a `VPC Service Controls Perimeter` and an `Access Context Manager Access Level`.

More information about VPC Service Controls Perimeters can be found [here](https://cloud.google.com/vpc-service-controls/docs/service-perimeters).

More information about Access Context Manager Access Levels can be found [here](https://cloud.google.com/access-context-manager/docs/overview#access-levels).

It should be noted that due to the complex nature of VPC Service Controls and Access Context Manager, and the fact that no requirements currently exist, that this policy only checks for the existence of either a Service Perimeter or an Access Level. It does not verify any of the contents or the validity of the actual setup.

### Policy Flow Diagram

![09-access-policy](../policy_diagrams/09-access-policy.png "09-access-policy")

### Compliant

To ensure the policy is `COMPLIANT` you should have a `VPC Service Controls Perimeter` and an `Access Context Manager Access Level` configured at the Organization level.

As mentioned in the `Overview` section, the actual configuration of either resource will not be verified - only the actual existence of either.

Instructions on setting up a VPC Service Controls Perimeter can be found [here](https://cloud.google.com/vpc-service-controls/docs/create-service-perimeters).

Instructions on setting up an Access Context Manager Access Level can be found [here](https://cloud.google.com/access-context-manager/docs/create-basic-access-level).

### Warn

If this policy is found to be `WARN` please ensure you have a `VPC Service Controls Perimeter` and an `Access Context Manager Access Level` configured at the Organization level.
