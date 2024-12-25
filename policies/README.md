# Compliance as Code Toolkit

This repository contains all the policy artifacts for the CaC Tool. Each policy has a seperate readme document explaining the control, check process and flow used to evaluate the target GCP organization.

<!-- TOC start -->
- [Compliance as Code Toolkit](#compliance-as-code-toolkit)
  - [Overall workflow for CaC Validation Checking](#overall-workflow-for-cac-validation-checking)
  - [Guardrail 1](01-protect-accounts/README.md#guardrail-1): Protect root or master account used to establish the cloud service.
  - [Guardrail 2](02-mgmt-admin-privileges/README.md#guardrail-2): Establish access control policies and procedures for management of administrative privileges.
  - [Guardrail 3](03-cloud-console-access/README.md#guardrail-3): Limit access to GC managed devices and authorized users.
  - [Guardrail 4](04-monitoring-account/README.md#guardrail-4): Create role-based account to enable enterprise monitoring and visibility.
  - [Guardrail 5](05-data-location/README.md#guardrail-5): Establish policies to restrict GC sensitive workloads to approved geographic locations
  - [Guardrail 6](06-protect-data-at-rest/README.md#guardrail-6): Protect data at rest by default (e.g. storage) for cloud-based workloads.
  - [Guardrail 7](07-protect-data-in-transit/README.md#guardrail-7): Protect data transiting networks through the use of appropriate encryption and network safeguards.
  - [Guardrail 8](08-segment-and-separate/README.md#guardrail-8): Segment and separate information based on sensitivity of information.
  - [Guardrail 9](09-network-security-services/README.md#guardrail-9): Establish external and internal network perimeters and monitor network traffic.
  - [Guardrail 10](10-cyber-defense-services/README.md#guardrail-10): Establish MOU for defensive services and threat monitoring protection services.
  - [Guardrail 11](11-logging-and-monitoring/README.md#guardrail-11): Enable logging for the cloud environment and for cloud-based workloads.
  - [Guardrail 12](12-market-place/README.md#guardrail-12): Restrict Third-Party CSP Marketplace software to GC-approved products.
  - [Guardrail 13](13-plan-for-continuity/README.md#guardrail-13): Restrict Third-Party CSP Marketplace software to GC-approved products.

<!-- TOC end -->
## Overall workflow for CaC Validation Checking

![Compliance Validation Workflow](assets/policy_diagrams/compliance-workflow.png "Compliance Validation Workflow")
