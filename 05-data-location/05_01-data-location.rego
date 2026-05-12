# METADATA
# title: Guardrail 05, Validation 01 - Check Asset Location
# description: Check assets are in approved location
package policies.guardrail_05_01_location

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Import common functions
import data.policies.common

# Metadata variables
guardrail := {"guardrail": "05"}
validation := {"validation": "01"}
description := {"description": "Data Location Restriction Policy"}

# Set check type based on profile and guardrail number
check := common.set_check_type(guardrail.guardrail)

# List of allowed regions that assets must reside in
allowed_regions := [
	"northamerica-northeast1",
	"northamerica-northeast2",
	"northamerica-northeast1-a",
	"northamerica-northeast1-b",
	"northamerica-northeast1-c",
	"northamerica-northeast2-a",
	"northamerica-northeast2-b",
	"northamerica-northeast2-c",		
]

required_tagged_asset_kind := "cloudresourcemanager#tagged#asset"


# List of resources that will be exempt if they are located outside of the allowed regions.
# This list should contain non-region based resources (global only), or resources
# that can't exist in allowed_regions.
# in v2, Organization, Folder, Project, and Organization Policies was added to the list
exempt_resources := [
  "cloudresourcemanager.googleapis.com/Organization",
  "cloudresourcemanager.googleapis.com/Folder",
  "cloudresourcemanager.googleapis.com/Project",
  "cloudresourcemanager.googleapis.com/TagBinding",
  "cloudresourcemanager.googleapis.com/TagKey",
  "cloudresourcemanager.googleapis.com/TagValue",

  "orgpolicy.googleapis.com/Policy",

  "compute.googleapis.com/Firewall",
  "compute.googleapis.com/FirewallPolicy",
  "compute.googleapis.com/Route",
  "compute.googleapis.com/Network",
  "compute.googleapis.com/Subnetwork",
  "compute.googleapis.com/Project",
  "compute.googleapis.com/GlobalAddress",
  "compute.googleapis.com/GlobalForwardingRule",
  "compute.googleapis.com/HttpHealthCheck",

  "cloudkms.googleapis.com/CryptoKey",
  "cloudkms.googleapis.com/KeyRing",
  "cloudkms.googleapis.com/CryptoKeyVersion",

  "serviceusage.googleapis.com/Service",

  "servicenetworking.googleapis.com/networks/VPCnetworks",

  "secretmanager.googleapis.com/SecretVersion",
  "secretmanager.googleapis.com/Secret",

  "logging.googleapis.com/LogSink",

  "monitoring.googleapis.com/AlertPolicy",
  "monitoring.googleapis.com/NotificationChannel",
  "monitoring.googleapis.com/Dashboard",

  "pubsub.googleapis.com/Topic",
  "pubsub.googleapis.com/Subscription",

  "cloudbilling.googleapis.com/ProjectBillingInfo",
  "cloudbilling.googleapis.com/BillingAccount",

  "iam.googleapis.com/ServiceAccount",
  "iam.googleapis.com/workloadIdentityPool",

  "binaryauthorization.googleapis.com/Attestor",
  "binaryauthorization.googleapis.com/Policy",

  "artifactregistry.googleapis.com/DockerImage",

  "bigquery.googleapis.com/Table",

  "cloudasset.googleapis.com/Feed",

  "dataplex.googleapis.com/EntryGroup",

  "essentialcontacts.googleapis.com/Contact",

  "logging.googleapis.com/Settings",
  "logging.googleapis.com/RecentQuery",

  "securitycenter.googleapis.com/ContainerThreatDetectionSettings",
  "securitycenter.googleapis.com/MuteConfig",
  "securitycenter.googleapis.com/EventThreatDetectionSettings",
  "securitycenter.googleapis.com/WebSecurityScannerSettings",
  "securitycenter.googleapis.com/SecurityHealthAnalyticsSettings",

  "securitycentermanagement.googleapis.com/SecurityCenterService",
  "securitycentermanagement.googleapis.com/EventThreatDetectionCustomModule",

  "storagetransfer.googleapis.com/TransferJob",
  
  "dns.googleapis.com/ResourceRecordSet",
  "dns.googleapis.com/ResponsePolicyRule",
  "dns.googleapis.com/ResponsePolicy",

  "networkconnectivity.googleapis.com/PolicyBasedRoute",

  "networkmanagement.googleapis.com/connectivityTest"
]

# METADATA
# description: related to GR10.2, these are the jobs Cyber Defense deployed resorses to be exempt from GR5.1 
# for project info, need to include project ID and project number as different services reference projects differently
exempt_cbs_project_info := [
  "projects/cbs-logging-for-gcp-5dc566bf4a/",
  "projects/228662832372/",
]

exempt_cbs_resources := [
  "functions/cbs-",
  "services/cbs-",
  "storage.googleapis.com/cbs-",
  "subscriptions/eventarc-",
  "subscriptions/cbs-",
  "topics/cbs-",
]

# METADATA
# title: CLIENT INPUT
env := opa.runtime().env
# description: takes on the value of env var, GR05_01_SECURITY_CATEGORY_KEY
#              i.e. export GR05_01_SECURITY_CATEGORY_KEY = 'DATA_CLASSIFICATION'
#              NOTE it is recommended you set the key to 'DATA_CLASSIFICATION'
required_security_category_key := env["GR05_01_SECURITY_CATEGORY_KEY"]

# description: the following values for the required_security_category_key are exempt
#              here, this is the tag value for the tag key, DATA_CLASSIFICATION
#              example: a GCS bucket tagged with DATA_CLASSIFICATION: Protected A,
#                       is exempt from the policy (provided client also signs ICA)
exempt_security_categories := ["Unclassified", "Protected A"]



# METADATA
# title: HELPER FUNCTIONS
# description: Ensure asset has location field, otherwise not region-based
has_resource_location_field(asset) if {
	asset.resource.location
  not asset.kind
}

# description: Check if asset has ancestors field (used for project matching)
has_ancestors_field(asset) if {
  asset.ancestors
  not asset.kind
}

# description: should not report on the individual Cloud Build step
is_legacy_cloudbuild_build_step(asset) if {
  not asset.kind
  asset.asset_type == "cloudbuild.googleapis.com/Build"
  asset.resource.data.options.logging == "LEGACY"
}

# description: Check if asset is exempt
is_exempt_asset(asset) if {
	asset.asset_type in exempt_resources
}

is_exempt_cbs_project(asset) if {
  not asset.kind
  some cbs_project in exempt_cbs_project_info
  contains(asset.name, cbs_project)
}

is_exempt_cbs_asset(asset) if {
  not asset.kind
  some cbs_resource in exempt_cbs_resources
	contains(asset.name, cbs_resource)
}

is_tagged_asset(asset) if {
    asset.kind == required_tagged_asset_kind
}

is_exempt_tagged_asset(asset) if {
  is_tagged_asset(asset)
  endswith(asset.tag_key, required_security_category_key)
  some value in exempt_security_categories
  endswith(asset.tag_value, value)
}

# description: Check if asset is in allowed location
in_allowed_resource_location(asset) if {
  has_resource_location_field(asset)
	asset.resource.location in allowed_regions
}

is_exempt_audit(asset) if {
  has_resource_location_field(asset)
	asset.resource.data.description == "Audit bucket"
	asset.resource.location == "global"
}

is_exempt_default(asset) if {
  has_resource_location_field(asset)
	asset.resource.data.description == "Default bucket"
	asset.resource.location == "global"
}

# METADATA
# title: Consolidated Exemption Check
# description: Single entry point for all exemption checks. Asset is exempt if any condition matches.
is_exempt(asset) if {
  is_exempt_asset(asset)
}

is_exempt(asset) if {
  is_legacy_cloudbuild_build_step(asset)
}

is_exempt(asset) if {
  is_exempt_cbs_project(asset)
}

is_exempt(asset) if {
  is_exempt_cbs_asset(asset)
}

is_exempt(asset) if {
  is_exempt_default(asset)
}

is_exempt(asset) if {
  is_exempt_audit(asset)
}

is_exempt(asset) if {
  asset.name in assets_with_exempt_tags
}

# description: processing project profile overrides
is_project_profile_tag(asset) if {
  asset.kind == "cloudresourcemanager#tagged#project"
  endswith(asset.tag_key, "PROJECT_PROFILE")
}

# description: Extract project_number and tag_value from tagged projects
# Result: [project_number, tag_value]
project_profile_details := {[asset.project_number, asset.tag_value] |
  some asset in input.data
  is_project_profile_tag(asset)
}

# description: Extract project_number and profile_level
# Result: [project_number, profile_level]
project_id_and_profile_list := {[project_number, profile_level] |
  some entry in project_profile_details
  project_number := entry[0]
  parts := split(entry[1], "/")
  profile_level := array.reverse(parts)[0]
}

# description: Check if asset belongs to a tagged project
is_in_tagged_project(asset) if {
  has_ancestors_field(asset)
  some proj_id_profile in project_id_and_profile_list
  proj_id_profile[0] in asset.ancestors
}

# description: Names of assets with valid exemption tags (from tagged asset records)
assets_with_exempt_tags := {asset.name |
  some asset in input.data
  is_exempt_tagged_asset(asset)
}

# description: Set of violating assets (not in allowed location and not exempt)
violating_assets := {asset |
  some asset in input.data
  has_resource_location_field(asset)
  not in_allowed_resource_location(asset)
  not is_exempt(asset)
}

# description: Violating assets that belong to tagged projects
# Result: [asset, project_number, profile_level]
violating_assets_with_tagged_project := {[asset, proj_id_profile[0], proj_id_profile[1]] |
  some asset in violating_assets
  has_ancestors_field(asset)
  some proj_id_profile in project_id_and_profile_list
  proj_id_profile[0] in asset.ancestors
}

# description: Violating assets NOT in tagged projects (use global profile)
violating_assets_without_tagged_project := {asset |
  some asset in violating_assets
  not is_in_tagged_project(asset)
}

# METADATA
# title: Policy COMPLIANT
# description: If no violating assets, then COMPLIANT
reply contains response if {
  count(violating_assets) == 0
  status := {"status": "COMPLIANT"}
  msg := {"msg": "Assets are in found to be in accordance to the data location policy and have appropriate tags where applicable."}
  asset_name := {"asset_name": assets_with_exempt_tags}
  response := object.union_n([guardrail, validation, status, asset_name, msg, description, check])
}

# METADATA
# title: NON-COMPLIANT - violating assets in non-tagged projects (use global profile)
reply contains response if {
  count(violating_assets_without_tagged_project) > 0
  some asset in violating_assets_without_tagged_project
  status := common.set_status(guardrail.guardrail)
  msg := {"msg": "Asset has been found to violate the data location policy"}
  asset_name := {"asset_name": asset.name}
  response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}

# METADATA
# title: NON-COMPLIANT - violating assets in tagged projects (use override profile)
reply contains response if {
  count(violating_assets_with_tagged_project) > 0
  some violating_asset in violating_assets_with_tagged_project
  override_profile := violating_asset[2]   # violating_asset structure: [asset, project_number, profile_level]
  status := common.set_status_for_profile(guardrail.guardrail, override_profile)
  check_override := common.set_check_type_for_profile(guardrail.guardrail, override_profile)
  msg := {"msg": "Asset has been found to violate the data location policy"}
  asset_name := {"asset_name": violating_asset[0].name}
  proj_parent := {"proj_parent": violating_asset[1]}
  proj_profile := {"proj_profile": override_profile}
  response := object.union_n([guardrail, validation, status, msg, asset_name, description, check_override, proj_parent, proj_profile])
}
