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

# Metadata variables
guardrail := {"guardrail": "05"}
validation := {"validation": "01"}
description := {"description": "Data Location Restriction Policy"}

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
	"cloudkms.googleapis.com/CryptoKey",
	"cloudkms.googleapis.com/KeyRing",
	"cloudkms.googleapis.com/CryptoKeyVersion",
	"serviceusage.googleapis.com/Service",
	"secretmanager.googleapis.com/SecretVersion",
	"secretmanager.googleapis.com/Secret",
	"logging.googleapis.com/LogSink",
	"monitoring.googleapis.com/AlertPolicy",
	"pubsub.googleapis.com/Topic",
	"cloudbilling.googleapis.com/ProjectBillingInfo",
	"cloudbilling.googleapis.com/BillingAccount",
  "iam.googleapis.com/ServiceAccount",
  "binaryauthorization.googleapis.com/Attestor",
  "binaryauthorization.googleapis.com/Policy",
  "artifactregistry.googleapis.com/DockerImage",
  "bigquery.googleapis.com/Table",
  "cloudasset.googleapis.com/Feed",
  "dataplex.googleapis.com/EntryGroup",
  "essentialcontacts.googleapis.com/Contact",
  "logging.googleapis.com/Settings",
  "monitoring.googleapis.com/NotificationChannel",
  "securitycenter.googleapis.com/ContainerThreatDetectionSettings",
  "securitycenter.googleapis.com/MuteConfig",
  "securitycentermanagement.googleapis.com/SecurityCenterService",
  "storagetransfer.googleapis.com/TransferJob",
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
# title: processing project profile overrides
is_project_profile_tag(asset) if {
	asset.kind = "cloudresourcemanager#tagged#project"
	endswith(asset.tag_key, "PROJECT_PROFILE")
}

project_profile_details := {[asset.name, asset.tag_value] | 
	some asset in input.data
	is_project_profile_tag(asset)
}

asset_with_project_profile(asset) if {
  is_tagged_asset(asset)
  some tagged_project in project_profile_details
  asset.parent == tagged_project[0]
}

project_profile_tag_value := {project_profile_details[_][1] | 
  some asset in input.data
  asset_with_project_profile(asset)
}

# description: tag value is PROJECT_ID/TAG_KEY/tag_value
# here we're extracting just the project_id and tag_value
project_id_and_profile := split(project_profile_tag_value[_], "/PROJECT_PROFILE/")


# METADATA
# title: VALIDATION / DATA PROCESSING
# description: Store assets that have a location field
assets_with_resource_location := {asset |
  some asset in input.data
  has_resource_location_field(asset)
}

# METADATA
# description: Store the names assets that are not part of the exempt_resources list
assets_resource_location_not_exempt := {asset.name |
	some asset in assets_with_resource_location
  not in_allowed_resource_location(asset)
  not is_legacy_cloudbuild_build_step(asset)
  not is_exempt_cbs_project(asset)
  not is_exempt_cbs_asset(asset)
	not is_exempt_asset(asset)
	not is_exempt_default(asset)
	not is_exempt_audit(asset)
}

# descripiton: Store the names of assets with valid exemption tags
assets_resource_location_with_exempt_tags := {asset.name |
  some asset in input.data
  has_resource_location_field(asset)
  is_exempt_tagged_asset(asset)
}

# METADATA
# title: Policy COMPLIANT
# description: | 
# Find the difference between the list of asset names that are NOT exempt
# and the list of names that are
# If the difference is an empty list, then COMPLIANT
reply contains response if {
  count(project_profile_tag_value) == 0
  count(assets_resource_location_not_exempt - assets_resource_location_with_exempt_tags) == 0
	status := {"status": "COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": "Assets are in found to be in accordance to the data location policy and have appropriate tags where applicable."}
  asset_name := {"asset_name": assets_resource_location_with_exempt_tags}
	response := object.union_n([guardrail, validation, status, asset_name, msg, description, check])
}

reply contains response if {
  count(project_profile_tag_value) > 0
  count(assets_resource_location_not_exempt - assets_resource_location_with_exempt_tags) == 0
	status := {"status": "COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": "Assets are in found to be in accordance to the data location policy and have appropriate tags where applicable."}
  asset_name := {"asset_name": assets_resource_location_with_exempt_tags}
  proj_parent := {"proj_parent": project_id_and_profile[0]}
  proj_profile := {"proj_profile": project_id_and_profile[1]}
	response := object.union_n([guardrail, validation, status, asset_name, msg, description, check, proj_parent, proj_profile])
}

# description: | 
# Find the difference between the list of asset names that are NOT exempt
# and the list of names that are
# If the difference is NOT an empty list, then NON-COMPLIANT and report list
reply contains response if {
  count(project_profile_tag_value) == 0
  count(assets_resource_location_not_exempt - assets_resource_location_with_exempt_tags) > 0
  violating_assets := assets_resource_location_not_exempt - assets_resource_location_with_exempt_tags
  some violating_asset in violating_assets
	status := {"status": "NON-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
  msg := {"msg": "Asset has been found to violate the data location policy"}
  asset_name := {"asset_name": violating_asset}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}

reply contains response if {
  count(project_profile_tag_value) > 0
  count(assets_resource_location_not_exempt - assets_resource_location_with_exempt_tags) > 0
  violating_assets := assets_resource_location_not_exempt - assets_resource_location_with_exempt_tags
  some violating_asset in violating_assets
	status := {"status": "NON-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
  msg := {"msg": "Asset has been found to violate the data location policy"}
  asset_name := {"asset_name": violating_asset}
  proj_parent := {"proj_parent": project_id_and_profile[0]}
  proj_profile := {"proj_profile": project_id_and_profile[1]}
	response := object.union_n([guardrail, validation, status, asset_name, msg, description, check, proj_parent, proj_profile])
}
