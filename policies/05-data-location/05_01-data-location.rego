# METADATA
# title: Guardrail 05, Validation 01 - Check Asset Location
# description: Check assets are in approved location
package policies.guardrail_05_01_audit

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Metadata variables
guardrail := {"guardrail": "05"}
description := {"description": "validation 01 - Data Location"}

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

trimmed_regions := [
	"northamerica-northeast1",
	"northamerica-northeast2",
]

required_tagged_asset_kind := "cloudresourcemanager#tagged#asset"



# List of resources that will be exempt if they are located outside of the allowed regions.
# This list should contain non-region based resources (global only), or resources
# that can't exist in allowed_regions.
exempt_resources := [
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
]

# METADATA
# title: CLIENT INPUT
env := opa.runtime().env
# description: takes on the value of env var, GR05_01_SECURITY_CATEGORY_KEY
#              i.e. export GR05_01_SECURITY_CATEGORY_KEY = 'SECURITY_CATEGORY'
#              NOTE it is recommended you set the key to 'SECURITY_CATEGORY'
required_security_category_key := env["GR05_01_SECURITY_CATEGORY_KEY"]

# description: the following values for the required_security_category_key are exempt
#              here, this is the tag value for the tag key, SECURITY_CATEGORY
#              example: a GCS bucket tagged with SECURITY_CATEGORY: Protected A,
#                       is exempt from the policy (provided client also signs ICA)
exempt_security_categories := ["Unclassified", "Protected A"]



# METADATA
# title: HELPER FUNCTIONS
# description: Ensure asset has location field, otherwise not region-based
has_location_field(asset) if {
	asset[location]
}

# description: Check if asset is exempt
is_exempt_asset(asset) if {
	asset.asset_type in exempt_resources
}

is_tagged_asset(asset) if {
    asset.kind == required_tagged_asset_kind
}

is_exempt_security_categories(asset) if {
  is_tagged_asset(asset)
  endswith(asset.tag_key, required_security_category_key)
  some value in exempt_security_categories
  endswith(asset.tag_value, value)
}

# description: Check if asset is in allowed location
in_allowed_location(asset) if {
	asset.resource.location in allowed_regions
}
is_exempt_audit(asset) if {
	asset.resource.data.description == "Audit bucket"
	asset.resource.location == "global"
}
is_exempt_default(asset) if {
	asset.resource.data.description == "Default bucket"
	asset.resource.location == "global"
}


# METADATA
# title: VALIDATION / DATA PROCESSING
# description: Store assets that have a location field
assets_with_location := {asset |
	some asset in input.data
	has_location_field(asset)
}

# METADATA
# description: Store the names assets that are not part of the exempt_resources list
assets_not_exempt := {asset.name |
	some asset in assets_with_location
	not is_exempt_asset(asset)
	not is_exempt_default(asset)
	not is_exempt_audit(asset)
}

# descripiton: Store the names of assets with valid exemption tags
assets_with_exempt_security_categories := {asset.name |
  some asset in input.data
  is_exempt_security_categories(asset)
}


# METADATA
# title: Policy COMPLIANT
# description: | 
# Find the difference between the list of asset names that are NOT exempt
# and the list of names that are
# If the difference is an empty list, then COMPLIANT
reply contains response if {
  count(assets_not_exempt - assets_with_exempt_security_categories) == 0
	status := {"status": "COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": "Assets are in found to be in accordance to the data location policy"}
	response := object.union_n([guardrail, status, msg, description, check])
}

# description: | 
# Find the difference between the list of asset names that are NOT exempt
# and the list of names that are
# If the difference is NOT an empty list, then NON-COMPLIANT and report list
reply contains response if {
  count(assets_not_exempt - assets_with_exempt_security_categories) > 0
	status := {"status": "NON-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("The following assets have been found to violate the data location policy: [%v]", [assets_not_exempt - assets_with_exempt_security_categories])}
	response := object.union_n([guardrail, status, msg, description, check])
}
