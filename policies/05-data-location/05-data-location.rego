# METADATA
# title: Guardrail 05 - Check Asset Location
# description: Check assets are in approved location
package policies.guardrail_05_location

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

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
# Metadata variables
guardrail := {"guardrail": "05"}

description := {"description": "Data Location"}

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
# description: Ensure asset has location field, otherwise not region-based
has_location_field(asset) if {
	asset[location]
}

# METADATA
# description: Check if asset is exempt
is_exempt_asset(asset) if {
	asset.asset_type in exempt_resources
}

# METADATA
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
# title: Check for assets with location field
# description: Store assets that have a location field
assets_with_location := {asset |
	some asset in input.data
	has_location_field(asset)
}

# METADATA
# title: Check for assets that aren't exempt
# description: Store assets that are not part of the exempt_resources list
assets_not_exempt := {asset |
	some asset in assets_with_location
	not is_exempt_asset(asset)
	not is_exempt_default(asset)
	not is_exempt_audit(asset)
}

# METADATA
# title: Policy COMPLIANT
# description: | 
# Iterate through assets that aren't exempt (if any exist) and check if they're 
# located in an allowed location. If they are then reply back
# COMPLIANT. Include the name of the asset, its current location
# and which locations are allowed.
reply contains response if {
	some asset in assets_not_exempt
	in_allowed_location(asset)
	status := {"status": "COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("Asset [%v] is located in [%v] which is an allowed region [%v]", [asset.asset_type, asset.resource.location, trimmed_regions])}
	asset_name := {"asset_name": asset.name}
	response := object.union_n([guardrail, status, msg, asset_name, description, check])
}

# METADATA
# title: Policy NON-COMPLIANT
# description: | 
# Iterate through assets that aren't exempt (if any exist) and check if they're 
# not located in an allowed location. If they aren't then reply back
# NON-COMPLIANT. Include the name of the asset, its current location
# and which locations it should be in.
reply contains response if {
	some asset in assets_not_exempt
	not in_allowed_location(asset)
	status := {"status": "NON-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("Asset [%v] is located in [%v] when it is required to be in [%v] or one of the associated zones", [asset.asset_type, asset.resource.location, trimmed_regions])}
	asset_name := {"asset_name": asset.name}
	response := object.union_n([guardrail, status, msg, asset_name, description, check])
}
