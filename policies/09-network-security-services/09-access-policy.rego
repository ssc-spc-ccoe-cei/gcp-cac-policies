# METADATA
# title: Guardrail 09 - Conditional Access Policy
# description: Check for Conditional Access Policy & VPC Service Controls
package policies.guardrail_09_access

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Asset type must match below
required_asset_type := "cloudresourcemanager.googleapis.com/Organization"

# Metadata variables
guardrail := {"guardrail": "09"}

description := {"description": "GUARDRAIL 9: NETWORK SECURITY SERVICES"}

# METADATA
# description: Check if asset's type matches what's required
is_correct_asset(asset) if {
	asset.asset_type == required_asset_type
}

# METADATA
# description: |
# Check if asset has a service perimeter key present.
# This indicates that it's been configured
is_service_perimeter(asset) if {
	asset.service_perimeter
}

# METADATA
# description: |
# Check if asset has an access level key present.
# This indicates that it's been configured
is_access_level(asset) if {
	asset.access_level
}

# METADATA
# title: Check for matching assets
# description: Store assets matching required asset type
matching_assets := {asset |
	some asset in input.data
	is_correct_asset(asset)
}

# METADATA
# title: Check for service perimeter
# description: Store assets that are service perimeters
service_perimeters := {asset |
	some asset in matching_assets
	is_service_perimeter(asset)
}

# METADATA
# title: Check for access level
# description: Store assets that are access levels
access_levels := {asset |
	some asset in matching_assets
	is_access_level(asset)
}

# METADATA
# title: Policy COMPLIANT
# description: If service perimeter(s) exist, reply back COMPLIANT and with name
reply contains response if {
	some asset in service_perimeters
	asset_name := {"asset_name": asset.service_perimeter.name}
	status := {"status": "COMPLIANT"}
	check := {"check_type": "RECOMMENDED"}
	msg := {"msg": "Service Perimeter detected at Organization level."}
	response := object.union_n([guardrail, status, msg, description, asset_name, check])
}

# METADATA
# title: Policy COMPLIANT
# description: If access level(s) exist, reply back COMPLIANT and with name
reply contains response if {
	some asset in access_levels
	asset_name := {"asset_name": asset.access_level.name}
	status := {"status": "COMPLIANT"}
	check := {"check_type": "RECOMMENDED"}
	msg := {"msg": "Access Level detected at Organization level."}
	response := object.union_n([guardrail, status, msg, description, asset_name, check])
}

# METADATA
# title: Policy WARN
# description: If no service perimeters found, reply back WARN
reply contains response if {
	count(service_perimeters) == 0
	status := {"status": "WARN"}
	check := {"check_type": "RECOMMENDED"}
	msg := {"msg": "Service Perimeter NOT detected at Organization level."}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Policy WARN
# description: If no access levels found, reply back WARN
reply contains response if {
	count(access_levels) == 0
	status := {"status": "WARN"}
	check := {"check_type": "RECOMMENDED"}
	msg := {"msg": "Access Level NOT detected at Organization level."}
	response := object.union_n([guardrail, status, msg, description, check])
}
