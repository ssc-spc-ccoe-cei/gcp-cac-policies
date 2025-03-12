# METADATA
# title: Guardrail 05, Validation 01 - Resource Location Restriction
# description: Check for Resource Location Restriction Organization Policy.
package policies.guardrail_05_01_restrict

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

# Asset type must match below
required_asset_type := "orgpolicy.googleapis.com/Policy"

# Org Policy must be gcp.resourceLocations
required_policy := "policies/gcp.resourceLocations"

# Org Policy value must match in:canada-locations
required_value := "in:canada-locations"


# METADATA
# title: HELPER FUNCTIONS
# description: Checks if asset is required type
is_correct_asset(asset) if {
	asset.asset_type == required_asset_type
}

# METADATA
# description: Checks if org policy is correct
is_correct_org_policy(asset) if {
	endswith(asset.name, required_policy)
}

# METADATA
# description: Checks that only one value is set, and it matches required_value
is_enforced(asset) if {
	every value in asset.resource.data.spec.rules[0].values.allowedValues {
		value == required_value
	}
}

# METADATA
# title: Organizational Org Policy
# description: Checks if Org Policy is set at Organization level
is_org_level_policy(asset) if {
	split(asset.name, "/")[3] == "organizations"
}

# METADATA
# title: Project Org Policy
# description: Checks if Org Policy is set at Project level
is_proj_level_policy(asset) if {
	split(asset.name, "/")[3] == "projects"
}

# METADATA
# title: VALIDATION / DATA PROCESSING  
# description: Check if Asset's type is Org Policy matching required_policy
matching_assets := {asset |
	some asset in input.data
	is_correct_asset(asset)
	is_correct_org_policy(asset)
}

# METADATA
# title: Check for Org Level Assets
# description: Check if Org Policy is configured at Org level and is enforced
enforced_org_level_assets := {asset |
	some asset in matching_assets
	is_org_level_policy(asset)
	is_enforced(asset)
}

# METADATA
# title: Check for Org Level Assets
# description: Check if Org Policy is configured at Org level and is NOT enforced
non_enforced_org_level_assets := {asset |
	some asset in matching_assets
	is_org_level_policy(asset)
	not is_enforced(asset)
}

# METADATA
# title: Check for Project Level Assets
# description: Check if Org Policy is configured at Project level and is enforced
enforced_proj_level_assets := {asset |
	some asset in matching_assets
	is_proj_level_policy(asset)
	is_enforced(asset)
}

# METADATA
# title: Check for Project Level Assets
# description: Check if Org Policy is configured at Project level and is NOT enforced
non_enforced_proj_level_assets := {asset |
	some asset in matching_assets
	is_proj_level_policy(asset)
	not is_enforced(asset)
}


# METADATA
# title: Enforced Org Level Org Policy - COMPLIANT
# description: |
# Iterate through org level org policy assets that are enforced 
# (if any exist). Check that no project level org policies
# that are not enforced exist. If yes to all then reply back 
# COMPLIANT and with name of asset
reply contains response if {
	some asset in enforced_org_level_assets
	count(non_enforced_proj_level_assets) == 0
	status := {"status": "COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("Organization Policy [%v] detected at the Organization level and enforced.", [required_policy])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Not Enforced Org Level Org Policy - NON-COMPLIANT
# description: |
# Iterate through org level org policy assets that are NOT
# enforced(if any exist). If any exist then reply back 
# NON-COMPLIANT and with name of asset
reply contains response if {
	some asset in non_enforced_org_level_assets
	status := {"status": "WARN"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("Organization Policy [%v] detected at the Organization level and NOT enforced.", [required_policy])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Enforced Project Level Org Policy - WARNING
# Iterate through project level org policy asset(s) that are enforced
# (if any exist). If yes to any then reply back WARNING and with name 
# of asset(s)
reply contains response if {
	some asset in enforced_proj_level_assets
	status := {"status": "NOT-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("Organization Policy [%v] detected at Project level and enforced.", [required_policy])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Not Enforced Project Level Org Policy & Enforced Org Level Policy - NON-COMPLIANT
# Iterate through project level policy asset(s) that are NOT enforced
# (if any exist) and also check if an org level org policy that IS enforced
# exists. If both exist then reply back NON-COMPLIANT and with name of asset(s)
reply contains response if {
	some asset in non_enforced_proj_level_assets
	count(enforced_org_level_assets) > 0
	status := {"status": "NOT-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("Organization Policy [%v] override detected at the Project level.", [required_policy])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Not Enforced Project Level Org Policy & No Enforced Org Level Policy- WARNING
# Iterate through project level policy asset(s) that are enforced
# (if any exist) and also check if an org level org policy that is NOT enforced
# exists. If both exist then reply back NON-COMPLIANT and with name of asset(s)
reply contains response if {
	some asset in non_enforced_proj_level_assets
	count(enforced_org_level_assets) == 0
	status := {"status": "NOT-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("Organization Policy [%v] detected at the Project level and NOT enforced.", [required_policy])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Org Level Org Policy Not Found - NON-COMPLIANT
# description: If no org level org policy asset(s) are found, reply back NON-COMPLIANT
reply contains response if {
	count(enforced_org_level_assets) == 0
	count(non_enforced_org_level_assets) == 0
	status := {"status": "NON-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("Organization Policy [%v] NOT detected at the Organization Level.", [required_policy])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}
