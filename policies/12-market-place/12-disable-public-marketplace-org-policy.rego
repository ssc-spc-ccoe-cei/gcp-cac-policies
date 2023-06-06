# METADATA
# title: Guardrail 12 - Check for Org Policy
# description: Check for Disable Public Marketplace  Organization Policy.
package policies.guardrail_12_public

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Asset type must be Policy
required_asset_type := "orgpolicy.googleapis.com/Policy"

# Org Policy must be commerceorggovernance.disablePublicMarketplace
required_policy := "policies/commerceorggovernance.disablePublicMarketplace"

# Metadata variables
guardrail := {"guardrail": "12"}

description := {"description": "Configuration of Cloud Marketplaces"}

# METADATA
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
# title: Policy Enforced
# description: Checks if Org Policy is enforced
is_enforced(asset) if {
	asset.resource.data.spec.rules[0].enforce == true
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
# title: Check for Matching Assets
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
	asset_name := {"asset_name": asset.name}
	response := object.union_n([guardrail, status, msg, asset_name, description, check])
}

# METADATA
# title: Not Enforced Org Level Org Policy - NON-COMPLIANT
# description: |
# Iterate through org level org policy assets that are NOT
# enforced(if any exist). If any exist then reply back 
# NON-COMPLIANT and with name of asset
reply contains response if {
	some asset in non_enforced_org_level_assets
	status := {"status": "NON-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("Organization Policy [%v] detected at the Organization level and NOT enforced.", [required_policy])}
	asset_name := {"asset_name": asset.name}
	response := object.union_n([guardrail, status, msg, asset_name, description, check])
}

# METADATA
# title: Enforced Project Level Org Policy - WARNING
# Iterate through project level org policy asset(s) that are enforced
# (if any exist). If yes to any then reply back WARNING and with name 
# of asset(s)
reply contains response if {
	some asset in enforced_proj_level_assets
	status := {"status": "WARN"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("Organization Policy [%v] detected at Project level and enforced.", [required_policy])}
	asset_name := {"asset_name": asset.name}
	response := object.union_n([guardrail, status, msg, asset_name, description, check])
}

# METADATA
# title: Not Enforced Project Level Org Policy & Enforced Org Level Policy - NON-COMPLIANT
# Iterate through project level policy asset(s) that are NOT enforced
# (if any exist) and also check if an org level org policy that IS enforced
# exists. If both exist then reply back NON-COMPLIANT and with name of asset(s)
reply contains response if {
	some asset in non_enforced_proj_level_assets
	count(enforced_org_level_assets) > 0
	status := {"status": "NON-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("Organization Policy [%v] override detected at the Project level.", [required_policy])}
	asset_name := {"asset_name": asset.name}
	response := object.union_n([guardrail, status, msg, asset_name, description, check])
}

# METADATA
# title: Not Enforced Project Level Org Policy & No Enforced Org Level Policy- WARNING
# Iterate through project level policy asset(s) that are enforced
# (if any exist) and also check if an org level org policy that is NOT enforced
# exists. If both exist then reply back NON-COMPLIANT and with name of asset(s)
reply contains response if {
	some asset in non_enforced_proj_level_assets
	count(enforced_org_level_assets) == 0
	status := {"status": "NON-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("Organization Policy [%v] detected at the Project level and NOT enforced.", [required_policy])}
	asset_name := {"asset_name": asset.name}
	response := object.union_n([guardrail, status, msg, asset_name, description, check])
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
	response := object.union_n([guardrail, status, msg, description, check])
}
