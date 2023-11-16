# METADATA
# title: Guardrail 03 - Domain Restricted Sharing
# description: Check for Domain Restricted Sharing Organization Policy
package policies.guardrail_03_console

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Asset type must match below
required_asset_type := "orgpolicy.googleapis.com/Policy"

# Org Policy must be allowedPolicyMemberDomains
required_policy := "policies/iam.allowedPolicyMemberDomains"

# Metadata variables
guardrail := {"guardrail": "03"}

description := {"description": "GUARDRAIL 3: CLOUD CONSOLE ACCESS"}

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
# description: Checks if Org Policy is enforced
is_enforced(asset) if {
	asset.resource.data.spec.rules[0].values.allowedValues
}

# METADATA
# description: Checks if Org Policy is set at Organization level
is_org_policy(asset) if {
	split(asset.name, "/")[3] == "organizations"
}

# METADATA
# description: Checks if Org Policy is set at Project level
is_project_policy(asset) if {
	split(asset.name, "/")[3] == "projects"
}

# METADATA
# title: Check for Matching Assets
# description: Store assets who are correct asset_type and org_policy
matching_assets := {asset |
	some asset in input.data
	is_correct_asset(asset)
	is_correct_org_policy(asset)
}

# METADATA
# title: Enforced Org Policy - COMPLIANT
# description: |
# Iterate through org policy asset(s) (if any exist),
# check if set at Org level, and are enforced. If yes to 
# all then reply back COMPLIANT and with name of asset
reply contains response if {
	some asset in matching_assets
	is_org_policy(asset)
	is_enforced(asset)
	check := {"check_type": "RECOMMENDED"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("Organization Policy [%v] detected and enforced.", [required_policy])}
	asset_name := {"asset_name": asset.name}
	response := object.union_n([guardrail, status, msg, asset_name, description, check])
}

# METADATA
# title: Not Enforced Org Policy - WARN
# description: |
# Iterate through org policy asset(s) (if any exist),
# check if set at Org level, and are NOT enforced. If yes to 
# all then reply back WARN and with name of asset
reply contains response if {
	some asset in matching_assets
	is_org_policy(asset)
	not is_enforced(asset)
	check := {"check_type": "RECOMMENDED"}
	status := {"status": "WARN"}
	msg := {"msg": sprintf("Organization Policy [%v] detected and NOT enforced.", [required_policy])}
	asset_name := {"asset_name": asset.name}
	response := object.union_n([guardrail, status, msg, asset_name, description, check])
}

# METADATA
# title: Project-Level Org Policy - WARN
# Iterate through org policy asset(s) (if any exist),
# check if set at Project level. If yes to 
# all then reply back WARN and with name of asset
reply contains response if {
	some asset in matching_assets
	is_project_policy(asset)
	status := {"status": "WARN"}
	check := {"check_type": "RECOMMENDED"}
	msg := {"msg": sprintf("Organization Policy [%v] detected at Project level.", [required_policy])}
	asset_name := {"asset_name": asset.name}
	response := object.union_n([guardrail, status, msg, asset_name, description, check])
}

# METADATA
# title: Policy WARN
# description: If no org policy asset(s) are found, reply back WARN
reply contains response if {
	count(matching_assets) == 0
	status := {"status": "WARN"}
	check := {"check_type": "RECOMMENDED"}
	msg := {"msg": sprintf("Organization Policy [%v] not detected.", [required_policy])}
	response := object.union_n([guardrail, status, msg, description, check])
}
