# METADATA
# title: Guardrail 12 - Disallow Private Catalogue Admin
# description: Check IAM Policies for existence of Private Catalogue Admin binding
package policies.guardrail_12_catalogue

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Required asset_type
required_asset_type := "cloudresourcemanager.googleapis.com/Organization"

# Role to look for and alert on if assigned to any member
blocked_role := ["roles/cloudprivatecatalogproducer.admin"]

# Metadata variables
guardrail := {"guardrail": "12"}

description := {"description": "Configuration of Cloud Marketplaces"}

# METADATA
# description: Checks role bindings matches blocked_role
is_blocked_role(binding) if {
	binding.role == blocked_role[_]
}

# METADATA
# description: Checks if asset is required type
is_correct_asset(asset) if {
	asset.asset_type == required_asset_type
}

# METADATA
# title: Check for Matching Assets
# description: Store the IAM policy bindings if asset's type is correct
binding_assets := {asset.iam_policy.bindings |
	some asset in input.data
	is_correct_asset(asset)
}

# METADATA
# title: Check for Blocked Role
# description: Store the member(s) who have been assigned the blocked role
disallowed_binding_members := [binding.members |
	some asset in binding_assets
	some binding in asset
	is_blocked_role(binding)
]

# METADATA
# title: Policy COMPLIANT
# description: |
# If no members have been found with the assigned blocked role then
# reply back compliant
reply contains response if {
	count(disallowed_binding_members) == 0
	status := {"status": "COMPLIANT"}
	check := {"check_type": "RECOMMENDED"}
	msg := {"msg": sprintf("IAM Role Binding for blocked role [%v] NOT detected in Organization IAM Policy.", [blocked_role])}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Policy WARN
# description: |
# Iterate through members who have been found with the assigned blocked
# role (if any exist). Iterate through the list (if more than one exists) and
# reply back WARN. Include the IAM members who have the blocked role assigned
reply contains response if {
	some members in disallowed_binding_members
	some member in members
	status := {"status": "WARN"}
	check := {"check_type": "RECOMMENDED"}
	msg := {"msg": sprintf("IAM Role Binding for blocked role [%v] detected in Organization IAM Policy.", [blocked_role])}
	member_name := {"member_name": member}
	response := object.union_n([guardrail, status, msg, member_name, description, check])
}
