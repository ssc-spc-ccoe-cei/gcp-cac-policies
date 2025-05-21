# METADATA
# title: Guardrail 04 - Check Monitoring Account IAM Roles
# description: Check roles assigned to account are correct to to enable enterprise monitoring and visibility
package policies.guardrail_04_01_monitor

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Metadata variables
guardrail := {"guardrail": "04"}
validation := {"validation": "01"}
description := {"description": "Enterprise Monitoring Accounts"}

# IAM Roles required
roles_required := [
	"roles/resourcemanager.organizationViewer",
	"roles/billing.admin"
]

# Required asset_type
required_asset_type := "cloudresourcemanager.googleapis.com/Organization"

# IAM member to look for
required_iam_member := "group:gcxm163-cloud-brokering-service-b-billing-admin@ent.cloud-nuage.canada.ca"


# METADATA
# title: HELPER FUNCTIONS
# description: Check if asset's type matches what's required
is_correct_asset(asset) if {
	asset.asset_type == required_asset_type
}

# METADATA
# description: Check is member matchs IAM member to look for
is_correct_member(binding) if {
	found := binding.members[_] == required_iam_member
	print("Checking IAM Member in binding:", binding.members, "Result:", found)
}

# METADATA
# description: Check if role exists in roles stored in member_roles
role_found(role) if {
	role in member_roles
}


# METADATA
# title: VALIDATION / DATA PROCESSING
# description: Store policy binding(s) if asset is correct
binding_assets := {asset.iam_policy.bindings |
	some asset in input.data
	is_correct_asset(asset)
}

# description: Store role bindings for required_iam_member
member_roles := [binding.role |
	some asset in binding_assets
	some binding in asset
	is_correct_member(binding)
]

# description: |
# Iterate through roles in roles_required and check if they match
# the roles that are assigned to required_iam_member. Store
# any roles that aren't found, and consider these missing.
missing_roles := [role |
	some role in roles_required
	not role_found(role)
]


# METADATA
# title: Policy COMPLIANT
# description: |
# If no missing roles are found, then member has all the correct roles assigned to them.
# Reply back COMPLIANT and include the name of the IAM member searched for
reply contains response if {
	count(missing_roles) == 0
	status := {"status": "COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("IAM Member [%v] found with correct roles assigned.", [required_iam_member])}
  asset_name := {"asset_name": roles_required}
	response := object.union_n([guardrail, validation, status, asset_name, msg, description, check])
}

# METADATA
# title: Policy NON-COMPLIANT
# description: |
# If missing roles are found, then reply back with which one that's missing individually
reply contains response if {
	count(missing_roles) > 0
	status := {"status": "NON-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("IAM Member [%v] missing required role.", [required_iam_member])}
  asset_name := {"asset_name": missing_roles}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}
