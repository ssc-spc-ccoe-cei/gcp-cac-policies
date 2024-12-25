# METADATA
# title: Guardrail 01 , Validation 04 - Check for Monitioring & Audit Logs
# description: Check whether monitoring & auditing is implemented for all user accounts
package policies.guardrail_01_06_audit
#package example

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

required_asset_type := "cloudresourcemanager.googleapis.com/Organization"

# METADATA
# description: list of UPNs of privileged users' accounts (UPN should be prefixed with "user:")
required_privileged_users_list := ["user:ca_labadmins@acceleratorlabs.ca"]

# METADATA
# description: list of UPNs of privileged users' regular accounts (UPN should be prefixed with "user:")
required_regular_users_list := ["user:jenn.charland@acceleratorlabs.ca", "user:glen.z.yu@acceleratorlabs.ca"]
#required_regular_users_list := ["user:glen.z.yu@acceleratorlabs.ca", "user:ca_labadmins@acceleratorlabs.ca"] # this would fail

# Metadata variables
guardrail := {"guardrail": "01"}

description := {"description": "validation 06 - Dedicated Admin accounts"}

# METADATA
# description: Checks if asset's type matches what's required
is_correct_asset_type(asset) if {
	asset.asset_type == required_asset_type
}

# METADATA
# description: Check if role is Org Admin and if corresponding members has users
has_user_members(asset) if {
  binding = asset.iam_policy.bindings[_]
  binding.role == "roles/resourcemanager.organizationAdmin"
  startswith(binding.members[_], "user:")
}

# METADATA
# description: Check if user is Org Admin AND is in the privileged users list
has_user_members_in_org_admins_list(asset) if {
  binding = asset.iam_policy.bindings[_]
  binding.role == "roles/resourcemanager.organizationAdmin"
  some member in binding.members
  some user in required_privileged_users_list 
  endswith(member, user)
}

# METADATA
# description: Check if user is Org Admin AND is in the regular users list
has_user_members_in_reg_users_list(asset) if {
  binding = asset.iam_policy.bindings[_]
  binding.role == "roles/resourcemanager.organizationAdmin"
  some member in binding.members
  some user in required_regular_users_list 
  endswith(member, user)
}

# METADATA
# title: Check for existence of Workspace logs
# description: Check for audit log with correct log name
contains_dedicated_org_admin_users := {asset |
  some asset in input.data
  has_user_members(asset)
  has_user_members_in_org_admins_list(asset)    # privileged user is an Org Admin
  not has_user_members_in_reg_users_list(asset) # regular user is not an Org Admin
}

# METADATA
# title: Dedicated user accounts for administration - COMPLIANT
# description: If priveged user accounts are dedicated Organization Admins then reply back COMPLIANT
reply contains response if {
	count(contains_dedicated_org_admin_users) > 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": "Dedicated Organization Admin users detected."}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Dedicated user accounts for administration - NON-COMPLIANT
# description: If priveged user accounts are NOT dedicated Organization Admins then reply back NON-COMPLIANT
reply contains response if {
	count(contains_dedicated_org_admin_users) == 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": "Dedicated Organization Admin users NOT detected."}
	response := object.union_n([guardrail, status, msg, description, check])
}
