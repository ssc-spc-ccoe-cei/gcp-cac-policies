# METADATA
# title: Guardrail 01, Validation 06 - Dedicated Admin accounts
# description: Check whether monitoring & auditing is implemented for all user accounts
package policies.guardrail_01_06_accounts

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Metadata variables
guardrail := {"guardrail": "01"}
validation := {"validation": "06"}
description := {"description": "Dedicated Admin accounts"}

required_asset_type := "cloudresourcemanager.googleapis.com/Organization"


# METADATA
# title: CLIENT INPUT
env := opa.runtime().env
# description: takes on the value of env var, GR01_06_PRIVILEGED_USERS
#              list of UPNs of privileged users' accounts (UPN should be prefixed with "user:")
#              i.e. export GR01_06_PRIVILEGED_USERS='user:adminuser.one@ssc.gc.ca,user:anotheradmin.two@ssc.gc.ca'
required_privileged_users_list := split(env["GR01_06_PRIVILEGED_USERS"], ",")
# description: takes on the value of env var, GR01_06_REGULAR_USERS
#              list of UPNs of privileged users' regular accounts (UPN should be prefixed with "user:")
#              i.e. export GR01_06_REGULAR_USERS='user:someuser.one@ssc.gc.ca,user:anotheruser.two@ssc.gc.ca'
required_regular_users_list := split(env["GR01_06_REGULAR_USERS"], ",")


# METADATA
# title: HELPER FUNCTIONS
is_correct_asset_type(asset) if {
	asset.asset_type == required_asset_type
}

# description: Check if role is Org Admin and if corresponding members has users
has_user_members(asset) if {
  binding = asset.iam_policy.bindings[_]
  binding.role == "roles/resourcemanager.organizationAdmin"
  startswith(binding.members[_], "user:")
}

# description: Check if user is Org Admin AND is in the privileged users list
has_user_members_in_org_admins_list(asset) if {
  binding = asset.iam_policy.bindings[_]
  binding.role == "roles/resourcemanager.organizationAdmin"
  every user in required_privileged_users_list {
    some member in binding.members
    endswith(user, member)
  }
#  some member in binding.members
#  some user in required_privileged_users_list 
#  endswith(member, user)
}

# description: Check if user is Org Admin AND is in the regular users list
has_user_members_in_reg_users_list(asset) if {
  binding = asset.iam_policy.bindings[_]
  binding.role == "roles/resourcemanager.organizationAdmin"
  some member in binding.members
  some user in required_regular_users_list 
  endswith(member, user)
}


# METADATA
# title: VALIDATION / DATA PROCESSING
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
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Dedicated user accounts for administration - NON-COMPLIANT
# description: If priveged user accounts are NOT dedicated Organization Admins then reply back NON-COMPLIANT
reply contains response if {
	count(contains_dedicated_org_admin_users) == 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": "Dedicated Organization Admin users NOT detected."}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}
