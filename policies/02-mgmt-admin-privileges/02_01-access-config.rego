# METADATA title: Guardrail 02, Validation 01 - Access Configuration & Policies
# description: Check that access configurations & policies have been implemented
package policies.guardrail_02_01_access

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Name of files data object to look for
required_name := "guardrail-02"
validation_number := "01"

# Metadata variables
guardrail := {"guardrail": "02"}
validation := {"validation": "01"}
description := {"description": "Access Configuration & Policies"}


# METADATA
# title: CLIENT INPUT
env := opa.runtime().env
# description: Organization domain
required_domain := env["GR02_01_DOMAIN"]
# description: takes on the value of env var, GR02_01_PRIVILEGED_USERS
#              list of UPNs of privileged users' accounts (UPN should be prefixed with "user:")
#              i.e. export GR02_01_PRIVILEGED_USERS='user:someadminuser.one@ssc.gc.ca,user:anotheradminuser.two@ssc.gc.ca'
required_privileged_users_list := split(env["GR02_01_PRIVILEGED_USERS"], ",")
# description: takes on the value of env var, GR02_01_REGULAR_USERS
#              list of UPNs of privileged users' regular accounts (UPN should be prefixed with "user:")
#              i.e. export GR02_01_REGULAR_USERS='user:someuser.one@ssc.gc.ca,user:anotheruser.two@ssc.gc.ca'
required_regular_users_list := split(env["GR02_01_REGULAR_USERS"], ",")



# METADATA
# title: HELPER FUNCTIONS
# description: Check if asset's name matches what's required
is_correct_asset(asset) if {
  asset.kind == "cloudidentity#groups#membership"
}

is_member_of_privileged_users_list(user) if {
  some member in required_privileged_users_list
  contains(user, member)
}

is_member_of_regular_users_list(user) if {
  some member in required_regular_users_list
  contains(user, member)
}

# description: for cloud identity group memberships
has_user_members_in_priv_users_list(asset) if {
  is_correct_asset(asset)
  asset.groupEmail == concat("@", ["gcp-organization-admins", required_domain])
  every member in asset.members {
    some user in required_privileged_users_list
    contains(member, user)
  }
}

has_user_members_in_reg_users_list(asset) if {
  is_correct_asset(asset)
  asset.groupEmail == concat("@", ["gcp-organization-admins", required_domain])
  some member in asset.members
  some user in required_regular_users_list
  contains(member, user)
}


# METADATA
# title: VALIDATION / DATA PROCESSING
org_admin_role_priv_users_list := {user_members |
  some asset in input.data
  bindings := asset.iam_policy.bindings
  some binding in bindings
  binding.role == "roles/resourcemanager.organizationAdmin"
  members := binding.members
  user_members := [user | user := members[_]; startswith(user, "user:"); is_member_of_privileged_users_list(user); not is_member_of_regular_users_list(user)]
}

# description: a non-privileged user is one that is NOT privileged and also NOT the regular user counterpart of a privileged user.  e.g. any user that's not supposed to be privileged (and this includes regular users)
org_admin_role_non_priv_users_list := {user_members |
  some asset in input.data
  bindings := asset.iam_policy.bindings
  some binding in bindings
  binding.role == "roles/resourcemanager.organizationAdmin"
  members := binding.members
  user_members := [user | user := members[_]; startswith(user, "user:"); not is_member_of_privileged_users_list(user)]
}

# description: group contains non privileged users
group_contains_non_dedicated_org_admin_users := {asset.members[_] |
  some asset in input.data
  is_correct_asset(asset)
  not has_user_members_in_priv_users_list(asset)
}


# METADATA
# title: Access Configuration & Policies - COMPLIANT
# description: If NO regular users have been assigned Org Admin rights, then COMPLIANT
reply contains response if {
  count(group_contains_non_dedicated_org_admin_users) == 0
  count(org_admin_role_priv_users_list[_]) > 0
  count(org_admin_role_non_priv_users_list[_]) == 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("No regular users have been detected to be assigned Org Admin rights in [%v, validation %v].", [required_name, validation_number])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If non-privileged users have been assigned Org Admin rights, then NON-COMPLIANT
reply contains response if {
  count(org_admin_role_non_priv_users_list[_]) > 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Non-privileged user(s) has been found to have the organizationAdmin role in [%v, validation %v]. Regular users found: [%v]", [required_name, validation_number, org_admin_role_non_priv_users_list])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If regular users have been assigned Org Admin rights, then NON-COMPLIANT
reply contains response if {
  count(group_contains_non_dedicated_org_admin_users) > 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Regular user(s) has been found to have the GCP Org Admins group in [%v, validation %v].", [required_name, validation_number])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}
