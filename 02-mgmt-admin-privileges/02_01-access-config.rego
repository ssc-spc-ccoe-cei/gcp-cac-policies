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
description := {"description": "Access Configuration and Policies"}


# METADATA
# title: CLIENT INPUT
env := opa.runtime().env
# description: Organization domain
#required_domain := env["GR02_01_DOMAIN"]
required_org_admin_group_email := env["GR02_01_ORG_ADMIN_GROUP_EMAIL"]
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

list_to_set(list) := {set |
  set := list
}


# METADATA
# title: VALIDATION / DATA PROCESSING
# description: users who are org admins, part of the priv users list and not the regular users list
iam_org_admin_role_users_list := {user_members |
  some asset in input.data
  bindings := asset.iam_policy.bindings
  some binding in bindings
  binding.role == "roles/resourcemanager.organizationAdmin"
  members := binding.members
  user_members := [user | user := members[_]; startswith(user, "user:")]
}

#workspace_org_admin_group_users_list(asset) if {
workspace_org_admin_group_users_list := {asset.members |
  some asset in input.data
  is_correct_asset(asset)
  asset.groupEmail == required_org_admin_group_email
}

combined_org_admin_set := {combined_list |
  temp_list := array.concat(iam_org_admin_role_users_list[_], workspace_org_admin_group_users_list[_])
  combined_list := list_to_set(temp_list[_])
}


required_regular_users_set := {users_set |
  users_set := list_to_set(required_regular_users_list[_])
}

regular_user_w_org_admin_role := combined_org_admin_set & required_regular_users_set


#reply contains response if {
#	check := {"check_type": "MANDATORY"}
#	status := {"status": "DEBUG"}
	#msg := {"msg": sprintf("count: [%v], group_contains_non_dedicated_org_admin_users: [%v].", [count(group_contins_non_dedicated_org_admin_users), group_contains_non_dedicated_org_admin_users])}
	#msg := {"msg": sprintf("count: [%v], iam_org_admin_role_users_list: [%v].", [count(iam_org_admin_role_users_list[_]), iam_org_admin_role_users_list[_]])}
	#msg := {"msg": sprintf("count: [%v], workspace_org_admin_group_users_list: [%v].", [count(workspace_org_admin_group_users_list[_]), workspace_org_admin_group_users_list[_]])}
	#msg := {"msg": sprintf("count: [%v], combined_org_admin_set: [%v], required_regular_users_set: [%v]", [count(combined_org_admin_set), combined_org_admin_set, required_regular_users_set])}
#	msg := {"msg": sprintf("count: [%v], org_admin_group_w_regular_user: [%v]", [count(org_admin_group_w_regular_user), org_admin_group_w_regular_user])}
	#msg := {"msg": sprintf("count: [%v], org_admin_role_reg_users_list: [%v].", [count(org_admin_role_reg_users_list[_]), org_admin_role_reg_users_list[_]])}
#	response := object.union_n([guardrail, validation, status, msg, description, check])
#}

# METADATA
# title: Access Configuration & Policies - COMPLIANT
# description: If NO regular users have been assigned Org Admin rights, then COMPLIANT
reply contains response if {
  #count(group_contains_non_dedicated_org_admin_users) == 0
#  count(org_admin_role_priv_users_list[_]) > 0
  count(regular_user_w_org_admin_role) == 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("No regular users have been detected to be assigned Org Admin rights in [%v, validation %v].", [required_name, validation_number])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If non-privileged users have been assigned Org Admin rights, then NON-COMPLIANT
reply contains response if {
  #count(org_admin_role_reg_users_list[_]) > 0
  count(regular_user_w_org_admin_role) > 0
  #count(group_contains_non_dedicated_org_admin_users) == 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("[%v] regular user(s) has been found to have the organizationAdmin role in [%v, validation %v].", [count(regular_user_w_org_admin_role), required_name, validation_number])}
  asset_name := {"asset_name": regular_user_w_org_admin_role}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}
