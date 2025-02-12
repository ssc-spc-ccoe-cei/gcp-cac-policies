# METADATA
# title: Guardrail 01, Validation 01 & 02 - MFA Enforcement
# description: Check for presence of required user MFA enforcement
package policies.guardrail_01_0102_mfa

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Name of files data object to look for
required_name := "guardrail-01"
validation_number := "01 & 02"

# Metadata variables
guardrail := {"guardrail": "01"}
validation := {"validation": "0102"}
description := {"description": "MFA Enforcement"}


# METADATA
# title: HELPER FUNCTIONS
is_correct_asset(asset) if {
  asset.kind == "admin#directory#users"
}

list_to_set(list) := {set |
   set := list  # items are unique in a set
}


# METADATA
# title: CHECKS / DATA PROCESSING
mfa_not_enforced_users_list := {user_members |
  some asset in input.data
  asset.kind == "admin#directory#users"
  users := asset.users
  user_members := [user.primaryEmail | user := users[_]; not user.isEnforcedIn2Sv]
}

mfa_not_enforced_set := {combined_set |
  user_list := mfa_not_enforced_users_list
  every item in user_list {
    is_array(item) # ensure every item in user_list is also a list
  }
  flattened_list := [item | inner_array := user_list[_]; item := inner_array[_]]
  combined_set := list_to_set(flattened_list[_])
}


# METADATA
# title: MFA Enforcement Policy - COMPLIANT
# description: If MFA is enforced user all users, then COMPLIANT
reply contains response if {
  count(mfa_not_enforced_users_list) == 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("Required MFA Enforcement policy detected for users in [%v, validation %v].", [required_name, validation_number])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If MFA is enforced user all users, then NON-COMPLIANT
reply contains response if {
  count(mfa_not_enforced_users_list) > 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Required MFA Enforcement policy NOT detected for user(s) in [%v, validation %v]. Found [%v] users without MFA Enforced", [required_name, validation_number, count(mfa_not_enforced_set)])}
  asset_name := {"asset_name": mfa_not_enforced_set}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}
