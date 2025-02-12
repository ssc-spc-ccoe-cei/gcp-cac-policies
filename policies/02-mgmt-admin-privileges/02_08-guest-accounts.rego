# METADATA title: Guardrail 02, Validation 08 - Guest User Access
# description: Check for presence of authorized guest users
package policies.guardrail_02_08_access

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Name of files data object to look for
required_name := "guardrail-02"
validation_number := "08"

# Metadata variables
guardrail := {"guardrail": "02"}
validation := {"validation": "08"}
description := {"description": "Guest User Access"}


# METADATA
# description: CLIENT INPUT
env := opa.runtime().env
# description: takes on the value of env var, GR02_08_ALLOWED_DOMAINS
#              i.e. export GR02_08_ALLOWED_DOMAINS='ssc.gc.ca'
required_domains_allow_list := split(env["GR02_08_ALLOWED_DOMAINS"], ",")
# description: takes on the value of env var, GR02_08_DENY_DOMAINS
#              i.e. export GR02_08_DENY_DOMAINS='gmail.com,outlook.com'
required_domains_deny_list := split(env["GR02_08_DENY_DOMAINS"], ",")

# METADATA
# description: HELPER FUNCTIONS
list_to_set(list) := {set |
   set := list  # items are unique in a set
}

is_member_of_allowed_domain(user) if {
  some domain in required_domains_allow_list
  endswith(user, domain)
}

is_member_of_denied_domain(user) if {
  some domain in required_domains_deny_list
  endswith(user, domain)
}


# METADATA
# description: VALIDATION / DATA PROCESSING
unauthorized_guests_list := {user_members |
  some asset in input.data
  bindings := asset.iam_policy.bindings
  some binding in bindings
  startswith(binding.role, "roles/")
  members := binding.members
  user_members := [user | user := members[_]; startswith(user, "user:"); not is_member_of_allowed_domain(user); not is_member_of_denied_domain(user)]
}

denied_guests_list := {user_members |
  some asset in input.data
  bindings := asset.iam_policy.bindings
  some binding in bindings
  startswith(binding.role, "roles/")
  members := binding.members
  user_members := [user | user := members[_]; startswith(user, "user:"); is_member_of_denied_domain(user)]
}

unauthorized_guests_set := {combined_set |
  user_list := unauthorized_guests_list
  every item in user_list {
    is_array(item) # ensure every item in user_list is also a list
  }
  flattened_list := [item | inner_array := user_list[_]; item := inner_array[_]]
  combined_set := list_to_set(flattened_list[_])
}

denied_guests_set := {combined_set |
  user_list := denied_guests_list 
  every item in user_list {
    is_array(item) # ensure every item in user_list is also a list
  }
  flattened_list := [item | inner_array := user_list[_]; item := inner_array[_]]
  combined_set := list_to_set(flattened_list[_])
}


# METADATA
# title: Guest Access Policy - COMPLIANT
# description: If guests are from approved/allowed domains, then COMPLIANT
reply contains response if {
  count(unauthorized_guests_set) + count(denied_guests_set) == 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("No unauthorized guest users have been detected for [%v, validation %v].", [required_name, validation_number])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If guests are NOT from approved/allowed domains OR en NON-COMPLIANT
reply contains response if {
  count(unauthorized_guests_set) + count(denied_guests_set) > 0
  combined_set := unauthorized_guests_set | denied_guests_set
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Unauthorized guest users were detected for [%v, validation %v]. [%v] unauthorized guests were found.  And [%v] guests were found to be from banned domains.", [required_name, validation_number, count(unauthorized_guests_set), count(denied_guests_set)])}
  asset_name := {"asset_name": combined_set}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}
