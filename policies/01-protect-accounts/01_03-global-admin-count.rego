# METADATA title: Guardrail 01, Validation 03 - Global Admin count
# description: Check for global admin count
package policies.guardrail_01_03_accounts

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Name of files data object to look for
required_name := "guardrail-01"
validation_number := "03"

# Metadata variables
guardrail := {"guardrail": "01"}
validation := {"validation": "03"}
description := {"description": "Global Admins count"}

# METADATA
# title: CLIENT INPUT
# description: takes on the value of env var, GR01_03_DOMAIN
#              i.e. export GR01_03_DOMAIN='ssc.gc.ca'
env := opa.runtime().env
required_domain := env["GR01_03_DOMAIN"]


# METADATA
# title: HELPER FUNCTIONS
list_to_set(list) := {set | 
   set := list  # items are unique in a set  
}

is_correct_asset(asset) if {
  asset.kind == "cloudidentity#groups#membership"
}


# METADATA
# title: VALIDATION / DATA PROCESSING
gcp_org_admin_members_list := {gcp_user_members |
  some asset in input.data
  is_correct_asset(asset)
  asset.groupEmail == concat("@", ["gcp-organization-admins", required_domain])
  gcp_user_members := asset.members
}

iam_org_admin_members_list := {user_members |
  some asset in input.data
  bindings := asset.iam_policy.bindings
  some binding in bindings
  binding.role == "roles/resourcemanager.organizationAdmin"
  members := binding.members 
  user_members := [user | user := members[_]; startswith(user, "user:")]
}

combined_members_set := {combined_set |
  temp_list := array.concat(gcp_org_admin_members_list[_], iam_org_admin_members_list[_])
  combined_set := list_to_set(temp_list[_])
}


# METADATA
# title: Global Admins Policy - COMPLIANT
# description: If number of Global/Org Admins is between 2 and 5 (inclusive), then COMPLIANT
reply contains response if {
  count(combined_members_set) >= 2
  count(combined_members_set) <= 5
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("Valid number of Org Admins found for [%v, validation %v]. [%v] Org Admins were found.", [required_name, validation_number, count(combined_members_set)])}
  asset_name := {"asset_name": combined_members_set}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If too few Global/Org Admins detected, then NON-COMPLIANT
reply contains response if {
  count(combined_members_set) < 2
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Less than 2 Organization Admins found.  There should be at least 2, and no more than 5 for [%v, validation %v]. [%v] were found.", [required_name, validation_number, count(combined_members_set)])}
  asset_name := {"asset_name": combined_members_set}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If too many Global/Org Admins detected, then NON-COMPLIANT
reply contains response if {
  count(combined_members_set) > 5
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("More than 5 Organization Admins found.  There should be at least 2, and no more than 5 for [%v, validation %v]. [%v] were found.", [required_name, validation_number, count(combined_members_set)])}
  asset_name := {"asset_name": combined_members_set}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}
