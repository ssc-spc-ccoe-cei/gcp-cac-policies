# METADATA title: Guardrail 01, Validation 03 - Global Admin count
# description: Check for presence of required file(s) in Cloud Storage
package policies.guardrail_01_03_files

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Name of files data object to look for
required_name := "guardrail-01"
validation_number := "03"

required_domain := "ssc.gc.ca"

# Metadata variables
guardrail := {"guardrail": "01"}

description := {"description": "validation 03 - Global Admins count"}

# METADATA
# description: Check if asset's name matches what's required
is_correct_asset_01(asset) if {
  asset.kind == "cloudidentity#groups#membership"
}

is_correct_asset_02(asset) if {
  asset.asset_type == "cloudresourcemanager.googleapis.com/Organization"
}

gcp_org_admin_members := {gcp_user_members |
  some asset in input.data
  is_correct_asset_01(asset)
  asset.groupEmail == concat("@", ["gcp-organization-admins", required_domain])
  gcp_user_members := asset.members
}

# print the members list only for the role match
iam_org_admin_members := {user_members |
  some asset in input.data
  bindings := asset.iam_policy.bindings
  some binding in bindings
  binding.role == "roles/resourcemanager.organizationAdmin"
  members := binding.members 
  user_members := [user | user := members[_]; startswith(user, "user:")]
}

list_to_set(list) := {set | 
   set := list  # items are unique in a set  
}

combined_members := {combined_list |
  temp_list := array.concat(gcp_org_admin_members[_], iam_org_admin_members[_])
  combined_list := list_to_set(temp_list[_])
}


# METADATA
# title: Global Admins Policy - COMPLIANT
# description: If number of Global/Org Admins is between 2 and 5 (inclusive), then COMPLIANT
reply contains response if {
  count(combined_members) >= 2
  count(combined_members) <= 5
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("Valid number of Org Admins found for [%v, validation %v]. The following Org Admins were found: [%v]", [required_name, validation_number, combined_members])}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If too few Global/Org Admins detected, then NON-COMPLIANT
reply contains response if {
  count(combined_members) < 2
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Less than 2 Organization Admins found.  There should be at least 2, and no more than 5 for [%v, validation %v].  The following were found: [%v].", [required_name, validation_number, combined_members])}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If too many Global/Org Admins detected, then NON-COMPLIANT
reply contains response if {
  count(combined_members) > 5
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("More than 5 Organization Admins found.  There should be at least 2, and no more than 5 for [%v, validation %v].  The following were found: [%v].", [required_name, validation_number, combined_members])}
	response := object.union_n([guardrail, status, msg, description, check])
}
