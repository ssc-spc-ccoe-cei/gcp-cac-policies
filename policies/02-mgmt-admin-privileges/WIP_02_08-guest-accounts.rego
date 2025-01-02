# METADATA title: Guardrail 02, Validation 08 - Access Configuration & Policies
# description: Check for presence of required file(s) in Cloud Storage
package policies.guardrail_02_08_files

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Name of files data object to look for
required_name := "guardrail-02"
validation_number := "01"

required_domain := "ssc.gc.ca"

required_regular_users_list := ["user:jenn.charland@ssc.gc.ca", "user:glen.yu@ssc.gc.ca"]

# Metadata variables
guardrail := {"guardrail": "02"}

description := {"description": "validation 01 - Access Configuration & Policies"}

# METADATA
# description: Check if asset's name matches what's required
is_correct_asset(asset) if {
  asset.kind == "cloudidentity#groups#membership"
}

has_user_members_in_reg_users_list(asset) if {
  is_correct_asset(asset)
  asset.groupEmail == concat("@", ["gcp-organization-admins", required_domain])
  some member in asset.members
  some user in required_regular_users_list
  contains(member, user)
}

contains_dedicated_org_admin_users := {asset.members[_] |
  some asset in input.data
  is_correct_asset(asset)
  has_user_members_in_reg_users_list(asset) # regular user is not an Org Admin
}

# METADATA
# title: Essential Contacts Policy - COMPLIANT
# description: If essential contacts are in SECURITY category AND meets minimum count, then COMPLIANT
reply contains response if {
  count(contains_dedicated_org_admin_users) == 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("No regular users have been detected to be assigned Org Admin rights in [%v, validation %v].", [required_name, validation_number])}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If insufficient essential contacts are in SECURITY category OR does not meets minimum count, then NON-COMPLIANT
reply contains response if {
  count(contains_dedicated_org_admin_users) > 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Regular user(s) has been found to have the Org Admin role in [%v, validation %v].", [required_name, validation_number])}
	response := object.union_n([guardrail, status, msg, description, check])
}
