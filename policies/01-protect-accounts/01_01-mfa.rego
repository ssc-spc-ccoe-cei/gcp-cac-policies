# METADATA
# title: Guardrail 01, Validation 01 - Essential Contacts
# description: Check for presence of required file(s) in Cloud Storage
package policies.guardrail_01_01_files

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Name of files data object to look for
required_name := "guardrail-01"
validation_number := "01"

# Metadata variables
guardrail := {"guardrail": "01"}

description := {"description": "validation 01 - MFA Enforcement"}

# METADATA
# description: Check if asset's name matches what's required
is_correct_asset(asset) if {
  asset.kind == "admin#directory#users"
}

# get list of all the 'isEnforcedIn2Sv' values for all users
mfa_enforcement_status := {asset.users[_].isEnforcedIn2Sv |
  some asset in input.data
  asset.users[_].kind == "admin#directory#user"
  is_correct_asset(asset)
}

# check if there's a 'false' value amongst the list
has_false(mfa_enforcement_status) {
  some i in mfa_enforcement_status
  not mfa_enforcement_status[i]
}


# METADATA
# title: Essential Contacts Policy - COMPLIANT
# description: If essential contacts are in SECURITY category AND meets minimum count, then COMPLIANT
reply contains response if {
  not has_false(mfa_enforcement_status)
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("Required MFA Enforcement policy detected for users in [%v, validation %v].", [required_name, validation_number])}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If insufficient essential contacts are in SECURITY category OR does not meets minimum count, then NON-COMPLIANT
reply contains response if {
  has_false(mfa_enforcement_status)
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Required MFA Enforcement policy NOT detected for user(s) in [%v, validation %v].", [required_name, validation_number])}
	response := object.union_n([guardrail, status, msg, description, check])
}
