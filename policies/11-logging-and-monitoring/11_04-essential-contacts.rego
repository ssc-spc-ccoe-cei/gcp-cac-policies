# METADATA
# title: Guardrail 11, Validation 04 - Essential Contacts
# description: Check for presence of required file(s) in Cloud Storage
package policies.guardrail_11_04_files

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Metadata variables
guardrail := {"guardrail": "11"}
validation := {"validation": "04"}
description := {"description": "Essential Contacts"}


# Name of files data object to look for
required_name := "guardrail-11"
validation_number := "04"

# Number of files that need to be present for compliance
required_security_contacts_count := 2
# description: takes on the value of env var, GR11_04_ORG_ID
#              i.e. export GR11_04_ORG_ID='1234567890'
env := opa.runtime().env
required_org_id := env["GR11_04_ORG_ID"]


# METADATA
# title: HELPER FUNCTIONS
# description: Check if asset's name matches what's required
is_correct_asset(asset) if {
  startswith(asset.name, concat("/", ["organizations", required_org_id, "contacts"]))
}

has_security_notification(asset) if {
  notification_categories = asset.notificationCategorySubscriptions[_]
  contains(notification_categories, "SECURITY")
}


# METADATA
# title: VALIDATION / DATA PROCESSING
contains_security_essentialcontacts := {asset.email |
  some asset in input.data
  is_correct_asset(asset)
  has_security_notification(asset)
}


# METADATA
# title: Essential Contacts Policy - COMPLIANT
# description: If essential contacts are in SECURITY category AND meets minimum count, then COMPLIANT
reply contains response if {
  count(contains_security_essentialcontacts) >= required_security_contacts_count 
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("Required number of Essential Contacts for Security detected for [%v, validation %v].", [required_name, validation_number])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If insufficient essential contacts are in SECURITY category OR does not meets minimum count, then NON-COMPLIANT
reply contains response if {
  count(contains_security_essentialcontacts) < required_security_contacts_count
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Required number of Essential Contacts for Security NOT detected for [%v, validation %v]. [%v] were found.", [required_name, validation_number, count(contains_security_essentialcontacts)])}
  asset_name := {"asset_name": contains_security_essentialcontacts}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}
