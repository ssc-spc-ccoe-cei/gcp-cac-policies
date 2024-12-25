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

# Name of files data object to look for
required_name := "guardrail-11"
validation_number := "04"

# Number of files that need to be present for compliance
required_org_id := "1234567890"
required_security_contacts_count := 2

# Metadata variables
guardrail := {"guardrail": "11"}

description := {"description": "validation 04 - Essential Contacts"}

# METADATA
# description: Check if asset's name matches what's required
is_correct_asset(asset) if {
  startswith(asset.name, concat("/", ["organizations", required_org_id, "contacts"]))
}

has_security_notification(asset) if {
  notification_categories = asset.notificationCategorySubscriptions[_]
  contains(notification_categories, "SECURITY")
}

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
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If insufficient essential contacts are in SECURITY category OR does not meets minimum count, then NON-COMPLIANT
reply contains response if {
  count(contains_security_essentialcontacts) < required_security_contacts_count
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Required number of Essential Contacts for Security NOT detected for [%v, validation %v]. Only the following contacts were found: [%v]", [required_name, validation_number, contains_security_essentialcontacts])}
	response := object.union_n([guardrail, status, msg, description, check])
}
