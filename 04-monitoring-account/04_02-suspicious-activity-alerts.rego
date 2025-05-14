# METADATA
# title: Guardrail 04, Validation 02 - Ensure Alerts for Suspicious Activity have been implemented
# description: Check for presence of required file(s) in Cloud Storage
#              NOTE this is a duplicate of GR1.5
package policies.guardrail_04_02_files

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Name of files data object to look for
required_name := "guardrail-04"
validation_number := "02"
compliant_dependency := "05"

# Metadata variables
guardrail := {"guardrail": "04"}
validation := {"validation": "02"}
description := {"description": "Suspicious Activity Alerts"}

# description: GR04_02 is dependent on GR01_05, so we're checking for GR01_05's compliance status
required_guardrail_check := "guardrail-01"


# METADATA
# title: CLIENT INPUT
# description: there is NO client input required here as it should already exist for GR1.5
required_file_count := 1
required_approval_filename := "GUARDRAIL_APPROVAL"

# METADATA
# title: HELPER FUNCTIONS
# description: Check if asset's name matches what's required
is_correct_name(asset) if {
	asset.name = required_guardrail_check
}

# METADATA
# title: VALIDATION / DATA PROCESSING
validation_files_list := {file |
  some asset in input.data
  some file in asset.files
  startswith(file, concat("/", [required_guardrail_check, "evidence", compliant_dependency]))
}



# METADATA
# title: VALIDATION / DATA PROCESSING
# description: checking GR01_05 for approval file
contains_approval if {
  count(validation_files_list) >= required_file_count
  some asset in input.data
  some file in asset.files
  startswith(file, required_approval_filename)
}




# METADATA
# title: Suspicious Activity Alerts Policy - COMPLIANT
# description: If GR01_05 is compliant, then COMPLIANT
reply contains response if {
  count(validation_files_list) >= required_file_count
  contains_approval
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("Required suspicious activity alerts compliant for [%v, validation %v] as Guardrail 01, Validation 05 is also compliant.", [required_name, validation_number])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Policy - PENDING
# description: If validation/evidence file count meets miniumum, but not approval, then PENDING 
reply contains response if {
  count(validation_files_list) >= required_file_count
  not contains_approval
	check := {"check_type": "MANDATORY"}
	status := {"status": "PENDING"}
	msg := {"msg": sprintf("Required suspicious activity alerts PENDING for [%v, validation %v] as Guardrail 01, missing aproval file. Validation 05 is also PENDING.", [required_name, validation_number])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If validation/evidence file count does NOT  miniumum, then NON-COMPLIANT 
reply contains response if {
  count(validation_files_list) < required_file_count
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Required suspicious activity alerts for [%v, validation %v] NOT detected. Please confirm Guardrail 01, Validation 05 is compliant.", [required_name, validation_number])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}