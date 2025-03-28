# METADATA
# title: Guardrail 02, Validation 10 - Guest Users Reviewed (periodically)
# description: Check for presence of required file(s) in Cloud Storage
package policies.guardrail_02_10_files

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Name of files data object to look for
required_name := "guardrail-02"
validation_number := "10"

# Metadata variables
guardrail := {"guardrail": "02"}
validation := {"validation": "10"}
description := {"description": "Guest Account Reviews"} 


# METADATA
# title: CLIENT INPUT
# description: Number of files that need to be present for compliance
required_file_count := 1
required_approval_filename := "GUARDRAIL_APPROVAL"

env := opa.runtime().env
# description: set to "true" if there are guest users
required_has_guest_users := env["GR02_10_HAS_GUEST_USERS"]


# METADATA
# title: HELPER FUNCTIONS
# description: Check if asset's name matches what's required
is_correct_name(asset) if {
	asset.name = required_name
}


# METADATA
# title: VALIDATION / DATA PROCESSING
validation_files_list := {file |
  some asset in input.data
  some file in asset.files
  startswith(file, concat("/", [required_name, "validations", validation_number]))
}

contains_approval if {
  count(validation_files_list) >= required_file_count
  some asset in input.data
  some file in asset.files
  startswith(file, required_approval_filename)
}


# METADATA
# title: NO Guest Users. Policy - COMPLIANT
# description: There are no guest users; automatically compliant
reply contains response if {
  required_has_guest_users == "false"
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("No non-organization users detected for [%v, validation %v].", [required_name, validation_number])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Guest Users Review Policy - COMPLIANT
# description: If validation/evidence file count meets miniumum AND has approval, then COMPLIANT
reply contains response if {
  required_has_guest_users == "true"
  count(validation_files_list) >= required_file_count
  contains_approval
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("Required Guest Account Review file(s) AND Approval file for [%v, validation %v] detected.", [required_name, validation_number])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Policy - PENDING
# description: If validation/evidence file count meets miniumum, but not approval, then PENDING
reply contains response if {
  required_has_guest_users == "true"
  count(validation_files_list) >= required_file_count
  not contains_approval
	check := {"check_type": "MANDATORY"}
	status := {"status": "PENDING"}
	msg := {"msg": sprintf("Required Guest Account Review file(s) for [%v, validation %v] detected. Approval file NOT detected.", [required_name, validation_number])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If validation/evidence file count does NOT  miniumum, then NON-COMPLIANT
reply contains response if {
  required_has_guest_users == "true"
  count(validation_files_list) < required_file_count
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Required Guest Account Reviews file(s) for [%v, validation %v] NOT detected. Only the following was found: [%v]", [required_name, validation_number, validation_files_list])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}
