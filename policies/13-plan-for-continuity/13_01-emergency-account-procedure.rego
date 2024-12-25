# METADATA
# title: Guardrail 13, Validation 01 - Emergency Account procedure
# description: Check for presence of required file(s) in Cloud Storage
package policies.guardrail_13_01_files

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Name of files data object to look for
required_name := "guardrail-13"
validation_number := "01"

# Number of files that need to be present for compliance
required_file_count := 1

required_approval_filename := "01_APPROVAL_email.pdf"

# Metadata variables
guardrail := {"guardrail": "13"}

description := {"description": "validation 01 - Emergency Account Procedure"}

# METADATA
# description: Check if asset's name matches what's required
is_correct_name(asset) if {
  asset.name = required_name
}

validation_files_list := {file |
  some asset in input.data
  some file in asset.files
  startswith(file, concat("/", [required_name, "validations", validation_number]))
}

contains_approval if {
  count(validation_files_list) >= required_file_count + 1
  some asset in input.data
  some file in asset.files
  endswith(file, concat("/", [required_name, "validations", required_approval_filename]))
}


# METADATA
# title: Emergency Account Procedure Policy - COMPLIANT
# description: If validation/evidence file count meets miniumum AND has approval, then COMPLIANT
reply contains response if {
  count(validation_files_list) >= required_file_count
  contains_approval
  check := {"check_type": "MANDATORY"}
  status := {"status": "COMPLIANT"}
  msg := {"msg": sprintf("Required Emergency Account Procedure file(s) AND Approval file for [%v, validation %v] detected.", [required_name, validation_number])}
  response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Policy - PENDING
# description: If validation/evidence file count meets miniumum, but not approval, then PENDING
reply contains response if {
  count(validation_files_list) >= required_file_count
  not contains_approval
  check := {"check_type": "MANDATORY"}
	status := {"status": "PENDING"}
	msg := {"msg": sprintf("Required Emergency Account Procedure file(s) for [%v, validation %v] detected. Approval file NOT detected.", [required_name, validation_number])}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If validation/evidence file count does NOT  miniumum, then NON-COMPLIANT
reply contains response if {
  count(validation_files_list) < required_file_count
  check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Required Emergency Account Procedure file(s) for [%v, validation %v] NOT detected. Only the following was found: [%v]", [required_name, validation_number, validation_files_list])}
	response := object.union_n([guardrail, status, msg, description, check])
}
