# METADATA
# title: Guardrail 13, Validation 04 - Emergency Account procedure
# description: Check for presence of required file(s) in Cloud Storage
package policies.guardrail_13_04_files

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Name of files data object to look for
required_name := "guardrail-13"
validation_number := "04"

# Number of files that need to be present for compliance
# No upload required here: document should be uploaded in GR13.1
required_file_count := 0
# description: filename should begin with "GUARDRAIL_APPROVAL" but can have different suffix and file type
required_approval_filename := "GUARDRAIL_APPROVAL"

# Metadata variables
guardrail := {"guardrail": "13"}
validation := {"validation": "04"}
description := {"description": "Deptartmental CIO Approval of Emergency Account Procedure"}

# METADATA
# description: Check if asset's name matches what's required
is_correct_name(asset) if {
  asset.name = required_name
}

validation_files_list := {file |
  some asset in input.data
  some file in asset.files
  startswith(file, concat("/", [required_name, "evidence", validation_number]))
}

contains_approval if {
  count(validation_files_list) >= required_file_count
  some asset in input.data
  some file in asset.files
  startswith(file, required_approval_filename)
}


# METADATA
# title: Departmental CIO Approval - COMPLIANT
# description: If validation/evidence file count meets miniumum AND has approval, then COMPLIANT
reply contains response if {
  count(validation_files_list) >= required_file_count
  contains_approval
  check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("Required Departmental CIO approval Emergency Account Procedure file(s) for [%v, validation %v] detected.", [required_name, validation_number])}
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
	msg := {"msg": sprintf("Required Departmental CIO approval Emergency Account Procedure file(s) for [%v, validation %v] NOT detected.", [required_name, validation_number])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}
