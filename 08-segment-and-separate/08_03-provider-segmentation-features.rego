# METADATA
# title: Guardrail 08, Validation 03 - Ensure Cloud Provider's Segmentation Features are leveraged
# description: Check for presence of required file(s) in Cloud Storage
package policies.guardrail_08_03_files

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Name of files data object to look for
required_name := "guardrail-08"
validation_number := "03"

# Number of files that need to be present for compliance
# There is nothing to upload for this validation
# This validation is to ensure the network architecture and cloud deployment guide makes use of provider features
# There is no "NON-COMPLIANT" status that comes out of this as it builds on 8.1 and 8.2
required_file_count := 0
# description: filename should begin with "GUARDRAIL_APPROVAL" but can have different suffix and file type
required_approval_filename := "GUARDRAIL_APPROVAL"

# Metadata variables
guardrail := {"guardrail": "08"}
validation := {"validation": "03"}
description := {"description": "Provider Segmentation Features"}

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
# title: Provider Segmentation Feature Policy - COMPLIANT
# description: If validation/evidence file count meets miniumum AND has approval, then COMPLIANT
reply contains response if {
  count(validation_files_list) >= required_file_count
  contains_approval
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("Required Provider Segmentation Feature usage Approval file for [%v, validation %v] detected.", [required_name, validation_number])}
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
	msg := {"msg": sprintf("Required Provider Segmentation Feature usage Approval for [%v, validation %v] NOT detected.", [required_name, validation_number])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}
