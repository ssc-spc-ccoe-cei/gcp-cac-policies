# METADATA
# title: Guardrail 08 - Network Architecture Diagram
# description: Check for presence of required file(s) in Cloud Storage
package policies.guardrail_08_files

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Name of files data object to look for
required_name := "guardrail-08"

# Number of files that need to be present for compliance (including default instructions.txt file)
required_file_count := 2

# Metadata variables
guardrail := {"guardrail": "08"}

description := {"description": "Segment and Seperate"}

# METADATA
# description: Check if asset's name matches what's required
is_correct_name(asset) if {
	asset.name = required_name
}

# METADATA
# description: |
# Count how many file are present in Cloud Storage (including default instructions.txt) 
# and ensure it's equal or greater than what's required.
all_files_exist(asset) if {
	count(asset.files) >= required_file_count
}

# METADATA
# title: Check for Files
# description: |
# Will be TRUE if correct name is found and all files are present
matching_assets if {
	some asset in input.data
	is_correct_name(asset)
	all_files_exist(asset)
}

# METADATA
# title: Network Architecture Diagram - COMPLIANT
# description: If matching_assets is TRUE (all files found) then reply back COMPLIANT
reply contains response if {
	matching_assets
	status := {"status": "COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("Required [Network Architecture Diagram] file for [%v] detected.", [required_name])}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Policy NON-COMPLIANT
# description:  If matching_assets is not TRUE (all files not found) then reply back NON-COMPLIANT
reply contains response if {
	not matching_assets
	status := {"status": "NON-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("Required [Network Architecture Diagram] file(s) for [%v] NOT detected.", [required_name])}
	response := object.union_n([guardrail, status, msg, description, check])
}
