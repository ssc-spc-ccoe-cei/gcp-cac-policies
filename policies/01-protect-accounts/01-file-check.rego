# METADATA
# title: Guardrail 01 - Break Glass/MFA Policy
# description: Check for presence of required file(s) in Cloud Storage
package policies.guardrail_01_files

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Name of files data object to look for
required_name := "guardrail-01"

# Number of files that need to be present for compliance (including default instructions.txt file)
required_file_count := 3

# Metadata variables
guardrail := {"guardrail": "01"}

description := {"description": "Protect Root/Global Admin Account"}

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
# title: Break Glass Procedure - COMPLIANT
# description: If matching_assets is TRUE (all files found) then reply back COMPLIANT
reply contains response if {
	matching_assets
	status := {"status": "COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("Required [Break Glass account Procedure] file for [%v] detected.", [required_name])}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: MFA Policy Enforcement - COMPLIANT
# description: If matching_assets is TRUE (all files found) then reply back COMPLIANT
reply contains response if {
	matching_assets
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("Required [MFA Policy Enforcement] file for [%v] detected.", [required_name])}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Policy NON-COMPLIANT
# description:  If matching_assets is not TRUE (all files not found) then reply back NON-COMPLIANT
reply contains response if {
	not matching_assets
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Required [MFA Policy Enforcement] and [Break Glass account Procedure] file(s) for [%v] NOT detected.", [required_name])}
	response := object.union_n([guardrail, status, msg, description, check])
}
