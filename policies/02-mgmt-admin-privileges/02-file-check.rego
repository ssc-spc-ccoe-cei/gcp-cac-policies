# METADATA
# title: Guardrail 02 - Account Mgmt Plan/Password Guidance/MFA Policy
# description: Check for presence of required file(s) in Cloud Storage
package policies.guardrail_02_files

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Name of files data object to look for
required_name := "guardrail-02"

# Number of files that need to be present for compliance (including default instructions.txt file)
required_file_count := 4

# Metadata variables
guardrail := {"guardrail": "02"}

description := {"description": "Management of Administrative Privileges"}

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
# title: Privileged Account Management Plan - COMPLIANT
# description: If matching_assets is TRUE (all files found) then reply back COMPLIANT
reply contains response if {
	matching_assets
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("Required [Privileged Account Management Plan] file for [%v] detected.", [required_name])}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: GC Password Guidance Doc. - COMPLIANT
# description: If matching_assets is TRUE (all files found) then reply back COMPLIANT
reply contains response if {
	matching_assets
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("Required [GC Password Guidance Doc.] file for [%v] detected.", [required_name])}
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
	msg := {"msg": sprintf("Required [Privileged Account Management Plan], [GC Password Guidance Doc.] and [MFA Policy Enforcement] file(s) for [%v] NOT detected.", [required_name])}
	response := object.union_n([guardrail, status, msg, description, check])
}
