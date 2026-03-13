# METADATA
# title: Guardrail 02, Validation 02 - Ensure Authorization Mechanisms are in place
# description: Check for presence of required file(s) in Cloud Storage
package policies.guardrail_02_02_files

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Import common functions
import data.policies.common

# Name of files data object to look for
required_name := "guardrail-02"
validation_number := "02"

# Metadata variables
guardrail := {"guardrail": "02"}
validation := {"validation": "02"}
description := {"description": "Authorization Mechanisms"}

# Set check type based on profile and guardrail number
check := common.set_check_type(guardrail.guardrail)

# METADATA
# title: Policy AUTO COMPLIANT
# description: This policy is auto compliant.
reply contains response if {
	status := {"status": "COMPLIANT"}
	msg := {"msg": "Compliance with this guardrail is contingent upon ICA."}
	asset_name := {"asset_name": "N/A"}
	response := object.union_n([guardrail, validation, status, asset_name, msg, description, check])
}
