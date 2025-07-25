# METADATA
# title: Guardrail 06, Validation 01
# description: Check that Encryption of Data at Rest is enabled
package policies.guardrail_06_01_encryption

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Import common functions
import data.policies.common

# Metadata variables
guardrail := {"guardrail": "06"}
validation := {"validation": "01"}
description := {"description": "Encryption of Data at Rest"}

# Set check type based on profile and guardrail number
check := common.set_check_type(guardrail.guardrail)

# METADATA
# description: this validation has an automatic pass
default allow = true

# METADATA
# title: Policy COMPLIANT
# description: automatics pass 
reply contains response if {
  allow = true
	status := {"status": "COMPLIANT"}
	msg := {"msg": "GCP offers default encryption at rest."}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}
