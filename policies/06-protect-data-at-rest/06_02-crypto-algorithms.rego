# METADATA
# title: Guardrail 06, Validation 02
# description: Check that approved Cryptographic Algorithms are used
package policies.guardrail_06_02_crypto

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Metadata variables
guardrail := {"guardrail": "06"}
validation := {"validation": "02"}
description := {"description": "Cryptographic Algorithms"}


# METADATA
# description: this validation has an automatic pass
default allow = true

# METADATA
# title: Policy COMPLIANT
# description: automatics pass 
reply contains response if {
  allow = true
	status := {"status": "COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": "GCP uses approved or betterr cryptographic algorithms."}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}
