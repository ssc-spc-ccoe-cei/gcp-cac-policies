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

# Metadata variables
guardrail := {"guardrail": "06"}
validation := {"validation": "01"}
description := {"description": "Encryption of Data at Rest"}


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
	msg := {"msg": "GCP offers default encryption at rest."}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}
