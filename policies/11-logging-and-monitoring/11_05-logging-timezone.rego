# METADATA
# title: Guardrail 11, Validation 05
# description: Check that logs are collected in an appropriate timezone
package policies.guardrail_11_05_timezone

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Metadata variables
guardrail := {"guardrail": "11"}
validation := {"validation": "05"}
description := {"description": "Ensure that logs are collected in an appropriate timezone"}


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
	msg := {"msg": "GCP logs are always collected in UTC time."}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}
