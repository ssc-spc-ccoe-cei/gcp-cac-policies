# METADATA
# title: Guardrail 02, Validation 07
# description: Check that account lockout policies are in place 
package policies.guardrail_02_07_lockout

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Import common functions
import data.policies.common

# Metadata variables
guardrail := {"guardrail": "02"}
validation := {"validation": "07"}
description := {"description": "Ensure account lockout policies and machanisms are in place"}

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
	msg := {"msg": "Google Workspace has default built-in safety features that meet the requirement."}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}
