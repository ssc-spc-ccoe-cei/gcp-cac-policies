# METADATA
# title: Guardrail 02, Validation 05
# description: Check that default passwords have been changed for Built-in Accounts
package policies.guardrail_02_05_accounts

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Metadata variables
guardrail := {"guardrail": "02"}
validation := {"validation": "05"}
description := {"description": "Ensure default passwords have been changed for built-in accounts"}


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
	msg := {"msg": "GCP has no built-in accounts."}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}
