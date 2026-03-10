# METADATA
# title: Guardrail 04 - Check Monitoring Account IAM Roles
# description: Check roles assigned to account are correct to to enable enterprise monitoring and visibility
package policies.guardrail_04_01_monitor

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Import common functions
import data.policies.common

# Metadata variables
guardrail := {"guardrail": "04"}
validation := {"validation": "01"}
description := {"description": "Enterprise Monitoring Accounts"}

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
