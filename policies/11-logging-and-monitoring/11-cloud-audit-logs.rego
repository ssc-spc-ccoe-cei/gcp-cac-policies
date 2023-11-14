# METADATA
# title: Guardrail 11 - Check for Audit Logs
# description: Check for Admin Activity cloud audit logs
package policies.guardrail_11_audit

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Log name to check for
required_log_name := "cloudaudit.googleapis.com%2Fdata_access"

# Metadata variables
guardrail := {"guardrail": "11"}

description := {"description": "Logging and Monitoring"}

# METADATA
# description: Checks if log name matches required_log_name
is_correct_log_name(asset) if {
	endswith(asset.logName, required_log_name)
}

# METADATA
# title: Check for Matching Assets
# description: Check for audit log with correct log name
audit_log_assets := {asset |
	some asset in input.data
	is_correct_log_name(asset)
}

# METADATA
# title: Audit Logs Detected - COMPLIANT
# description: If audit logs are found with correct name then reply back COMPLIANT
reply contains response if {
	count(audit_log_assets) > 0
	status := {"status": "COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": "Audit Logs at Organization-level detected."}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Audit Logs Not Detected - NON-COMPLIANT
# description: If audit logs are NOT found with correct name then reply back NON-COMPLIANT
reply contains response if {
	count(audit_log_assets) == 0
	status := {"status": "NON-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": "Audit Logs at Organization-level NOT detected."}
	response := object.union_n([guardrail, status, msg, description, check])
}
