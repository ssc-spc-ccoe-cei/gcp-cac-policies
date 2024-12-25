# METADATA
# title: Guardrail 01 , Validation 04 - Check for Monitioring & Audit Logs
# description: Check whether monitoring & auditing is implemented for all user accounts
package policies.guardrail_01_04_audit
#package example

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Log name to check for
required_log_name := "cloudaudit.googleapis.com%2Factivity"

# Metadata variables
guardrail := {"guardrail": "01"}

description := {"description": "validation 04 - User account Monitoring and Auditing"}

# METADATA
# description: Checks if log name matches required_log_name
is_correct_log_name(asset) if {
	endswith(asset.logName, required_log_name)
}

# METADATA
# description: Checks if log contains Google Workspace entries
has_workspace_logs(asset) if {
  is_correct_log_name(asset)
  asset.resource.type = "audited_resource"
  asset.resource.labels.service = "admin.googleapis.com"
}

# METADATA
# title: Check for existence of Workspace logs
# description: Check for audit log with correct log name
contains_workspace_logs := {asset |
  some asset in input#.data
  has_workspace_logs(asset)
}

# METADATA
# title: Audit Logs Detected - COMPLIANT
# description: If audit logs are found with correct name then reply back COMPLIANT
reply contains response if {
	count(contains_workspace_logs) > 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": "Google Workspace Audit Logs at Organization-level detected."}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Audit Logs Not Detected - NON-COMPLIANT
# description: If audit logs are NOT found with correct name then reply back NON-COMPLIANT
reply contains response if {
	count(contains_workspace_logs) == 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": "Google Workspace Audit Logs at Organization-level NOT detected."}
	response := object.union_n([guardrail, status, msg, description, check])
}
