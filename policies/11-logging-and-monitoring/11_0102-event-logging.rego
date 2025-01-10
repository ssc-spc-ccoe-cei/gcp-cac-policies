# METADATA
# title: Guardrail 11 , Validation 01 & 02 - Check for that Essential & Event Logging is Enabled
# description: Check whether monitoring & auditing is implemented for all user accounts
package policies.guardrail_11_0102_audit

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in


# Metadata variables
guardrail := {"guardrail": "11"}
description := {"description": "validation 01 & 02 - Essential & Event Logging Enabled"}

# Log name to check for
required_log_name := "cloudaudit.googleapis.com%2Factivity"


# METADATA
# title: HELPER FUNCTIONS
is_correct_log_name(asset) if {
	endswith(asset.logName, required_log_name)
}

# description: Checks if log contains Google Workspace entries
has_workspace_logs(asset) if {
  is_correct_log_name(asset)
  asset.resource.type = "audited_resource"
  asset.resource.labels.service = "admin.googleapis.com"
}


# METADATA
# title: VALIDATION / DATA PROCESSING
contains_workspace_logs := {asset |
  some asset in input.data
  has_workspace_logs(asset)
}


# METADATA
# title: Essential & Event Logs Detected - COMPLIANT
# description: If audit logs are found with correct name then reply back COMPLIANT
reply contains response if {
	count(contains_workspace_logs) > 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": "Essential & Event Logs detected."}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Essential & Event Logs Not Detected - NON-COMPLIANT
# description: If audit logs are NOT found with correct name then reply back NON-COMPLIANT
reply contains response if {
	count(contains_workspace_logs) == 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": "Essential & Event Logs NOT detected."}
	response := object.union_n([guardrail, status, msg, description, check])
}
