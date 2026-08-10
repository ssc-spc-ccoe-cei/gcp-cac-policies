# METADATA
# title: Guardrail 13, Validation 02 - Emergency Account alerts
# description: Check for alerting for Breakglass account usage
package policies.guardrail_13_02_alerts

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Import common functions
import data.policies.common


# Name of files data object to look for
required_name := "guardrail-13"
validation_number := "02"

# Number of evidence files that need to be present when alerts cannot be detected
required_file_count := 1

# Filename should begin with "GUARDRAIL_APPROVAL" but can have a different suffix and file type
required_approval_filename := "GUARDRAIL_APPROVAL"

required_asset_type := "monitoring.googleapis.com/AlertPolicy"
required_scc_asset_type := "securitycentermanagement.googleapis.com/EventThreatDetectionCustomModule"
required_scc_module_type := "CONFIGURABLE_BREAKGLASS_ACCOUNT_USED"

# METADATA
# title: CLIENT INPUT
env := opa.runtime().env
# description: takes on the value of env var, BREAKGLASS_USER_EMAILS
#              which contains a JSON array of breakglass account emails
#              i.e. BREAKGLASS_USER_EMAILS='["breakglass1@example.com","breakglass2@example.com"]'
required_emergency_account_emails := json.unmarshal(env["GR13_02_BREAKGLASS_USER_EMAILS"])

# Metadata variables
guardrail := {"guardrail": "13"}
validation := {"validation": "02"}
description := {"description": "Emergency Account alerts"}

# Set check type based on profile and guardrail number
check := common.set_check_type(guardrail.guardrail)

# METADATA
# description: Check if asset's name matches what's required
is_correct_asset(asset) if {
	asset.asset_type == required_asset_type
}

# METADATA
# description: |
#   Check for an enabled, organization-resident SCC Event Threat Detection
#   custom module that detects break-glass account usage. Folder- and
#   project-resident modules do not provide organization-wide coverage.
is_organization_scc_breakglass_module(asset) if {
  asset.asset_type == required_scc_asset_type
  asset.resource.data.type == required_scc_module_type
  asset.resource.data.enablementState == "ENABLED"
  startswith(asset.resource.data.name, "organizations/")
}

# METADATA
# description: |
#    Check if an email is covered by an alert filter
#    This function checks if a given email is included in an alert filter
email_covered_by_filter(email, filter) if {
  email_pattern := sprintf("protoPayload.authenticationInfo.principalEmail=\"%s\"", [email])
  contains(filter, email_pattern)
}

# METADATA
# description: Check if an alert has filters for any of the required emails
has_emergency_account_alert(asset) if {
  filter := asset.resource.data.conditions[_].conditionMatchedLog.filter
  some email in required_emergency_account_emails
  email_covered_by_filter(email, filter)
}

# METADATA
# title: Track which emails have alerts configured
emails_with_alerts contains email if {
  some email in required_emergency_account_emails
  some asset in input.data
  is_correct_asset(asset)
  filter := asset.resource.data.conditions[_].conditionMatchedLog.filter
  email_covered_by_filter(email, filter)
}

# METADATA
# title: Track emails covered by organization-level SCC break-glass modules
emails_with_alerts contains email if {
  some email in required_emergency_account_emails
  some asset in input.data
  is_organization_scc_breakglass_module(asset)
  email in asset.resource.data.config.accounts
}

# METADATA
# title: Track which emails are missing alerts
emails_missing_alerts contains email if {
  some email in required_emergency_account_emails
  not emails_with_alerts[email]
}

# METADATA
# title: Track uploaded evidence files
validation_files_list := {file |
  some asset in input.data
  some file in asset.files
  startswith(file, concat("/", [required_name, "evidence", validation_number]))
}

contains_approval if {
  count(validation_files_list) >= required_file_count
  some asset in input.data
  some file in asset.files
  startswith(file, required_approval_filename)
}

# METADATA
# title: Emergency Account Alerting Policy - COMPLIANT
# description: If all required emergency accounts have alerts and no evidence file is present, then COMPLIANT
reply contains response if {
  count(validation_files_list) < required_file_count
  count(emails_missing_alerts) == 0
  status := {"status": "COMPLIANT"}
  msg := {"msg": sprintf("Required Emergency Account alerts for all accounts %v detected for [%v, validation %v].", [required_emergency_account_emails, required_name, validation_number])}
  response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Emergency Account Alerting Evidence - COMPLIANT
# description: If the required evidence file count is met and approval is present, then COMPLIANT
reply contains response if {
  count(validation_files_list) >= required_file_count
  contains_approval
  status := {"status": "COMPLIANT"}
  msg := {"msg": sprintf("Evidence file and Approval file detected for [%v, validation %v]; Required Emergency Account alerts exist outside of Google Cloud.", [required_name, validation_number])}
  response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Emergency Account Alerting Evidence - PENDING
# description: If the required evidence file count is met but approval is absent, then PENDING
reply contains response if {
  count(validation_files_list) >= required_file_count
  not contains_approval
  status := {"status": "PENDING"}
  msg := {"msg": sprintf("Evidence file detected for [%v, validation %v]; Required Emergency Account alerts exist outside of Google Cloud. Approval file NOT detected.", [required_name, validation_number])}
  response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If alerts are missing and the required evidence file count is not met, then NON-COMPLIANT
reply contains response if {
  count(emails_missing_alerts) > 0
  count(validation_files_list) < required_file_count
	status := common.set_status(guardrail.guardrail)
  msg := {"msg": sprintf("Required Emergency Account alerts are missing for accounts %v and no evidence file was detected for [%v, validation %v].", [emails_missing_alerts, required_name, validation_number])}
  response := object.union_n([guardrail, validation, status, msg, description, check])
}
