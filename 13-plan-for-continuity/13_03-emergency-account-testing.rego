# METADATA
# title: Guardrail 13, Validation 03 - Emergency Account testing
# description: Check for presence of Emergency/Breakglass Account Testing
package policies.guardrail_13_03_breakglass

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Import common functions
import data.policies.common

#import time


# Name of files data object to look for
required_name := "guardrail-13"
validation_number := "03"

# Metadata variables
guardrail := {"guardrail": "13"}
validation := {"validation": "03"}
description := {"description": "Emergency Account testing"}

# Set check type based on profile and guardrail number
check := common.set_check_type(guardrail.guardrail)

required_asset_kind := "logging#breakglass#auth"

# METADATA
# title: CLIENT INPUT
env := opa.runtime().env
# description: takes on the value of env var, BREAKGLASS_USER_EMAILS
#              which containns a JSON array of breakglass account emails
#              i.e. BREAKGLASS_USER_EMAILS=["breakglass1@example.com","breakglass2@example.com"]
required_emergency_account_emails := json.unmarshal(env["GR13_03_BREAKGLASS_USER_EMAILS"])


# METADATA
# description: Check if asset's kind matches what's required
is_correct_kind(asset) if {
  asset.kind == required_asset_kind
}

# METADATA
# description: Check if asset's email is in the list of required breakglass emails
is_breakglass_email(asset) if {
  some email in required_emergency_account_emails
  asset.principalEmail == email
}

# METADATA
# title: Get all unique breakglass emails found in logs
breakglass_emails_found contains asset.principalEmail if {
  some asset in input.data
  is_correct_kind(asset)
  is_breakglass_email(asset)
}

# METADATA
# title: Get matching logs for each breakglass email
matching_logs_by_email[email] = timestamps if {
  some email in required_emergency_account_emails
  timestamps = [asset.timestamp | 
    some asset in input.data
    asset.kind == required_asset_kind
    asset.principalEmail == email
  ]
}

# METADATA
# title: Check which emails have log entries
emails_with_logs contains email if {
  some email in required_emergency_account_emails
  count(matching_logs_by_email[email]) > 0
}

# METADATA
# title: Check which emails are missing log entries
emails_missing_logs contains email if {
  some email in required_emergency_account_emails
  not emails_with_logs[email]
}

# METADATA
# title: Emergency Account Procedure Policy - COMPLIANT
# description: If validation/evidence file count meets miniumum AND has approval, then COMPLIANT
reply contains response if {
  count(emails_missing_logs) == 0
  status := {"status": "COMPLIANT"}
  msg := {"msg": sprintf("All required Emergency Accounts %v have testing logs for [%v, validation %v].", [required_emergency_account_emails, required_name, validation_number])}
  asset_name := {"asset_name": breakglass_emails_found}
  response := object.union_n([guardrail, validation, status, asset_name, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If validation/evidence file count does NOT  miniumum, then NON-COMPLIANT
reply contains response if {
  count(emails_missing_logs) > 0
  status := common.set_status(guardrail.guardrail)
  msg := {"msg": sprintf("Required Emergency Accounts %v missing testing logs for [%v, validation %v].", [emails_missing_logs, required_name, validation_number])}
  response := object.union_n([guardrail, validation, status, msg, description, check])
}
