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

#import time


# Name of files data object to look for
required_name := "guardrail-13"
validation_number := "03"

# Metadata variables
guardrail := {"guardrail": "13"}
validation := {"validation": "03"}
description := {"description": "Emergency Account testing"}


required_asset_kind := "logging#breakglass#auth"

# METADATA
# title: CLIENT INPUT
env := opa.runtime().env
# description: takes on the value of env var, GR13_03_BREAKGLASS_USER_EMAIL
#              breakglass account email -- i.e. GR13_03_BREAKGLASS_USER_EMAIL="breakglass@ssc.gc.ca"
required_emergency_account_email := env["GR13_03_BREAKGLASS_USER_EMAIL"]


# METADATA
# description: Check if asset's name matches what's required
# METADATA
# description: Check if asset's service name matches what's required
is_correct_asset(asset) if {
  asset.kind == required_asset_kind
	asset.principalEmail == required_emergency_account_email
}

is_breakglass_login(asset) if {
	asset.principalEmail == required_emergency_account_email
}

# METADATA
# title: Check for matching assets
# description: Store assets matching required service name
matching_auth_logs := {asset.timestamp |
	some asset in input.data
	is_correct_asset(asset)
	is_breakglass_login(asset)
}


# METADATA
# title: Emergency Account Procedure Policy - COMPLIANT
# description: If validation/evidence file count meets miniumum AND has approval, then COMPLIANT
reply contains response if {
  count(matching_auth_logs) > 0
  check := {"check_type": "MANDATORY"}
  status := {"status": "COMPLIANT"}
  msg := {"msg": sprintf("Required Emergency Account, [%v] testing for [%v, validation %v] detected.", [required_emergency_account_email, required_name, validation_number])}
  asset_name := {"asset_name": matching_auth_logs}
  response := object.union_n([guardrail, validation, status, asset_name, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If validation/evidence file count does NOT  miniumum, then NON-COMPLIANT
reply contains response if {
  count(matching_auth_logs) == 0
  check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Required Emergency Account, [%v] testing for [%v, validation %v] NOT detected.", [required_emergency_account_email, required_name, validation_number])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}
