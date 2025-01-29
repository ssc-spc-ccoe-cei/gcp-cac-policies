# METADATA
# title: Guardrail 13, Validation 03 - Emergency Account testing
# description: Check for presence of Emergency/Breakglass Account Testing
package policies.guardrail_13_03_files

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

# UPN = user principal name (email)
required_emergency_account_upn := "breakglass@ssc.gc.ca"

# Metadata variables
guardrail := {"guardrail": "13"}
validation := {"validation": "03"}
description := {"description": "Emergency Account testing"}

# METADATA
# description: Check if asset's name matches what's required
# METADATA
# description: Check if asset's service name matches what's required
is_correct_asset(asset) if {
	asset.protoPayload.authenticationInfo.principalEmail == required_emergency_account_upn
}

# METADATA
# title: Check for matching assets
# description: Store assets matching required service name
matching_assets := {asset.timestamp |
	some asset in input.data
	is_correct_asset(asset)
}


# METADATA
# title: Emergency Account Procedure Policy - COMPLIANT
# description: If validation/evidence file count meets miniumum AND has approval, then COMPLIANT
reply contains response if {
  count(matching_assets) > 0
  check := {"check_type": "MANDATORY"}
  status := {"status": "COMPLIANT"}
  msg := {"msg": sprintf("Required Emergency Account testing for [%v, validation %v] detected at these times: [%v].", [required_name, validation_number, matching_assets])}
  response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If validation/evidence file count does NOT  miniumum, then NON-COMPLIANT
reply contains response if {
  count(matching_assets) == 0
  check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Required Emergency Account testing for [%v, validation %v] NOT detected.", [required_name, validation_number])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}
