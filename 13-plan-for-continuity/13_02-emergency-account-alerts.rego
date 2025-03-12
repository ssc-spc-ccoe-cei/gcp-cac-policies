# METADATA
# title: Guardrail 13, Validation 02 - Emergency Account alerts
# description: Check for presence of Log-based Alerts for Breakglass account usage
package policies.guardrail_13_02_alerts

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in


# Name of files data object to look for
required_name := "guardrail-13"
validation_number := "02"


required_asset_type := "monitoring.googleapis.com/AlertPolicy"

required_alert_filter := "protoPayload.authenticationInfo.principalEmail = \"breakglass@ssc.gc.ca\""

# Metadata variables
guardrail := {"guardrail": "13"}
validation := {"validation": "02"}
description := {"description": "Emergency Account alerts"}

# METADATA
# description: Check if asset's name matches what's required
is_correct_asset(asset) if {
	asset.asset_type == required_asset_type
}

has_user_auth_alert(asset) if {
  filter = asset.resource.data.conditions[_].conditionMatchedLog.filter
  contains(filter, required_alert_filter)
}

contains_user_auth_alert := {asset |
  some asset in input.data
  is_correct_asset(asset)
  has_user_auth_alert(asset)
}

# METADATA
# title: Emergency Account Alerting Policy - COMPLIANT
# description: If validation/evidence file count meets miniumum AND has approval, then COMPLIANT
reply contains response if {
  count(contains_user_auth_alert) > 0
  check := {"check_type": "MANDATORY"}
  status := {"status": "COMPLIANT"}
  msg := {"msg": sprintf("Required Emergency Account alert(s) for [%v, validation %v] detected.", [required_name, validation_number])}
  response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If validation/evidence file count does NOT  miniumum, then NON-COMPLIANT
reply contains response if {
  count(contains_user_auth_alert) == 0
  check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Required Emergency Account alert(s) for [%v, validation %v] NOT detected.", [required_name, validation_number])}
  response := object.union_n([guardrail, validation, status, msg, description, check])
}
