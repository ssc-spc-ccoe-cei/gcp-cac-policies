# METADATA
# title: Guardrail 03 , Validation 01 - Check for User Auth Source IPs
# description: Check whether users are authenticating from approved source IPs
package policies.guardrail_03_01_userip

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Metadata variables
guardrail := {"guardrail": "03"}
validation := {"validation": "01"}
description := {"description": "Endpoint Management - Allowed Policy Member Domains and User Source IP Constraints"}

required_asset_kind:= "logging#user#auth"


# METADATA
# title: CLIENT INPUT
# description: list of allowed IPs
env := opa.runtime().env
# description: takes on the value of env var, GR03_01_ALLOWED_IPS
#              i.e. export GR03_01_ALLOWED_IPS='10.0.0.7,192.168.1.134'
required_allowed_ips := split(env["GR03_01_ALLOWED_IPS"], ",")
# description: set to "true" if using federated users
required_has_federated_users := env["GR03_01_HAS_FEDERATED_USERS"]

# METADATA
# title: HELPER FUNCTIONS
# description: Checks if asset's type matches what's required
is_correct_asset_type(asset) if {
	asset.kind == required_asset_kind
}

is_allowed_ip(asset) if {
  asset.sourceIp in required_allowed_ips
}

# METADATA
# title: VALIDATION / DATA PROCESSING
# description: Check for a NON MATCH between the provided list and the ipSubnetworks list in ACM policy
contains_non_approved_ip := {[asset.principalEmail, asset.sourceIp, asset.timestamp] |
  some asset in input.data
  is_correct_asset_type(asset)
  not is_allowed_ip(asset)
}

# METADATA
# title: Access Context Manager IP Restriction Policy - COMPLIANT
# description: If IP restrictions provided to ACM, then reply back COMPLIANT
reply contains response if {
	required_has_federated_users == "true"
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": "Users are federated users and this guardrail is handled by the IdP."}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

reply contains response if {
	required_has_federated_users == "false"
	count(contains_non_approved_ip) == 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": "All users are connecting from approved IPs in the last 24hrs."}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Dedicated user accounts for administration - NON-COMPLIANT
# description: If NO IP restrictions provided to ACM, then reply back NON-COMPLIANT
reply contains response if {
	required_has_federated_users == "false"
	count(contains_non_approved_ip) > 0
  some violating_login in contains_non_approved_ip
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
  msg := {"msg": sprintf("[%v] authentication instances found where user connected from non-approved source IP.", [count(contains_non_approved_ip)])}
  asset_name := {"asset_name": violating_login}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}
