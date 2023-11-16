# METADATA
# title: Guardrail 01 - Protect Accounts
# description: Check for presence of admin.googleapis.com logs
package policies.guardrail_01_protect

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Log service name must be admin.googleapis.com
required_service_name := "admin.googleapis.com"

# Metadata variables
guardrail := {"guardrail": "01"}

description := {"description": "GUARDRAIL 1: PROTECT ROOT/GLOBAL ADMINS ACCOUNT"}

# METADATA
# description: Check if asset's service name matches what's required
is_correct_asset(asset) if {
	asset.protoPayload.serviceName = required_service_name
}

# METADATA
# title: Check for matching assets
# description: Store assets matching required service name
matching_assets := {asset |
	some asset in input.data
	is_correct_asset(asset)
}

# METADATA
# title: Policy COMPLIANT
# description: If matching assets found, reply back COMPLIANT
reply contains response if {
	check := {"check_type": "RECOMMENDED"}
	count(matching_assets) > 0
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("Log event with service name [%v] detected.", [required_service_name])}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Policy WARN
# description:  If no matching assets found, reply back WARN
reply contains response if {
	check := {"check_type": "RECOMMENDED"}
	count(matching_assets) == 0
	status := {"status": "WARN"}
	msg := {"msg": sprintf("Log event with service name [%v] not detected.", [required_service_name])}
	response := object.union_n([guardrail, status, msg, description, check])
}
