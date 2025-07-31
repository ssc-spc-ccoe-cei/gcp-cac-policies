# METADATA title: Guardrail 01, Validation 03 - Global Admin count
# description: Check for global admin count
package policies.guardrail_01_03_accounts

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Import common functions
import data.policies.common

# Name of files data object to look for
required_name := "guardrail-01"
validation_number := "03"

# Metadata variables
guardrail := {"guardrail": "01"}
validation := {"validation": "03"}
description := {"description": "Global Admins count"}

# Set check type based on profile and guardrail number
check := common.set_check_type(guardrail.guardrail)

# METADATA
# title: CLIENT INPUT
# description: takes on the value of env var, GR01_03_ORG_ADMIN_GROUP_EMAIL
# i.e. export GR01_03_ORG_ADMIN_GROUP_EMAIL='gcp-organization-admins@ssc.gc.ca'
env := opa.runtime().env
required_org_admin_group_email := env["GR01_03_ORG_ADMIN_GROUP_EMAIL"]

is_correct_asset(asset) if {
  asset.kind == "cloudidentity#groups#membership"
}

# METADATA
# title: VALIDATION / DATA PROCESSING
gcp_org_admin_members_list := { member |
  some asset in input.data
  is_correct_asset(asset)
  asset.groupEmail == required_org_admin_group_email
  some member in asset.members
}

iam_org_admin_members_list := { member |
  some asset in input.data
  bindings := asset.iam_policy.bindings
  some binding in bindings
  binding.role == "roles/resourcemanager.organizationAdmin"
  some user in binding.members
  startswith(user, "user:")
  member := user
}

combined_members_set := gcp_org_admin_members_list | iam_org_admin_members_list

# METADATA
# title: Global Admins Policy - COMPLIANT
# description: If number of Global/Org Admins is between 2 and 5 (inclusive), then COMPLIANT
reply contains response if {
  count(combined_members_set) >= 2
  count(combined_members_set) <= 5
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("Valid number of Org Admins found for [%v, validation %v]. [%v] Org Admins were found.", [required_name, validation_number, count(combined_members_set)])}
  asset_name := {"asset_name": combined_members_set}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If too few Global/Org Admins detected, then NON-COMPLIANT
reply contains response if {
  count(combined_members_set) < 2
	status := common.set_status(guardrail.guardrail)
	msg := {"msg": sprintf("Less than 2 Organization Admins found.  There should be at least 2, and no more than 5 for [%v, validation %v]. [%v] were found.", [required_name, validation_number, count(combined_members_set)])}
  asset_name := {"asset_name": combined_members_set}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If too many Global/Org Admins detected, then NON-COMPLIANT
reply contains response if {
  count(combined_members_set) > 5
	status := common.set_status(guardrail.guardrail)
	msg := {"msg": sprintf("More than 5 Organization Admins found.  There should be at least 2, and no more than 5 for [%v, validation %v]. [%v] were found.", [required_name, validation_number, count(combined_members_set)])}
  asset_name := {"asset_name": combined_members_set}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}
