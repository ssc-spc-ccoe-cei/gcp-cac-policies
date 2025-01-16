# METADATA
# title: Guardrail 03 , Validation 01 - Check for Allowed Policy Member Domains
# description: Check whether monitoring & auditing is implemented for all user accounts
package policies.guardrail_03_01_domains

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in


# Metadata variables
guardrail := {"guardrail": "03"}
description := {"description": "validation 01 - Dedicated Admin accounts"}

required_asset_type := "orgpolicy.googleapis.com/Policy"
required_policy := "policies/iam.allowedPolicyMemberDomains"


# METADATA
# title: CLIENT INPUT
# description: list of GCP Org and/or Workspace Customer IDs
# run `gcloud organization list` to find yours
required_customer_ids := ["C03xxxx4x", "Abc123", "XYZ890"]
env := opa.runtime().env
# description: takes on the value of env var, GR03_01_CUSTOMER_IDS
#              list of GCP Org and/or Workspace Customer IDs
#              run `gcloud organization list` to find yours
#              i.e. export GR03_01_CUSTOMER_IDS='C03xxxx4x,Abc123,XYZ890'
required_customer_ids := split(env["GR03_01_CUSTOMER_IDS"], ",")


# METADATA
# title: HELPER FUNCTIONS
# description: Checks if asset's type matches what's required
is_correct_asset_type(asset) if {
	asset.asset_type == required_asset_type
  endswith(asset.name, required_policy)
}

is_org_policy(asset) if {
  split(asset.name, "/")[3] == "organizations"
}

# description: Check if for every element in the policy's allowed values list,
# it matches an element in the client provided list
# AND the corollary must also be true
has_allowed_customer_ids(asset) if {
  values = asset.resource.data.spec.rules[_].values
  count(values.allowedValues) != 0
  every allowed_id in values.allowedValues {
   some customer_id in required_customer_ids
   allowed_id == customer_id
  }
  every customer_id in required_customer_ids {
   some allowed_id in values.allowedValues
   allowed_id == customer_id
  }
}


# METADATA
# title: VALIDATION / DATA PROCESSING
# title: Check for existence of Workspace logs
# description: Check for a NON MATCH between the provided list and the allowedValues list in policy
contains_non_match := {asset.resource.data.spec.rules[_].values.allowedValues[_] |
  some asset in input.data
  is_correct_asset_type(asset)
  is_org_policy(asset)
  not has_allowed_customer_ids(asset)
}


# METADATA
# title: Dedicated user accounts for administration - COMPLIANT
# description: If priveged user accounts are dedicated Organization Admins then reply back COMPLIANT
reply contains response if {
	count(contains_non_match) == 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": "Policy Member Domains configuration detected."}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Dedicated user accounts for administration - NON-COMPLIANT
# description: If priveged user accounts are NOT dedicated Organization Admins then reply back NON-COMPLIANT
reply contains response if {
	count(contains_non_match) > 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Items in policy allowed values of [%v] do NOT match the client provided list of %v.", [contains_non_match, required_customer_ids])}
	response := object.union_n([guardrail, status, msg, description, check])
}
