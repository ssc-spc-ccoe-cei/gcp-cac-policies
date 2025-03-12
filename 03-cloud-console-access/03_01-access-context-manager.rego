# METADATA
# title: Guardrail 03 , Validation 01 - Check for Access Context Manage IP Constraints
# description: Check whether IP Constraints being implemented for Endpoint Management
package policies.guardrail_03_01_acm
#package example

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Metadata variables
guardrail := {"guardrail": "03"}
validation := {"validation": "01"}
description := {"description": "Endpoint Management - Allowed Policy Member Domains and Access Context Manager IP Constraints"}

required_asset_type:= "accesscontextmanager#accesspolicy"


# METADATA
# title: CLIENT INPUT
# description: list of allowed CIDRs
env := opa.runtime().env
# description: takes on the value of env var, GR03_01_ALLOWED_CIDRS
#              list of allowed network CIDRs
#              i.e. export GR03_01_ALLOWED_CIDRS='10.0.0.0/8,192.168.1.0/24'
required_allowed_cidrs := split(env["GR03_01_ALLOWED_CIDRS"], ",")


# METADATA
# title: HELPER FUNCTIONS
# description: Checks if asset's type matches what's required
is_correct_asset_type(asset) if {
	asset.kind == required_asset_type
}

has_ip_condition(asset) if {
	asset.kind == required_asset_type
  access_levels = asset.config.accessLevels[_]
  conditions = access_levels.basic.conditions[_]
  count(conditions.ipSubnetworks) != 0
}

has_region_condition(asset) if {
	asset.kind == required_asset_type
  access_levels = asset.config.accessLevels[_]
  conditions = access_levels.basic.conditions[_]
  count(conditions.regions) != 0
}

# description: Check if for every element in the policy's allowed values list,
# it matches an element in the client provided list
# AND the corollary must also be true
has_allowed_customer_ids(asset) if {
  is_correct_asset_type(asset)
  access_levels = asset.config.accessLevels[_]
  conditions = access_levels.basic.conditions[_]
  count(conditions.ipSubnetworks) != 0
  every allowed_ip in conditions.ipSubnetworks {
   some client_ip in required_allowed_cidrs
   allowed_ip == client_ip
  }
  every client_ip in required_allowed_cidrs {
   some allowed_ip in conditions.ipSubnetworks
   allowed_ip == client_ip
  }
}


# METADATA
# title: VALIDATION / DATA PROCESSING
# description: Check for a NON MATCH between the provided list and the ipSubnetworks list in ACM policy
contains_non_match := {asset.policyName |
  some asset in input.data
  has_ip_condition(asset)
  not has_allowed_customer_ids(asset)
}

contains_region_conditions_only := {asset.policyName |
  some asset in input.data
  has_region_condition(asset)
  not has_ip_condition(asset)
}

# METADATA
# title: Access Context Manager IP Restriction Policy - COMPLIANT
# description: If IP restrictions provided to ACM, then reply back COMPLIANT
reply contains response if {
  not contains_region_conditions_only
	count(contains_non_match) == 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": "Access Context Manager IP restrictions detected."}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Dedicated user accounts for administration - NON-COMPLIANT
# description: If NO IP restrictions provided to ACM, then reply back NON-COMPLIANT
reply contains response if {
  not contains_region_conditions_only
	count(contains_non_match) > 0
  some non_match in contains_non_match
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
  msg := {"msg": "Access Policy contained IPs that did NOT match with provided allowed IP CIDRs."}
  asset_name := {"asset_name": non_match}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}

# METADATA
# title: Dedicated user accounts for administration - NON-COMPLIANT
# description: If NO IP restrictions provided to ACM, then reply back NON-COMPLIANT
reply contains response if {
  contains_region_conditions_only
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
  msg := {"msg": "Access Policy contains REGION conditions. This guardrail requires that you set IP conditions."}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}
