# METADATA
# title: Guardrail 03 , Validation 01 - Check for Monitioring & Audit Logs
# description: Check whether monitoring & auditing is implemented for all user accounts
package policies.guardrail_03_01_acm
#package example

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

required_asset_type:= "accesscontextmanager#accesspolicy"
required_allowed_ip_cidrs:= ["10.0.0.0/8", "192.168.1.0/24"]

# METADATA
# description: list of GCP Org and/or Workspace Customer IDs
# this is not the same as an org ID
# run `gcloud organization list` to find yours
#required_ip_subnets := ["C03xxxx4x", "Abc123", "XYZ890"]


# Metadata variables
guardrail := {"guardrail": "03"}

description := {"description": "validation 01 - Access Context Manager IP Constraints"}

# METADATA
# description: Checks if asset's type matches what's required
is_correct_asset_type(asset) if {
	asset.kind == required_asset_type
}

# METADATA
# description: Check if for every element in the policy's allowed values list,
# it matches an element in the client provided list
# AND the corollary must also be true
has_allowed_customer_ids(asset) if {
  access_levels = asset.config.accessLevels[_]
  conditions = access_levels.basic.conditions[_]
  count(conditions.ipSubnetworks) != 0
  every allowed_ip in conditions.ipSubnetworks {
   some client_ip in required_allowed_ip_cidrs
   allowed_ip == client_ip
  }
  every client_ip in required_allowed_ip_cidrs {
   some allowed_ip in conditions.ipSubnetworks
   allowed_ip == client_ip
  }
}

# METADATA
# title: Check for existence of Workspace logs
# description: Check for a NON MATCH between the provided list and the ipSubnetworks list in ACM policy
contains_non_match := {asset.policyName |
  some asset in input.data
  is_correct_asset_type(asset)
  not has_allowed_customer_ids(asset)
}

# METADATA
# title: Access Context Manager IP Restriction Policy - COMPLIANT
# description: If IP restrictions provided to ACM, then reply back COMPLIANT
reply contains response if {
	count(contains_non_match) == 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": "Access Context Manager IP restrictions detected."}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Dedicated user accounts for administration - NON-COMPLIANT
# description: If NO IP restrictions provided to ACM, then reply back NON-COMPLIANT
reply contains response if {
	count(contains_non_match) > 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
  msg := {"msg": sprintf("Access Policy [%v] contained IPs that did NOT match with provided allowed IP CIDRs.", [contains_non_match])}
	response := object.union_n([guardrail, status, msg, description, check])
}
