# METADATA
# title: Guardrail 09 - Check for Broad Firewall Rules
# description: Check for ingress allow firewall rules with source range too broad
package policies.guardrail_09_firewall

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Asset type must be Policy
required_asset_type := "compute.googleapis.com/Firewall"

# Broad subnet to look foor
broad_subnet := ["0.0.0.0/0"]

# Metadata variables
guardrail := {"guardrail": "09"}

description := {"description": "GUARDRAIL 9: NETWORK SECURITY SERVICES"}

# METADATA
# description: Checks if asset matches required asset type
is_correct_asset(asset) if {
	asset.asset_type == required_asset_type
}

# METADATA
# description: Checks if firewall rule is for INGRESS
is_ingress(asset) if {
	asset.resource.data.direction == "INGRESS"
}

# METADATA
# description: Check if source range matches broad subnet
source_too_broad(asset) if {
	asset.resource.data.sourceRanges == broad_subnet
}

# METADATA
# description: Check if allowed key exists, indicating allow rule
is_allow_rule(asset) if {
	asset.resource.data.allowed
}

# METADATA
# title: Check for Matching Assets
# description: Store assets who match the required asset_type and are ingress rules
matching_assets := {asset |
	some asset in input.data
	is_correct_asset(asset)
	is_ingress(asset)
}

# METADATA
# title: Check for Failing Assets
# description: |
# Store assets who have a source range set that's too broad
# and who's rule type is allow
failing_assets := {asset |
	some asset in matching_assets
	source_too_broad(asset)
	is_allow_rule(asset)
}

# METADATA
# title: Firwall Rule with Broad Source Range - WARN
# description: | 
# Iterate through assets who have source range set too broad, and who
# are allow rules (if any exist) and reply back WARN. Include the name of the asset
# and the ports that it's configured for
reply contains response if {
	some asset in failing_assets
	status := {"status": "WARN"}
	check := {"check_type": "RECOMMENDED"}
	ports := asset.resource.data.allowed[_].ports
	msg := {"msg": sprintf("Ingress Firewall allow rule detected with source range too broad %v on port(s) %v.", [broad_subnet, ports])}
	asset_name := {"asset_name": asset.name}
	response := object.union_n([guardrail, status, msg, asset_name, description, check])
}

# METADATA
# title: No Non-Compliant Firewall Rules Found - COMPLIANT
# description: |
# If no firewall rules found that have too broad a source range set are found, then
# reply back COMPLIANT
reply contains response if {
	count(failing_assets) == 0
	status := {"status": "COMPLIANT"}
	check := {"check_type": "RECOMMENDED"}
	msg := {"msg": sprintf("No Ingress Firewall allow rules detected with source range too broad [%v].", [broad_subnet])}
	response := object.union_n([guardrail, status, msg, description, check])
}
