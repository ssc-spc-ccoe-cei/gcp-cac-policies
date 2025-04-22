# METADATA
# title: Guardrail 07, Validation 01 -  Check for External Forwarding Rules
# description: Check for ingress allow firewall rules with source range too broad
package policies.guardrail_07_0102_fwdingrule

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Asset type must be Policy
required_asset_type := "compute.googleapis.com/ForwardingRule"

# Broad subnet to look foor
insecure_port_range := [
	"80-80",
	"8080-8080",
	"8000-8000",
	"81-81",
	"22-22",
	"3389-3389",
]

# Metadata variables
guardrail := {"guardrail": "07"}
validation := {"validation": "0102"}
description := {"description": "Protection of Data-in-Transit"}

# METADATA
# description: Checks if asset matches required asset type
is_correct_asset(asset) if {
	asset.asset_type == required_asset_type
}

# METADATA
# description: Checks if Forwarding rule is for External LB
is_ingress(asset) if {
	asset.resource.data.loadBalancingScheme == "EXTERNAL"
}

# METADATA
# description: Check if source range matches broad subnet
insecure_open_ports(asset) if {
	asset.resource.data.portRange in insecure_port_range
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
	insecure_open_ports(asset)
}


# METADATA
# title: No Non-Compliant Firewall Rules Found - COMPLIANT
# description: |
# If no firewall rules found that have too broad a source range set are found, then
# reply back COMPLIANT
reply contains response if {
	count(failing_assets) == 0
	status := {"status": "COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": "No TCP Load Balancer/ForwardingRule combination detected using insecure ports"}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Firwall Rule with Broad Source Range - NON-COMPLIANT
# description: | 
# Iterate through assets who have source range set too broad, and who
# are allow rules (if any exist) and reply back NON-COMPLIANT. Include the name of the asset
# and the ports that it's configured for
reply contains response if {
	some asset in matching_assets
	status := {"status": "NON-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	ports := asset.resource.data.portRange
	msg := {"msg": sprintf("TCP Load Balancer/ForwardingRule combination detected using insecure port: [%v].", [ports])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}
