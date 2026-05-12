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

# Import common functions
import data.policies.common

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

# Set check type based on profile and guardrail number
check := common.set_check_type(guardrail.guardrail)

# METADATA
# description: Checks if asset matches required asset type
is_correct_asset(asset) if {
	asset.asset_type == required_asset_type
}

# description: Check if asset has ancestors field (used for project matching)
has_ancestors_field(asset) if {
	asset.ancestors
	not asset.kind
}

# METADATA
# title: processing project profile overrides
is_project_profile_tag(asset) if {
	asset.kind == "cloudresourcemanager#tagged#project"
	endswith(asset.tag_key, "PROJECT_PROFILE")
}

# description: Extract project_number and tag_value from tagged projects
# Result: [project_number, tag_value]
project_profile_details := {[asset.project_number, asset.tag_value] |
	some asset in input.data
	is_project_profile_tag(asset)
}

# description: Extract project_number and profile_level
# tag_value format: "ORG_ID/PROJECT_PROFILE/LEVEL" (e.g., "779217891544/PROJECT_PROFILE/1")
# Result: [project_number, profile_level]
project_id_and_profile_list := {[project_number, profile_level] |
	some entry in project_profile_details
	project_number := entry[0]
	parts := split(entry[1], "/")
	profile_level := array.reverse(parts)[0]
}

# description: Check if asset belongs to a tagged project
is_in_tagged_project(asset) if {
	has_ancestors_field(asset)
	some proj_id_profile in project_id_and_profile_list
	proj_id_profile[0] in asset.ancestors
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

# description: Failing assets that belong to tagged projects
# Result: [asset, project_number, profile_level]
failing_assets_with_tagged_project := {[asset, proj_id_profile[0], proj_id_profile[1]] |
	some asset in failing_assets
	has_ancestors_field(asset)
	some proj_id_profile in project_id_and_profile_list
	proj_id_profile[0] in asset.ancestors
}

# description: Failing assets NOT in tagged projects (use global profile)
failing_assets_without_tagged_project := {asset |
	some asset in failing_assets
	not is_in_tagged_project(asset)
}


# METADATA
# title: No Non-Compliant Firewall Rules Found - COMPLIANT
# description: |
# If no firewall rules found that have too broad a source range set are found, then
# reply back COMPLIANT
reply contains response if {
	count(failing_assets) == 0
	status := {"status": "COMPLIANT"}
	msg := {"msg": "No TCP Load Balancer/ForwardingRule combination detected using insecure ports"}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: NON-COMPLIANT - failing assets in non-tagged projects (use global profile)
reply contains response if {
	count(failing_assets_without_tagged_project) > 0
	some asset in failing_assets_without_tagged_project
	status := common.set_status(guardrail.guardrail)
	ports := asset.resource.data.portRange
	msg := {"msg": sprintf("TCP Load Balancer/ForwardingRule combination detected using insecure port: [%v].", [ports])}
	asset_name := {"asset_name": asset.name}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}

# METADATA
# title: NON-COMPLIANT - failing assets in tagged projects (use override profile)
reply contains response if {
	count(failing_assets_with_tagged_project) > 0
	some failing_asset in failing_assets_with_tagged_project
	# failing_asset structure: [asset, project_number, profile_level]
	override_profile := failing_asset[2]
	status := common.set_status_for_profile(guardrail.guardrail, override_profile)
	check_override := common.set_check_type_for_profile(guardrail.guardrail, override_profile)
	ports := failing_asset[0].resource.data.portRange
	msg := {"msg": sprintf("TCP Load Balancer/ForwardingRule combination detected using insecure port: [%v].", [ports])}
	asset_name := {"asset_name": failing_asset[0].name}
	proj_parent := {"proj_parent": failing_asset[1]}
	proj_profile := {"proj_profile": override_profile}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check_override, proj_parent, proj_profile])
}
