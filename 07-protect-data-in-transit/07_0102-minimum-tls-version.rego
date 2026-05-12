# METADATA
# title: Guardrail 07 - Check Minimum TLS Version
# description: Check web-based services are leveraging minimum TLS 1.2
package policies.guardrail_07_0102_tls

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Import common functions
import data.policies.common

# Metadata variables
guardrail := {"guardrail": "07"}
validation := {"validation": "0102"}
description := {"description": "Protection of Data-in-Transit"}

# Set check type based on profile and guardrail number
check := common.set_check_type(guardrail.guardrail)

# Asset type requirement for both Regional and Global Load Balancers
required_lb_asset_types := ["compute.googleapis.com/ForwardingRule", "compute.googleapis.com/GlobalForwardingRule"]

# Asset type requirement for Target HTTPS Proxies
required_target_proxy_asset_type := "compute.googleapis.com/TargetHttpsProxy"

# Required scheme for external Load Balancers
required_external_scheme := "EXTERNAL_MANAGED"

# Required scheme for internal Load Balancers
required_internal_scheme := "INTERNAL_MANAGED"

# Asset type requirement for SSL Policy
required_ssl_policy_asset_type := "compute.googleapis.com/SslPolicy"

# Required minimum TLS version
required_min_tls_version := "TLS_1_2"

# Required SSL Policy profiles
required_ssl_policy_profiles := ["RESTRICTED", "MODERN"]

# METADATA
# description: Checks if asset matches required load balancer asset type
is_correct_lb_asset(asset) if {
	asset.asset_type in required_lb_asset_types
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
# Result: [project_number, profile_level]
project_id_and_profile_list := {[project_number, profile_level] |
	some entry in project_profile_details
	project_number := entry[0]
	parts := split(entry[1], "/")
	profile_level := array.reverse(parts)[0]
}

# description: Get profile level for an asset based on its ancestors
# Returns the profile level if asset is in a tagged project, empty otherwise
get_asset_profile(asset) := profile_level if {
	has_ancestors_field(asset)
	some proj_id_profile in project_id_and_profile_list
	proj_id_profile[0] in asset.ancestors
	profile_level := proj_id_profile[1]
}

# description: Check if asset belongs to a tagged project
is_in_tagged_project(asset) if {
	has_ancestors_field(asset)
	some proj_id_profile in project_id_and_profile_list
	proj_id_profile[0] in asset.ancestors
}

# description: Get project number for an asset in tagged project
get_asset_project_number(asset) := project_number if {
	has_ancestors_field(asset)
	some proj_id_profile in project_id_and_profile_list
	proj_id_profile[0] in asset.ancestors
	project_number := proj_id_profile[0]
}

# METADATA
# description: Checks if asset matches required target proxy asset type
is_correct_target_proxy_asset(asset) if {
	asset.asset_type == required_target_proxy_asset_type
}

# METADATA
# description: Checks if asset matches required target ssl policy asset type
is_correct_ssl_policy_asset(asset) if {
	asset.asset_type == required_ssl_policy_asset_type
}

# METADATA
# description: Check asset is an external load balancer
is_external_lb(asset) if {
	asset.resource.data.loadBalancingScheme == required_external_scheme
}

# METADATA
# description: Check if asset is an internal load balancer
is_internal_lb(asset) if {
	asset.resource.data.loadBalancingScheme == required_internal_scheme
}

# METADATA
# description: |
# Check if proxy is being used by any of the loadbalancers contained
# in the loadbalancers variable.
is_target(proxy, loadbalancers) if {
	proxy.resource.data.selfLink == loadbalancers[_].resource.data.target
}

# METADATA
# description: Check if min TLS version set matches what's required
is_required_mintls_version(asset) if {
	asset.resource.data.minTlsVersion == required_min_tls_version
}

# METADATA
# description: Check if profile used is in required_ssl_policy_profile list
is_required_tls_profile(asset) if {
	asset.resource.data.profile == required_ssl_policy_profiles[_]
}

# METADATA
# description: |
# If GCP Default SSL policy is being used, it won't show up
# in asset inventory. Therefore, we can check for the lack of
# sslPolicy key and assume it's being used if not present
is_using_default_ssl_policy(asset) if {
	not asset.resource.data.sslPolicy
}

# description: |
# Check for the policy's name in variable containing all
# the valid SSL policies. If found, then policy is valid
is_using_valid_ssl_policy(policy_name) if {
	policy_name == valid_ssl_policies[_].resource.data.selfLink
}

# METADATA
# title: Check for Load Balancers
# description: Store assets who are load balancers (forwarding rules)
load_balancing_assets := {asset |
	some asset in input.data
	is_correct_lb_asset(asset)
}

# METADATA
# title: Check for External Load Balancers
# description: Store assets who are external load balancers
ext_load_balancing_assets := {asset |
	some asset in load_balancing_assets
	is_external_lb(asset)
}

# METADATA
# title: Check for Internal Load Balancers
# description: Store assets who are internal load balancers
int_load_balancing_assets := {asset |
	some asset in load_balancing_assets
	is_internal_lb(asset)
}

# METADATA
# title: Check for Target Proxies
# description: Store assets who are target proxies
target_proxy_assets := {asset |
	some asset in input.data
	is_correct_target_proxy_asset(asset)
}

# METADATA
# title: Check for External Target Proxies
# description: Store target proxies that are targets of external load balancers
ext_target_proxy_assets := {proxy |
	some proxy in target_proxy_assets
	is_target(proxy, ext_load_balancing_assets)
}

# METADATA
# title: Check for Internal Target Proxies
# description: Store target proxies that are targets of internal load balancers
int_target_proxy_assets := {proxy |
	some proxy in target_proxy_assets
	is_target(proxy, int_load_balancing_assets)
}

# METADATA
# title: Check for SSL Policies
# description: Store SSL policies assets
ssl_policy_assets := {asset |
	some asset in input.data
	is_correct_ssl_policy_asset(asset)
}

# METADATA
# title: Check for valid SSL Policy
# description: Check if SSL Policy Asset is set with correct min. TLS version and profile
valid_ssl_policies := {asset |
	some asset in ssl_policy_assets
	is_required_mintls_version(asset)
	is_required_tls_profile(asset)
}

# METADATA
# title: Check for Invalid min. TLS
# description: Check if SSL Policy Asset is not set with correct min. TLS version
invalid_version_ssl_policies := {asset |
	some asset in ssl_policy_assets
	not is_required_mintls_version(asset)
}

# METADATA
# title: Check for Invalid Profile
# description: Check if SSL Policy Asset is not set with correct profile
invalid_profile_ssl_policies := {asset |
	some asset in ssl_policy_assets
	not is_required_tls_profile(asset)
}

# METADATA
# title: SSL Policy Invalid Minimum TLS - NON-COMPLIANT (non-tagged projects)
reply contains response if {
	some asset in invalid_version_ssl_policies
	not is_in_tagged_project(asset)
	asset_min_tls_version := asset.resource.data.minTlsVersion
	status := common.set_status(guardrail.guardrail)
	msg := {"msg": sprintf("SSL Policy with invalid Minimum TLS Version set. Correct: [%v]. Detected: [%v].", [required_min_tls_version, asset_min_tls_version])}
	asset_name := {"asset_name": asset.name}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}

# METADATA
# title: SSL Policy Invalid Minimum TLS - NON-COMPLIANT (tagged projects)
reply contains response if {
	some asset in invalid_version_ssl_policies
	is_in_tagged_project(asset)
	override_profile := get_asset_profile(asset)
	status := common.set_status_for_profile(guardrail.guardrail, override_profile)
	check_override := common.set_check_type_for_profile(guardrail.guardrail, override_profile)
	asset_min_tls_version := asset.resource.data.minTlsVersion
	msg := {"msg": sprintf("SSL Policy with invalid Minimum TLS Version set. Correct: [%v]. Detected: [%v].", [required_min_tls_version, asset_min_tls_version])}
	asset_name := {"asset_name": asset.name}
	proj_parent := {"proj_parent": get_asset_project_number(asset)}
	proj_profile := {"proj_profile": override_profile}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check_override, proj_parent, proj_profile])
}

# METADATA
# title: SSL Policy Invalid Profile - NON-COMPLIANT (non-tagged projects)
reply contains response if {
	some asset in invalid_profile_ssl_policies
	not is_in_tagged_project(asset)
	asset_ssl_policy_profile := asset.resource.data.profile
	status := common.set_status(guardrail.guardrail)
	msg := {"msg": sprintf("SSL Policy with invalid Profile set. Correct: [%v]. Detected: [%v].", [required_ssl_policy_profiles, asset_ssl_policy_profile])}
	asset_name := {"asset_name": asset.name}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}

# METADATA
# title: SSL Policy Invalid Profile - NON-COMPLIANT (tagged projects)
reply contains response if {
	some asset in invalid_profile_ssl_policies
	is_in_tagged_project(asset)
	override_profile := get_asset_profile(asset)
	status := common.set_status_for_profile(guardrail.guardrail, override_profile)
	check_override := common.set_check_type_for_profile(guardrail.guardrail, override_profile)
	asset_ssl_policy_profile := asset.resource.data.profile
	msg := {"msg": sprintf("SSL Policy with invalid Profile set. Correct: [%v]. Detected: [%v].", [required_ssl_policy_profiles, asset_ssl_policy_profile])}
	asset_name := {"asset_name": asset.name}
	proj_parent := {"proj_parent": get_asset_project_number(asset)}
	proj_profile := {"proj_profile": override_profile}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check_override, proj_parent, proj_profile])
}

# METADATA
# title: SSL Policy Valid - COMPLIANT
# description: | 
# Iterate through SSL policies with valid profile and min. TLS
# set (if any exist) and reply back COMPLIANT. Include the name of the asset
reply contains response if {
	some asset in valid_ssl_policies
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("SSL Policy with valid Profile set [%v] and valid Min. TLS set [%v] detected.", [required_ssl_policy_profiles, required_min_tls_version])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: External LB using Default SSL Policy - NON-COMPLIANT (non-tagged projects)
reply contains response if {
	some asset in ext_target_proxy_assets
	is_using_default_ssl_policy(asset)
	not is_in_tagged_project(asset)
	status := common.set_status(guardrail.guardrail)
	msg := {"msg": "External HTTPS Load Balancer using [GCP Default] SSL Policy."}
	asset_name := {"asset_name": asset.name}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}

# METADATA
# title: External LB using Default SSL Policy - NON-COMPLIANT (tagged projects)
reply contains response if {
	some asset in ext_target_proxy_assets
	is_using_default_ssl_policy(asset)
	is_in_tagged_project(asset)
	override_profile := get_asset_profile(asset)
	status := common.set_status_for_profile(guardrail.guardrail, override_profile)
	check_override := common.set_check_type_for_profile(guardrail.guardrail, override_profile)
	msg := {"msg": "External HTTPS Load Balancer using [GCP Default] SSL Policy."}
	asset_name := {"asset_name": asset.name}
	proj_parent := {"proj_parent": get_asset_project_number(asset)}
	proj_profile := {"proj_profile": override_profile}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check_override, proj_parent, proj_profile])
}

# METADATA
# title: External LB using Invalid SSL Policy - NON-COMPLIANT (non-tagged projects)
reply contains response if {
	some asset in ext_target_proxy_assets
	policy_name := asset.resource.data.sslPolicy
	not is_using_valid_ssl_policy(policy_name)
	not is_in_tagged_project(asset)
	status := common.set_status(guardrail.guardrail)
	msg := {"msg": "External HTTPS Load Balancer using invalid SSL Policy."}
	asset_name := {"asset_name": policy_name}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}

# METADATA
# title: External LB using Invalid SSL Policy - NON-COMPLIANT (tagged projects)
reply contains response if {
	some asset in ext_target_proxy_assets
	policy_name := asset.resource.data.sslPolicy
	not is_using_valid_ssl_policy(policy_name)
	is_in_tagged_project(asset)
	override_profile := get_asset_profile(asset)
	status := common.set_status_for_profile(guardrail.guardrail, override_profile)
	check_override := common.set_check_type_for_profile(guardrail.guardrail, override_profile)
	msg := {"msg": "External HTTPS Load Balancer using invalid SSL Policy."}
	asset_name := {"asset_name": policy_name}
	proj_parent := {"proj_parent": get_asset_project_number(asset)}
	proj_profile := {"proj_profile": override_profile}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check_override, proj_parent, proj_profile])
}

# METADATA
# title: External LB using Valid SSL Policy - Compliant
# description: | 
# Iterate through external LBs (if any exist) and check if the SSL policy they're
# using is valid. If yes, reply back COMPLIANT and include the name of the LB 
# and the SSL policy it's using
reply contains response if {
	some asset in ext_target_proxy_assets
	policy_name := asset.resource.data.sslPolicy
	is_using_valid_ssl_policy(policy_name)
	status := {"status": "COMPLIANT"}
	msg := {"msg": "External HTTPS Load Balancer using valid SSL Policy."}
  asset_name := {"asset_name": policy_name}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}

# METADATA
# title: Internal LB using Default SSL Policy - NON-COMPLIANT (non-tagged projects)
reply contains response if {
	some asset in int_target_proxy_assets
	is_using_default_ssl_policy(asset)
	not is_in_tagged_project(asset)
	status := common.set_status(guardrail.guardrail)
	msg := {"msg": "Internal HTTPS Load Balancer using [GCP Default] SSL Policy."}
	asset_name := {"asset_name": asset.name}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}

# METADATA
# title: Internal LB using Default SSL Policy - NON-COMPLIANT (tagged projects)
reply contains response if {
	some asset in int_target_proxy_assets
	is_using_default_ssl_policy(asset)
	is_in_tagged_project(asset)
	override_profile := get_asset_profile(asset)
	status := common.set_status_for_profile(guardrail.guardrail, override_profile)
	check_override := common.set_check_type_for_profile(guardrail.guardrail, override_profile)
	msg := {"msg": "Internal HTTPS Load Balancer using [GCP Default] SSL Policy."}
	asset_name := {"asset_name": asset.name}
	proj_parent := {"proj_parent": get_asset_project_number(asset)}
	proj_profile := {"proj_profile": override_profile}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check_override, proj_parent, proj_profile])
}

# METADATA
# title: Internal LB using Invalid SSL Policy - NON-COMPLIANT (non-tagged projects)
reply contains response if {
	some asset in int_target_proxy_assets
	policy_name := asset.resource.data.sslPolicy
	not is_using_valid_ssl_policy(policy_name)
	not is_in_tagged_project(asset)
	status := common.set_status(guardrail.guardrail)
	msg := {"msg": "Internal HTTPS Load Balancer using invalid SSL Policy."}
	asset_name := {"asset_name": policy_name}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}

# METADATA
# title: Internal LB using Invalid SSL Policy - NON-COMPLIANT (tagged projects)
reply contains response if {
	some asset in int_target_proxy_assets
	policy_name := asset.resource.data.sslPolicy
	not is_using_valid_ssl_policy(policy_name)
	is_in_tagged_project(asset)
	override_profile := get_asset_profile(asset)
	status := common.set_status_for_profile(guardrail.guardrail, override_profile)
	check_override := common.set_check_type_for_profile(guardrail.guardrail, override_profile)
	msg := {"msg": "Internal HTTPS Load Balancer using invalid SSL Policy."}
	asset_name := {"asset_name": policy_name}
	proj_parent := {"proj_parent": get_asset_project_number(asset)}
	proj_profile := {"proj_profile": override_profile}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check_override, proj_parent, proj_profile])
}

# METADATA
# title: Internal LB using Valid SSL Policy - Compliant
# description: | 
# Iterate through internal LBs (if any exist) and check if the SSL policy they're
# using is valid. If yes, reply back COMPLIANT and include the name of the LB 
# and the SSL policy it's using
reply contains response if {
	some asset in int_target_proxy_assets
	policy_name := asset.resource.data.sslPolicy
	is_using_valid_ssl_policy(policy_name)
	status := {"status": "COMPLIANT"}
	msg := {"msg": "Internal HTTPS Load Balancer using valid SSL Policy."}
  asset_name := {"asset_name": policy_name}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}
