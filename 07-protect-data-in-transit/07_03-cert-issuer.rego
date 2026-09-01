# METADATA
# title: Guardrail 07, Validation 03 - Check Certificate CAs
# description: Check that certificates are from approved Certificate Authorities
package policies.guardrail_07_03_certs

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
validation := {"validation": "03"}
description := {"description": "Certificates from Approved CA Issuers"}

# Set check type based on profile and guardrail number
check := common.set_check_type(guardrail.guardrail)

required_asset_kind := "certificatemanager#certificate#issuer"


# METADATA
# title: CLIENT INPUT
# description: |
#   List of approved CAs
#   i.e. required_allowed_ca_issuers_list := ["Let's Encrypt" , "Verisign"]
env := opa.runtime().env
# description: takes on the value of env var, GR07_03_ALLOWED_CA_ISSUERS
#              i.e. export GR07_03_ALLOWED_CA_ISSUERS="Let's Encrypt,Verisign"
required_allowed_ca_issuers_list := split(env["GR07_03_ALLOWED_CA_ISSUERS"], ",")


# METADATA
# title: HELPER FUNCTIONS
is_correct_asset(asset) if {
  asset.kind == required_asset_kind
}

# description: Check if cert is from approved CAs list
has_allowed_ca(asset) if {
  some ca in required_allowed_ca_issuers_list
  is_correct_asset(asset)
  asset.issuer_org == ca
}

# METADATA
# description: processing project profile overrides
is_project_profile_tag(asset) if {
	asset.kind == "cloudresourcemanager#tagged#project"
	endswith(asset.tag_key, "PROJECT_PROFILE")
}

# METADATA
# description: Extract project_id and tag_value from tagged projects
# Result: [project_id, tag_value]
project_profile_details := {[project_id, asset.tag_value] |
	some asset in input.data
	is_project_profile_tag(asset)
	project_id := split(asset.name, "/projects/")[1]
}

# METADATA
# description: |
#   Extract project_id and profile_level
#   Result: [project_id, profile_level]
project_id_and_profile_list := {[project_id, profile_level] |
	some entry in project_profile_details
	project_id := entry[0]
	profile_level := common.extract_profile_from_tag(entry[1])
}

# METADATA
# description: Check if certificate belongs to a tagged project
is_in_tagged_project(asset) if {
	is_correct_asset(asset)
	certificate_project_id := split(asset.name, "/")[1]
	some project_profile in project_id_and_profile_list
	project_profile[0] == certificate_project_id
}


# METADATA
# title: VALIDATION / DATA PROCESSING
# description: Store certificates that are not from approved CAs
violating_assets := {asset |
	some asset in input.data
	is_correct_asset(asset)
	not has_allowed_ca(asset)
}

# METADATA
# description: Violating assets that belong to tagged projects
# Result: [asset, project_id, profile_level]
violating_assets_with_tagged_project := {[asset, project_profile[0], project_profile[1]] |
	some asset in violating_assets
	certificate_project_id := split(asset.name, "/")[1]
	some project_profile in project_id_and_profile_list
	project_profile[0] == certificate_project_id
}

# METADATA
# description: Violating assets NOT in tagged projects (use global profile)
violating_assets_without_tagged_project := {asset |
	some asset in violating_assets
	not is_in_tagged_project(asset)
}


# METADATA
# title: Policy COMPLIANT
# description: If all certificates are from approved CAs, then COMPLIANT
reply contains response if {
	count(violating_assets) == 0
	status := {"status": "COMPLIANT"}
	msg := {"msg": "Certificates are in found to be from approved Certificate Authorities"}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: NON-COMPLIANT - violating assets in non-tagged projects (use global profile)
reply contains response if {
	count(violating_assets_without_tagged_project) > 0
	some asset in violating_assets_without_tagged_project
	status := common.set_status(guardrail.guardrail)
	msg := {"msg": "Certificates have been found to come from non-approved Certificate Authorities"}
	asset_name := {"asset_name": asset.name}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}

# METADATA
# title: NON-COMPLIANT - violating assets in tagged projects (use override profile)
reply contains response if {
	count(violating_assets_with_tagged_project) > 0
	some violating_asset in violating_assets_with_tagged_project
	override_profile := violating_asset[2]
	status := common.set_status_for_profile(guardrail.guardrail, override_profile)
	check_override := common.set_check_type_for_profile(guardrail.guardrail, override_profile)
	msg := {"msg": "Certificates have been found to come from non-approved Certificate Authorities"}
	asset_name := {"asset_name": violating_asset[0].name}
	proj_parent := {"proj_parent": violating_asset[1]}
	proj_profile := {"proj_profile": override_profile}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check_override, proj_parent, proj_profile])
}
