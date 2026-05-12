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
# description: List of approved CAs
#required_allowed_ca_issuers_list := ["Let's Encrypt" , "Verisign"]
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

# description: Check if asset belongs to a tagged project
is_in_tagged_project(asset) if {
	has_ancestors_field(asset)
	some proj_id_profile in project_id_and_profile_list
	proj_id_profile[0] in asset.ancestors
}


# METADATA
# title: VALIDATION / DATA PROCESSING
# description: Store violating cert assets (not from approved CAs)
violating_certs := {asset |
	some asset in input.data
	is_correct_asset(asset)
	not has_allowed_ca(asset)
}

# description: Violating certs that belong to tagged projects
# Result: [asset, project_number, profile_level]
violating_certs_with_tagged_project := {[asset, proj_id_profile[0], proj_id_profile[1]] |
	some asset in violating_certs
	has_ancestors_field(asset)
	some proj_id_profile in project_id_and_profile_list
	proj_id_profile[0] in asset.ancestors
}

# description: Violating certs NOT in tagged projects (use global profile)
violating_certs_without_tagged_project := {asset |
	some asset in violating_certs
	not is_in_tagged_project(asset)
}


# METADATA
# title: Policy COMPLIANT
# description: If all certificates are from approved CAs, then COMPLIANT
reply contains response if {
	count(violating_certs) == 0
	status := {"status": "COMPLIANT"}
	msg := {"msg": "Certificates are found to be from approved Certificate Authorities"}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: NON-COMPLIANT - violating certs in non-tagged projects (use global profile)
reply contains response if {
	count(violating_certs_without_tagged_project) > 0
	some asset in violating_certs_without_tagged_project
	status := common.set_status(guardrail.guardrail)
	msg := {"msg": "Certificates have been found to come from non-approved Certificate Authorities"}
	asset_name := {"asset_name": asset.name}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}

# METADATA
# title: NON-COMPLIANT - violating certs in tagged projects (use override profile)
reply contains response if {
	count(violating_certs_with_tagged_project) > 0
	some violating_cert in violating_certs_with_tagged_project
	# violating_cert structure: [asset, project_number, profile_level]
	override_profile := violating_cert[2]
	status := common.set_status_for_profile(guardrail.guardrail, override_profile)
	check_override := common.set_check_type_for_profile(guardrail.guardrail, override_profile)
	msg := {"msg": "Certificates have been found to come from non-approved Certificate Authorities"}
	asset_name := {"asset_name": violating_cert[0].name}
	proj_parent := {"proj_parent": violating_cert[1]}
	proj_profile := {"proj_profile": override_profile}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check_override, proj_parent, proj_profile])
}
