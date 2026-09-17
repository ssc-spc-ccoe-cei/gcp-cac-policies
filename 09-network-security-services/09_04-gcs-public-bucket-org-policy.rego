# METADATA
# title: Guardrail 09 - Enforce Public Access Prevention Org. Policy
# description: Check for Enforce Public Access Prevention Organization Policy.
package policies.guardrail_09_04_bucket

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Import common functions
import data.policies.common

# Metadata variables
guardrail := {"guardrail": "09"}
validation := {"validation": "04"}
description := {"description": "Storage Bucket Public Access Prevention"}

# Set check type based on profile and guardrail number
check := common.set_check_type(guardrail.guardrail)

# Asset type must be Policy
required_asset_type := "orgpolicy.googleapis.com/Policy"

# Org Policy must be storage.publicAccessPrevention
required_policy := "policies/storage.publicAccessPrevention"

# METADATA
# description: Checks if asset is required type
is_correct_asset(asset) if {
	asset.asset_type == required_asset_type
}

# METADATA
# description: Checks if org policy is correct
is_correct_org_policy(asset) if {
	endswith(asset.name, required_policy)
}

# METADATA
# title: Policy Enforced
# description: Checks if Org Policy is enforced
is_enforced(asset) if {
	asset.resource.data.spec.rules[0].enforce == true
}

# METADATA
# title: Organizational Org Policy
# description: Checks if Org Policy is set at Organization level
is_org_level_policy(asset) if {
	split(asset.name, "/")[3] == "organizations"
}

# METADATA
# title: Project Org Policy
# description: Checks if Org Policy is set at Project level
is_proj_level_policy(asset) if {
	split(asset.name, "/")[3] == "projects"
}

# METADATA
# title: PROJECT_PROFILE TAG PROCESSING
# description: |
#   Mirrors the pattern in 05_01-restrict-location-org-policy.rego. The
#   collector emits records of kind "cloudresourcemanager#tagged#project"
#   with project_number in the form "projects/<NUMBER>" and tag_value in
#   the form "<ORG_ID>/PROJECT_PROFILE/<LEVEL>".
is_project_profile_tag(asset) if {
	asset.kind == "cloudresourcemanager#tagged#project"
	endswith(asset.tag_key, "PROJECT_PROFILE")
}

# METADATA
# description: Extract [project_number, profile_level] from tagged projects
project_id_and_profile_list := {[asset.project_number, profile_level] |
	some asset in input.data
	is_project_profile_tag(asset)
	parts := split(asset.tag_value, "/")
	count(parts) >= 3
	profile_level := array.reverse(parts)[0]
}

# METADATA
# description: |
#   Profile levels for which a project-level storage.publicAccessPrevention
#   exception is tolerated. Profile 1 (Experimentation) per client request.
#   GR09 is recommended for Profile 1 and required for Profiles 2-6 per
#   common.profile_enforcement.
exempt_profile_levels := {"1"}

# METADATA
# description: Projects tagged with an exempt profile level
exempt_profile_projects := {entry[0] |
	some entry in project_id_and_profile_list
	entry[1] in exempt_profile_levels
}

# METADATA
# description: |
#   Org Policy asset belongs to a project tagged with an exempt profile.
#   Primary join is via CAI ancestors; fallback join is on the asset name
#   segment for exports where the orgpolicy asset carries no ancestors field.
is_exempt_profile_project_policy(asset) if {
	some proj in exempt_profile_projects
	proj in asset.ancestors
}

is_exempt_profile_project_policy(asset) if {
	some proj in exempt_profile_projects
	startswith(asset.name, sprintf("//orgpolicy.googleapis.com/%s/", [proj]))
}

# METADATA
# title: Check for Matching Assets
# description: Check if Asset's type is Org Policy matching required_policy
matching_assets := {asset |
	some asset in input.data
	is_correct_asset(asset)
	is_correct_org_policy(asset)
}

# METADATA
# title: Check for Org Level Assets
# description: Check if Org Policy is configured at Org level and is enforced
enforced_org_level_assets := {asset |
	some asset in matching_assets
	is_org_level_policy(asset)
	is_enforced(asset)
}

# METADATA
# title: Check for Org Level Assets
# description: Check if Org Policy is configured at Org level and is NOT enforced
non_enforced_org_level_assets := {asset |
	some asset in matching_assets
	is_org_level_policy(asset)
	not is_enforced(asset)
}

# METADATA
# title: Check for Project Level Assets
# description: Check if Org Policy is configured at Project level and is enforced
enforced_proj_level_assets := {asset |
	some asset in matching_assets
	is_proj_level_policy(asset)
	is_enforced(asset)
}

# METADATA
# title: Check for Project Level Assets
# description: |
#   Check if Org Policy is configured at Project level and is NOT enforced.
#   Projects tagged with an exempt PROJECT_PROFILE level are excluded.
non_enforced_proj_level_assets := {asset |
	some asset in matching_assets
	is_proj_level_policy(asset)
	not is_enforced(asset)
	not is_exempt_profile_project_policy(asset)
}

# METADATA
# title: Exempt Project Level Assets
# description: |
#   Project level Org Policies that are NOT enforced but belong to projects
#   tagged with an exempt PROJECT_PROFILE level. Tracked separately for
#   reporting visibility - these do not block the COMPLIANT verdict.
exempt_profile_proj_level_assets := {asset |
	some asset in matching_assets
	is_proj_level_policy(asset)
	not is_enforced(asset)
	is_exempt_profile_project_policy(asset)
}

# METADATA
# title: Enforced Org Level Org Policy - COMPLIANT
# description: |
#   Iterate through org level org policy assets that are enforced 
#   (if any exist). Check that no project level org policies
#   that are not enforced exist. If yes to all then reply back 
#   COMPLIANT and with name of asset
reply contains response if {
	some asset in enforced_org_level_assets
	count(non_enforced_proj_level_assets) == 0
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("Organization Policy [%v] detected at the Organization level and enforced.", [required_policy])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Not Enforced Org Level Org Policy - NON-COMPLIANT
# description: |
#   Iterate through org level org policy assets that are NOT
#   enforced(if any exist). If any exist then reply back 
#   NON-COMPLIANT and with name of asset
reply contains response if {
	some asset in non_enforced_org_level_assets
	status := common.set_status(guardrail.guardrail)
	msg := {"msg": sprintf("Organization Policy [%v] detected at the Organization level and NOT enforced.", [required_policy])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Not Enforced Project Level Org Policy & Enforced Org Level Policy - NON-COMPLIANT
# description: |
#   Iterate through project level policy asset(s) that are NOT enforced
#   (if any exist) and also check if an org level org policy that IS enforced
#   exists. If both exist then reply back NON-COMPLIANT and with name of asset(s)
reply contains response if {
	some asset in non_enforced_proj_level_assets
	count(enforced_org_level_assets) > 0
	status := common.set_status(guardrail.guardrail)
	msg := {"msg": sprintf("Organization Policy [%v] override detected at the Project level.", [required_policy])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Not Enforced Project Level Org Policy & No Enforced Org Level Policy- NON-COMPLIANT
# description: |
#   Iterate through project level policy asset(s) that are enforced
#   (if any exist) and also check if an org level org policy that is NOT enforced
#   exists. If both exist then reply back NON-COMPLIANT and with name of asset(s)
reply contains response if {
	some asset in non_enforced_proj_level_assets
	count(enforced_org_level_assets) == 0
	status := common.set_status(guardrail.guardrail)
	msg := {"msg": sprintf("Organization Policy [%v] detected at the Project level and NOT enforced.", [required_policy])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: Exempt Project Level Exception - COMPLIANT (informational)
# description: |
#   A non-enforced project level storage.publicAccessPrevention policy was
#   found, but the project is tagged with an exempt PROJECT_PROFILE level.
#   Reported for visibility with the asset name; does not affect the verdict.
reply contains response if {
	some asset in exempt_profile_proj_level_assets
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("Organization Policy [%v] exception detected at the Project level - permitted via PROJECT_PROFILE tag.", [required_policy])}
	asset_name := {"asset_name": asset.name}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}

# METADATA
# title: Org Level Org Policy Not Found - NON-COMPLIANT
# description: If no org level org policy asset(s) are found, reply back NON-COMPLIANT
reply contains response if {
	count(enforced_org_level_assets) == 0
	count(non_enforced_org_level_assets) == 0
	status := common.set_status(guardrail.guardrail)
	msg := {"msg": sprintf("Organization Policy [%v] NOT detected at the Organization Level.", [required_policy])}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}
