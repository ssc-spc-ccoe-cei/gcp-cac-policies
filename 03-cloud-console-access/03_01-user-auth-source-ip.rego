# METADATA
# title: Guardrail 03 , Validation 01 - Check for User Auth Source IPs
# description: Check whether users are authenticating from approved source IPs
package policies.guardrail_03_01_userip

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Import common functions
import data.policies.common

# Metadata variables
guardrail := {"guardrail": "03"}
validation := {"validation": "01"}
description := {"description": "Endpoint Management - Allowed Policy Member Domains and User Source IP Constraints"}

# Set check type based on profile and guardrail number
check := common.set_check_type(guardrail.guardrail)

required_asset_kind:= "logging#user#auth"


# METADATA
# title: CLIENT INPUT
# description: list of allowed IPs
env := opa.runtime().env
# description: takes on the value of env var, GR03_01_ALLOWED_IPS
#              i.e. export GR03_01_ALLOWED_IPS='10.0.0.7,192.168.1.134'
required_allowed_ips := split(env["GR03_01_ALLOWED_IPS"], ",")
# description: set to "true" if using federated users
required_has_federated_users := env["GR03_01_HAS_FEDERATED_USERS"]

# METADATA
# title: HELPER FUNCTIONS
# description: Checks if asset's type matches what's required
is_correct_asset_type(asset) if {
	asset.kind == required_asset_kind
}

is_allowed_ip(asset) if {
  asset.sourceIp in required_allowed_ips
}


# METADATA
# title: processing project profile overrides
is_project_profile_tag(asset) if {
	asset.kind == "cloudresourcemanager#tagged#project"
	endswith(asset.tag_key, "PROJECT_PROFILE")
}

# description: Extract project name from the full resource name
# "//cloudresourcemanager.googleapis.com/projects/testing-ground-new" -> "testing-ground-new"
extract_project_name(full_name) := project_name if {
	parts := split(full_name, "/projects/")
	count(parts) >= 2
	project_name := parts[1]
}

# description: Extract project_number, project_name, and tag_value from tagged projects
# Result: [project_number, project_name, tag_value]
project_profile_details := {[asset.project_number, extract_project_name(asset.name), asset.tag_value] |
	some asset in input.data
	is_project_profile_tag(asset)
}

# description: Extract project_number, project_name, and profile_level
# tag_value format: "ORG_ID/PROJECT_PROFILE/LEVEL" (e.g., "779217891544/PROJECT_PROFILE/1")
# Result: [project_number, project_name, profile_level]
project_id_and_profile_list := {[project_number, project_name, profile_level] |
	some entry in project_profile_details
	project_number := entry[0]
	project_name := entry[1]
	parts := split(entry[2], "/")
	profile_level := array.reverse(parts)[0]
}

# METADATA
# title: VALIDATION / DATA PROCESSING
# description: All log entries with non-approved IPs
# Result: [insertId, principalEmail, sourceIp, timestamp, logName]
contains_non_approved_ip := {[asset.insertId, asset.principalEmail, asset.sourceIp, asset.timestamp, asset.logName] |
  some asset in input.data
  is_correct_asset_type(asset)
  not is_allowed_ip(asset)
}

# description: Log entries with non-approved IPs that belong to tagged projects
# Use "projects/PROJECT_NAME/" pattern to avoid partial matches
# Result: [insertId, principalEmail, sourceIp, timestamp, project_number, profile_level]
tagged_project_contains_non_approved_ip := {[asset.insertId, asset.principalEmail, asset.sourceIp, asset.timestamp, proj_id_profile[0], proj_id_profile[2]] |
  some asset in input.data
  is_correct_asset_type(asset)
  not is_allowed_ip(asset)
  some proj_id_profile in project_id_and_profile_list
  contains(asset.logName, sprintf("projects/%s/", [proj_id_profile[1]]))  # exact project match
}

# description: InsertIds of violations in tagged projects (for set difference)
tagged_violation_ids := {violation[0] |
  some violation in tagged_project_contains_non_approved_ip
}

# description: Violations NOT in tagged projects (use global profile)
# Result: [insertId, principalEmail, sourceIp, timestamp, logName]
non_tagged_project_contains_non_approved_ip := {violation |
  some violation in contains_non_approved_ip
  not violation[0] in tagged_violation_ids
}

# METADATA
# title: Access Context Manager IP Restriction Policy - COMPLIANT
# description: If IP restrictions provided to ACM, then reply back COMPLIANT
reply contains response if {
	required_has_federated_users == "true"
	status := {"status": "COMPLIANT"}
	msg := {"msg": "Users are federated users and this guardrail is handled by the IdP."}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

reply contains response if {
	required_has_federated_users == "false"
	count(contains_non_approved_ip) == 0
	status := {"status": "COMPLIANT"}
	msg := {"msg": "All users are connecting from approved IPs in the last 24hrs."}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# METADATA
# title: NON-COMPLIANT - violations in non-tagged projects (use global profile)
reply contains response if {
	required_has_federated_users == "false"
	count(non_tagged_project_contains_non_approved_ip) > 0
	some violating_login in non_tagged_project_contains_non_approved_ip
	# violating_login structure: [insertId, principalEmail, sourceIp, timestamp, logName]
	status := common.set_status(guardrail.guardrail)
	msg := {"msg": sprintf("[%v] authentication instances found where user connected from non-approved source IP.", [count(non_tagged_project_contains_non_approved_ip)])}
	asset_name := {"asset_name": [violating_login[0], violating_login[1], violating_login[2], violating_login[3]]}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}

# METADATA
# title: NON-COMPLIANT - violations in tagged projects (use override profile)
reply contains response if {
	required_has_federated_users == "false"
	count(tagged_project_contains_non_approved_ip) > 0
	some violating_login in tagged_project_contains_non_approved_ip
	# violating_login structure: [insertId, principalEmail, sourceIp, timestamp, project_number, profile_level]
	override_profile := violating_login[5]
	status := common.set_status_for_profile(guardrail.guardrail, override_profile)
	check_override := common.set_check_type_for_profile(guardrail.guardrail, override_profile)
	msg := {"msg": sprintf("[%v] authentication instances found where user connected from non-approved source IP.", [count(tagged_project_contains_non_approved_ip)])}
	asset_name := {"asset_name": [violating_login[0], violating_login[1], violating_login[2], violating_login[3]]}
	proj_parent := {"proj_parent": violating_login[4]}
	proj_profile := {"proj_profile": override_profile}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check_override, proj_parent, proj_profile])
}
