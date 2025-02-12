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

# Metadata variables
guardrail := {"guardrail": "07"}
validation := {"validation": "03"}
description := {"description": "Certificates from Approved CA Issuers"}

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


# METADATA
# title: VALIDATION / DATA PROCESSING
# description: Store certs names that are not from approved CAs
assets_with_non_approved_ca := {asset.name |
	some asset in input.data
  is_correct_asset(asset)
  not has_allowed_ca(asset)
}


# METADATA
# title: Policy COMPLIANT
# description: If all certificates are from approved CAs, then COMPLIANT
reply contains response if {
  count(assets_with_non_approved_ca) == 0
	status := {"status": "COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": "Certificates are in found to be from approved Certificate Authorities"}
	response := object.union_n([guardrail, validation, status, msg, description, check])
}

# description: If some certificates are NOT from approved CAs, then NON-COMPLIANT and report list
reply contains response if {
  count(assets_with_non_approved_ca) > 0
	status := {"status": "NON-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": "Certificates have been found to come from non-approved Certificate Authorities"}
  asset_name := {"asset_name": assets_with_non_approved_ca}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}
