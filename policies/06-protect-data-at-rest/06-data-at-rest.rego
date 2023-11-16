# METADATA
# title: Guardrail 06 - Protection of Data-at-Rest
# description: Check Security Command Center for alerts around CMEK being Disabled
package policies.guardrail_06_cmek

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# SCC finding category to look for
required_scc_category := "CMEK_DISABLED"

# Metadata variables
guardrail := {"guardrail": "06"}

description := {"description": "GUARDRAIL 6: PROTECTION OF DATA-AT-REST"}

# METADATA
# description: Checks if finding is required type
is_correct_finding(asset) if {
	endswith(asset.finding.category, required_scc_category)
}

# METADATA
# title: Check for Matching findings
# description: Store SCC findings who's category matches required_scc_category
matching_findings := {asset |
	some asset in input.data
	is_correct_finding(asset)
}

# METADATA
# title: Policy WARN
# description: If matching findings are found, reply back WARN
reply contains response if {
	count(matching_findings) > 0
	status := {"status": "WARN"}
	check := {"check_type": "RECOMMENDED"}
	msg := {"msg": sprintf("SCC category ending in [%v] detected. Check Security Command Center for more information.", [required_scc_category])}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Policy COMPLIANT
# description: If matching findings are NOT found, reply back compliant
reply contains response if {
	count(matching_findings) == 0
	status := {"status": "COMPLIANT"}
	check := {"check_type": "RECOMMENDED"}
	msg := {"msg": sprintf("SCC category ending in [%v] not detected.", [required_scc_category])}
	response := object.union_n([guardrail, status, msg, description, check])
}
