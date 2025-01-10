# METADATA
# title: Guardrail 10, Validation 02 - Ensure Cyber Centre's sensors are installed
# description: Check for presence of required Cyber Centre components
package policies.guardrail_10_02_files

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in


# Metadata variables
guardrail := {"guardrail": "10"}
description := {"description": "validation 02 - Cyber Centre Sensors"}

# Name of files data object to look for
required_name := "guardrail-10"
validation_number := "02"
required_asset_type_01 := "pubsub.googleapis.com/Topic"
required_asset_type_02 := "pubsub.googleapis.com/Subscription"
required_asset_type_03 := "cloudfunctions.googleapis.com/Function"
required_asset_type_04 := "run.googleapis.com/Service"
required_asset_type_05 := "storage.googleapis.com/Bucket"


# METADATA
# title: HELPER FUNCTIONS
# description: Check if asset's name matches what's required and has expected name(s)
is_correct_asset_01(asset) if {
  asset.asset_type = required_asset_type_01
  regex.match(`topics/cbs-\w+`, asset.name) 
}

is_correct_asset_02(asset) if {
  asset.asset_type = required_asset_type_02
  regex.match(`subscriptions/(cbs-|eventarc-)\w+`, asset.name) 
}

is_correct_asset_03(asset) if {
  asset.asset_type = required_asset_type_03
  regex.match(`functions/cbs-\w+`, asset.name) 
}

is_correct_asset_04(asset) if {
  asset.asset_type = required_asset_type_04
  regex.match(`services/cbs-\w+`, asset.name) 
}

is_correct_asset_05(asset) if {
  asset.asset_type = required_asset_type_05
  regex.match(`storage.googleapis.com/cbs-\w+`, asset.name) 
}


# METADATA
# title: VALIDATION / DATA PROCESSING
matching_assets_01 := {asset |
	some asset in input.data
	is_correct_asset_01(asset)
}

matching_assets_02 := {asset |
	some asset in input.data
	is_correct_asset_02(asset)
}

matching_assets_03 := {asset |
	some asset in input.data
	is_correct_asset_03(asset)
}

matching_assets_04 := {asset |
	some asset in input.data
	is_correct_asset_04(asset)
}

matching_assets_05 := {asset |
	some asset in input.data
	is_correct_asset_05(asset)
}


# METADATA
# title: Cyber Centre Sensors Policy - COMPLIANT
# description: If ALL Cyber Centre Sensor components are installed, then COMPLIANT
reply contains response if {
  count(matching_assets_01) > 0
  count(matching_assets_02) > 0
  count(matching_assets_03) > 0
  count(matching_assets_04) > 0
  count(matching_assets_05) > 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "COMPLIANT"}
	msg := {"msg": sprintf("Required Cyber Centre Sensor components installed for [%v, validation %v].", [required_name, validation_number])}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If required Pub/Sub Topic not installed, then NON-COMPLIANT
reply contains response if {
  count(matching_assets_01) == 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Required Cyber Centre Sensor component Pub/Sub Topic NOT installed for [%v, validation %v].", [required_name, validation_number])}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If required Pub/Sub Subscription not installed, then NON-COMPLIANT
reply contains response if {
  count(matching_assets_02) == 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Required Cyber Centre Sensor component Pub/Sub Subscription NOT installed for [%v, validation %v].", [required_name, validation_number])}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If required Cloud (Run) Function not installed, then NON-COMPLIANT
reply contains response if {
  count(matching_assets_03) == 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Required Cyber Centre Sensor component Cloud (Run) Functions NOT installed for [%v, validation %v].", [required_name, validation_number])}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If required Cloud Run Service not installed, then NON-COMPLIANT
reply contains response if {
  count(matching_assets_04) == 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Required Cyber Centre Sensor component Cloud Run Service NOT installed for [%v, validation %v].", [required_name, validation_number])}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Policy - NON-COMPLIANT
# description: If required GCS Bucket not installed, then NON-COMPLIANT
reply contains response if {
  count(matching_assets_05) == 0
	check := {"check_type": "MANDATORY"}
	status := {"status": "NON-COMPLIANT"}
	msg := {"msg": sprintf("Required Cyber Centre Sensor component GCS Bucket NOT installed for [%v, validation %v].", [required_name, validation_number])}
	response := object.union_n([guardrail, status, msg, description, check])
}
