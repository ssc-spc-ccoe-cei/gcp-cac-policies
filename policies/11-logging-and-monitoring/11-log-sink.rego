# METADATA
# title: Guardrail 11 - Check for Log Sink and Storage Bucket
# description: Check for 
package policies.guardrail_11_sink

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Asset type must match below to be considered log sink
required_log_sink_asset_type := "logging.googleapis.com/LogSink"

# Log Sink name must start with below
required_log_sink_name := "org_log_sink"

# Asset type must match below to be considered storage bucket
required_bucket_asset_type := "storage.googleapis.com/Bucket"

# Bucket name must start with below
required_bucket_name := "org_log_bucket"

# Metadata variables
guardrail := {"guardrail": "11"}

description := {"description": "Logging and Monitoring"}

# METADATA
# description: Checks if asset is a log sink
is_log_sink_asset(asset) if {
	asset.asset_type == required_log_sink_asset_type
}

# METADATA
# description: Checks if log sink name starts with required_log_sink_name
log_sink_name_correct(asset) if {
	endswith(asset.name, required_log_sink_name)
}

# METADATA
# description: Checks if asset is a storage bucket
is_log_bucket_asset(asset) if {
	asset.asset_type == required_bucket_asset_type
}

# METADATA
# description: Checks if storage bucket name starts with required_bucket_name
log_bucket_name_correct(asset) if {
	startswith(asset.name, required_bucket_name)
}

# METADATA
# description: Check if log sink is using a compliant bucket for log destination
is_correct_log_bucket_destination(log_sink) if {
	log_sink_destination := log_sink.resource.data.destination
	startswith(compliant_log_bucket[_].name, log_sink_destination)
}

# METADATA
# title: Check for Log Sink Assets
# description: Store any log sink assets that match the correct asset type
log_sink_assets := {asset |
	some asset in input.data
	is_log_sink_asset(asset)
}

# METADATA
# title: Check for Compliant Log Sink Assets
# description: Store any log sink assets with name that starts with required name
compliant_log_sink := {asset |
	some asset in log_sink_assets
	log_sink_name_correct(asset)
}

# METADATA
# title: Check for Storage Bucket Assets
# description: Store any storage bucket assets that match the correct asset type
log_bucket_assets := {asset |
	some asset in input.data
	is_log_bucket_asset(asset)
}

# METADATA
# title: Check for Compliant Storage Bucket Assets
# description: Store any storage bucket assets with name that starts with required name
compliant_log_bucket := {asset |
	some asset in log_bucket_assets
	log_bucket_name_correct(asset)
}

# METADATA
# title: No Compliant Log Sink Found - NON-COMPLIANT
# description: |
# If no compliant log sinks are found, reply back with NON-COMPLIANT
# and the required log sink name.
reply contains response if {
	count(compliant_log_sink) == 0
	status := {"status": "NON-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("Log Sink starting with required name [%v] NOT detected.", [required_log_sink_name])}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Compliant Log Sink Found - COMPLIANT
# description: |
# Iterate through compliant log sink asset(s) (if any exist). Reply back
# with COMPLIANT. Include name of log sink.
reply contains response if {
	some log_sink in compliant_log_sink
	status := {"status": "COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("Log Sink starting with required name [%v] detected.", [required_log_sink_name])}
	asset_name := {"asset_name": log_sink.name}
	response := object.union_n([guardrail, status, msg, description, asset_name, check])
}

# METADATA
# title: No Compliant Storage Bucket Found - NON-COMPLIANT
# description: |
# If no compliant storage buckets are found, reply back with NON-COMPLIANT
# and the required storage bucket name.
reply contains response if {
	count(compliant_log_bucket) == 0
	status := {"status": "NON-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("Storage Bucket starting with required name [%v] NOT detected.", [required_bucket_name])}
	response := object.union_n([guardrail, status, msg, description, check])
}

# METADATA
# title: Compliant Storage Bucket Found - COMPLIANT
# description: |
# Iterate through compliant storage bucket asset(s) (if any exist). Reply back
# with COMPLIANT. Include name of storage bucket.
reply contains response if {
	some log_bucket in compliant_log_bucket
	status := {"status": "COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": sprintf("Storage Bucket starting with required name [%v] detected.", [required_bucket_name])}
	asset_name := {"asset_name": log_bucket.name}
	response := object.union_n([guardrail, status, msg, description, asset_name, check])
}

# METADATA
# title: Compliant Log Sink Destination Found - COMPLIANT
# description: |
# Iterate through compliant log sink asset(s) (if any exist), check if log sink is 
# setup with a compliant storage bucket as log destination. If yes, reply
# back COMPLIANT. Include name of log sink.
reply contains response if {
	some log_sink in compliant_log_sink
	is_correct_log_bucket_destination(log_sink)
	status := {"status": "COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": "Log Sink using required Storage Bucket set as destination detected."}
	asset_name := {"asset_name": log_sink.name}
	response := object.union_n([guardrail, status, msg, description, asset_name, check])
}

# METADATA
# title: Compliant Log Sink Destination Not Found - COMPLIANT
# description: |
# Iterate through compliant log sink asset(s) (if any exist), check if log sink is 
# setup with a compliant storage bucket as log destination. If no, reply
# back NON-COMPLIANT. Include name of log sink.
reply contains response if {
	some log_sink in compliant_log_sink
	not is_correct_log_bucket_destination(log_sink)
	status := {"status": "NON-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
	msg := {"msg": "Log Sink using required Storage Bucket set as destination NOT detected."}
	asset_name := {"asset_name": log_sink.name}
	response := object.union_n([guardrail, status, msg, description, asset_name, check])
}
