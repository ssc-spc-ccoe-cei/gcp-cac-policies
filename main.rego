# METADATA
# title: Main
# description: Provides single entrypoint for running query against
package main

# Import future keywords
# More info here: https://www.openpolicyagent.org/docs/latest/policy-language/#future-keywords
import future.keywords.contains

# METADATA
# description: |
# Running query against this rule will iterate through all existing policies.
# Allows your query to be 'data.main.guardrail'
guardrail contains response {
	data.policies[_].reply[response]
}
