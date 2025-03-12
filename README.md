# Compliance as Code Toolkit

This repository contains all the policy artifacts for the CaC Tool. Each policy has a seperate readme document explaining the control, check process and flow used to evaluate the target GCP organization.

- [Compliance as Code Toolkit](#compliance-as-code-toolkit)
  - [Overall workflow for CaC Validation Checking](#overall-workflow-for-cac-validation-checking)
  - [Environment Variables with OPA repository](#environment-variables-with-opa-repository)
    - [List of ENV VARS](#list-of-env-vars)

## Overall workflow for CaC Validation Checking

![Compliance Validation Workflow](documentation/policy_diagrams/compliance-workflow.png "Compliance Validation Workflow")

## Environment Variables with OPA repository

If you want to pass a list as a variable (i.e. you want `myvar := ["item1", "item2", "item3"]`), you *CANNOT* do `export MYVAR = '["item1", "item2", "item3"]'` as this will be interpreted as a string (that just looks like a list).

Attempting to make the item a list using square brackets `[ ]` in Rego will introduce a lot of additional escape `\\` characters for the escapes and quotes -- and this is not what we want. Instead, what you want is to export your list variable values as unquoted, comma-delimited strings and we then use Rego's [`string.split`](https://www.openpolicyagent.org/docs/latest/policy-reference/#builtin-strings-split) function to split your string and returns a list object where and item will be in double quotes.

For example: `export MYVAR = "item1,item2,item3"`, once passed to `string.split(env["MYVAR"], ",")`, will become `["item1", "item2", "item3"]`


### List of ENV VARS

Naming format is `GR<GUARDRAIL_NUMBER>_<VALIDATION_NUMBER>_VARNAME`.  If the `VARNAME` is plural, then the env var is expected to be a list.

|Variable | Description | Example|
|:-|:-|:-|
|GR01_03_DOMAIN |||
|GR01_06_PRIVILEGED_USERS|||
|GR02_01_DOMAIN|||
|GR01_03_DOMAIN|||
|GR01_06_PRIVILEGED_USERS|||
|GR01_06_REGULAR_USERS|||
|GR02_01_DOMAIN|||
|GR02_01_PRIVILEGED_USERS|||
|GR02_01_REGULAR_USERS|||
|GR02_08_ALLOWED_DOMAINS|||
|GR02_08_DENY_DOMAINS|||
|GR02_09_HAS_GUEST_USERS|||
|GR02_10_HAS_GUEST_USERS|||
|GR03_01_CUSTOMER_IDS|||
|GR03_01_ALLOWED_CIDRS|||
|GR05_01_SECURITY_CATEGORY_KEY|||
|GR07_03_ALLOWED_CA_ISSUERS|||
|GR11_04_ORG_ID|||


## Output aggregate or individual?
- example of outputting an aggregate result for `asset_name`, which takes on the list, `violating_assets` (with an "s"!):
```
reply contains response if {
  count(assets_resource_location_not_exempt - assets_resource_location_with_exempt_tags) > 0
  violating_assets := assets_resource_location_not_exempt - assets_resource_location_with_exempt_tags
	status := {"status": "NON-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
  msg := {"msg": sprintf("[%v] assets have been found to violate the data location policy", [count(violating_assets)])}
  asset_name := {"asset_name": violating_assets}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}
```

- example of outputting a individual results for `asset_name`, taken from the same list, `violating_assets`.  To output individual, I added `some violating_asset in violating_assets`, which works as a "for-loop" for the list items.  I then changed `asset_name` to be `violating_asset` (no s!) instead:
```
reply contains response if {
  count(assets_resource_location_not_exempt - assets_resource_location_with_exempt_tags) > 0
  violating_assets := assets_resource_location_not_exempt - assets_resource_location_with_exempt_tags
  some violating_asset in violating_assets
	status := {"status": "NON-COMPLIANT"}
	check := {"check_type": "MANDATORY"}
  msg := {"msg": sprintf("[%v] assets have been found to violate the data location policy", [count(violating_assets)])}
  asset_name := {"asset_name": violating_asset}
	response := object.union_n([guardrail, validation, status, msg, asset_name, description, check])
}
```
