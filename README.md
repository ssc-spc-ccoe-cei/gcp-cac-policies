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
|GR01_03_ORG_ADMIN_GROUP_EMAIL|Group email for org admin group|gcp-organization-admins@ssc.gc.ca|
|GR01_06_PRIVILEGED_USERS|Comma-delimited list of privileged user accounts. Username/emails should be prefixed with `user:`|user:admin-user1@ssc.gc.ca,user:admin-user2@ssc.gc.ca,user:user3-admin@ssc.gc.ca|
|GR01_06_REGULAR_USERS|Comma-delimited list of regular user accounts for for the privileged users. Username/emails should be prefixed with `user:`|user:reg-user1@123gccspm.gccspm.gc.ca,user:reg-user2@123cspmdev.onmicrosoft.com,user:some-user3@ssc.gc.ca|
|GR02_01_ORG_ADMIN_GROUP_EMAIL|Group email for org admin group|gcp-organization-admins@ssc.gc.ca|
|GR02_01_PRIVILEGED_USERS|Comma-delimited list of privileged user accounts. Username/emails should be prefixed with `user:`|user:admin-user1@ssc.gc.ca,user:admin-user2@ssc.gc.ca,user:user3-admin@ssc.gc.ca|
|GR02_01_REGULAR_USERS|Comma-delimited list of regular user accounts for for the privileged users. Username/emails should be prefixed with `user:`|user:reg-user1@123gccspm.gccspm.gc.ca,user:reg-user2@123cspmdev.onmicrosoft.com,user:some-user3@ssc.gc.ca|
|GR02_08_ALLOWED_DOMAINS|Comma-delimited list of allowed domains|ssc.gc.ca,gccspm.gc.ca|
|GR02_08_DENY_DOMAINS|Comma-delimited list of denied domains|gmail.com,outlook.com,yahoo.com|
|GR02_09_HAS_GUEST_USERS|Whether org has guest users|false|
|GR02_10_HAS_GUEST_USERS|Whehter or has guest users|false|
|GR03_01_CUSTOMER_IDS|Customer ID associated with domain. Obtain this with `gcloud organizations list`|C0a1b7d|
|GR03_01_ALLOWED_IPS|Comma-delimited list of approved IPs|10.0.7.44,192.168.0.16|
|GR05_01_SECURITY_CATEGORY_KEY||DATA_CLASSIFICATION|
|GR07_03_ALLOWED_CA_ISSUERS|Comma-delimited list of approved CAs|Let's Encrypt,Verisign|
|GR11_04_ORG_ID|GCP organization ID|1234567890|
|GR13_03_BREAKGLASS_USER_EMAIL||breakglass@ssc.gc.ca|


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

## Misc. Rego Tips & Tricks

### Convert list to set
```
list_to_set(list) := {set |
  set := list
}
```

### Combine 2 lists and turn into a set
```
combined_members := {combined_set |
  temp_list := array.concat(list1[_], list2[_])
  combined_set := list_to_set(temp_list[_])
}
```

### Flatten a list of lists and turn into a set
```
combined_members := {combined_set |
  user_list := list_of_lists
  every item in user_list {
    is_array(item)  # ensure every item in user_list is also a list
  }
  # inner_array is the list of items of the main list (user_list)
  # item is the items of inner_array
  flattened_list := [item | inner_array := user_list[_]; item := inner_array[_]]
  combined_set := list_to_set(flattened_list[_])
}
```

### Environment Variables with OPA
OPA can read env vars as inputs:
- [examples](https://www.openpolicyagent.org/docs/v0.70.0/policy-reference/#pre-signed-request-example)

#### List variables
What if you need to pass a list as a variable?

Suppose you want ot set `variable := ["item1", "item2", "item3"]`

You can't do:
```
export MY_VARIABLE = '["item1", "item2", "item3"]'

variable = opa.runtime()["env"]["MY_VARIABLE"]
```
Because even though it may come out the same, it's a string instead of a list.  If you try to put `[]` around a string value, it will add extra escape backslashes `\\` in there and you still won't get what you want.

What you want to do here is actually use the [`string.split`](https://www.openpolicyagent.org/docs/v0.70.0/policy-reference/#builtin-strings-split) built-in function to split a non-quoted, comma-delimited string (which produces a list output)

```
export MY_VARIABLE ='item1,item2,item3'

variable := string.split(opa.runtime()["env"]["MY_VARIABLE"], ",")
````

The output is alread a list where the items are double-quoted, so you get the `["item1", "item2", "item3"]` that you wanted!