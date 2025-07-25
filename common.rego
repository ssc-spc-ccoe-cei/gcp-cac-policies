# METADATA
# title: Common Package
# description: Common Package with functions to use across guardrail policies
package policies.common

# Import Cloud Usage Profile environment variable
profile := opa.runtime().env.GC_PROFILE

# This map defines which guardrails are required or recommended for each profile
profile_enforcement := {
    # For GC_PROFILE "1"
    "1": {
        "recommended": {"03", "05", "06", "07", "09", "10", "11", "13"},
        "required": {"01", "02", "04", "08", "12"},
    },
    # For GC_PROFILE "2"
    "2": {
        "recommended": {"05", "06"},
        "required": {"01", "02", "03", "04", "07", "08", "09", "10", "11", "12", "13"},
    },
    # For GC_PROFILE "3"
    "3": {
        "recommended": set(),
        "required": {"01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13"},
    },
    # For GC_PROFILE "4"
    "4": {
        "recommended": set(),
        "required": {"01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13"},
    },
    # For GC_PROFILE "5"
    "5": {
        "recommended": set(),
        "required": {"01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13"},
    },
    # For GC_PROFILE "6"
    "6": {
        "recommended": set(),
        "required": {"01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13"},
    },
}

# This function looks up the enforcement level for a given guardrail number.
# If the guardrail number is found as recommended based on the profile, set the check type to RECOMMENDED.
set_check_type(guardrail_number) := {
"check_type": "RECOMMENDED",
} if {
    profile_enforcement[profile].recommended[guardrail_number]
}

# This function looks up the enforcement level for a given guardrail number.
# If the guardrail number is found as required based on the profile, set the check type to REQUIRED.
set_check_type(guardrail_number) := {
"check_type": "REQUIRED",
} if {
    profile_enforcement[profile].required[guardrail_number]
}

# This function looks up the status for a given guardrail number.
# If the guardrail number is found as recommended based on the profile, set the status to WARN.
set_status(guardrail_number) := {
"status": "WARN"
} if {
    profile_enforcement[profile].recommended[guardrail_number]
}

# This function looks up the status for a given guardrail number.
# If the guardrail number is found as required based on the profile, set the status to NON-COMPLIANT.
set_status(guardrail_number) := {
"status": "NON-COMPLIANT"
} if {
    profile_enforcement[profile].required[guardrail_number]
}

