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
# It will dynamically set the check_type value based on the profile_enforcement map.
# Returns REQUIRED if the guardrail is required, otherwise returns RECOMMENDED if guardrail is recommended.
set_check_type(guardrail_number) := result if {
    # Check if profile has guardrail as required
    profile_enforcement[profile].required[guardrail_number]
    result := {"check_type": "REQUIRED"}
} else := result if {
    # Check if profile has guardrail as recommended
    profile_enforcement[profile].recommended[guardrail_number]
    result := {"check_type": "RECOMMENDED"}
}

# This function looks up the enforcement level for a given guardrail number.
# It will dynamically set the status value based on the profile_enforcement map.
# Returns NON-COMPLIANT if the guardrail is required, otherwise returns WARN if guardrail is recommended.
set_status(guardrail_number) := result if {
    profile_enforcement[profile].required[guardrail_number]
    result := {"status": "NON-COMPLIANT"}
} else := result if {
    profile_enforcement[profile].recommended[guardrail_number]
    result := {"status": "WARN"}
}

# Helper function to extract the profile level from a tag value.
# Tag value format: "ORG_ID/PROJECT_PROFILE/LEVEL" (e.g., "779217891544/PROJECT_PROFILE/1")
# Returns the profile level as a string (e.g., "1")
extract_profile_from_tag(tag_value) := profile_level if {
    parts := split(tag_value, "/")
    count(parts) >= 3
    profile_level := array.reverse(parts)[0]
}

# Version of set_check_type that accepts a specific profile level.
# Use this when a resource belongs to a project with a profile override tag.
set_check_type_for_profile(guardrail_number, profile_level) := result if {
    profile_enforcement[profile_level].required[guardrail_number]
    result := {"check_type": "REQUIRED"}
} else := result if {
    profile_enforcement[profile_level].recommended[guardrail_number]
    result := {"check_type": "RECOMMENDED"}
}

# Version of set_status that accepts a specific profile level.
# Use this when a resource belongs to a project with a profile override tag.
set_status_for_profile(guardrail_number, profile_level) := result if {
    profile_enforcement[profile_level].required[guardrail_number]
    result := {"status": "NON-COMPLIANT"}
} else := result if {
    profile_enforcement[profile_level].recommended[guardrail_number]
    result := {"status": "WARN"}
}