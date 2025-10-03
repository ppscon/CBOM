package fips_compliance_cdx16

import future.keywords.in
import future.keywords.if

# ==================================
# CycloneDX Format Helpers
# ==================================

# Get property value from component.properties array (1.6 format)
get_property(component, prop_name) = value if {
    some prop in component.properties
    prop.name == prop_name
    value := prop.value
}

# Get crypto algorithm (supports both 1.4 and 1.6)
get_algorithm(component) = algo if {
    # Try 1.4 format first
    component.crypto.algorithm
    algo := component.crypto.algorithm
} else = algo if {
    # Try 1.6 format
    algo := get_property(component, "cbom:algorithm")
}

# Get quantum safe status (supports both 1.4 and 1.6)
is_quantum_safe(component) if {
    # Try 1.4 format
    component.crypto.quantumSafe == true
}

is_quantum_safe(component) if {
    # Try 1.6 format
    value := get_property(component, "cbom:quantumSafe")
    value == "true"
}

# Get quantum risk (supports both 1.4 and 1.6)
get_quantum_risk(component) = risk if {
    # Try 1.4 format
    component.crypto.quantumRisk
    risk := component.crypto.quantumRisk
} else = risk if {
    # Try 1.6 format
    risk := get_property(component, "cbom:quantumRisk")
}

# Check if component has crypto properties
has_crypto(component) if {
    component.crypto  # 1.4 format
}

has_crypto(component) if {
    # 1.6 format - check for cbom: properties
    some prop in component.properties
    startswith(prop.name, "cbom:")
}

# ==================================
# CBOM Input Handling
# ==================================

# Get components from various input structures
get_components() = components if {
    # Wrapped format: input.cbom.components
    input.cbom.components
    components := input.cbom.components
} else = components if {
    # Direct CycloneDX format: input.components
    input.components
    components := input.components
} else = [] if {
    # No components found
    true
}

# ==================================
# Quantum-Safe Validation
# ==================================

# Deny quantum-vulnerable cryptography
deny[res] if {
    some component in get_components()
    has_crypto(component)
    not is_quantum_safe(component)
    risk := get_quantum_risk(component)
    risk != "None"
    algo := get_algorithm(component)
    msg := sprintf(
        "Quantum-vulnerable cryptography: %s (Algorithm: %s, Risk: %s)",
        [component.name, algo, risk]
    )
    res := {
        "msg": msg,
        "id": __rego_metadata__.id,
        "title": __rego_metadata__.title,
        "severity": __rego_metadata__.severity,
        "type": __rego_metadata__.type,
    }
}

# Warn about missing CMVP validation
warn[msg] if {
    some component in get_components()
    has_crypto(component)
    purpose := get_property(component, "cbom:purpose")
    purpose in ["Encryption", "Signature", "KeyExchange"]
    not has_cmvp_validation(component)
    algo := get_algorithm(component)
    msg := sprintf(
        "Missing CMVP validation: %s (Algorithm: %s)",
        [component.name, algo]
    )
}

# Check for CMVP validation (supports both formats)
has_cmvp_validation(component) if {
    component.crypto.cmvpValidated == true  # 1.4
}

has_cmvp_validation(component) if {
    value := get_property(component, "cbom:cmvpValidated")  # 1.6
    value == "true"
}

# ==================================
# FIPS 140-3 Algorithm Validation
# ==================================

# FIPS 140-3 approved algorithms
# Note: FIPS 140-3 includes provisions for post-quantum cryptography (PQC)
# algorithms once NIST completes standardization
fips_approved_algorithms := {
    "AES-128", "AES-192", "AES-256",
    "SHA-256", "SHA-384", "SHA-512",
    "SHA3-256", "SHA3-384", "SHA3-512",  # SHA-3 family (FIPS 202)
    "RSA-2048", "RSA-3072", "RSA-4096",
    "ECDSA-P256", "ECDSA-P384", "ECDSA-P521",
    "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512"
}

# Deprecated/weak algorithms (not approved under FIPS 140-3)
# Note: 3DES deprecated for new implementations as of 2023
fips_deprecated_algorithms := {
    "MD5", "SHA-1", "DES", "3DES",
    "RSA-1024", "RC4", "RC2", "Blowfish"
}

# Deny deprecated algorithms
deny[res] if {
    some component in get_components()
    has_crypto(component)
    algo := get_algorithm(component)
    algo in fips_deprecated_algorithms
    msg := sprintf(
        "Deprecated algorithm detected: %s in %s (Not FIPS 140-3 approved)",
        [algo, component.name]
    )
    res := {
        "msg": msg,
        "id": __rego_metadata__.id,
        "title": __rego_metadata__.title,
        "severity": __rego_metadata__.severity,
        "type": __rego_metadata__.type,
    }
}

# Warn about non-approved algorithms
warn[msg] if {
    some component in get_components()
    has_crypto(component)
    algo := get_algorithm(component)
    not algo in fips_approved_algorithms
    not algo in fips_deprecated_algorithms
    msg := sprintf(
        "Non-standard algorithm: %s in %s (Verify FIPS 140-3 approval)",
        [algo, component.name]
    )
}

# ==================================
# CBOM Summary Validation
# ==================================

# Check CBOM summary for compliance metrics
get_cbom_summary() = summary if {
    input.cbom.summary
    summary := input.cbom.summary
} else = summary if {
    input.summary
    summary := input.summary
}

# Validate quantum-safe asset count
deny[res] if {
    summary := get_cbom_summary()
    summary.quantum_safe_assets < summary.total_assets
    vulnerable := summary.total_assets - summary.quantum_safe_assets
    msg := sprintf(
        "CBOM shows %d quantum-vulnerable assets out of %d total",
        [vulnerable, summary.total_assets]
    )
    res := {
        "msg": msg,
        "id": __rego_metadata__.id,
        "title": __rego_metadata__.title,
        "severity": __rego_metadata__.severity,
        "type": __rego_metadata__.type,
    }
}

# ==================================
# Reporting
# ==================================

# Generate compliance report
compliance_report = report if {
    components := get_components()
    total := count(components)
    quantum_safe := count([c | c := components[_]; has_crypto(c); is_quantum_safe(c)])
    deprecated := count([c | c := components[_]; has_crypto(c); algo := get_algorithm(c); algo in fips_deprecated_algorithms])

    report := {
        "total_components": total,
        "quantum_safe_count": quantum_safe,
        "deprecated_count": deprecated,
        "compliance_percentage": (quantum_safe * 100) / total
    }
}

# ==================================
# Usage Examples
# ==================================
#
# Test with CycloneDX 1.4:
# opa eval --data fips-compliance-cdx16.rego --input cbom-1.4.json 'data.fips_compliance_cdx16.deny'
#
# Test with CycloneDX 1.6:
# opa eval --data fips-compliance-cdx16.rego --input cbom-1.6.json 'data.fips_compliance_cdx16.deny'
#
# Generate compliance report:
# opa eval --data fips-compliance-cdx16.rego --input cbom.json 'data.fips_compliance_cdx16.compliance_report'