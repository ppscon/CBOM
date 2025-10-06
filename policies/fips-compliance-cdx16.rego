package fips_compliance_cdx16

# FIPS 140-3 Compliance Policy for CycloneDX 1.6 CBOM
# Validates cryptographic assets against FIPS requirements
# Blocks deprecated and quantum-vulnerable algorithms

# Deprecated algorithms that violate FIPS 140-3
deprecated_algorithms := {
    "MD5": "CRITICAL",
    "SHA-1": "HIGH",
    "DES": "CRITICAL",
    "3DES": "HIGH",
    "RC4": "CRITICAL",
    "MD2": "CRITICAL",
    "MD4": "CRITICAL"
}

# Weak key lengths (below FIPS minimums)
weak_key_lengths := {
    "RSA": 2048,
    "DSA": 2048,
    "ECDSA": 256
}

# DENY rules - pipeline blocking violations
deny[msg] {
    asset := input.cryptographicAssets[_]
    severity := deprecated_algorithms[asset.algorithm]
    msg := sprintf("FIPS VIOLATION: %s algorithm detected (%s severity) - deprecated and insecure", [asset.algorithm, severity])
}

deny[msg] {
    asset := input.cryptographicAssets[_]
    asset.algorithm == "RSA"
    asset.keyLength < 2048
    msg := sprintf("FIPS VIOLATION: RSA key length %d < 2048 bits (minimum required)", [asset.keyLength])
}

deny[msg] {
    asset := input.cryptographicAssets[_]
    asset.algorithm == "ECDSA"
    asset.keyLength < 256
    msg := sprintf("FIPS VIOLATION: ECDSA key length %d < 256 bits (minimum required)", [asset.keyLength])
}

# WARN rules - non-blocking warnings
warn[msg] {
    asset := input.cryptographicAssets[_]
    asset.algorithm == "RSA"
    asset.keyLength >= 2048
    asset.keyLength < 3072
    msg := sprintf("WARNING: RSA %d-bit keys are quantum-vulnerable. Migrate to PQC.", [asset.keyLength])
}

warn[msg] {
    asset := input.cryptographicAssets[_]
    contains(asset.algorithm, "SHA-2")
    msg := sprintf("WARNING: %s is quantum-vulnerable. Consider SHA-3 or CRYSTALS.", [asset.algorithm])
}

# Count violations
violation_count := count(deny)

# Summary for reporting
summary := {
    "total_assets": count(input.cryptographicAssets),
    "critical_violations": violation_count,
    "warnings": count(warn),
    "compliant": violation_count == 0
}
