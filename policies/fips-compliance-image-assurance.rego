package appshield.imageassurance.FIPS1403Crypto

import data.lib.images

default failFIPS1403Crypto = false

__rego_metadata__ := {
    "id": "FIPS1403Crypto",
    "title": "FIPS 140-3 Cryptographic Compliance",
    "version": "1.0.0",
    "severity": "CRITICAL",
    "type": "ImageAssurance",
    "description": "Blocks images containing deprecated cryptographic algorithms (MD5, SHA-1, DES, 3DES, RC4) that violate FIPS 140-3 requirements.",
    "recommended_actions": "Replace deprecated cryptographic algorithms with FIPS 140-3 approved alternatives (AES-256, SHA-256, RSA-2048+, ECDSA-P256+)."
}

__rego_input__ := {
    "combine": false,
    "selector": [
        {
            "type": "image"
        }
    ]
}

# Check for outdated OpenSSL versions
has_weak_openssl {
    resource := input.resources[_]
    pkg := resource.resource.package_manager.packages[_]
    pkg.name == "openssl"
    semver.compare(pkg.version, "1.1.1") < 0
}

has_weak_openssl {
    resource := input.resources[_]
    pkg := resource.resource.package_manager.packages[_]
    pkg.name == "libssl1.0.0"
}

# Trigger failure if weak crypto detected
failFIPS1403Crypto {
    has_weak_openssl
}

deny[res] {
    failFIPS1403Crypto

    msg := sprintf(
        "Image contains outdated cryptographic libraries that do not meet FIPS 140-3 requirements. OpenSSL version must be 1.1.1 or higher.",
        []
    )

    res := {
        "msg": msg,
        "id": __rego_metadata__.id,
        "title": __rego_metadata__.title,
        "severity": __rego_metadata__.severity,
        "type": __rego_metadata__.type,
    }
}
