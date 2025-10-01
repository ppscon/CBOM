# CMVP FIPS 140-3 Module Reference Guide

## Overview

The Cryptographic Module Validation Program (CMVP) is jointly run by NIST and the Canadian Centre for Cyber Security (CCCS) to validate cryptographic modules against FIPS 140-3 standards. This guide provides reference information for identifying and using FIPS 140-3 validated modules.

---

## CMVP Transition Timeline

### Critical Dates

| Date | Milestone |
|------|-----------|
| **September 22, 2019** | FIPS 140-3 standard published |
| **September 22, 2020** | CMVP begins accepting 140-3 validation submissions |
| **April 21, 2022** | CMVP **stops accepting** new FIPS 140-2 validations |
| **September 21, 2026** | FIPS 140-2 certificates move to "historical" list |
| **September 21, 2026+** | Only FIPS 140-3 certificates accepted for new implementations |

**Key Takeaway**: After September 2026, only FIPS 140-3 validated modules can be used for new FIPS-compliant systems.

---

## Finding FIPS 140-3 Validated Modules

### NIST CMVP Database

**URL**: https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules

**Search Process**:
1. Go to CMVP Validated Modules page
2. Filter by:
   - **Standard**: FIPS 140-3
   - **Status**: Active
   - **Module Type**: Software (for container environments)
3. Search by vendor or module name

**Example Validated Modules** (as of 2025):

| Module Name | Vendor | Certificate # | Security Level | Notes |
|-------------|--------|---------------|----------------|-------|
| OpenSSL 3.0 FIPS Module | OpenSSL Project | #4282 (example) | Level 1 | Most common for containers |
| Red Hat Enterprise Linux 9 Crypto | Red Hat | #4XXX | Level 1 | OS-level crypto |
| Ubuntu Pro FIPS Crypto | Canonical | #4XXX | Level 1 | Ubuntu FIPS modules |
| AWS-LC FIPS | Amazon Web Services | #4XXX | Level 1 | AWS cryptographic library |

**Note**: Certificate numbers are examples. Always verify current numbers at NIST CMVP website.

### Vendor-Specific References

**Red Hat**:
- **URL**: https://access.redhat.com/articles/compliance_activities_and_gov_standards
- **Products**: RHEL 8, RHEL 9, OpenShift
- **Modules**: System crypto libraries, OpenSSL, NSS, libgcrypt
- **Validation**: Published certificate numbers per RHEL version

**Canonical (Ubuntu)**:
- **URL**: https://ubuntu.com/security/certifications/docs/fips
- **Products**: Ubuntu Pro 20.04 LTS, 22.04 LTS FIPS
- **Modules**: OpenSSL, libgcrypt, openssh, strongswan
- **Validation**: FIPS 140-3 certified modules included

**Amazon Web Services**:
- **URL**: https://aws.amazon.com/compliance/fips/
- **Products**: Amazon Linux 2, AWS-LC (AWS Libcrypto)
- **Modules**: AWS-LC FIPS module
- **Validation**: CMVP certificates for AWS cryptographic libraries

---

## Recommended FIPS 140-3 Modules for Containers

### 1. OpenSSL 3.0 FIPS Provider (Recommended)

**Why Recommended**:
- ✅ Most widely adopted
- ✅ Extensive platform support (Linux, containers, cloud)
- ✅ Active development and maintenance
- ✅ Drop-in replacement for non-FIPS OpenSSL
- ✅ FIPS 140-3 validated

**Usage in Containers**:
```dockerfile
FROM registry.redhat.io/ubi9/ubi:latest

# Install OpenSSL 3.0 with FIPS provider
RUN dnf install -y openssl openssl-fips

# Enable FIPS mode
RUN fips-mode-setup --enable

# Verify FIPS module
RUN openssl list -providers | grep -i fips
```

**Verification**:
```bash
# Check FIPS provider is loaded
openssl list -providers -verbose

# Expected output:
# fips
#     name: OpenSSL FIPS Provider
#     version: 3.0.x
#     status: active
```

**Certificate Information**:
- **Vendor**: OpenSSL Software Foundation
- **Module**: OpenSSL FIPS Object Module
- **Standard**: FIPS 140-3
- **Security Level**: Level 1
- **Validation**: Check https://csrc.nist.gov/projects/cryptographic-module-validation-program

### 2. Red Hat Enterprise Linux 9 System Crypto

**Why Recommended**:
- ✅ Enterprise support from Red Hat
- ✅ Integrated with RHEL ecosystem
- ✅ Includes multiple cryptographic libraries (OpenSSL, libgcrypt, NSS)
- ✅ Validated as complete system

**Usage**:
```dockerfile
FROM registry.redhat.io/ubi9/ubi:latest

# Enable FIPS mode (enables all system crypto modules)
RUN fips-mode-setup --enable && \
    cat /etc/system-fips
```

**Certificate Information**:
- **Vendor**: Red Hat, Inc.
- **Product**: Red Hat Enterprise Linux 9
- **Modules**: kernel crypto, OpenSSL, libgcrypt, NSS
- **Standard**: FIPS 140-3
- **Security Level**: Level 1

### 3. Ubuntu Pro FIPS Modules

**Why Recommended**:
- ✅ Ubuntu Pro subscription includes FIPS modules
- ✅ Validated cryptographic libraries
- ✅ Suitable for Ubuntu-based containers

**Usage**:
```dockerfile
FROM ubuntu:pro-22.04-fips

# FIPS modules already installed and enabled
# Verify FIPS status
RUN cat /proc/sys/crypto/fips_enabled
# Output: 1
```

**Certificate Information**:
- **Vendor**: Canonical Ltd.
- **Product**: Ubuntu Pro 22.04 LTS FIPS
- **Modules**: OpenSSL, libgcrypt, openssh, strongswan
- **Standard**: FIPS 140-3
- **Security Level**: Level 1

---

## Verifying FIPS 140-3 Compliance

### Method 1: CMVP Certificate Lookup

**Process**:
1. Identify module name and version in your container
   ```bash
   openssl version
   # Output: OpenSSL 3.0.7 1 Nov 2022 (Library: OpenSSL 3.0.7 1 Nov 2022)
   ```

2. Search CMVP database for "OpenSSL 3.0.7"

3. Verify certificate shows:
   - ✅ Standard: FIPS 140-3
   - ✅ Status: Active
   - ✅ Security Level: 1 (or higher)

4. Document certificate number for audit

**Example Documentation**:
```markdown
## FIPS 140-3 Compliance Evidence

**Cryptographic Module**: OpenSSL 3.0 FIPS Provider
**Version**: 3.0.7
**CMVP Certificate**: #4282
**Standard**: FIPS 140-3
**Security Level**: Level 1
**Validation Date**: 2023-06-15
**Status**: Active

**Verification Date**: 2025-01-15
**Verified By**: Security Team
**Source**: https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4282
```

### Method 2: Module Self-Test Verification

**Process**:
```bash
# Verify FIPS module self-tests pass
openssl list -providers -verbose | grep -A 5 fips

# Expected output:
# fips
#     name: OpenSSL FIPS Provider
#     version: 3.0.7
#     status: active
#     selftest: passed  # ← Critical indicator
```

### Method 3: Aqua-CBOM Validation

**Process**:
```bash
# Generate CBOM
./aqua-cbom-darwin -mode file -dir /app -output-cbom > cbom.json

# Check for CMVP validation status
jq '.components[] | select(.crypto) | {
  name: .name,
  algorithm: .crypto.algorithm,
  cmvpValidated: .crypto.cmvpValidated
}' cbom.json
```

**Expected Output**:
```json
{
  "name": "/usr/lib64/libssl.so.3.0",
  "algorithm": "AES-256",
  "cmvpValidated": true
}
```

---

## Container Base Image Recommendations

### Recommended FIPS 140-3 Base Images

| Base Image | Vendor | FIPS 140-3 Support | Notes |
|------------|--------|-------------------|-------|
| `registry.redhat.io/ubi9/ubi` | Red Hat | ✅ Native | Enable with `fips-mode-setup` |
| `ubuntu:pro-22.04-fips` | Canonical | ✅ Pre-enabled | Requires Ubuntu Pro |
| `amazonlinux:2-fips` | AWS | ✅ Pre-enabled | AWS-specific |
| `registry.access.redhat.com/ubi9/ubi-minimal` | Red Hat | ✅ Native | Minimal footprint |

### NOT Recommended (Non-FIPS or 140-2 only)

| Base Image | Issue |
|------------|-------|
| `ubuntu:22.04` | Not FIPS-enabled (requires Ubuntu Pro) |
| `alpine:latest` | No FIPS 140-3 support (musl libc) |
| `debian:bookworm` | No official FIPS 140-3 modules |
| `centos:8` | EOL, no 140-3 updates |

---

## Integration with Aqua-CBOM

### Workflow: CMVP Validation + CBOM

**Step 1: Select FIPS 140-3 Base Image**
```dockerfile
FROM registry.redhat.io/ubi9/ubi:latest
RUN fips-mode-setup --enable
```

**Step 2: Build Application Image**
```bash
docker build -t myapp:fips .
```

**Step 3: Generate CBOM**
```bash
docker run enhanced-scanner --CBOM image myapp:fips
```

**Step 4: Validate CMVP Compliance**
```bash
# Check all crypto modules have CMVP validation
jq '.components[] | select(.crypto) | select(.crypto.cmvpValidated != true)' cbom.json

# Expected: No output (all modules validated)
```

**Step 5: Document for Audit**
```bash
# Generate compliance report
jq '{
  image: .metadata.component.name,
  scanDate: .metadata.timestamp,
  fipsModules: [
    .components[] | select(.crypto.cmvpValidated == true) | {
      module: .name,
      algorithm: .crypto.algorithm,
      cmvpValidated: .crypto.cmvpValidated
    }
  ]
}' cbom.json > compliance-report.json
```

---

## Troubleshooting CMVP Issues

### Issue 1: Module Not Found in CMVP Database

**Symptom**: Can't find module in NIST CMVP search

**Causes**:
- Module not yet validated for FIPS 140-3
- Incorrect module name or version
- Module still in validation process

**Solution**:
```bash
# Check exact module name and version
openssl version -a

# Search CMVP with exact vendor and module name
# Example: "OpenSSL Software Foundation" + "OpenSSL FIPS Object Module"

# If not found, contact vendor for validation status
```

### Issue 2: Certificate Shows 140-2 Instead of 140-3

**Symptom**: CMVP certificate is FIPS 140-2

**Cause**: Using legacy module version

**Solution**:
```dockerfile
# Update to FIPS 140-3 validated version
FROM registry.redhat.io/ubi9/ubi:latest  # ← UBI 9, not UBI 8
RUN dnf install -y openssl-3.0  # ← Version 3.0, not 1.1
```

### Issue 3: Self-Test Failures

**Symptom**: Module self-test fails at startup

**Cause**: Module file integrity check failed (possible tampering)

**Solution**:
```bash
# Reinstall FIPS module
dnf reinstall openssl-fips

# Verify checksum
sha256sum /usr/lib64/openssl/engines/fips.so
# Compare against vendor-published checksum

# Enable file integrity monitoring (Aqua)
# Prevent future tampering
```

---

## Best Practices

### DO

✅ **Verify CMVP certificates** - Always check NIST database
✅ **Document certificate numbers** - Include in audit evidence
✅ **Use vendor-supported modules** - Red Hat, Canonical, AWS
✅ **Keep modules updated** - Security patches may affect validation
✅ **Test module self-tests** - Verify pass before deployment
✅ **Monitor CMVP status** - Certificates can be revoked

### DON'T

❌ **Don't assume FIPS-named packages are validated** - Verify CMVP
❌ **Don't mix FIPS and non-FIPS modules** - Breaks compliance
❌ **Don't modify validated modules** - Voids certification
❌ **Don't use expired certificates** - Check status regularly
❌ **Don't skip version verification** - Wrong version = not validated

---

## Summary

### FIPS 140-3 CMVP Compliance Checklist

- [ ] Select FIPS 140-3 validated cryptographic module (OpenSSL 3.0 recommended)
- [ ] Verify CMVP certificate in NIST database
- [ ] Document certificate number and validation details
- [ ] Use approved base image (UBI 9, Ubuntu Pro FIPS, Amazon Linux 2 FIPS)
- [ ] Enable FIPS mode on host and in container
- [ ] Verify module self-tests pass
- [ ] Generate CBOM showing cmvpValidated: true
- [ ] Validate with REGO policy
- [ ] Monitor with Aqua file integrity monitoring
- [ ] Maintain audit documentation

### Key Resources

- **NIST CMVP Database**: https://csrc.nist.gov/projects/cryptographic-module-validation-program
- **OpenSSL FIPS**: https://www.openssl.org/docs/fips.html
- **Red Hat FIPS**: https://access.redhat.com/articles/compliance_activities_and_gov_standards
- **Ubuntu FIPS**: https://ubuntu.com/security/certifications/docs/fips
- **AWS FIPS**: https://aws.amazon.com/compliance/fips/

---

**Last Updated**: January 2025
**Next Review**: July 2025 (check for new FIPS 140-3 modules)
