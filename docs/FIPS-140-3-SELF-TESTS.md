# FIPS 140-3 Self-Testing Requirements

## Overview

FIPS 140-3 introduces enhanced self-testing requirements that differ significantly from FIPS 140-2's approach. This document explains these requirements and how our solution addresses them.

---

## Key Changes from 140-2 to 140-3

### FIPS 140-2 Approach
- **One-time power-up self-test**: All algorithm tests run at module startup
- **Known Answer Tests (KATs)**: Verified all algorithms regardless of usage
- **Blocking behavior**: Entire module startup delayed until all tests complete

### FIPS 140-3 Approach
- **Two-phase testing**: Separates integrity checks from algorithm validation
- **On-demand testing**: Only tests algorithms that are actually used
- **More efficient**: Reduces startup overhead while maintaining security

---

## Pre-Operational Self-Test (POST)

### What is POST?

**Pre-Operational Self-Test** is the integrity verification phase that runs when a cryptographic module initializes.

**Purpose**:
- Verify module code hasn't been tampered with in memory or storage
- Ensure cryptographic module binary integrity
- Detect unauthorized modifications before any crypto operations

**How It Works**:
1. Module loads into memory
2. POST calculates checksum/hash of module code
3. Compares against known-good value
4. If match: Module proceeds to operational state
5. If mismatch: Module enters error state, refuses to operate

### POST in Container Environments

**QVS-CBOM Support**:
- **File Integrity Monitoring**: Aqua runtime policy monitors FIPS module files
  - `/usr/lib64/openssl/engines/fips.so` (OpenSSL FIPS provider)
  - `/proc/sys/crypto/fips_enabled` (kernel FIPS flag)
  - `/etc/system-fips` (system-wide FIPS indicator)

**Terraform Runtime Policy**:
```hcl
file_integrity_monitoring {
  enabled = true
  monitored_files = [
    "/proc/sys/crypto/fips_enabled",
    "/etc/system-fips",
    "/usr/lib64/openssl/engines/fips.so"
  ]
  monitored_files_modify = true
  monitored_files_delete = true
}
```

**How This Aligns with POST**:
- Detects any modification to cryptographic module files
- Triggers alert if POST-validated binaries are altered
- Maintains integrity throughout container lifecycle
- Prevents runtime tampering with FIPS modules

---

## Conditional Self-Tests

### What are Conditional Self-Tests?

**Conditional Self-Tests** are algorithm-specific tests that run **on-demand** before an algorithm's first use.

**Key Principle**: If an algorithm isn't used, its test doesn't run.

**Example Flow**:
1. Container starts with FIPS-validated OpenSSL module
2. POST verifies module integrity (file checksums)
3. Application makes first AES-256 encryption call
4. **Conditional Self-Test triggers**: AES-256 KAT runs before operation
5. If KAT passes: AES-256 becomes available for use
6. If KAT fails: Operation fails, error logged
7. SHA-256 hashing requested later
8. **Another Conditional Self-Test**: SHA-256 KAT runs on first use
9. Subsequent SHA-256 or AES-256 calls use already-validated algorithms (no re-test)

### Benefits Over 140-2

| Aspect | FIPS 140-2 | FIPS 140-3 |
|--------|------------|------------|
| **Startup Time** | Tests all algorithms | Tests only module integrity |
| **Runtime Overhead** | None (all done at startup) | Minimal (first use only) |
| **Unused Algorithms** | Tested anyway | Never tested |
| **Efficiency** | Lower | Higher |
| **Coverage** | Complete upfront | Complete when used |

### QVS-CBOM and Conditional Tests

**How QVS-CBOM Helps**:

1. **Algorithm Inventory**: CBOM identifies which algorithms are actually used
   ```json
   {
     "component": "/app/lib/crypto.js",
     "crypto": {
       "algorithm": "AES-256",
       "purpose": "Encryption"
     }
   }
   ```

2. **Usage Validation**: Know which algorithms need Conditional Self-Tests
   - If CBOM shows only AES-256 and SHA-256 used
   - Only those two algorithms need on-demand KATs
   - Unused algorithms (RSA, ECDSA, etc.) never trigger tests

3. **Compliance Evidence**: CBOM provides audit trail
   - Documents which algorithms were validated
   - Shows quantum-safe status of each
   - Proves only FIPS-approved algorithms used

**Integration with Aqua**:
```bash
# Generate CBOM showing algorithm usage
docker run enhanced-scanner --CBOM image myapp:latest

# REGO policy validates only approved algorithms present
opa eval --data policies/fips-compliance-cdx16.rego \
  --input cbom.json 'data.fips_compliance_cdx16.deny'

# If passes: Only algorithms in CBOM will trigger Conditional Self-Tests
# Result: Efficient runtime with FIPS 140-3 compliance
```

---

## Implementation Requirements

### For Container Images

**At Build Time**:
1. Use FIPS 140-3 validated cryptographic modules
   - OpenSSL 3.0 FIPS provider (recommended)
   - RHEL 9 system crypto libraries
   - Ubuntu Pro FIPS modules

2. Enable FIPS mode in base image
   ```dockerfile
   FROM registry.redhat.io/ubi9/ubi:latest
   RUN fips-mode-setup --enable
   ```

3. Verify POST capability
   ```bash
   # Check FIPS module has integrity verification
   openssl list -providers
   # Should show FIPS provider with self-test capability
   ```

**At Runtime**:
1. Host must be in FIPS mode
   ```bash
   cat /proc/sys/crypto/fips_enabled
   # Should output: 1
   ```

2. Monitor module integrity (Aqua runtime policy)
   - File Integrity Monitoring enabled
   - Alert on any module file changes
   - Block package installations that could replace modules

3. Log self-test results
   - POST failures logged to container stderr/stdout
   - Conditional Self-Test failures logged per operation
   - Aqua captures these logs for audit

---

## Validation and Compliance

### How to Verify POST Compliance

**Method 1: OpenSSL FIPS Provider Check**
```bash
# In container
openssl list -providers -verbose | grep -A 10 fips

# Expected output should include:
# - Self-test status: passed
# - Module integrity: verified
```

**Method 2: Kernel FIPS Mode**
```bash
# On host and in container
cat /proc/sys/crypto/fips_enabled
# Output: 1 (enabled)
```

**Method 3: Aqua Runtime Monitoring**
```bash
# Check runtime policy compliance
# Aqua dashboard shows:
# - File integrity status: Clean
# - No unauthorized module modifications
```

### How to Verify Conditional Self-Tests

**Method 1: CBOM Algorithm Inventory**
```bash
# Generate CBOM
./qvs-cbom-darwin -mode file -dir /app -output-cbom > cbom.json

# Extract algorithms
jq '.components[] | select(.crypto) | .crypto.algorithm' cbom.json

# Result: List of algorithms that will trigger Conditional Self-Tests
```

**Method 2: Application Logs**
```bash
# FIPS modules log self-test execution
# Check container logs for:
grep "FIPS.*self-test" /var/log/app.log

# Example entries:
# FIPS: AES-256 self-test passed
# FIPS: SHA-256 self-test passed
```

**Method 3: REGO Policy Validation**
```bash
# Ensure only FIPS-approved algorithms present
opa eval --data policies/fips-compliance-cdx16.rego \
  --input cbom.json 'data.fips_compliance_cdx16.deny'

# No output = compliant (all algorithms approved)
# Output = violations (non-approved algorithms found)
```

---

## Best Practices

### DO

✅ **Use FIPS 140-3 validated modules** (OpenSSL 3.0 FIPS provider)
✅ **Enable host FIPS mode** before running containers
✅ **Monitor file integrity** for crypto module files
✅ **Generate CBOM** for algorithm inventory
✅ **Validate with REGO** before deployment
✅ **Capture logs** for POST/Conditional test results
✅ **Use read-only containers** to prevent module tampering

### DON'T

❌ **Don't bypass self-tests** (never use --no-self-test flags)
❌ **Don't modify crypto modules** after validation
❌ **Don't mix FIPS and non-FIPS libraries** in same image
❌ **Don't run privileged containers** (breaks isolation)
❌ **Don't ignore self-test failures** (indicates compromise)

---

## Troubleshooting

### POST Failures

**Symptom**: Container fails to start, FIPS module error

**Causes**:
1. Module file corrupted or modified
2. FIPS mode not enabled on host
3. Incorrect module version

**Solutions**:
```bash
# Verify module integrity
sha256sum /usr/lib64/openssl/engines/fips.so
# Compare against known-good checksum

# Re-enable FIPS mode
fips-mode-setup --enable && reboot

# Reinstall FIPS module
dnf reinstall openssl-fips
```

### Conditional Self-Test Failures

**Symptom**: Cryptographic operation fails at runtime

**Causes**:
1. Algorithm KAT failure (rare, indicates hardware issue)
2. Non-FIPS algorithm requested
3. Module not properly initialized

**Solutions**:
```bash
# Check which algorithm failed
grep "self-test.*failed" /var/log/messages

# Verify algorithm is FIPS-approved
opa eval --data policies/fips-compliance-cdx16.rego \
  --input cbom.json 'data.fips_compliance_cdx16.deny'

# Re-initialize module
systemctl restart application
```

---

## Summary

FIPS 140-3 self-testing represents a significant improvement over 140-2:

| Requirement | How We Comply |
|-------------|---------------|
| **POST** | Aqua file integrity monitoring + OS FIPS modules |
| **Conditional Self-Tests** | QVS-CBOM algorithm inventory + FIPS module native support |
| **Integrity Verification** | Aqua runtime policy + read-only containers |
| **Audit Trail** | CBOM + Aqua logs + REGO policy results |

**Key Takeaway**: Our solution aligns perfectly with FIPS 140-3 requirements by combining:
- **QVS-CBOM**: Identifies what algorithms are used
- **REGO**: Validates only approved algorithms present
- **Aqua**: Monitors module integrity and enforces runtime controls
- **FIPS Modules**: Provide native POST and Conditional Self-Test capability

This layered approach ensures FIPS 140-3 compliance while maintaining efficiency and security.
