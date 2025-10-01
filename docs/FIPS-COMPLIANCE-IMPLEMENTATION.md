# FIPS 140-3 Compliance Implementation Guide

## Overview

This document explains the FIPS 140-3 compliance implementation using Aqua Security policies integrated with QVS-CBOM (Cryptography Bill of Materials) analysis. The solution provides automated cryptographic compliance validation for container images, runtime environments, and Kubernetes workloads.

## Architecture

### Components

1. **Terraform Policies** (`policies/fips-compliance-policies-corrected.tf`)
   - Image Assurance Policy
   - Container Runtime Policy
   - Kubernetes Assurance Policy

2. **REGO Policy** (`policies/fips-compliance-cdx16.rego`)
   - Policy-as-Code validation rules
   - CycloneDX 1.4 and 1.6 format support

3. **Validation Script** (`policies/validate-fips-compliance.sh`)
   - End-to-end compliance testing
   - Integrates CBOM generation with REGO evaluation

4. **QVS-CBOM Generator**
   - Scans for cryptographic algorithms
   - Identifies quantum-vulnerable cryptography
   - Generates CycloneDX-compliant CBOM

---

## FIPS 140-3 Policy Breakdown

### 1. Image Assurance Policy

**Purpose**: Ensures container images meet FIPS 140-3 cryptographic requirements before deployment.

**Key Controls**:

#### FIPS Level 1: Basic Cryptographic Requirements
- **Trusted Base Images**: Only approved base images containing FIPS-validated cryptographic modules
- **Block Failed Scans**: Automatically blocks non-compliant images
- **CI/CD Integration**: Fails pipeline builds for non-compliant images

#### FIPS Level 2: Cryptographic Package Control
```hcl
packages_black_list_enabled = true
packages_white_list_enabled = true
```
- Prevents installation of non-FIPS cryptographic packages
- Enforces use of approved cryptographic libraries

#### CMVP Validation Requirements
```hcl
scan_sensitive_data = true
disallow_malware    = true
```
- Ensures cryptographic modules have CMVP (Cryptographic Module Validation Program) certification
- Scans for sensitive data exposure

#### Security Level 4: Tamper Evidence
```hcl
docker_cis_enabled = true
linux_cis_enabled  = true
maximum_score      = 5
cvss_severity      = "high"
```
- CIS benchmark compliance for Docker and Linux
- Vulnerability severity thresholds
- Enhanced scanning for crypto-specific vulnerabilities

**License Compliance**:
```hcl
whitelisted_licenses = [
  "OpenSSL",
  "BSD-3-Clause",
  "MIT",
  "Apache-2.0",
  "GPL-2.0-with-linking-exception"
]
```
Ensures cryptographic modules use approved licenses compatible with FIPS requirements.

---

### 2. Container Runtime Policy

**Purpose**: Enforces FIPS 140-3 operational security controls during container execution.

**Key Controls**:

#### Physical Security: Access Control
```hcl
block_access_host_network = true
block_use_pid_namespace   = true
block_use_ipc_namespace   = true
block_use_uts_namespace   = true
no_new_privileges         = true
```
- Prevents containers from accessing host resources
- Enforces namespace isolation
- Blocks privilege escalation

#### Container Privilege Controls
```hcl
limit_container_privileges {
  enabled                  = true
  privileged               = true   # Blocks privileged containers
  prevent_root_user        = true   # Blocks root user
  prevent_low_port_binding = true
  netmode                  = true
  pidmode                  = true
  ipcmode                  = true
  usermode                 = true
  utsmode                  = true
}
```
**Rationale**: FIPS modules must run in controlled environments. Privileged containers could bypass cryptographic controls.

#### File Integrity Monitoring (Self-Tests)
```hcl
file_integrity_monitoring {
  enabled = true
  monitored_files = [
    "/proc/sys/crypto/fips_enabled",
    "/etc/system-fips",
    "/usr/lib64/openssl/engines/fips.so",
    "/etc/crypto-policies/back-ends/opensslcnf.config",
    "/etc/ssl/fips/*",
    "/usr/lib/fipscheck/*"
  ]
  monitored_files_modify = true
  monitored_files_delete = true
  monitored_files_create = true
}
```
**Purpose**: Detects tampering with FIPS cryptographic modules and configuration files.

#### Package Protection (Tamper Detection)
```hcl
package_block {
  enabled = true
  packages_black_list = [
    "openssl-libs",
    "python-crypto",
    "openssl-devel"
  ]
}
```
**Rationale**: Prevents runtime installation of non-FIPS cryptographic packages that could bypass validated modules.

#### Executable Control
```hcl
executable_blacklist {
  enabled = true
  executables = [
    "openssl-non-fips",
    "ssh-keygen-non-fips",
    "crypto-test-tools"
  ]
}
```
**Purpose**: Blocks execution of non-validated cryptographic binaries.

#### Volume Security
```hcl
restricted_volumes {
  enabled = true
  volumes = [
    "/", "/boot", "/dev", "/etc", "/lib",
    "/proc", "/sys", "/usr",
    "/etc/ssl",
    "/etc/crypto-policies",
    "/usr/lib/fipscheck"
  ]
}
```
**Rationale**: Prevents containers from mounting sensitive filesystem paths containing cryptographic assets.

#### Audit Controls
```hcl
auditing {
  enabled                       = true
  audit_all_processes           = true
  audit_process_cmdline         = true
  audit_user_account_management = true
  audit_success_login           = true
  audit_failed_login            = true
}
```
**Purpose**: Provides audit trail for cryptographic operations as required by FIPS.

#### Network Security
```hcl
enable_ip_reputation        = true
enable_port_scan_protection = true
enable_crypto_mining_dns    = true
```
**Rationale**: Protects cryptographic communications from network-based attacks.

#### System Integrity Protection
```hcl
system_integrity_protection {
  enabled                     = true
  audit_systemtime_change     = true
  monitor_audit_log_integrity = true
}
```
**Purpose**: Detects system-level tampering that could compromise cryptographic operations.

---

### 3. Kubernetes Assurance Policy

**Purpose**: Enforces FIPS 140-3 controls at the Kubernetes orchestration layer.

**Key Controls**:

#### Key Management: Secret Protection

**AVD-KSV-0109: ConfigMap with Secrets**
```hcl
avd_id      = "AVD-KSV-0109"
description = "Storing secrets in configMaps is unsafe"
severity    = "critical"
```
**Rationale**: Cryptographic keys must be stored in Secrets, not ConfigMaps. ConfigMaps are not encrypted at rest.

**AVD-KSV-01010: ConfigMap with Sensitive Content**
```hcl
avd_id      = "AVD-KSV-01010"
description = "Storing sensitive content such as usernames and email addresses in configMaps is unsafe"
severity    = "medium"
```
**Purpose**: Prevents exposure of credentials used to access cryptographic services.

**AVD-KSV-0041: Manage Secrets**
```hcl
avd_id      = "AVD-KSV-0041"
description = "Viewing secrets at the cluster-scope is akin to cluster-admin"
severity    = "critical"
```
**Rationale**: RBAC control over secret access prevents unauthorized access to cryptographic keys.

#### Role-Based Authentication

**AVD-KSV-0012: Runs as Root User**
```hcl
avd_id      = "AVD-KSV-0012"
description = "Force the running image to run as a non-root user to ensure least privileges"
severity    = "medium"
```
**Purpose**: FIPS modules should run with least privilege.

**AVD-KSV-0017: Privileged Containers**
```hcl
avd_id      = "AVD-KSV-0017"
description = "Privileged containers share namespaces with the host system and do not offer any security"
severity    = "high"
```
**Rationale**: Privileged containers can bypass all security controls including cryptographic protections.

#### Operational Environment: Network Security

**AVD-KSV-0008: Access to Host IPC Namespace**
```hcl
avd_id      = "AVD-KSV-0008"
description = "Sharing the host's IPC namespace allows container processes to communicate with processes on the host"
severity    = "high"
```

**AVD-KSV-0009: Access to Host Network**
```hcl
avd_id      = "AVD-KSV-0009"
description = "Sharing the host's network namespace permits processes in the pod to communicate with processes bound to the host's loopback adapter"
severity    = "critical"
```
**Purpose**: Cryptographic communications must be isolated from host network access.

#### Physical Security: Volume Protection

**AVD-KSV-0023: HostPath Volumes Mounted**
```hcl
avd_id      = "AVD-KSV-0023"
description = "According to pod security standard 'HostPath Volumes', HostPath volumes must be forbidden"
severity    = "high"
```

**AVD-KSV-0014: Root Filesystem Not Read-Only**
```hcl
avd_id      = "AVD-KSV-0014"
description = "An immutable root file system prevents applications from writing to their local disk"
severity    = "high"
```
**Rationale**: Immutable filesystem prevents tampering with FIPS cryptographic binaries.

#### Resource Controls (Tamper Evidence)

**AVD-KSV-0011: CPU Not Limited**
```hcl
avd_id      = "AVD-KSV-0011"
description = "Enforcing CPU limits prevents DoS via resource exhaustion"
severity    = "medium"
```

**AVD-KSV-0018: Memory Not Limited**
```hcl
avd_id      = "AVD-KSV-0018"
description = "Enforcing memory limits prevents DoS via resource exhaustion"
severity    = "medium"
```
**Purpose**: Resource limits prevent DoS attacks that could disrupt cryptographic operations.

#### Required Labels (Namespace Isolation)
```hcl
required_labels = [
  {
    key   = "fips.compliance"
    value = "required"
  },
  {
    key   = "crypto.level"
    value = "fips-140-2"
  },
  {
    key   = "security.clearance"
    value = "controlled"
  }
]
```
**Purpose**: Identifies FIPS workloads for audit and compliance tracking.

---

## REGO Policy (`fips-compliance-cdx16.rego`)

### Purpose
Validates CBOM output against FIPS 140-3 cryptographic requirements using Policy-as-Code.

### Key Features

#### Dual Format Support
```rego
# Extract crypto properties from both CycloneDX 1.4 and 1.6 formats
get_algorithm(component) = algorithm {
  algorithm := component.crypto.algorithm
} else = algorithm {
  prop := component.properties[_]
  prop.name == "cbom:algorithm"
  algorithm := prop.value
}
```
**Benefit**: Works with both legacy (1.4) and modern (1.6) CBOM formats.

#### Approved Algorithms
```rego
approved_algorithms := {
  "AES-256", "AES-192", "AES-128",
  "SHA-256", "SHA-384", "SHA-512",
  "SHA3-256", "SHA3-384", "SHA3-512",
  "RSA-2048", "RSA-3072", "RSA-4096",
  "ECDSA-P256", "ECDSA-P384", "ECDSA-P521",
  "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512"
}
```
**Source**: NIST SP 800-131A Rev. 2 (Transitioning the Use of Cryptographic Algorithms)

#### Violations Detection
```rego
# Detect non-FIPS algorithms
violations[msg] {
  component := input.components[_]
  algorithm := get_algorithm(component)
  not approved_algorithms[algorithm]
  msg := sprintf("Component '%s' uses non-FIPS algorithm: %s", [component.name, algorithm])
}

# Detect quantum-vulnerable algorithms
quantum_vulnerable[msg] {
  component := input.components[_]
  quantum_safe := get_quantum_safe(component)
  quantum_safe == "false"
  msg := sprintf("Component '%s' uses quantum-vulnerable cryptography", [component.name])
}
```

#### Compliance Check
```rego
# Overall compliance decision
compliant {
  count(violations) == 0
  count(quantum_vulnerable) == 0
}
```

---

## Validation Script (`validate-fips-compliance.sh`)

### Workflow

```bash
#!/usr/bin/env bash
# End-to-end FIPS 140-3 compliance validation
```

#### Step 1: Generate CBOM
```bash
echo "Generating CBOM for $IMAGE_NAME..."
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/outputs":/out \
  -e CBOM_CDX_TARGET=1.6 \
  -e CBOM_OUTPUT_FILE=/out/fips-cbom.json \
  enhanced-scanner --CBOM image "$IMAGE_NAME"
```
**Purpose**: Extracts cryptographic inventory from container image.

#### Step 2: Validate with REGO
```bash
echo "Validating CBOM against FIPS 140-3 policy..."
opa eval --data policies/fips-compliance-cdx16.rego \
  --input outputs/fips-cbom.json \
  --format pretty \
  'data.fips_compliance'
```
**Purpose**: Applies policy-as-code rules to CBOM.

#### Step 3: Report Results
```bash
if [ "$COMPLIANT" = "true" ]; then
  echo "✓ Image is FIPS 140-3 COMPLIANT"
  exit 0
else
  echo "✗ Image FAILED FIPS 140-3 compliance"
  echo "Violations:"
  opa eval --data policies/fips-compliance-cdx16.rego \
    --input outputs/fips-cbom.json \
    'data.fips_compliance.violations'
  exit 1
fi
```

---

## QVS-CBOM Integration Examples

### 1. Quantum-Safe Cryptography Assessment
```bash
qvs-cbom -mode file -dir /tmp/image | \
  jq -r '.components[] | select(.crypto.quantumSafe == false) | .crypto.algorithm' | \
  wc -l | test $(cat) -eq 0
```
**Purpose**: Counts quantum-vulnerable algorithms in image.

### 2. CMVP Module Validation
```bash
qvs-cbom -mode file -dir /tmp/image | \
  jq -r '.components[] | select(.crypto.cmvpValidated == false) | .name' | \
  wc -l | test $(cat) -eq 0
```
**Purpose**: Verifies all cryptographic modules have CMVP certification.

### 3. Cryptographic Asset Inventory
```bash
qvs-cbom -mode file -dir /tmp/image -output-cbom > /tmp/compliance-cbom.json && \
  test -s /tmp/compliance-cbom.json
```
**Purpose**: Generates complete CBOM for compliance reporting and audit trail.

---

## FIPS 140-3 Security Levels Mapping

| FIPS Level | Requirement | Implementation |
|------------|-------------|----------------|
| **Level 1** | Cryptographic Module Specification | Image Assurance Policy: Trusted base images with FIPS-validated modules |
| **Level 2** | Tamper Evidence | Runtime Policy: File integrity monitoring of crypto binaries |
| **Level 3** | Tamper Detection/Response | Runtime Policy: Package blocking, executable blacklist |
| **Level 4** | Physical Security | Kubernetes Policy: Volume restrictions, namespace isolation |

---

## Usage Workflow

### 1. Deploy Policies to Aqua
```bash
cd policies
terraform init
terraform plan
terraform apply
```

### 2. Test Image Compliance
```bash
./policies/validate-fips-compliance.sh bkimminich/juice-shop:latest
```

### 3. Review CBOM Output
```bash
cat outputs/fips-cbom.json | jq '.components[] | select(.crypto.quantumSafe == false)'
```

### 4. Generate Compliance Report
```bash
./qvs-cbom-csv.sh outputs/fips-cbom.json --output fips-compliance-report.csv
```

---

## Benefits

### Automated Compliance
- No manual cryptographic audits required
- Continuous validation in CI/CD pipeline
- Real-time detection of non-compliant changes

### Quantum Readiness
- Identifies quantum-vulnerable algorithms
- Provides migration path to post-quantum cryptography
- Future-proofs cryptographic infrastructure

### Audit Trail
- Complete cryptographic asset inventory
- CycloneDX standard format (industry-standard SBOM)
- Integration with compliance management tools

### Defense in Depth
- Image-level controls (pre-deployment)
- Runtime controls (during execution)
- Kubernetes controls (orchestration layer)

---

## References

- **NIST SP 800-131A Rev. 2**: Transitioning the Use of Cryptographic Algorithms and Key Lengths
- **FIPS 140-3**: Security Requirements for Cryptographic Modules
- **CycloneDX Specification**: https://cyclonedx.org/specification/overview/
- **Aqua Security Policies**: https://docs.aquasec.com/docs/policies
- **Open Policy Agent (OPA)**: https://www.openpolicyagent.org/

---

## Next Steps

1. **Test in Non-Production**: Validate policies against existing workloads in development/staging
2. **Tune Whitelists**: Adjust approved algorithms based on organizational requirements
3. **Enable Enforcement**: Set `enforce = true` after validation period
4. **Integrate CI/CD**: Add CBOM validation to pipeline gates
5. **Monitor Compliance**: Set up dashboards for ongoing compliance tracking