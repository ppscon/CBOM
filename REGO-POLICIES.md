# REGO Policy Documentation

## Overview: Two REGO Policies, Two Purposes

This project uses **two distinct REGO policies** that serve different security gates in the FIPS 140-3 compliance workflow:

```
┌─────────────────────────────────────────────────────────────────┐
│                    CI/CD Pipeline (Build Time)                  │
├─────────────────────────────────────────────────────────────────┤
│  REGO Policy #1: OPA Pipeline Validation                       │
│  File: policies/fips-compliance-cdx16.rego                      │
│  Engine: Open Policy Agent (OPA)                                │
│  Input: CBOM JSON (CycloneDX 1.6)                               │
│  Purpose: Validate cryptographic compliance                     │
│  Action: Block image push if violations found                   │
└─────────────────────────────────────────────────────────────────┘
                            ↓
                    Image pushed to registry
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│                 Kubernetes Cluster (Runtime)                    │
├─────────────────────────────────────────────────────────────────┤
│  REGO Policy #2: Aqua Admission Controller                     │
│  File: policies/aqua-fips-crypto-compliance.rego                │
│  Engine: Aqua Security Platform                                 │
│  Input: Kubernetes workload manifest                            │
│  Purpose: Enforce FIPS-certified base images                    │
│  Action: Block deployment if non-compliant base image           │
└─────────────────────────────────────────────────────────────────┘
```

---

## REGO Policy #1: Pipeline CBOM Validation (OPA)

### Purpose
Validates the **Cryptographic Bill of Materials (CBOM)** generated during the CI/CD pipeline to ensure no deprecated or quantum-vulnerable algorithms are present in the container image.

### File Location
```
policies/fips-compliance-cdx16.rego
```

### Execution Context
- **When**: After CBOM generation in CI/CD pipeline
- **Where**: GitHub Actions workflow (Stage 4: REGO Compliance)
- **Engine**: Open Policy Agent (OPA)
- **Input Format**: CycloneDX 1.6 CBOM JSON

### Key Features

#### 1. Deprecated Algorithm Detection
```rego
fips_deprecated_algorithms := {
    "MD5", "SHA-1", "DES", "3DES",
    "RSA-1024", "RC4", "RC2", "Blowfish"
}

deny[res] if {
    some component in get_components()
    has_crypto(component)
    algo := get_algorithm(component)
    algo in fips_deprecated_algorithms
    # ... generates violation message
}
```

**What it catches:**
- MD5 usage (cryptographically broken)
- SHA-1 (collision attacks possible)
- 3DES (deprecated as of 2023)
- Weak key sizes (RSA-1024)

#### 2. Quantum Vulnerability Assessment
```rego
deny[res] if {
    some component in get_components()
    has_crypto(component)
    not is_quantum_safe(component)
    risk := get_quantum_risk(component)
    risk != "None"
    # ... generates violation message
}
```

**What it catches:**
- Algorithms vulnerable to Grover's Algorithm (halves security)
- Algorithms vulnerable to Shor's Algorithm (breaks RSA/ECDSA)
- Non-quantum-resistant cryptography

#### 3. CMVP Validation Warnings
```rego
warn[msg] if {
    some component in get_components()
    has_crypto(component)
    purpose := get_property(component, "cbom:purpose")
    purpose in ["Encryption", "Signature", "KeyExchange"]
    not has_cmvp_validation(component)
    # ... generates warning message
}
```

**What it checks:**
- CMVP (Cryptographic Module Validation Program) certification
- FIPS 140-3 module validation status

#### 4. CBOM Summary Validation
```rego
deny[res] if {
    summary := get_cbom_summary()
    summary.quantum_safe_assets < summary.total_assets
    vulnerable := summary.total_assets - summary.quantum_safe_assets
    # ... generates violation for quantum-vulnerable assets
}
```

**What it validates:**
- Overall quantum readiness of the image
- Ratio of quantum-safe to total cryptographic assets

### Policy Output

**On Success (No Violations):**
```json
{
  "result": []
}
```
Exit code: 0 → Image push proceeds

**On Failure (Violations Found):**
```json
{
  "result": [
    {
      "msg": "Deprecated algorithm detected: MD5 in /app/lib/crypto.js (Not FIPS 140-3 approved)",
      "id": "FIPS-CBOM-001",
      "severity": "CRITICAL",
      "title": "FIPS 140-3 CBOM Compliance",
      "type": "Cryptographic Bill of Materials"
    }
  ]
}
```
Exit code: 1 → Image push BLOCKED

### Demo Talking Points (Pipeline REGO)

**"This REGO policy is our cryptographic compliance gate..."**

- "It reads the CBOM generated in Stage 3"
- "Checks for deprecated algorithms like MD5, 3DES"
- "Assesses quantum vulnerability (627/628 assets in Juice Shop)"
- "If violations found: Pipeline shows 'BLOCKED' and exits with code 1"
- "This prevents non-compliant images from reaching production"

---

## REGO Policy #2: Kubernetes Admission Controller (Aqua)

### Purpose
Enforces **FIPS-certified base image** requirements at deployment time, ensuring only approved container images can run in the Kubernetes cluster.

### File Location
```
policies/aqua-fips-crypto-compliance.rego
```

### Execution Context
- **When**: Kubernetes workload deployment (kubectl apply)
- **Where**: Aqua Kubernetes Admission Controller
- **Engine**: Aqua Security Platform
- **Input Format**: Kubernetes workload manifest (Pod, Deployment, etc.)

### Policy Structure

#### Metadata Definition
```rego
package appshield.kubernetes.FIPSCryptoCompliance

__rego_metadata__ := {
    "id": "FIPSCryptoCompliance",
    "avd_id": "AVDFIPS001",
    "title": "FIPSCryptographicCompliance",
    "version": "v1.0.0",
    "severity": "CRITICAL",
    "type": "Kubernetes Security Check"
}
```

**Key fields:**
- `package`: Must be `appshield.kubernetes.*` for Aqua integration
- `avd_id`: Aqua Vulnerability Database ID
- `type`: "Kubernetes Security Check" (required for admission controller)

#### FIPS-Approved Base Images
```rego
fipsApprovedPrefixes := [
    "registry.access.redhat.com/ubi8",
    "registry.access.redhat.com/ubi9",
    "ubuntu/fips",
    "ironbank"
]
```

**Approved sources:**
- Red Hat Universal Base Image (UBI) 8/9 - FIPS validated
- Ubuntu FIPS images - FIPS 140-2/140-3 certified
- Iron Bank - DoD hardened containers

#### Violation Detection
```rego
violatesFIPSCompliance if {
    containers := kubernetes.containers[_]
    image := containers.image
    not any([startswith(image, prefix) | prefix := fipsApprovedPrefixes[_]])
}

deny[res] {
    violatesFIPSCompliance
    msg := kubernetes.format(sprintf(
        "%s %s in namespace %s requires FIPS certified base images",
        [kubernetes.kind, kubernetes.name, kubernetes.namespace]
    ))
    res := {
        "msg": msg,
        "id": __rego_metadata__.id,
        "title": __rego_metadata__.title,
        "severity": __rego_metadata__.severity,
        "type": __rego_metadata__.type
    }
}
```

**What it checks:**
- Every container image in the workload
- Image prefix must match approved list
- Applies to Pods, Deployments, StatefulSets, DaemonSets, etc.

### Integration with Aqua Platform

#### 1. Import via Aqua UI
Navigate to: **Policies → Image Assurance → Custom Checks**

1. Click "Add Custom Check"
2. Select "Import from REGO"
3. Upload `aqua-fips-crypto-compliance.rego`
4. Policy appears in available checks list

#### 2. Assign to Kubernetes Assurance Policy
```hcl
resource "aquasec_kubernetes_assurance_policy" "fips_k8s_compliance" {
  name        = "fips-140-3-kubernetes-compliance"

  custom_checks {
    script_id   = "FIPSCryptoCompliance"  # Matches __rego_metadata__.id
    author      = "Security Team"
    severity    = "critical"
  }

  # ... other settings
}
```

**Terraform deployment:**
```bash
cd policies/
terraform init
terraform plan
terraform apply
```

#### 3. Admission Controller Enforcement
```hcl
resource "aquasec_kubernetes_assurance_policy" "fips_k8s_compliance" {
  # ... policy definition

  admission_control_enabled = true  # Enable blocking at runtime
  block_admission_control   = true  # Hard block (not just audit)
}
```

### Policy Output (Kubernetes)

**On Success:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: compliant-app
spec:
  containers:
  - name: app
    image: registry.access.redhat.com/ubi9/ubi-minimal:latest
```
→ Deployment proceeds

**On Failure:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: non-compliant-app
spec:
  containers:
  - name: app
    image: alpine:latest  # Not FIPS-certified
```
→ Admission controller blocks with:
```
Error from server: admission webhook denied the request:
Pod non-compliant-app in namespace default requires FIPS certified base images
```

### Demo Talking Points (Kubernetes REGO)

**"This REGO policy is our runtime enforcement layer..."**

- "Imported into Aqua Platform as a Kubernetes Security Check"
- "Enforced by Aqua's Admission Controller at deployment time"
- "Checks that base images come from FIPS-certified sources"
- "Examples: Red Hat UBI, Ubuntu FIPS, Iron Bank"
- "If non-compliant image: kubectl apply fails immediately"
- "This is our last line of defense - nothing runs without approval"

---

## Comparison: Pipeline vs. Kubernetes REGO

| Aspect | Pipeline REGO (OPA) | Kubernetes REGO (Aqua) |
|--------|---------------------|------------------------|
| **File** | `fips-compliance-cdx16.rego` | `aqua-fips-crypto-compliance.rego` |
| **Engine** | Open Policy Agent (OPA) | Aqua Security Platform |
| **When** | Build time (CI/CD) | Runtime (deployment) |
| **Input** | CBOM JSON (CycloneDX 1.6) | Kubernetes manifest (YAML) |
| **Checks** | Cryptographic algorithms | Base image compliance |
| **Focus** | Algorithm-level validation | Image source validation |
| **Action** | Block image push | Block pod creation |
| **Package** | `fips_compliance_cdx16` | `appshield.kubernetes.*` |
| **Metadata** | Optional | Required (`__rego_metadata__`) |

---

## Why Two REGO Policies?

### Different Concerns, Different Gates

**Pipeline REGO (OPA):**
- ✅ Analyzes **what's inside** the image
- ✅ Detects deprecated algorithms (MD5, 3DES)
- ✅ Identifies quantum vulnerabilities
- ✅ Validates cryptographic inventory
- ❌ Doesn't know about Kubernetes
- ❌ Doesn't enforce base image standards

**Kubernetes REGO (Aqua):**
- ✅ Enforces **where images come from**
- ✅ Ensures FIPS-certified base layers
- ✅ Integrates with Aqua Admission Controller
- ✅ Blocks non-compliant deployments
- ❌ Doesn't analyze image contents
- ❌ Doesn't detect algorithm-level issues

### Defense-in-Depth Strategy

```
┌─────────────────────────────────────────┐
│  Layer 1: Aqua Image Assurance          │
│  → CVEs, malware, CIS benchmarks        │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│  Layer 2: Pipeline REGO (OPA)           │
│  → Cryptographic algorithm validation   │
│  → CBOM-based compliance                │
└─────────────────────────────────────────┘
                  ↓
         Image pushed to registry
                  ↓
┌─────────────────────────────────────────┐
│  Layer 3: Kubernetes REGO (Aqua)        │
│  → FIPS base image enforcement          │
│  → Admission controller blocking        │
└─────────────────────────────────────────┘
                  ↓
         Workload runs in cluster
```

**Together, they provide:**
- ✅ Build-time algorithm validation
- ✅ Runtime base image enforcement
- ✅ Complete FIPS 140-3 compliance coverage
- ✅ Defense at multiple checkpoints

---

## Configuration Files

### Pipeline REGO (OPA)

**File:** `policies/fips-compliance-cdx16.rego`

**Key Configuration:**
```rego
# Approved algorithms
fips_approved_algorithms := {
    "AES-128", "AES-192", "AES-256",
    "SHA-256", "SHA-384", "SHA-512",
    "SHA3-256", "SHA3-384", "SHA3-512",
    "RSA-2048", "RSA-3072", "RSA-4096",
    "ECDSA-P256", "ECDSA-P384", "ECDSA-P521",
    "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512"
}

# Deprecated algorithms (blocking)
fips_deprecated_algorithms := {
    "MD5", "SHA-1", "DES", "3DES",
    "RSA-1024", "RC4", "RC2", "Blowfish"
}
```

**Customization:**
- Add/remove algorithms from approved/deprecated lists
- Adjust severity levels
- Modify quantum risk thresholds

---

### Kubernetes REGO (Aqua)

**File:** `policies/aqua-fips-crypto-compliance.rego`

**Key Configuration:**
```rego
# FIPS-certified base image sources
fipsApprovedPrefixes := [
    "registry.access.redhat.com/ubi8",
    "registry.access.redhat.com/ubi9",
    "ubuntu/fips",
    "ironbank"
]
```

**Customization:**
- Add your organization's FIPS-certified registries
- Include private registry prefixes
- Add specific image tags if needed

**Example customization:**
```rego
fipsApprovedPrefixes := [
    # Red Hat UBI
    "registry.access.redhat.com/ubi8",
    "registry.access.redhat.com/ubi9",

    # Ubuntu FIPS
    "ubuntu/fips",

    # DoD Iron Bank
    "ironbank",

    # Your organization's FIPS registry
    "registry.yourcompany.com/fips-certified",

    # Specific approved images
    "docker.io/library/postgres:14-fips"
]
```

---

## Testing REGO Policies

### Test Pipeline REGO (OPA)

```bash
# Install OPA
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod +x opa
sudo mv opa /usr/local/bin/

# Validate syntax
opa check policies/fips-compliance-cdx16.rego

# Test with CBOM JSON
opa eval \
  --data policies/fips-compliance-cdx16.rego \
  --input outputs/cbom.json \
  --format pretty \
  'data.fips_compliance_cdx16.deny'

# Expected output with violations:
{
  "msg": "Deprecated algorithm detected: MD5 in /app/crypto.js",
  "severity": "CRITICAL",
  ...
}
```

---

### Test Kubernetes REGO (Aqua)

**Method 1: Via Aqua UI**
1. Navigate to **Policies → Image Assurance → Custom Checks**
2. Find "FIPSCryptographicCompliance"
3. Click "Test"
4. Enter sample Kubernetes manifest
5. View results

**Method 2: Dry-run with kubectl**
```bash
# Create test pod with non-compliant image
cat <<EOF | kubectl apply --dry-run=server -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-alpine
spec:
  containers:
  - name: app
    image: alpine:latest
EOF

# Expected: Admission webhook blocks with FIPS violation message
```

---

## Troubleshooting

### Pipeline REGO Issues

**Problem:** "Package not found"
```bash
# Solution: Check package name matches
grep "package" policies/fips-compliance-cdx16.rego
# Should be: package fips_compliance_cdx16
```

**Problem:** "Undefined function"
```bash
# Solution: Import required keywords
import future.keywords.in
import future.keywords.if
```

**Problem:** "Empty result set"
```bash
# Solution: Check CBOM input format
jq '.components' outputs/cbom.json  # Should return array
```

---

### Kubernetes REGO Issues

**Problem:** "Policy not showing in Aqua UI"
```
# Solution: Verify __rego_metadata__ structure
- Must include: id, title, severity, type
- type must be: "Kubernetes Security Check"
- package must start with: appshield.kubernetes
```

**Problem:** "Admission controller not blocking"
```bash
# Solution: Check policy enforcement settings
terraform state show aquasec_kubernetes_assurance_policy.fips_k8s_compliance

# Verify:
admission_control_enabled = true
block_admission_control = true
```

**Problem:** "Custom check not found"
```
# Solution: Re-import REGO into Aqua
1. Go to Custom Checks
2. Delete old version
3. Re-upload aqua-fips-crypto-compliance.rego
4. Verify script_id matches policy reference
```

---

## Best Practices

### Pipeline REGO (OPA)
1. ✅ Keep algorithm lists up-to-date with NIST standards
2. ✅ Version control all policy changes
3. ✅ Test with sample CBOM before deploying
4. ✅ Use `continue-on-error: true` only for demos
5. ✅ Monitor for new quantum-vulnerable algorithms

### Kubernetes REGO (Aqua)
1. ✅ Maintain approved image prefix list
2. ✅ Document why each prefix is approved
3. ✅ Test in audit mode before enforcing blocks
4. ✅ Provide clear error messages for developers
5. ✅ Keep Aqua policy synchronized with Terraform

---

## Summary

**Two REGO policies, two critical security gates:**

| Gate | Pipeline REGO (OPA) | Kubernetes REGO (Aqua) |
|------|---------------------|------------------------|
| **What** | Algorithm validation | Base image enforcement |
| **When** | Build time | Deployment time |
| **Input** | CBOM JSON | K8s manifest |
| **Action** | Block push | Block deployment |
| **Focus** | What's inside | Where it's from |

**Together:** Complete FIPS 140-3 compliance coverage from build to runtime.
