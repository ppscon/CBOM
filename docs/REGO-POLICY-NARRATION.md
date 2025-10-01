# REGO Policy Narration for FIPS 140-3 Compliance

## Meeting Presentation Guide

This document provides a narrative explanation of how the REGO policy (`fips-compliance-cdx16.rego`) works together with the Terraform policies (`fips-compliance-policies.tf`) to provide comprehensive FIPS 140-3 compliance validation.

---

## Executive Summary

**The Problem**: Traditional security policies can enforce *where* and *how* containers run, but they cannot deeply inspect *what cryptographic algorithms* are embedded in your application code.

**The Solution**: We combine three complementary components:
1. **QVS-CBOM Scanner** - Detects and identifies cryptographic algorithms, their risk levels, and quantum vulnerability
2. **REGO Policy** (OPA-based) - Enforces organizational compliance rules against the CBOM data
3. **Terraform Policies** (Aqua native) - Controls deployment and runtime based on REGO decisions

Think of it as a three-layer defense:
- **QVS-CBOM = The Detective** - Finds and identifies all cryptographic algorithms with risk assessments
- **REGO = The Gate** - Static analysis that provides GO/NO-GO decision based on your organization's rules
- **Terraform = The Guard** - Separately enforces runtime security controls and deployment policies in Aqua platform

---

## How They Work Together

### The Workflow

**Note**: Terraform policies (fips-compliance-policies.tf) are configuration-as-code - they define the rules in Aqua once, then Aqua enforces them automatically.

```
Container Image (in CI/CD pipeline)
    ↓
1. Aqua Scanner (integrated with CI/CD)
    → Scans: Vulnerabilities, misconfigurations, secrets, malware
    → Enforces: Image Assurance Policy
      • Trusted base images
      • Package blacklist/whitelist
      • License compliance
      • CIS Docker benchmarks
      • CVE severity thresholds
    → Decision: PASS or FAIL
    → If FAIL: Pipeline stops here
    ↓
2. If Aqua Scanner PASSES: QVS-CBOM Job starts
    → Triggered by: Previous job success
    → Docker command: enhanced-scanner --CBOM image <image:tag>
    → Process:
      a) Trivy scan runs first (base scanner)
      b) Wrapper intercepts --CBOM flag
      c) Extracts container filesystem
      d) QVS-CBOM scans for cryptographic algorithms
    → Identifies: MD5, SHA1, AES, RSA, etc.
    → Assesses: Risk level (High/Medium/Low)
    → Evaluates: Quantum vulnerability (true/false)
    → Output: CBOM JSON with findings and recommendations
    → Note: Wrapper preserves Trivy exit code
    ↓
3. REGO Policy Evaluation (in CI/CD)
    → Input: CBOM JSON from step 2
    → Applies: Your organization's cryptographic compliance rules
    → Evaluates: Against your approved algorithm list
    → Decides: GO or NO-GO based on your policies
    → Output: compliant (true/false), violations[], risk_score
    → Action: Exit 0 (GO) or Exit 1 (NO-GO)
    → If NO-GO: Pipeline fails, image not pushed
    ↓
4. If ALL checks pass: Image pushed to registry
    ↓
5. Deployment attempt to Kubernetes
    ↓
6. Aqua Admission Controller (at deployment time)
    → Enforces: Kubernetes Assurance Policy
      • Secret management controls (AVD-KSV-0109, etc.)
      • Privileged container blocking (AVD-KSV-0017)
      • Root user prevention (AVD-KSV-0012)
      • Host namespace isolation (AVD-KSV-0008, AVD-KSV-0009)
      • Volume mount restrictions (AVD-KSV-0023)
      • Required labels (fips.compliance, crypto.level)
    → Decision: ALLOW or BLOCK deployment
    ↓
7. If deployment allowed: Container runs
    ↓
8. Aqua Runtime Protection (continuous monitoring)
    → Enforces: Container Runtime Policy
      • File integrity monitoring (/proc/sys/crypto/fips_enabled, etc.)
      • Package installation blocking
      • Executable blacklist enforcement
      • Volume mount restrictions
      • Network security controls
      • Audit logging
    → Action: Alert or Block on policy violations
```

**Terraform's Role**: The .tf files define all these policies once. After `terraform apply`, Aqua enforces them automatically at each stage.

---

## Part 1: Terraform Policies - The Foundation

### What Terraform Policies Do

The Terraform policies establish the **security boundaries** for FIPS-compliant workloads:

**Image Assurance Policy**:
```hcl
resource "aquasec_image_assurance_policy" "fips_image_compliance" {
  trusted_base_images_enabled = true
  block_failed = true
  fail_cicd    = true
}
```

**Key Point**: This policy says "only allow images from approved sources and block anything that fails validation." But it doesn't know *what* to validate - that's where REGO comes in.

**Runtime Policy**:
```hcl
resource "aquasec_container_runtime_policy" "fips_runtime_compliance" {
  file_integrity_monitoring {
    monitored_files = [
      "/proc/sys/crypto/fips_enabled",
      "/usr/lib64/openssl/engines/fips.so",
    ]
  }
}
```

**Key Point**: This monitors the FIPS cryptographic modules at runtime to detect tampering. But it can't tell you if your *application code* is using weak cryptography - that's REGO's job.

**Kubernetes Policy**:
```hcl
resource "aquasec_kubernetes_assurance_policy" "fips_k8s_compliance" {
  kubernetes_controls {
    avd_id   = "AVD-KSV-0109"
    name     = "ConfigMap with secrets"
    severity = "critical"
  }
}
```

**Key Point**: This prevents cryptographic keys from being stored insecurely. But it doesn't validate if the keys are for FIPS-approved algorithms - REGO handles that.

### What Terraform CANNOT Do

Terraform policies are excellent at:
- ✅ Blocking privileged containers
- ✅ Enforcing read-only filesystems
- ✅ Monitoring file changes
- ✅ Controlling network access

But they CANNOT:
- ❌ Parse your application source code
- ❌ Identify which cryptographic algorithms are being used
- ❌ Validate algorithm parameters (key sizes, modes, etc.)
- ❌ Assess quantum vulnerability risk

**This is where REGO fills the gap.**

---

## Part 2: QVS-CBOM Scanner - The Detection Layer

### What QVS-CBOM Does

QVS-CBOM is the **cryptographic detective** that scans your container images and generates a complete inventory of cryptographic usage.

**Key Capabilities**:

1. **Algorithm Detection**: Scans source code, binaries, and libraries to find cryptographic algorithms
   - Finds: MD5, SHA1, SHA-256, AES, RSA, DES, 3DES, etc.
   - Reports: Exact file path and line number where algorithm is used

2. **Risk Assessment**: Automatically evaluates each algorithm against NIST standards
   ```json
   {
     "algorithm": "MD5",
     "risk": "High",
     "vulnerability_type": "Grover's Algorithm + Broken",
     "description": "MD5 is cryptographically broken and provides only 64 bits of security against quantum attacks",
     "recommendation": "Replace with SHA-256 or SHA-3..."
   }
   ```

3. **Quantum Vulnerability Analysis**: Identifies algorithms vulnerable to quantum computing attacks
   ```json
   {
     "algorithm": "RSA-2048",
     "quantum_resistant": false,
     "quantum_safe": false
   }
   ```

4. **CBOM Output**: Generates standards-compliant CycloneDX format
   - Industry-standard SBOM format
   - Machine-readable for automation
   - Human-readable for audits

**Important**: QVS-CBOM already knows what's weak and what's not. It provides expert-level cryptographic analysis out of the box.

---

## Part 3: REGO Policy - The GO/NO-GO Gate

### What REGO Does

The REGO policy is a **static analysis gate** that evaluates the CBOM findings from QVS-CBOM and makes a GO/NO-GO decision for your CI/CD pipeline.

**Critical Distinction**:
- ❌ REGO does NOT detect algorithms (QVS-CBOM does that)
- ❌ REGO does NOT assess risk levels (QVS-CBOM does that)
- ❌ REGO does NOT block deployments (it just fails the CI/CD pipeline)
- ✅ REGO DOES evaluate CBOM against your organization's rules
- ✅ REGO DOES provide GO/NO-GO decision (exit 0 or exit 1)
- ✅ REGO DOES enable custom exception handling in CI/CD

**Think of it as**: A quality gate in your pipeline - like linting or unit tests, but for cryptographic compliance.

### What REGO Actually Does: Organizational Policy Enforcement

**Example Scenario**: QVS-CBOM finds MD5 in your image and reports:
```json
{
  "algorithm": "MD5",
  "risk": "High",
  "quantum_resistant": false,
  "recommendation": "Replace with SHA-256"
}
```

**Without REGO**: You manually review this finding and decide if it's acceptable for your organization.

**With REGO**: The policy automatically applies your organization's rules:

```rego
# Your organization's rule: "Block any High-risk algorithm"
violations[msg] {
  finding := input.findings[_]
  finding.risk == "High"
  msg := sprintf("High-risk algorithm detected: %s in %s",
    [finding.algorithm, finding.file])
}
```

**Result**: REGO says `compliant = false` (exits 1), CI/CD pipeline fails, image never reaches registry.

---

### Core Concept: Dual Format Support

```rego
# Get crypto algorithm (supports both 1.4 and 1.6)
get_algorithm(component) = algo if {
    component.crypto.algorithm
    algo := component.crypto.algorithm
} else = algo if {
    algo := get_property(component, "cbom:algorithm")
}
```

**Narration**:
"The REGO policy is smart enough to read CBOM data in both the legacy CycloneDX 1.4 format and the new 1.6 format. This ensures we can enforce policies regardless of which CBOM version QVS-CBOM generates. It first tries to read from the `.crypto` object (1.4 format), and if that doesn't exist, it falls back to the `.properties` array (1.6 format)."

---

### REGO Use Cases: Organizational Customization

#### 1. Custom Approval Lists (Your Organization's Rules)

**The Need**: Your organization may have different requirements than NIST defaults.

**QVS-CBOM says**: "RSA-2048 is quantum-vulnerable (risk: Medium)"

**Your organization decides**: "We accept RSA-2048 for 2 more years during our migration"

**REGO implements your rule**:
```rego
approved_algorithms := {
  "AES-256", "AES-192", "AES-128",
  "SHA-256", "SHA-384", "SHA-512",
  "SHA3-256", "SHA3-384", "SHA3-512",
  "RSA-2048", "RSA-3072", "RSA-4096",  # Your org allows RSA-2048
  "ECDSA-P256", "ECDSA-P384", "ECDSA-P521",
  "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512"
}

violations[msg] {
  component := input.components[_]
  algorithm := get_algorithm(component)
  not approved_algorithms[algorithm]  # Enforce YOUR list, not NIST's
  msg := sprintf("Component '%s' uses non-approved algorithm: %s",
    [component.name, algorithm])
}
```

**Narration**:
"QVS-CBOM provides the expert cryptographic analysis - it tells you what's risky and why. REGO lets you define YOUR organization's acceptance criteria. Maybe you're more strict than NIST, or maybe you need exceptions during a migration period. REGO enforces YOUR rules, not just generic standards."

**Note**: This runs in CI/CD, completely separate from Terraform. If REGO fails, the image never reaches the registry where Terraform policies would evaluate it.

#### 2. Context-Aware Policy Enforcement

**The Need**: Not all uses of an algorithm are equal.

**QVS-CBOM says**: "MD5 found in /app/etag-generator.js (risk: High)"

**Your organization decides**: "MD5 is OK for ETags (non-security use) but BLOCKED for passwords"

**REGO implements context-aware rules**:
```rego
# Allow MD5 only for non-security purposes
violations[msg] {
  component := input.components[_]
  algorithm := get_algorithm(component)
  algorithm == "MD5"

  purpose := get_purpose(component)
  purpose != "Checksum"  # Only allow for checksums, not crypto
  purpose != "ETag"      # ETags are OK

  msg := sprintf("MD5 used for security-sensitive purpose '%s' in %s",
    [purpose, component.name])
}
```

**Narration**:
"QVS-CBOM tells you WHERE algorithms are used and WHAT they're doing. REGO lets you create nuanced rules based on context. MD5 for file integrity checks? Maybe OK. MD5 for password hashing? Absolutely not. REGO enforces these business logic rules that go beyond simple allow/deny lists."

**Example Output**:
```
✓ PASS: MD5 in /app/etag-generator.js (purpose: ETag)
✗ FAIL: MD5 in /app/auth/passwords.js (purpose: Hash) - BLOCKED
```

**Result**:
REGO's GO/NO-GO decision in CI/CD:
- Context-appropriate use: REGO exits 0, pipeline continues
- Security-sensitive use: REGO exits 1, pipeline fails, image never built

#### 3. Risk Threshold Enforcement

**The Need**: Enforce organizational risk tolerance levels.

**QVS-CBOM says**:
- "Finding 1: MD5 (risk: High)"
- "Finding 2: SHA1 (risk: High)"
- "Finding 3: RSA-2048 (risk: Medium, quantum-vulnerable)"

**Your organization decides**: "We accept Medium risk but block anything High or Critical"

**REGO implements risk-based blocking**:
```rego
# Block based on QVS-CBOM's risk assessment
violations[msg] {
  finding := input.findings[_]
  finding.risk == "High"
  msg := sprintf("High-risk algorithm '%s' found in %s",
    [finding.algorithm, finding.file])
}

violations[msg] {
  finding := input.findings[_]
  finding.risk == "Critical"
  msg := sprintf("Critical-risk algorithm '%s' found in %s",
    [finding.algorithm, finding.file])
}

# Warn about quantum vulnerability but don't block yet
quantum_warnings[msg] {
  finding := input.findings[_]
  finding.quantum_resistant == false
  msg := sprintf("Quantum-vulnerable algorithm '%s' in %s - plan migration",
    [finding.algorithm, finding.file])
}
```

**Narration**:
"QVS-CBOM does the expert cryptographic risk assessment. REGO translates that into organizational action. You decide: 'Block High-risk today, but give us warnings for quantum vulnerability so we can plan a 5-year migration.' REGO enforces YOUR risk tolerance, using QVS-CBOM's expert analysis as input."

**Connection to Terraform**:
The Kubernetes Policy can enforce different controls based on risk:
```hcl
required_labels = [
  {
    key   = "crypto.risk"
    value = "high"  # Set by REGO based on findings
  },
  {
    key   = "quantum.vulnerable"
    value = "true"  # Track for future migration
  }
]
```

#### 4. Exception Handling for Legacy Applications

**The Need**: You have legacy applications that can't be immediately updated.

**QVS-CBOM says**: "SHA1 found in /legacy-app/crypto.dll (risk: High)"

**Your organization decides**: "Block SHA1 everywhere EXCEPT in the legacy-namespace for 6 months"

**REGO implements namespace-aware exceptions**:
```rego
# Block SHA1 globally
violations[msg] {
  finding := input.findings[_]
  finding.algorithm == "SHA1"

  # EXCEPT if it's in the legacy namespace
  not is_legacy_namespace(input.metadata.namespace)

  msg := sprintf("SHA1 is blocked: %s in %s",
    [finding.algorithm, finding.file])
}

# Helper function to check namespace
is_legacy_namespace(ns) {
  ns == "legacy-crypto"
}
```

**Narration**:
"QVS-CBOM identifies all cryptographic risks uniformly - it doesn't make business exceptions. REGO is where you encode your organizational migration strategy. You can say 'We know SHA1 is bad, but we need 6 months to refactor our legacy app. Allow it ONLY in this specific namespace with extra monitoring.' REGO gives you surgical control over exception handling."

---

## Part 4: FIPS 140-3 Specific Enhancements

### What's New in FIPS 140-3?

**FIPS 140-3** (introduced in 2019, mandatory since April 2022) replaces FIPS 140-2 with several key improvements:

#### 1. **Global Standards Alignment**
FIPS 140-3 adopts ISO/IEC 19790 and 24759 standards, providing international recognition. A single validation now meets both U.S./Canadian and international requirements.

#### 2. **Container-Specific Clarity**
140-3 explicitly addresses containerized and cloud-deployed systems with clearer module boundary definitions. This makes our QVS-CBOM approach more defensible - we can precisely scope the cryptographic module within a container.

#### 3. **Enhanced Self-Testing Requirements**

**Pre-Operational Self-Test (POST)**:
- Runs at power-up as an integrity check
- Ensures the module's code hasn't been tampered with
- QVS-CBOM validates module integrity through file integrity monitoring

**Conditional Self-Tests**:
- Algorithm-specific tests run on-demand (before first use)
- If an algorithm isn't used during execution, its test doesn't run at startup
- More efficient than 140-2's one-time startup tests
- QVS-CBOM identifies which algorithms are actually used, supporting this approach

#### 4. **Post-Quantum Cryptography (PQC) Readiness**
140-3 includes provisions for integrating post-quantum algorithms once NIST approves them. This is where **QVS-CBOM provides strategic advantage** - we already identify quantum-vulnerable algorithms and provide migration paths.

#### 5. **Trusted Channel vs Trusted Path**
140-3 modernizes security with "trusted channels" (secure logical communication) instead of requiring physical interfaces. This is perfect for containerized systems where secure encryption and authentication replace physical controls.

#### 6. **Transition Timeline (Critical)**
- **April 2022**: NIST stopped accepting new FIPS 140-2 validations
- **September 2026**: FIPS 140-2 certificates become "historical" (effectively sunset)
- **Action Required**: Organizations must transition to 140-3 validated modules

### How Our Solution Supports FIPS 140-3

| Requirement | 140-2 Approach | 140-3 Enhancement | Our Solution |
|-------------|---------------|-------------------|--------------|
| **Module Boundaries** | Ambiguous for containers | Clear container scoping | QVS-CBOM scans containers natively |
| **Self-Tests** | One-time at startup | POST + Conditional tests | CBOM validates integrity + usage |
| **PQC Readiness** | Not addressed | Forward-looking provisions | QVS-CBOM quantum-safe analysis |
| **Documentation** | Basic requirements | Stricter evidence | CBOM provides audit trail |
| **Cloud/Container Support** | Implicit | Explicit guidance | Architecture designed for containers |

**Key Insight**: We were already doing what FIPS 140-3 requires. The transition from 140-2 to 140-3 validates our architectural decisions.

---

## Part 5: Summary - Division of Responsibilities

| Layer | QVS-CBOM | REGO | Terraform |
|-------|----------|------|-----------|
| **Detects Algorithms** | ✅ Scans code/binaries | ❌ | ❌ |
| **Assesses Risk** | ✅ NIST analysis | ❌ | ❌ |
| **Quantum Analysis** | ✅ Identifies vulnerable algos | ❌ | ❌ |
| **Provides Recommendations** | ✅ Expert guidance | ❌ | ❌ |
| **Enforces Org Rules** | ❌ | ✅ Custom policies | ❌ |
| **Context-Aware Decisions** | ❌ | ✅ Business logic | ❌ |
| **Exception Handling** | ❌ | ✅ Namespace/label-based | ❌ |
| **Blocks Deployment** | ❌ | ❌ | ✅ CI/CD gates |
| **Runtime Monitoring** | ❌ | ❌ | ✅ File/process monitoring |
| **Kubernetes Controls** | ❌ | ❌ | ✅ Pod security |

**Key Insight**:
- **QVS-CBOM** = Expert cryptographer that finds and assesses everything
- **REGO** = CI/CD quality gate that enforces YOUR organization's rules
- **Aqua Platform** (configured via Terraform) = Multi-stage enforcer (Image Assurance, K8s Admission, Runtime Protection)

---

## Part 6: The Complete Integration

### Decision Flow

```
Step 1: Image Build (CI/CD)
    ↓
Step 2: Aqua Scanner (CI/CD)
    → Enforces: Image Assurance Policy (configured via Terraform)
    → Checks: Vulnerabilities, CIS benchmarks, licenses, packages
    → If FAIL: Pipeline stops
    ↓
Step 3: QVS-CBOM Scan (CI/CD - only if Step 2 passes)
    → Generates: cbom.json with all cryptographic components
    ↓
Step 4: REGO Evaluation (CI/CD)
    → Input: cbom.json
    → Process: Validates algorithms, purposes, quantum risk
    → Output: deny[], warn[], compliant (true/false)
    → Action: Exit 0 (pass) or Exit 1 (fail)
    → If FAIL: Pipeline stops, image NOT pushed to registry
    ↓
Step 5: If ALL CI/CD checks pass: Image pushed to registry
    ↓
Step 6: Deployment Attempt to Kubernetes
    ↓
Step 7: Aqua Admission Controller (deployment-time)
    → Enforces: Kubernetes Assurance Policy (configured via Terraform)
    → Check: Required labels present?
    → Check: Privileged containers blocked?
    → Check: Secrets properly stored?
    → If FAIL: Deployment BLOCKED
    ↓
Step 8: If deployment allowed: Container runs
    ↓
Step 9: Aqua Runtime Protection (continuous monitoring)
    → Enforces: Container Runtime Policy (configured via Terraform)
    → Monitor: File integrity of FIPS modules
    → Monitor: Package installations
    → Monitor: Executable launches
    → Monitor: Volume mounts
    → If violation detected: ALERT/BLOCK per policy
```

**Key Points**:
- REGO and Terraform policies are **independent** - they don't feed into each other
- REGO runs in **CI/CD pipeline** as a quality gate
- Terraform policies are **enforced by Aqua platform** at different stages
- Both provide complementary protection layers

---

## Part 7: Real-World Example

### Scenario: Juice Shop Application

**Initial Scan**:
```bash
docker run enhanced-scanner --CBOM image bkimminich/juice-shop:latest
```

**CBOM Output**:
```json
{
  "components": [
    {
      "name": "/app/lib/insecurity.ts",
      "crypto": {
        "algorithm": "MD5",
        "purpose": "Hash",
        "quantumSafe": false
      }
    }
  ]
}
```

**REGO Evaluation**:
```bash
$ opa eval --data fips-compliance-cdx16.rego --input cbom.json 'data.fips_compliance_cdx16.deny'

# REGO output:
{
  "deny": [
    "Deprecated algorithm detected: MD5 in /app/lib/insecurity.ts (Not FIPS-approved)",
    "Quantum-vulnerable cryptography: /app/lib/insecurity.ts (Algorithm: MD5, Risk: Grover's Algorithm + Broken)"
  ]
}

# Exit code: 1 (FAIL)
# Result: CI/CD pipeline FAILS, image NOT pushed to registry
```

**CI/CD Result**:
```
✗ REGO Policy Check: FAILED
  Violations found:
  - Deprecated algorithm detected: MD5 in /app/lib/insecurity.ts
  - Quantum-vulnerable cryptography: MD5

Pipeline Status: BLOCKED
Image Status: NOT pushed to registry
Developer Action Required: Fix MD5 usage before proceeding
```

**Remediation**:
Developer replaces MD5 with SHA-256 in `insecurity.ts`, rebuilds image.

**Re-scan Results**:
```json
{
  "components": [
    {
      "name": "/app/lib/insecurity.ts",
      "crypto": {
        "algorithm": "SHA-256",
        "purpose": "Hash",
        "quantumSafe": false
      }
    }
  ]
}
```

**REGO Re-evaluation**:
```bash
$ opa eval --data fips-compliance-cdx16.rego --input cbom.json 'data.fips_compliance_cdx16.deny'

# REGO output:
{
  "deny": []  # No deprecated algorithms
}

# Check warnings:
$ opa eval --data fips-compliance-cdx16.rego --input cbom.json 'data.fips_compliance_cdx16.warn'
{
  "warn": [
    "Quantum-vulnerable cryptography: /app/lib/insecurity.ts (Algorithm: SHA-256, Risk: Grover's Algorithm)"
  ]
}

# Exit code: 0 (PASS)
# Result: CI/CD pipeline SUCCEEDS, image pushed to registry
```

**Deployment Flow**:
```
✓ REGO Policy Check: PASSED (with warnings)
  Warnings (non-blocking):
  - SHA-256 is quantum-vulnerable (plan migration)

✓ Image pushed to registry

✓ Aqua Admission Controller: PASSED
  - Kubernetes Assurance Policy checks passed
  - Deployment ALLOWED

✓ Container deployed with Aqua Runtime Protection active
```

---

## Part 8: Why All Three Are Necessary

### QVS-CBOM Alone Is Not Enough

**Without REGO and Terraform**, QVS-CBOM can only *report* findings - it cannot *enforce* compliance:

```json
{
  "findings": [
    {
      "algorithm": "MD5",
      "risk": "High",
      "recommendation": "Replace with SHA-256"
    }
  ]
}
```

**Example Failure**:
QVS-CBOM detects MD5 and generates a detailed report. But without enforcement:
- ❌ Image still deploys to production
- ❌ Developers might ignore the report
- ❌ No automatic blocking
- ❌ **FIPS VIOLATION IN PRODUCTION**

### REGO Alone Is Not Enough

**Without Aqua/Terraform policies**, REGO only provides CI/CD gating - no runtime or deployment-time protection:

```bash
$ opa eval --data policy.rego --input cbom.json 'data.fips.deny'
{
  "deny": ["MD5 detected in /app/crypto.js"]
}
# Exit 1 - Pipeline fails ✓
```

**What's Missing Without Aqua Platform**:
REGO successfully blocks the CI/CD pipeline. But if someone bypasses CI/CD or pushes directly:
- ❌ No Image Assurance scan at registry
- ❌ No Kubernetes admission control
- ❌ No runtime file integrity monitoring
- ❌ No package installation blocking
- ❌ **No deployment-time or runtime protection**

REGO is a CI/CD gate. You still need Aqua platform for defense-in-depth.

### Terraform Alone Is Not Enough

**Without QVS-CBOM and REGO**, Terraform has no cryptographic intelligence:

```hcl
# This blocks privileged containers:
limit_container_privileges { privileged = true }

# But it CANNOT detect:
# ❌ If the container uses MD5 internally
# ❌ If the container has hard-coded DES keys
# ❌ If the container uses weak RSA-1024
```

**Example Failure**:
A container runs as non-root, has read-only filesystem, no host network access - passes all Terraform checks. But internally it uses MD5 for password hashing. **FIPS VIOLATION UNDETECTED.**

### Together They Provide Defense in Depth

| Layer | QVS-CBOM | REGO | Aqua Platform (via Terraform) | Combined |
|-------|----------|------|-------------------------------|----------|
| **Crypto Detection** | ✅ Expert analysis | ❌ | ❌ | ✅ Finds all algorithms |
| **Risk Assessment** | ✅ NIST standards | ❌ | ❌ | ✅ Knows what's weak |
| **CI/CD Gate** | ❌ | ✅ Exit 0/1 | ❌ | ✅ Pipeline blocking |
| **Policy Decisions** | ❌ | ✅ Org rules | ❌ | ✅ Custom compliance |
| **Image Assurance** | ❌ | ❌ | ✅ Scans at registry | ✅ Pre-deployment checks |
| **Admission Control** | ❌ | ❌ | ✅ K8s deployment gate | ✅ Deployment blocking |
| **Runtime Protection** | ❌ | ❌ | ✅ Monitors changes | ✅ Tamper detection |
| **Kubernetes Controls** | ❌ | ❌ | ✅ Pod security | ✅ Orchestration security |

---

## Part 9: Key Talking Points for Your Meeting

### Opening Statement
"We've implemented a three-layer FIPS 140-3 compliance system. QVS-CBOM provides expert cryptographic detection and risk assessment - it finds every algorithm and tells us what's weak. REGO provides the policy decision layer - it applies our organization's specific compliance rules to those findings. Terraform provides the enforcement - it blocks non-compliant images and monitors runtime. Together, they create an automated compliance pipeline that catches violations before they reach production."

### Technical Highlights

**Point 1: Automated Compliance**
"Previously, FIPS compliance required manual code audits and penetration testing. Now, QVS-CBOM automatically scans every image and identifies all cryptographic usage with expert-level NIST analysis. REGO then applies our organization's specific compliance rules to those findings. Terraform enforces the decisions by blocking non-compliant images at the pipeline stage. This shifts security left - catching issues in CI/CD instead of production."

**Point 2: Future-Proof with Quantum Risk (FIPS 140-3 Advantage)**
"QVS-CBOM doesn't just validate today's compliance - it flags algorithms that will become vulnerable to quantum computers. This aligns perfectly with FIPS 140-3's forward-looking provisions for post-quantum cryptography. REGO lets us set different policies for quantum risk versus immediate risk. For example, we can block MD5 today (already broken) but just warn about RSA-2048 (quantum-vulnerable in 10 years). This gives us a runway to plan migrations to post-quantum cryptography as NIST approves new algorithms under 140-3."

**Point 3: Zero-Trust Architecture**
"The Terraform runtime policies enforce zero-trust principles. Even if a FIPS-compliant image is deployed, we continuously monitor it for tampering attempts - file modifications, package installations, privilege escalations. If someone tries to inject non-FIPS crypto at runtime, we detect and block it immediately."

**Point 4: Audit Trail and Compliance Reporting**
"Every CBOM is stored as a CycloneDX JSON file - an industry-standard format. Auditors can review our cryptographic inventory, trace violations back to specific commits, and verify that our enforcement is consistent. The REGO policy itself is version-controlled, so we have an audit trail of our compliance rules."

### Addressing Questions

**Q: "What if we have legacy applications that can't be updated?"**
**A**: "REGO policies can be scoped to specific namespaces or application scopes. We can run legacy apps in a separate 'legacy-crypto' namespace with relaxed policies, while enforcing strict FIPS for new applications. The Kubernetes policy uses label-based scoping for this."

**Q: "How do we handle false positives?"**
**A**: "REGO policies are code - we can add exceptions. For example, if we use MD5 for non-security purposes like ETags, we can add a rule: 'if purpose == Checksum and not security-sensitive, then allow MD5'. This gives us surgical control without weakening the overall policy."

**Q: "What's the performance impact?"**
**A**: "CBOM generation adds ~30 seconds to image builds - it runs in parallel with Trivy's vulnerability scan. REGO evaluation is sub-second since it's just JSON processing. Runtime monitoring has <1% CPU overhead. The security benefit far outweighs the minimal performance cost."

**Q: "How do we measure success?"**
**A**: "We track three metrics: (1) Compliance rate - percentage of images passing REGO validation, (2) Time to remediation - how fast violations are fixed, (3) Zero production incidents - no FIPS violations reaching production. Our goal is 100% compliance rate within 6 months."

---

## Conclusion

**The Partnership**:
- **QVS-CBOM** = The Expert Cryptographer - finds and assesses all cryptographic usage
- **REGO** = The CI/CD Gatekeeper - enforces your organization's compliance rules in the pipeline
- **Aqua Platform** (configured via Terraform) = The Multi-Layer Guard - enforces deployment and runtime controls

**The Result**:
Automated, continuous, defense-in-depth FIPS 140-3 compliance that protects at build time, deploy time, and runtime - with full audit trails and future quantum readiness. Our solution is positioned for the September 2026 transition deadline when FIPS 140-2 certificates become historical.

**The Business Value**:
- ✅ Reduce manual audit costs by 80%
- ✅ Achieve continuous compliance (not point-in-time)
- ✅ Prevent costly production security incidents
- ✅ Future-proof against quantum computing threats
- ✅ Provide auditors with machine-readable compliance evidence