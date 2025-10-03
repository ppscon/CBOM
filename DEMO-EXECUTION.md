# FIPS 140-3 CBOM Demo Execution Guide

## Quick Start

```bash
# Make script executable (first time only)
chmod +x demo-run-pipelines.sh

# Run compliant pipeline (PASS scenario)
./demo-run-pipelines.sh compliant

# Run violations pipeline (FAIL scenario)
./demo-run-pipelines.sh violations

# Run both pipelines
./demo-run-pipelines.sh both
```

## Important: Demo Mode with `continue-on-error`

**This pipeline uses `continue-on-error: true` to demonstrate ALL pipeline stages.**

### What You'll See:

1. **Aqua Scan** - May fail (FIPS 140-3 score < 5 is very strict)
2. **CBOM Generation** - Succeeds (detects cryptographic algorithms)
3. **REGO Evaluation** - **FAILS with violations** 🛑
   - Shows: "❌ FIPS 140-3 COMPLIANCE FAILED: 6 violation(s) detected"
   - Shows: "🛑 PIPELINE BLOCKED - Image does NOT meet FIPS 140-3 cryptographic requirements"
   - Shows: "🛑 Image will NOT be pushed to registry"
4. **Push Image** - Skipped due to REGO failure

### Demo Talking Points (Reference Screenshots):

#### Stage 2: Aqua Image Assurance Scan

**"First, let's look at what Aqua Security found..."**

**Aqua Scan Results:**
- **Disallowed: true** - Image failed Aqua's FIPS Image Assurance policy
- **Policy: fips-140-3-image-compliance**
- Aqua detected vulnerabilities and policy violations
- "This is our first layer of defense - traditional CVE and policy scanning"
- "Notice it caught issues, but we continue for demo purposes (`continue-on-error: true`)"
- "In production, this would also be a blocking gate"

**Why continue?**
- "FIPS 140-3 requires CVSS score < 5 (very strict)"
- "We want to demonstrate the SECOND layer: cryptographic compliance via CBOM/REGO"
- "This is where we detect specific algorithmic violations - not just CVEs"

---

#### Stage 4: REGO Cryptographic Compliance Check

**"Now let's see what the REGO policy detected in the CBOM..."**

**Lines 42-52: REGO Evaluation Results**
- "The policy evaluated the CBOM and found **6 critical violations**"
- "Line 43: CBOM shows **627 out of 628 assets are quantum-vulnerable**"
- "Lines 44-45: **MD5 detected** in Gruntfile.js and lib/insecurity.ts - NOT FIPS 140-3 approved"
- "Lines 46-48: Quantum-vulnerable cryptography detected:"
  - MD5 in Gruntfile.js (Grover's Algorithm + Broken)
  - SHA-3 in frontend/989.js (Grover's Algorithm)
  - MD5 in lib/insecurity.ts (Grover's Algorithm + Broken)

**Lines 53-67: Security Gate Response**
- "Line 60: ❌ **FIPS 140-3 COMPLIANCE FAILED: 6 violation(s) detected**"
- "Line 61: 🛑 **PIPELINE BLOCKED** - Image does NOT meet FIPS 140-3 requirements"
- "Line 62: 🛑 **Image will NOT be pushed to registry**"
- "Lines 65-67: Action required - remediate violations before re-deployment"

**Production vs Demo:**
- "In production, we'd remove `continue-on-error` and this would be a **hard stop**"
- "For this demo, we override to show all pipeline stages and capabilities"
- "The security gate is working - it detected deprecated MD5 and quantum-vulnerable algorithms"

---

## Defense-in-Depth: Two-Layer Security Model

This pipeline implements a **defense-in-depth** approach with two complementary security gates:

### Layer 1: Aqua Image Assurance (Traditional Security)
- ✅ CVE vulnerability scanning
- ✅ Malware detection
- ✅ CIS benchmarks
- ✅ Package compliance
- ✅ Maximum CVSS score < 5 (FIPS requirement)
- **Focus:** Known vulnerabilities and configuration issues

### Layer 2: CBOM + REGO (Cryptographic Compliance)
- ✅ Cryptographic Bill of Materials (CBOM) generation
- ✅ Algorithm detection (MD5, SHA-1, AES, RSA, etc.)
- ✅ Deprecated algorithm blocking (MD5, 3DES, RC4)
- ✅ Quantum vulnerability assessment
- ✅ FIPS 140-3 algorithmic compliance
- **Focus:** Cryptographic weaknesses and future threats

### Why Both?

**Aqua alone** catches traditional security issues but may miss:
- Use of deprecated cryptographic algorithms
- Quantum-vulnerable encryption
- Non-FIPS approved crypto implementations

**CBOM/REGO** catches cryptographic-specific issues:
- MD5 usage (even if no CVE)
- Quantum-vulnerable algorithms (secure today, vulnerable post-quantum)
- FIPS 140-3 algorithm compliance

**Together:** Complete coverage of both traditional security AND cryptographic compliance.

---

## Remediation Guidance Based on CBOM Findings

When the REGO policy detects violations, developers need clear guidance on how to fix them. Here's what to do for each violation type:

### Violation 1: MD5 Detected (Deprecated Algorithm)

**Found in:**
- `/tmp/cbom-image-*/juice-shop/Gruntfile.js`
- `/tmp/cbom-image-*/juice-shop/lib/insecurity.ts`

**Issue:** MD5 is cryptographically broken and not FIPS 140-3 approved

**Remediation:**
```javascript
// ❌ BAD - MD5 usage
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(data).digest('hex');

// ✅ GOOD - SHA-256 (FIPS approved)
const crypto = require('crypto');
const hash = crypto.createHash('sha256').update(data).digest('hex');

// ✅ BETTER - SHA-3 (quantum-resistant)
const crypto = require('crypto');
const hash = crypto.createHash('sha3-256').update(data).digest('hex');
```

**FIPS 140-3 Approved Alternatives:**
- **SHA-256** (FIPS 180-4) - General purpose
- **SHA-384** (FIPS 180-4) - Higher security
- **SHA-512** (FIPS 180-4) - Maximum security
- **SHA3-256** (FIPS 202) - Quantum-resistant

---

### Violation 2: Quantum-Vulnerable Cryptography

**Found:** 627 out of 628 assets use quantum-vulnerable algorithms

**Issue:** Current algorithms secure against classical computers but vulnerable to quantum computers (Grover's Algorithm, Shor's Algorithm)

**Timeline:** NIST recommends migration by 2030-2035

**Remediation Strategy:**

#### Phase 1: Identify (CBOM does this)
```bash
# CBOM already identified:
- RSA-2048/RSA-4096 (Shor's Algorithm vulnerable)
- ECDSA P-256/P-384 (Shor's Algorithm vulnerable)
- AES-128/AES-256 (Grover's Algorithm - doubles key search)
```

#### Phase 2: Plan Migration
```
Current → NIST PQC Standards
---
RSA/ECDSA → ML-KEM (FIPS 203) - Key Encapsulation
RSA/ECDSA → ML-DSA (FIPS 204) - Digital Signatures
            SLH-DSA (FIPS 205) - Stateless Signatures
AES-128   → AES-256 (double key size for Grover resistance)
```

#### Phase 3: Implement Hybrid Approach
```javascript
// Hybrid cryptography (classical + post-quantum)
// Protects against both current and future threats

// ✅ RECOMMENDED: Hybrid key exchange
const hybridKex = {
  classical: 'ECDH-P384',      // Secure now
  postQuantum: 'ML-KEM-768',   // Secure post-quantum
  mode: 'concatenate'          // Combine both
};
```

---

### Violation 3: Deprecated Symmetric Algorithms

**If CBOM detects:** 3DES, DES, RC4, RC2

**Remediation:**
```python
# ❌ BAD - 3DES (deprecated 2023)
from Crypto.Cipher import DES3
cipher = DES3.new(key, DES3.MODE_CBC)

# ✅ GOOD - AES-256-GCM (FIPS approved)
from Cryptography.hazmat.primitives.ciphers.aead import AESGCM
cipher = AESGCM(key)  # key must be 256 bits
```

**FIPS 140-3 Approved Symmetric Algorithms:**
- **AES-128** (FIPS 197) - Minimum
- **AES-192** (FIPS 197) - Better
- **AES-256** (FIPS 197) - Best (quantum-resistant with larger key)

---

### Violation 4: Weak Key Sizes

**If CBOM detects:** RSA-1024, ECDSA P-192

**Remediation:**
```python
# ❌ BAD - RSA-1024 (broken)
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)

# ✅ GOOD - RSA-3072 (FIPS minimum for new keys)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

# ✅ BETTER - RSA-4096 (higher security margin)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

# ✅ BEST - Prepare for PQC migration
# Use ML-DSA-65 (FIPS 204) when available in your crypto library
```

**FIPS 140-3 Minimum Key Sizes:**
- **RSA:** 2048 bits (3072+ recommended for new deployments)
- **ECDSA:** P-256 minimum (P-384 recommended)
- **AES:** 128 bits minimum (256 recommended for quantum resistance)

---

## Re-running Pipeline After Remediation

After fixing violations:

```bash
# 1. Update code with FIPS-approved algorithms
git add .
git commit -m "fix: replace MD5 with SHA-256 for FIPS 140-3 compliance"

# 2. Push to trigger pipeline
git push

# 3. Watch for clean REGO evaluation
./demo-run-pipelines.sh list
```

**Expected result after remediation:**
```
✅ FIPS 140-3 COMPLIANCE PASSED: No cryptographic policy violations
✅ Image pushed to registry
```

---

## Demo Scenario: Cryptographic Violations Detection

**Command:**
```bash
./demo-run-pipelines.sh violations
```

**What happens:**
1. Scans juice-shop image
2. Aqua scan: **FAILS** (continues for demo)
3. CBOM generation: **SUCCEEDS** (finds MD5, SHA-3)
4. REGO evaluation: **FAILS** (6 violations detected)
   - MD5 (deprecated algorithm)
   - 627/628 assets quantum-vulnerable
5. Image push: **BLOCKED** 🛑

**Demonstrates:**
- Cryptographic compliance gate working
- REGO policy detecting violations
- Security gate prevents deployment

---

## Manual Trigger (GitHub UI)

### Compliant Pipeline:
1. Go to: https://github.com/ppscon/CBOM/actions
2. Select "CBOM FIPS 140-3 Compliant Pipeline (PASS Demo)"
3. Click "Run workflow"
4. Select branch: `master`
5. Click "Run workflow"

### Violations Pipeline:
Automatically triggers on push to master:
```bash
git commit --allow-empty -m "demo: trigger violations pipeline"
git push
```

---

## Watching Pipeline Progress

```bash
# List recent runs
./demo-run-pipelines.sh list

# Watch specific run
./demo-run-pipelines.sh watch <run-id>

# Or use gh CLI directly
gh run watch --exit-status
```

---

## Demo Talking Points

### For Compliant Pipeline:
- "This is our baseline - a minimal, compliant image"
- "Notice the CBOM shows zero cryptographic findings"
- "All gates pass - this is our gold standard"
- "Image is successfully pushed and ready for deployment"

### For Violations Pipeline:
- "Now let's scan a real-world application - OWASP Juice Shop"
- "CBOM detects MD5 - a deprecated algorithm not FIPS-approved"
- "627 out of 628 cryptographic assets are quantum-vulnerable"
- "REGO policy blocks the push - security gate working as designed"
- "In production, developers would need to remediate before re-deployment"

---

## Pipeline Comparison

| Stage                | Compliant Pipeline | Violations Pipeline |
|----------------------|-------------------|---------------------|
| Build                | ✅ Minimal Alpine  | ✅ Juice Shop       |
| Aqua Scan            | ✅ Pass            | ⚠️ Fail (demo mode) |
| CBOM Generation      | ✅ No crypto found | ✅ Crypto detected  |
| REGO Evaluation      | ✅ Pass            | ❌ **6 violations** |
| Push Image           | ✅ **SUCCESS**     | 🛑 **BLOCKED**      |

---

## Artifacts

Both pipelines generate downloadable artifacts:

1. **aqua-scan-reports** - Aqua Security scan results
2. **cbom-reports** - Cryptographic Bill of Materials (JSON + CSV)

Download from GitHub Actions run page.

---

## Troubleshooting

### Pipeline not starting:
```bash
# Check GitHub CLI auth
gh auth status

# Re-authenticate if needed
gh auth login
```

### Can't find run ID:
```bash
# List all recent runs
gh run list --limit 10
```

### Watch command fails:
```bash
# Use browser instead
open https://github.com/ppscon/CBOM/actions
```
