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

### Demo Talking Points (Reference Screenshot):

**"Let me walk you through what the REGO policy detected in the Juice Shop image..."**

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
