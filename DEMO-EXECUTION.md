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

## Demo Scenarios

### Scenario 1: Compliant Image ✅ (PASS)

**Command:**
```bash
./demo-run-pipelines.sh compliant
```

**What happens:**
1. Builds minimal Alpine image (Dockerfile.compliant)
2. Aqua scan: **PASSES** (minimal vulnerabilities)
3. CBOM generation: **PASSES** (no crypto libraries found)
4. REGO evaluation: **PASSES** (no violations)
5. Image push: **SUCCESS** ✅

**Demonstrates:**
- Clean FIPS-compliant image
- All security gates pass
- Image successfully pushed to registry

---

### Scenario 2: Vulnerable Image ❌ (BLOCKED)

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
