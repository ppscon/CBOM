# Aqua Platform Setup Guide for FIPS 140-3 Pipeline

## Overview

This guide explains how to configure the FIPS 140-3 compliant pipeline with **Aqua Scanner** (not Trivy OSS). The pipeline follows the authoritative workflow from `docs/REGO Policy Narration for FIPS 140-3 Compliance.md`.

## Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              FIPS 140-3 Compliance Pipeline                 │
├─────────────────────────────────────────────────────────────┤
│  Stage 1: Build Application Image                           │
│    └─> ghcr.io/ppscon/cbom:{sha}                           │
├─────────────────────────────────────────────────────────────┤
│  Stage 2: Aqua Image Assurance (FIRST GATE)                │
│    └─> Aqua Scanner: CVE/malware/CIS/packages             │
│    └─> FAIL = Pipeline STOPS (CBOM never runs)            │
│    └─> Critical vulnerabilities = FIPS violation           │
├─────────────────────────────────────────────────────────────┤
│  Stage 3: CBOM Generation (Only if Stage 2 passes)         │
│    └─> Standalone aqua-cbom scanner                        │
│    └─> Cryptographic algorithm detection                   │
│    └─> PQC migration planning                              │
│    └─> Output: CycloneDX 1.6 CBOM + CSV                   │
├─────────────────────────────────────────────────────────────┤
│  Stage 4: REGO Policy Evaluation (GO/NO-GO GATE)           │
│    └─> Input: CBOM JSON from Stage 3                      │
│    └─> Validate: FIPS 140-3 cryptographic compliance      │
│    └─> FAIL = Image NOT pushed to registry                │
├─────────────────────────────────────────────────────────────┤
│  Stage 5: Push FIPS-Compliant Image                        │
│    └─> Tag: fips-140-3-compliant-{sha}                    │
│    └─> Only if ALL gates pass                              │
├─────────────────────────────────────────────────────────────┤
│  Stage 6: Deploy to Kubernetes (Optional)                  │
│    └─> Aqua Admission Controller enforces K8s policies    │
└─────────────────────────────────────────────────────────────┘
```

## Key Differences from Trivy Version

| Aspect | Trivy Version (OSS) | Aqua Version (Enterprise) |
|--------|---------------------|---------------------------|
| **Scanner** | Trivy OSS (open source) | Aqua Scanner (commercial) |
| **Stage 2** | Trivy vulnerability scan | Aqua Image Assurance (full platform) |
| **CBOM Integration** | Wrapper around Trivy | Separate job (not yet integrated) |
| **Secrets Required** | None (OSS tools) | 4 Aqua secrets |
| **Platform Features** | Basic vulnerability scan | CVE + malware + CIS + compliance + policy |
| **Runtime Protection** | Not available | Aqua Runtime Protection |
| **K8s Admission Control** | Not available | Aqua Admission Controller |

## Required Secrets

### 1. Aqua Scanner Secrets

Set these in GitHub: **Settings → Secrets and variables → Actions → New repository secret**

| Secret Name | Description | Where to Get | Example |
|-------------|-------------|--------------|---------|
| `AQUA_SERVER` | Aqua tenant URL | Aqua admin console | `https://cloud.aquasec.com` |
| `AQUA_TOKEN` | Scanner authentication token | Aqua UI → Integrations → Scanners → Generate Token | `eyJhbGc...` (JWT) |
| `AQUA_KEY` | API key for SBOM/CBOM | Aqua UI → Settings → API Keys → Create Key | `abc123...` |
| `AQUA_SECRET` | API secret for SBOM/CBOM | Aqua UI → Settings → API Keys → Create Key | `xyz789...` |

### 2. Docker Registry Authentication

| Secret Name | Description | How to Generate |
|-------------|-------------|-----------------|
| `DOCKER_AUTH_CONFIG` | Docker registry credentials | See instructions below |

**Generate DOCKER_AUTH_CONFIG**:

```bash
# 1. Login to Aqua's registry
docker login registry.aquasec.com
# (You'll be prompted for username/password from Aqua support)

# 2. Extract auth config
cat ~/.docker/config.json

# 3. Copy the entire JSON content as the secret value
# Example:
{
  "auths": {
    "registry.aquasec.com": {
      "auth": "base64encodedcredentials"
    }
  }
}
```

### 3. Optional: Kubernetes Deployment

| Secret Name | Description | How to Generate |
|-------------|-------------|-----------------|
| `KUBECONFIG` | Kubernetes config (base64) | `cat ~/.kube/config \| base64` |

## Setup Steps

### Step 1: Get Aqua Instance

Contact Aqua Security to provision a new instance:
- **Cloud SaaS**: Aqua will provide tenant URL
- **Self-Hosted**: Deploy Aqua Platform in your infrastructure

You'll receive:
- Aqua Server URL (e.g., `https://your-tenant.aquasec.com`)
- Admin credentials
- Scanner token
- API keys

### Step 2: Configure Aqua Secrets in GitHub

```bash
# Navigate to GitHub repository
# Settings → Secrets and variables → Actions

# Add each secret:
AQUA_SERVER:         https://your-tenant.aquasec.com
AQUA_TOKEN:          <token from Aqua UI>
AQUA_KEY:            <API key from Aqua UI>
AQUA_SECRET:         <API secret from Aqua UI>
DOCKER_AUTH_CONFIG:  <docker config.json content>
```

### Step 3: Deploy Aqua Terraform Policies (Optional)

The policies in `policies/fips-compliance-policies.tf` configure Aqua Platform for FIPS 140-3 compliance:

```bash
cd policies

# Set Aqua credentials
export TF_VAR_aqua_url="https://your-tenant.aquasec.com"
export TF_VAR_aqua_username="your-email@example.com"
export TF_VAR_aqua_password="your-password"

# Initialize Terraform
terraform init

# Review changes
terraform plan

# Apply policies to Aqua Platform
terraform apply
```

This creates:
- **Image Assurance Policy**: FIPS-approved base images, package controls
- **Runtime Policy**: File integrity monitoring, crypto module protection
- **Kubernetes Policy**: Pod security, secret management, required labels

### Step 4: Test Pipeline Locally (Optional)

Before pushing to GitHub, test Aqua Scanner locally:

```bash
# 1. Set Aqua credentials
export AQUA_SERVER="https://your-tenant.aquasec.com"
export AQUA_TOKEN="your-token"

# 2. Pull Aqua Scanner
docker pull registry.aquasec.com/scanner:2022.4

# 3. Scan a test image
docker run --rm \
  registry.aquasec.com/scanner:2022.4 \
  /opt/aquasec/scannercli scan \
    -H $AQUA_SERVER \
    --token $AQUA_TOKEN \
    --registry "Github" \
    nginx:latest \
    --show-negligible

# If this works, your credentials are correct
```

### Step 5: Enable Pipeline

```bash
# The pipeline file is ready: .github/workflows/cbom-fips-pipeline-aqua.yml

# Commit and push
git add .github/workflows/cbom-fips-pipeline-aqua.yml
git commit -m "feat: add Aqua Scanner FIPS 140-3 pipeline"
git push origin master

# Pipeline will trigger automatically on push to master
```

### Step 6: Monitor First Run

1. Go to **Actions** tab on GitHub
2. Click on **CBOM FIPS 140-3 Compliance Pipeline (Aqua Scanner)**
3. Watch stages execute:
   - ✅ Build (2-5 min)
   - ✅ Aqua Image Assurance (1-3 min) ← **Critical gate**
   - ✅ CBOM Generation (30-60 sec)
   - ✅ REGO Compliance (< 1 sec) ← **GO/NO-GO gate**
   - ✅ Push Compliant Image (30-60 sec)

## Understanding Results

### ✅ Success: All Gates Pass

```
Stage 2: Aqua Image Assurance
  ✅ Critical vulnerabilities: 0
  ✅ High vulnerabilities: 5 (acceptable)
  ✅ CIS benchmarks: PASSED
  ✅ FIPS requirements: MET

Stage 3: CBOM Generation
  ✅ Cryptographic algorithms detected: 12
  ✅ Sample: AES-256 (Risk: Low), SHA-256 (Risk: Low)

Stage 4: REGO Compliance
  ✅ FIPS 140-3 COMPLIANCE PASSED
  ℹ️  Quantum warnings: 3 (non-blocking)

Stage 5: Push Compliant
  ✅ Tagged: fips-140-3-compliant-abc123
  ✅ Pushed to registry

Result: Image is FIPS 140-3 compliant and ready for deployment
```

### ❌ Failure: Stage 2 (Aqua Image Assurance)

```
Stage 2: Aqua Image Assurance
  ❌ Critical vulnerabilities: 2
  ❌ CVE-2024-12345 (CVSS 9.8) - Critical
  ❌ CVE-2024-67890 (CVSS 9.1) - Critical

  🛑 FIPS 140-3 VIOLATION: Critical vulnerabilities detected
  🛑 Pipeline STOPPED - image does not meet FIPS security requirements

Stages 3-5: SKIPPED (never executed)

Action Required:
  1. Update base image to patched version
  2. Rebuild and re-scan
```

### ❌ Failure: Stage 4 (REGO Policy)

```
Stage 2: Aqua Image Assurance
  ✅ PASSED

Stage 3: CBOM Generation
  ✅ Cryptographic algorithms detected: 8
  ⚠️  Sample: MD5 (Risk: High) - /app/crypto.js

Stage 4: REGO Compliance
  ❌ FIPS 140-3 COMPLIANCE FAILED: 2 violations

  Violations:
    • Deprecated algorithm detected: MD5 in /app/crypto.js
    • Quantum-vulnerable: RSA-1024 in /app/auth/keys.js

  🛑 PIPELINE BLOCKED
  🛑 Image will NOT be pushed to registry

Stage 5: Push Compliant - SKIPPED

Action Required:
  1. Replace MD5 with SHA-256
  2. Replace RSA-1024 with RSA-2048 or higher
  3. Re-run pipeline
```

## CBOM vs Aqua Scanner: Current Status

### Current State (2025-10-03)

- **Aqua Scanner**: Fully integrated ✅
  - Scans for CVE, malware, CIS benchmarks
  - Enforces Image Assurance Policy
  - Registers compliant images in Aqua Platform

- **CBOM Generation**: Standalone job ⚠️
  - Runs as separate job after Aqua Scanner
  - Uses our custom `aqua-cbom` scanner
  - NOT yet integrated with Aqua Platform
  - Generates CycloneDX 1.6 CBOM independently

### Future Integration (When Available)

When Aqua Platform adds native CBOM support, we can:

1. **Remove Stage 3** (standalone CBOM generation)
2. **Use Aqua's CBOM** directly from Stage 2:
   ```bash
   # Future: Aqua Scanner with native CBOM
   /opt/aquasec/scannercli scan ... --generate-cbom
   ```
3. **Stage 4** (REGO) would consume Aqua's CBOM instead

Current pipeline is **ready to adapt** when Aqua releases this feature.

## Workflow Compliance with REGO Policy Narration

This pipeline implements the **exact workflow** from:
`docs/REGO Policy Narration for FIPS 140-3 Compliance.md`

| REGO Doc Stage | Pipeline Implementation | Status |
|----------------|------------------------|--------|
| Step 2: Aqua Scanner | Stage 2: aqua_image_assurance | ✅ Implemented |
| Step 3: CBOM Scan | Stage 3: cbom_generation | ✅ Implemented (standalone) |
| Step 4: REGO Evaluation | Stage 4: rego_compliance | ✅ Implemented |
| Step 5: Image Push | Stage 5: push_compliant_image | ✅ Implemented |
| Step 6: K8s Admission | Stage 6: deploy (commented) | ⏭️ Ready to enable |
| Step 7: Runtime Protection | Aqua Platform (separate) | ⏭️ Requires Aqua deployment |

**Compliance Status**: ✅ 100% aligned with FIPS 140-3 workflow architecture

## Troubleshooting

### Issue: "Aqua Scanner authentication failed"

**Cause**: Invalid AQUA_SERVER or AQUA_TOKEN

**Solution**:
1. Verify AQUA_SERVER URL is correct (no trailing slash)
2. Generate new AQUA_TOKEN in Aqua UI
3. Update GitHub secret
4. Re-run pipeline

### Issue: "Docker pull registry.aquasec.com/scanner: denied"

**Cause**: Invalid DOCKER_AUTH_CONFIG

**Solution**:
```bash
# Re-authenticate
docker logout registry.aquasec.com
docker login registry.aquasec.com
# Enter credentials from Aqua support

# Update secret
cat ~/.docker/config.json
# Copy to DOCKER_AUTH_CONFIG secret
```

### Issue: "Critical vulnerabilities detected, pipeline stopped"

**Cause**: Base image has critical CVEs (FIPS 140-3 violation)

**Solution**:
```bash
# Option 1: Update base image
# In Dockerfile:
FROM node:20-alpine  # Use latest patched version

# Option 2: Use Aqua-approved base images
# Check Aqua UI → Images → Approved Images
```

### Issue: "CBOM generation failed"

**Cause**: aqua-cbom binary build failed

**Solution**:
```bash
# Test Go build locally
cd scanner
go build -o ../aqua-cbom .

# Check for errors
go mod tidy
go build -o ../aqua-cbom .
```

### Issue: "REGO policy violations"

**Cause**: Image uses deprecated/weak cryptography

**Solution**:
```bash
# Download CBOM to see what was detected
# (From GitHub Actions artifacts)

# Check findings
jq '.findings[] | {algorithm, risk, file}' cbom.json

# Fix code
# Example: Replace MD5 with SHA-256
sed -i 's/createHash("md5")/createHash("sha256")/g' app/crypto.js

# Re-run pipeline
```

## Next Steps After Setup

1. **First Successful Run**: Verify all 5 stages complete
2. **Review CBOM**: Download artifacts and inspect cryptographic findings
3. **Customize REGO**: Adjust `policies/fips-compliance-cdx16.rego` for your org
4. **Deploy Terraform**: Apply Aqua policies with `terraform apply`
5. **Enable K8s Stage**: Uncomment Stage 6 when cluster is ready
6. **Monitor Compliance**: Track FIPS compliance metrics over time

## Support

**Pipeline Issues**: `.github/workflows/README.md`
**FIPS Architecture**: `docs/REGO Policy Narration for FIPS 140-3 Compliance.md`
**Demo Guide**: `DEMO-PIPELINE-GUIDE.md`
**GitHub Issues**: https://github.com/ppscon/CBOM/issues

---

**Status**: Ready for Aqua instance provisioning
**Last Updated**: 2025-10-03
**Pipeline File**: `.github/workflows/cbom-fips-pipeline-aqua.yml`
