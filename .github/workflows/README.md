# GitHub Actions CBOM FIPS Compliance Pipeline

## Overview

This workflow implements a **6-stage defense-in-depth pipeline** for cryptographic compliance validation using Aqua-CBOM and REGO policies.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              GitHub Actions CI/CD Pipeline              │
├─────────────────────────────────────────────────────────┤
│  Stage 1: Build Application Image                       │
│    └─> Builds and pushes image to GHCR                  │
│                                                          │
│  Stage 2: Aqua Image Assurance                          │
│    └─> Trivy scan (CVE/malware/CIS benchmarks)         │
│    └─> FAIL = Pipeline stops                            │
│                                                          │
│  Stage 3: Build Enhanced Scanner                        │
│    └─> Compiles aqua-cbom binary                        │
│    └─> Builds Trivy + Aqua-CBOM wrapper image          │
│                                                          │
│  Stage 4: CBOM Generation                               │
│    └─> Scans for cryptographic algorithms              │
│    └─> Generates CycloneDX 1.6 CBOM                    │
│    └─> PQC migration planning                           │
│    └─> CSV report generation                            │
│                                                          │
│  Stage 5: REGO Policy Evaluation                        │
│    └─> Validates CBOM against org policies             │
│    └─> FAIL = Image NOT pushed to registry             │
│                                                          │
│  Stage 6: Tag & Push Compliant Image                    │
│    └─> Tags as fips-compliant-{sha}                    │
│    └─> Only executes if all gates pass                 │
└─────────────────────────────────────────────────────────┘
```

## Workflow Order (Critical)

**Job Dependencies** ensure proper execution order:

```yaml
build
  ↓ (needs: build)
aqua_image_assurance
  ↓ (needs: aqua_image_assurance)
build_enhanced_scanner
  ↓ (needs: build_enhanced_scanner)
cbom_generation
  ↓ (needs: cbom_generation)
rego_compliance
  ↓ (needs: rego_compliance)
push_compliant_image
```

**If ANY stage fails, the pipeline stops immediately.**

## Required Secrets

### For Production Aqua Platform (Optional)

| Secret Name | Description | How to Obtain |
|-------------|-------------|---------------|
| `AQUA_SERVER` | Aqua tenant URL | Aqua admin console |
| `AQUA_TOKEN` | Scanner auth token | Aqua UI → Integrations → Scanners |
| `AQUA_KEY` | API key | Aqua UI → Settings → API Keys |
| `AQUA_SECRET` | API secret | Aqua UI → Settings → API Keys |

### For Kubernetes Deployment (Optional)

| Secret Name | Description | How to Obtain |
|-------------|-------------|---------------|
| `KUBECONFIG` | Base64-encoded kubeconfig | `cat ~/.kube/config \| base64` |

**Note**: For OSS/demo usage, the workflow uses Trivy as a fallback for Image Assurance. No Aqua secrets required.

## Repository Permissions

The workflow requires these GitHub permissions:

```yaml
permissions:
  contents: read          # Checkout code
  packages: write         # Push to GHCR
  security-events: write  # Upload SARIF results
```

Set in: **Settings → Actions → General → Workflow permissions**

## Configuration

### Migration Planning Environment Variables

Edit in job `cbom_generation` (line 174-180):

```yaml
-e CBOM_MIGRATION_CONTEXT=edge_ingress    # Options: edge_ingress, service_mesh, internal_api, data_at_rest
-e CBOM_MIGRATION_TIMELINE=2025-Q2        # Target migration quarter
```

### REGO Policy Customization

Edit `policies/fips-compliance-cdx16.rego` to customize:
- Approved algorithm list
- Risk thresholds (High/Medium/Low)
- Context-aware exceptions
- Namespace-based rules

## Artifacts Generated

Each pipeline run produces:

| Artifact | Location | Retention |
|----------|----------|-----------|
| `cbom.json` | Actions artifacts | 90 days |
| `cbom.csv` | Actions artifacts | 90 days |
| `trivy-results.sarif` | Security tab | Permanent |

Download via: **Actions → Run → Artifacts**

## Triggering the Workflow

### Automatic Triggers

- **Push to `master`**: Full pipeline execution
- **Push to `develop`**: Full pipeline execution
- **Pull Request to `master`**: Full pipeline execution

### Manual Trigger

```bash
# Via GitHub UI: Actions → CBOM FIPS Compliance Pipeline → Run workflow

# Via GitHub CLI:
gh workflow run cbom-fips-pipeline.yml
```

## Understanding Results

### ✅ Success Output

```
Pipeline Stages
- ✅ Image Build
- ✅ Image Assurance (Trivy)
- ✅ CBOM Generation
- ✅ REGO Policy Compliance
- ✅ Tagged and Pushed

Compliant Image: ghcr.io/ppscon/cbom:fips-compliant-abc123
```

### ❌ Failure Scenarios

**Scenario 1: Image Assurance Fails**
```
Stage 2: aqua_image_assurance
❌ Critical vulnerability found: CVE-2024-12345 (CVSS 9.8)
→ Pipeline stops, CBOM never runs
```

**Scenario 2: REGO Policy Fails**
```
Stage 5: rego_compliance
❌ REGO Policy FAILED: 2 violation(s) found
  - Deprecated algorithm detected: MD5 in /app/crypto.js
  - Quantum-vulnerable cryptography: RSA-1024
→ Pipeline stops, image NOT pushed
```

**Scenario 3: Success with Warnings**
```
Stage 5: rego_compliance
✅ REGO Policy PASSED: No blocking violations
ℹ️  Found 3 warning(s) (quantum-vulnerable algorithms)
  - SHA-256 (Grover's Algorithm - plan migration by 2030)
→ Pipeline continues, warnings logged
```

## Integration with Aqua Platform

### Replacing Trivy with Aqua Scanner

Uncomment lines 84-92 in `cbom-fips-pipeline.yml`:

```yaml
- name: Aqua Scanner
  uses: docker://registry.aquasec.com/scanner:2022.4
  env:
    AQUA_SERVER: ${{ secrets.AQUA_SERVER }}
    AQUA_TOKEN: ${{ secrets.AQUA_TOKEN }}
  with:
    args: scan --register ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
```

Then comment out the Trivy action (lines 77-82).

### Enabling Kubernetes Deployment

Uncomment lines 293-313 in `cbom-fips-pipeline.yml`:

```yaml
deploy:
  runs-on: ubuntu-latest
  needs: push_compliant_image
  # ... deployment steps
```

Requires:
- Kubernetes cluster configured
- Aqua Admission Controller installed
- `KUBECONFIG` secret configured

## Troubleshooting

### Issue: "Build aqua-cbom binary failed"

**Cause**: Go build environment issue

**Solution**:
```bash
# Verify Go version locally
go version  # Should be 1.21+

# Test build locally
cd scanner
env GOOS=linux GOARCH=amd64 go build -o ../aqua-cbom .
```

### Issue: "Enhanced scanner not found"

**Cause**: Build stage failed or image not pushed

**Solution**:
- Check Stage 3 logs for build errors
- Verify GHCR permissions: Settings → Packages → Manage Actions access
- Ensure `GITHUB_TOKEN` has `packages: write` permission

### Issue: "REGO evaluation failed with syntax error"

**Cause**: Invalid REGO policy syntax

**Solution**:
```bash
# Validate locally
opa fmt --fail policies/fips-compliance-cdx16.rego

# Test evaluation
opa eval --data policies/fips-compliance-cdx16.rego \
  --input test-cbom.json \
  'data.fips_compliance_cdx16.deny'
```

### Issue: "CSV generation failed"

**Cause**: `aqua-cbom-csv.sh` not found or not executable

**Solution**:
```bash
# Verify script exists
ls -la aqua-cbom-csv.sh

# Make executable
chmod +x aqua-cbom-csv.sh
git add aqua-cbom-csv.sh
git commit -m "fix: make CSV script executable"
```

### Issue: "Docker socket permission denied"

**Cause**: Enhanced scanner can't access Docker daemon

**Solution**: This shouldn't happen in GitHub Actions (Docker-in-Docker is supported). If it does:
```yaml
# Add privileged mode (line 170)
docker run --rm --privileged \
  -v /var/run/docker.sock:/var/run/docker.sock \
  # ... rest of command
```

## Local Testing

### Test Workflow Syntax

```bash
# Validate YAML
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/cbom-fips-pipeline.yml'))"

# Lint with actionlint (if installed)
actionlint .github/workflows/cbom-fips-pipeline.yml
```

### Simulate Pipeline Locally

```bash
# Stage 1: Build image
docker build -t test-app .

# Stage 2: Trivy scan
docker run --rm aquasec/trivy:latest image test-app

# Stage 3: Build enhanced scanner
cd scanner && GOOS=linux GOARCH=amd64 go build -o ../aqua-cbom . && cd ..
docker build -t enhanced-scanner .

# Stage 4: CBOM generation
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/outputs":/out \
  -e CBOM_OUTPUT_FILE=/out/cbom.json \
  -e CBOM_CDX_TARGET=1.6 \
  -e CBOM_GENERATE_MIGRATION_PLAN=true \
  -e CBOM_MIGRATION_CONTEXT=edge_ingress \
  -e CBOM_MIGRATION_TIMELINE=2025-Q2 \
  enhanced-scanner --CBOM image test-app

# Stage 5: REGO evaluation
opa eval --data policies/fips-compliance-cdx16.rego \
  --input outputs/cbom.json \
  --format pretty 'data.fips_compliance_cdx16.deny'
```

## Performance

| Stage | Typical Duration | Notes |
|-------|-----------------|-------|
| Build | 2-5 min | Depends on image size |
| Aqua/Trivy Scan | 1-3 min | Depends on layers |
| Enhanced Scanner Build | 1-2 min | Go compilation |
| CBOM Generation | 30-60 sec | Crypto algorithm scan |
| REGO Evaluation | <1 sec | JSON processing |
| Push Compliant | 30-60 sec | Depends on image size |
| **Total** | **5-12 min** | Full pipeline |

## Security Considerations

### Secrets Management

- **Never commit secrets** to the repository
- Use GitHub Secrets for sensitive data
- Rotate `AQUA_TOKEN` every 90 days
- Use environment-specific secrets (prod vs dev)

### Image Security

- Enhanced scanner image is rebuilt on each run (no stale binaries)
- Source image uses official Trivy base (regularly updated)
- All images are tagged with commit SHA for traceability

### REGO Policy Security

- REGO policies are version-controlled (audit trail)
- Policy changes require PR review
- Use branch protection to prevent unauthorized policy relaxation

## Maintenance

### Updating Trivy Version

Edit `Dockerfile` line 1:

```dockerfile
ARG BASE_IMAGE=aquasec/trivy:0.50.0  # Pin to specific version
```

### Updating OPA Version

Edit workflow line 218:

```yaml
curl -L -o opa https://openpolicyagent.org/downloads/v0.64.0/opa_linux_amd64
```

### Updating Go Version

If needed, update build job to specify Go version:

```yaml
- name: Set up Go
  uses: actions/setup-go@v4
  with:
    go-version: '1.21'
```

## References

- **Architecture**: `docs/REGO Policy Narration for FIPS 140-3 Compliance.md`
- **Demo Guide**: `DEMO-PIPELINE-GUIDE.md`
- **REGO Policy**: `policies/fips-compliance-cdx16.rego`
- **Aqua-CBOM**: `scanner/main.go`

## Support

**Issues**: https://github.com/ppscon/CBOM/issues
**Documentation**: `docs/`
**Workflow File**: `.github/workflows/cbom-fips-pipeline.yml`
