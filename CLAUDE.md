# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Aqua-CBOM is a quantum vulnerability scanner that generates CycloneDX-compliant CBOMs (Cryptography Bill of Materials). It works as a Docker wrapper around existing scanners (Trivy) and adds quantum-risk cryptography detection without disrupting existing workflows.

**Purpose**: Enable FIPS 140-3 compliance validation through automated cryptographic inventory and policy enforcement.

## Key Components

### Core Binaries
- `aqua-cbom`: Linux ELF binary for quantum vulnerability scanning
- `aqua-cbom-darwin`: macOS binary variant
- Both accept flags: `-mode` (file/k8s), `-dir`, `-namespace`, `-output-cbom`, `-json`

### Docker Integration
- Base image: `aquasec/trivy:latest` with Docker CLI added
- Wrapper script (`wrapper.sh`) intercepts `--CBOM` flag to trigger Aqua-CBOM after Trivy scan
- Requires Docker socket mount: `-v /var/run/docker.sock:/var/run/docker.sock`
- Environment variables:
  - `CBOM_CDX_TARGET=1.6` - Output CycloneDX 1.6 format
  - `CBOM_OUTPUT_FILE=/path/to/output.json` - Save CBOM to file

### CycloneDX Format Support
- **Version 1.4**: Uses `.crypto` object on components
- **Version 1.6**: Uses `.properties[]` array with `cbom:` prefixed names
- Wrapper automatically converts to 1.6 when `CBOM_CDX_TARGET=1.6` is set
- Both formats supported by REGO policy (`fips-compliance-cdx16.rego`)

### Workflow Sequence
1. **Trivy** performs standard vulnerability scan (exits with code)
2. **Wrapper** intercepts `--CBOM` flag (preserves Trivy exit code)
3. **Wrapper** extracts image filesystem (for image scans)
4. **Aqua-CBOM** analyzes and outputs CycloneDX CBOM with quantum-risk findings
5. **REGO** (separate step) evaluates CBOM against FIPS compliance rules

## Common Commands

### Build Docker Image
```bash
docker build -t enhanced-scanner .
```

### Run Scans
```bash
# Container image scan
docker run -v /var/run/docker.sock:/var/run/docker.sock \
  enhanced-scanner --CBOM image <image:tag>

# Filesystem scan
docker run -v /path:/workspace \
  enhanced-scanner --CBOM filesystem /workspace

# Kubernetes namespace scan
docker run -v /var/run/docker.sock:/var/run/docker.sock \
  -v $HOME/.kube:/root/.kube \
  enhanced-scanner --CBOM kubernetes --namespace <namespace>
```

### Demo Scripts
```bash
./demo.sh juice    # Scan Juice Shop demo container
./demo.sh k8s      # Scan Kubernetes namespace
```

### Bare Metal Usage (macOS)
```bash
./aqua-cbom-darwin -mode file -dir /path/to/scan -output-cbom
./aqua-cbom-darwin -mode k8s -namespace default -output-cbom
```

### CSV Conversion
```bash
./aqua-cbom-csv.sh input.json --output report.csv
```

## FIPS 140-3 Compliance Implementation

### Three-Layer Architecture

1. **Aqua-CBOM (Detection Layer)**
   - Scans source code, binaries, and libraries for cryptographic algorithms
   - Provides NIST-based risk assessment (High/Medium/Low)
   - Identifies quantum-vulnerable algorithms
   - Outputs CycloneDX-compliant CBOM with findings

2. **REGO Policy (CI/CD Gate)**
   - Location: `policies/fips-compliance-cdx16.rego`
   - Evaluates CBOM against organizational compliance rules
   - Provides GO/NO-GO decision (exit 0 or exit 1)
   - Supports both CycloneDX 1.4 and 1.6 formats
   - Uses OPA (Open Policy Agent) for evaluation

3. **Aqua Platform (Enforcement Layer)**
   - Configured via Terraform policies in `fips-compliance-policies.tf`
   - **Image Assurance**: Scans images at registry (vulnerabilities, packages, CIS benchmarks)
   - **Kubernetes Assurance**: Admission control at deployment (AVD rules, labels, secrets)
   - **Runtime Protection**: Continuous monitoring (file integrity, package blocking, audit)

### CI/CD Pipeline Flow

```
1. Aqua Scanner (Image Assurance)
   ↓ (if pass)
2. Aqua-CBOM Generation (enhanced-scanner --CBOM)
   ↓
3. REGO Policy Evaluation (fips-compliance-cdx16.rego)
   ↓ (if pass - exit 0)
4. Image pushed to registry
   ↓
5. Aqua Admission Controller (Kubernetes Assurance)
   ↓ (if allowed)
6. Container deploys
   ↓
7. Aqua Runtime Protection (continuous monitoring)
```

### Key Files

- `wrapper.sh` - Docker wrapper that runs Trivy + Aqua-CBOM
- `policies/fips-compliance-cdx16.rego` - FIPS compliance policy (OPA/REGO)
- `fips-compliance-policies.tf` - Terraform configuration for Aqua policies
- `workflows/cbom-fips-pipeline.yml` - GitHub Actions CI/CD pipeline
- `docs/FIPS-COMPLIANCE-IMPLEMENTATION.md` - Detailed policy documentation
- `docs/REGO-POLICY-NARRATION.md` - Meeting presentation guide

### Testing

```bash
# Test CycloneDX 1.6 generation
./test-cdx16.sh

# Validate REGO policy
opa eval --data policies/fips-compliance-cdx16.rego \
  --input outputs/cbom.json \
  'data.fips_compliance_cdx16.deny'
```

## Architecture Notes

- The wrapper preserves the original scanner's exit code while running CBOM analysis
- Custom CBOM commands can be set via `CBOM_COMMAND_TEMPLATE` environment variable
- The wrapper handles image filesystem extraction transparently using Docker export
- Aqua-CBOM identifies weak cryptographic algorithms (MD5, SHA1, DES, etc.) and provides NIST categorization
- Metadata branding: Vendor is "Aqua Security", tool name is "Aqua-CBOM-Generator"
- REGO and Aqua policies are **independent** - REGO runs in CI/CD, Aqua enforces at deployment/runtime