# Aqua-CBOM

Quantum vulnerability scanner that generates CycloneDX-compliant CBOMs as part of your regular image scans with zero workflow disruption.

## Quick Start (Containerized)
```bash
git clone https://github.com/ppscon/CBOM.git
cd CBOM
docker build -t enhanced-scanner .

# Basic CBOM scan (CycloneDX 1.6)
mkdir -p ./outputs
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD/outputs":/out -e CBOM_OUTPUT_FILE=/out/juice-shop.json -e CBOM_CDX_TARGET=1.6 enhanced-scanner --CBOM image bkimminich/juice-shop:latest

# With PQC Migration Planning (NEW!)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD/outputs":/out -e CBOM_OUTPUT_FILE=/out/juice-shop-migration.json -e CBOM_CDX_TARGET=1.6 -e CBOM_GENERATE_MIGRATION_PLAN=true -e CBOM_MIGRATION_CONTEXT=edge_ingress -e CBOM_MIGRATION_TIMELINE=2025-Q2 enhanced-scanner --CBOM image bkimminich/juice-shop:latest

# Convert JSON → CSV on the host
./aqua-cbom-csv.sh ./outputs/juice-shop.json --output ./outputs/juice-shop.csv
```

What happens:
1. The scanner performs its standard vulnerability scan on the image.
2. A CycloneDX 1.6 CBOM of cryptographic assets is generated and saved to `CBOM_OUTPUT_FILE`.
3. (Optional) Post-Quantum Cryptography migration plan with context-aware guidance based on NIST FIPS 203/204/205.

See `docs/DEMO-GUIDE.md` for a guided walkthrough and `docs/MIGRATION-PLANNING.md` for migration planning details.

## Demo Script
Run `./demo.sh juice` to scan the Juice Shop demo or `./demo.sh image nginx:latest` to scan another image. Use `./demo.sh --help` for options.

## Scan Other Targets
```bash
# Different container image
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/outputs":/out \
  -e CBOM_OUTPUT_FILE=/out/nginx.json \
  enhanced-scanner --CBOM image nginx:latest

# Local directory (bind mount)
docker run --rm \
  -v /host/path:/workspace \
  -v "$PWD/outputs":/out \
  -e CBOM_OUTPUT_FILE=/out/fs.json \
  enhanced-scanner --CBOM filesystem /workspace

# (Optional) Kubernetes namespace — de-emphasized for image-focused deployments
# docker run --rm \
#   -v /var/run/docker.sock:/var/run/docker.sock \
#   -v "$HOME/.kube":/root/.kube \
#   -v "$PWD/outputs":/out \
#   -e CBOM_OUTPUT_FILE=/out/k8s.json \
#   enhanced-scanner --CBOM kubernetes --namespace cbom
```

## Bare-Metal Usage (Optional)
```bash
# Make binaries executable
chmod +x aqua-cbom aqua-cbom-darwin aqua-cbom-csv.sh wrapper.sh

# Basic scan (macOS)
./aqua-cbom-darwin -mode file -dir /path/to/scan -output-cbom > cbom.json

# With PQC migration planning (macOS)
./aqua-cbom-darwin -mode file -dir /path/to/scan -output-cbom -migration-plan -migration-context edge_ingress -migration-timeline 2025-Q2 > cbom.json

# CSV conversion helper
./aqua-cbom-csv.sh cbom.json --output cbom.csv
```

## Confidence Handling
- Aqua-CBOM detections are based on deterministic pattern/static analysis; we do not require or surface a "confidence" score in reports.
- Any internal metadata fields like `confidence` present in raw JSON are ignored for reporting and excluded from CSV. They will be removed from the JSON schema in a subsequent release.

## Maintenance & Troubleshooting
- **No space left on device**: prune Docker resources (`docker system prune`) or mount a larger cache (`-v $HOME/.cache/trivy:/root/.cache/trivy`).
- **Private registries**: authenticate with `docker login` before running the scan.
- **Speed and caching**: the first run downloads vulnerability DBs; subsequent runs are faster.

The enhanced scanner demonstrates how Aqua-CBOM augments existing image scans without disrupting operator workflows.
