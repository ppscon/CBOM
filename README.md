# Aqua-CBOM

Quantum vulnerability scanner that generates CycloneDX-compliant CBOMs as part of your regular image scans with zero workflow disruption.

## Quick Start (Containerized)
```bash
git clone https://github.com/ppscon/CBOM.git
cd CBOM
docker build -t enhanced-scanner .

# Run an image scan and save CBOM JSON to a host directory
mkdir -p ./outputs
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/outputs":/out \
  -e CBOM_OUTPUT_FILE=/out/juice-shop.json \
  enhanced-scanner --CBOM image bkimminich/juice-shop:latest

# Convert JSON → CSV on the host
./json-to-csv.sh ./outputs/juice-shop.json ./outputs/juice-shop.csv
```

What happens:
1. The scanner performs its standard vulnerability scan on the image.
2. A CycloneDX 1.4 CBOM of cryptographic assets is generated and saved to `CBOM_OUTPUT_FILE`.

See `DEMO-GUIDE.md` for a guided walkthrough.

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
chmod +x aqua-cbom aqua-cbom-darwin json-to-csv.sh wrapper.sh

# File system (macOS)
./aqua-cbom-darwin -mode file -dir /path/to/scan -output-cbom > cbom.json

# CSV conversion helper (host)
./json-to-csv.sh cbom.json cbom.csv
```

## Confidence Handling
- Aqua-CBOM detections are based on deterministic pattern/static analysis; we do not require or surface a "confidence" score in reports.
- Any internal metadata fields like `confidence` present in raw JSON are ignored for reporting and excluded from CSV. They will be removed from the JSON schema in a subsequent release.

## Maintenance & Troubleshooting
- **No space left on device**: prune Docker resources (`docker system prune`) or mount a larger cache (`-v $HOME/.cache/trivy:/root/.cache/trivy`).
- **Private registries**: authenticate with `docker login` before running the scan.
- **Speed and caching**: the first run downloads vulnerability DBs; subsequent runs are faster.

The enhanced scanner demonstrates how Aqua-CBOM augments existing image scans without disrupting operator workflows.
