# Aqua-CBOM

Comprehensive CBOM (Cryptography Bill of Materials) generator with quantum vulnerability analysis. Generates CycloneDX 1.4/1.6 compliant output and integrates seamlessly with existing container scanning workflows.

## Quick Start (Docker Wrapper)
```bash
git clone https://github.com/ppscon/CBOM.git
cd CBOM
docker build -t enhanced-scanner .

# Run with the Docker socket mounted so CBOM can export image filesystems
docker run -v /var/run/docker.sock:/var/run/docker.sock \
  enhanced-scanner --CBOM image bkimminich/juice-shop:latest
```

What happens:
1. Trivy performs its standard vulnerability scan
2. The wrapper extracts the image filesystem
3. Aqua-CBOM analyzes cryptographic assets and generates a CycloneDX 1.4 CBOM (1.6 via `CBOM_CDX_TARGET=1.6`)

See `DEMO-GUIDE.md` for a detailed walkthrough.

## CycloneDX 1.6 Support
```bash
# Generate CycloneDX 1.6 format CBOM
docker run -v /var/run/docker.sock:/var/run/docker.sock \
  -e CBOM_CDX_TARGET=1.6 \
  -e CBOM_OUTPUT_FILE=/tmp/cbom16.json \
  enhanced-scanner --CBOM image bkimminich/juice-shop:latest
```

## Demo Script
Run `./demo.sh juice` to scan the Juice Shop demo or `./demo.sh k8s` to scan the demo namespace. Use `./demo.sh --help` for options.

## Scan Other Targets
```bash
# Different container image
docker run -v /var/run/docker.sock:/var/run/docker.sock \
  enhanced-scanner --CBOM image nginx:latest

# Local directory (bind mount)
docker run -v /host/path:/workspace \
  enhanced-scanner --CBOM filesystem /workspace

# Kubernetes namespace (kubectl configured on host)
docker run -v /var/run/docker.sock:/var/run/docker.sock \
  enhanced-scanner --CBOM kubernetes --namespace cbom

# Override CBOM invocation (advanced)
docker run -e CBOM_COMMAND_TEMPLATE='/qvs-cbom -mode file -dir /workspace -output-cbom' \
  -v /host/path:/workspace \
  enhanced-scanner --CBOM filesystem /workspace
```

## Bare-Metal Usage (Optional)
```bash
# Linux
./qvs-cbom -mode file -dir /path/to/scan -output-cbom

# macOS
./qvs-cbom-darwin -mode file -dir /path/to/scan -output-cbom

# Kubernetes
./qvs-cbom -mode k8s -namespace default -output-cbom

# CSV report generation
./qvs-cbom-csv.sh input.json --output report.csv
```

## Features

- **CycloneDX 1.4/1.6 Compliance**: Standards-compliant CBOM generation
- **Quantum Vulnerability Detection**: Identifies quantum-vulnerable cryptographic algorithms
- **FIPS 140-3 Alignment**: Supports FIPS compliance validation workflows
- **Zero Workflow Disruption**: Integrates with existing container security pipelines
- **Multi-format Output**: JSON CBOM + CSV reporting

## Maintenance & Troubleshooting

- **No space left on device**: Prune Docker resources (`docker system prune`)
- **Private registries**: Authenticate with `docker login` before scanning
- **Custom workflows**: Set `CBOM_COMMAND_TEMPLATE` for advanced use cases

---

**Aqua-CBOM** is part of the Aqua Security ecosystem for comprehensive supply chain security.
