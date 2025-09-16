# QVS-CBOM

Quantum vulnerability scanner that generates CycloneDX-compliant CBOMs and layers on top of existing tooling with zero workflow disruption.

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
1. Trivy performs its standard vulnerability scan.
2. The wrapper exports the target image using the bundled Docker CLI.
3. `/qvs-cbom` prints a CycloneDX 1.4 CBOM highlighting quantum-risk cryptography.

See `DEMO-GUIDE.md` for a detailed walkthrough.

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
# Make binaries executable
chmod +x qvs-cbom qvs-cbom-darwin qvs-cbom-csv.sh wrapper.sh

# Kubernetes (Linux)
./qvs-cbom -mode k8s -namespace default -output-cbom

# File system (macOS)
./qvs-cbom-darwin -mode file -dir /path/to/scan -output-cbom

# CSV conversion helper
./qvs-cbom-csv.sh input.json --output report.csv
```

## Maintenance & Troubleshooting
- **No space left on device**: prune Docker resources (`docker system prune`) or mount a larger cache (`-v $HOME/.cache/trivy:/root/.cache/trivy`).
- **Private registries**: authenticate with `docker login` before running the wrapper.
- **Custom workflows**: set `CBOM_COMMAND_TEMPLATE`; the original scanner arguments are available in `$CBOM_ORIGINAL_ARGS` for scripting.

The enhanced wrapper demonstrates how QVS-CBOM augments existing scanners without disrupting operator workflows.
