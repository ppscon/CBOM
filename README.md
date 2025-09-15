# QVS-CBOM

Quantum vulnerability scanner that generates CycloneDX-compliant CBOMs.

## Installation

### Download
```bash
git clone https://github.com/ppscon/CBOM.git
cd CBOM
```

### Platform Setup
```bash
# Linux
chmod +x qvs-cbom qvs-cbom-csv.sh wrapper.sh

# Darwin/macOS
chmod +x qvs-cbom-darwin qvs-cbom-csv.sh wrapper.sh
```

## Usage

```bash
# Kubernetes cluster (Linux)
./qvs-cbom -mode k8s -namespace default -output-cbom

# Kubernetes cluster (Darwin/macOS)
./qvs-cbom-darwin -mode k8s -namespace default -output-cbom

# File system
./qvs-cbom -mode file -dir /path/to/scan -output-cbom

# CSV output
./qvs-cbom-csv.sh input.json --output report.csv
```

## Docker Integration

```bash
# Mount binaries and wrapper
docker run -v ./wrapper.sh:/wrapper.sh -v ./qvs-cbom:/qvs-cbom \
  aquasec/trivy --cbom image nginx:latest

# Or build enhanced scanner
docker build -t enhanced-scanner .
docker run enhanced-scanner --cbom image nginx:latest
```

