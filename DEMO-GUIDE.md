# QVS-CBOM Quick Demo Guide

Follow these steps to verify the wrapped scanner and QVS-CBOM binary using a well-known vulnerable container image.

## 1. Prerequisites
- Docker installed and running (Docker Desktop or Docker Engine)
- Internet access to pull container images
- Local clone of this repository

## 2. Build the Enhanced Scanner Image
```bash
# From the repository root
docker build -t enhanced-scanner .
```

## 3. Run a Combined Scan
Use OWASP Juice Shop (`bkimminich/juice-shop`) as the demo target. It contains intentionally weak cryptography that QVS-CBOM will surface.

```bash
# Mount the Docker socket so the wrapper can export image filesystems
# The first run downloads Trivy databases; allow a few minutes
docker run \
  -v /var/run/docker.sock:/var/run/docker.sock \
  enhanced-scanner --CBOM image bkimminich/juice-shop:latest
```

### What to Expect
1. Trivy performs its standard vulnerability scan and prints a table of CVEs.
2. The wrapper exports the image filesystem.
3. `/qvs-cbom` runs automatically and prints a CycloneDX 1.4 CBOM with quantum-risk findings (e.g., MD5 usage).

## 4. Scan Additional Targets (Optional)
- Different container: replace `bkimminich/juice-shop:latest` with `image nginx:latest` or any other tag.
- Local folder: bind-mount the path and run `--CBOM filesystem /path/in/container`.
- Kubernetes namespace: connect `kubectl` to a cluster and run `--CBOM kubernetes --namespace your-namespace`.

## 5. Cleanup (Optional)
Free disk space after repeated testing:
```bash
docker container prune
docker image prune -a
docker volume prune
docker network prune
```

## Troubleshooting
- **DB download fails / no space**: run the prune commands above or mount a larger cache volume:
  ```bash
  docker run -v $HOME/.cache/trivy:/root/.cache/trivy \
    -v /var/run/docker.sock:/var/run/docker.sock \
    enhanced-scanner --CBOM image <image:tag>
  ```
- **Private image**: log in first (`docker login`) so Trivy can pull it.

the demo can integrate with existing scanners and highlights weak cryptography.
