# QVS-Pro Scanner Container Image
# This image contains the unified scanner binary for Kubernetes scanning
FROM alpine:latest

# Install necessary packages for the scanner
RUN apk add --no-cache ca-certificates

# Create non-root user for security
RUN adduser -D -s /bin/sh scanner

# Copy the scanner binary
COPY qvs-pro-linux /usr/local/bin/qvs-pro
RUN chmod +x /usr/local/bin/qvs-pro

# Switch to non-root user
USER scanner

# Set working directory
WORKDIR /app

# Default command is the scanner
ENTRYPOINT ["/usr/local/bin/qvs-pro"]

# Default arguments for cluster scanning
CMD ["--mode=cluster-scan", "--json", "--timeout=300s"]