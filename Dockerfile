ARG BASE_IMAGE=aquasec/trivy:latest
FROM ${BASE_IMAGE}

COPY qvs-cbom /qvs-cbom
COPY wrapper.sh /wrapper.sh

RUN chmod +x /qvs-cbom /wrapper.sh

ENTRYPOINT ["/wrapper.sh"]