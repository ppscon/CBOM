ARG BASE_IMAGE=aquasec/trivy:latest

FROM docker:cli AS docker-cli

FROM ${BASE_IMAGE}

COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
ADD qvs-cbom /qvs-cbom
ADD wrapper.sh /wrapper.sh

RUN chmod +x /usr/local/bin/docker /qvs-cbom /wrapper.sh

ENTRYPOINT ["/wrapper.sh"]
