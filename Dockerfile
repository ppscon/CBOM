ARG BASE_IMAGE=aquasec/trivy:latest

FROM docker:cli AS docker-cli

FROM curlimages/curl:8.10.1 AS fetch-jq
RUN curl -sSfL -o /tmp/jq https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-linux-amd64 \
    && chmod +x /tmp/jq

FROM ${BASE_IMAGE}

COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=fetch-jq /tmp/jq /usr/local/bin/jq
ADD aqua-cbom /aqua-cbom
ADD wrapper.sh /wrapper.sh
ADD migration-rules.yaml /migration-rules.yaml

RUN chmod +x /usr/local/bin/docker /usr/local/bin/jq /aqua-cbom /wrapper.sh

ENTRYPOINT ["/wrapper.sh"]
