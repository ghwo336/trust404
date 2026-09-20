FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# solc-select fetches linux-amd64 solc binaries. On amd64 hosts (the grading env) they run
# natively; on arm64 hosts they run under qemu-x86_64, which needs the amd64 loader + libc.
# Installing libc6:amd64 keeps this one Dockerfile portable across both architectures.
RUN dpkg --add-architecture amd64 && apt-get update \
    && apt-get install -y --no-install-recommends libc6:amd64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY detector/requirements.txt /app/detector/requirements.txt
RUN pip install --no-cache-dir -r /app/detector/requirements.txt "jsonschema>=4.20"

# INSTALLED_SOLC SSOT: detector/solc_versions.txt (copied first so compile.py edits do not bust this layer).
ENV HOME=/opt/detector-home DETECTOR_SOLC_ARTIFACTS=/opt/detector-home/.solc-select/artifacts
RUN mkdir -p /opt/detector-home
COPY detector/solc_versions.txt /app/detector/solc_versions.txt
RUN for v in $(cat /app/detector/solc_versions.txt); do solc-select install "$v"; done

COPY detector /app/detector
COPY vendor/openzeppelin-contracts /app/vendor/openzeppelin-contracts
COPY vendor/openzeppelin-contracts-v5 /app/vendor/openzeppelin-contracts-v5
RUN chmod -R a+rX /opt/detector-home /app

ENV DETECTOR_OZ_DIR=/app/vendor/openzeppelin-contracts DETECTOR_OZ_V5_DIR=/app/vendor/openzeppelin-contracts-v5 PYTHONPATH=/app PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "detector.docker_entry"]
