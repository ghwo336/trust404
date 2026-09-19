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

# Must match INSTALLED_SOLC in detector/compile.py (contiguous 0.8.24..0.8.37 for recent pragmas).
RUN for v in 0.4.26 0.5.17 0.6.12 0.7.6 0.8.20 \
             0.8.24 0.8.25 0.8.26 0.8.27 0.8.28 0.8.29 0.8.30 \
             0.8.31 0.8.32 0.8.33 0.8.34 0.8.35 0.8.36 0.8.37; do solc-select install $v; done

COPY detector /app/detector
COPY vendor/openzeppelin-contracts /app/vendor/openzeppelin-contracts

ENV DETECTOR_OZ_DIR=/app/vendor/openzeppelin-contracts PYTHONPATH=/app PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "detector.docker_entry"]
