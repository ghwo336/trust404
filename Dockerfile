# TRUST404 Track 1 - offline grading image for the ensemble (noexit + detector)
#   docker build -t trust404/ensemble .
#   docker run --rm --network none -v "$PWD/cases:/input:ro" trust404/ensemble /input > out.json
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates curl nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# solc-select fetches linux-amd64 solc binaries (see detector/Dockerfile for the arm64 note)
RUN dpkg --add-architecture amd64 && apt-get update \
    && apt-get install -y --no-install-recommends libc6:amd64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# --- detector (Python) ---
COPY detector/requirements.txt /app/detector/requirements.txt
RUN pip install --no-cache-dir -r /app/detector/requirements.txt "jsonschema>=4.20"
RUN for v in 0.4.26 0.5.17 0.6.12 0.7.6 0.8.20 \
             0.8.24 0.8.25 0.8.26 0.8.27 0.8.28 0.8.29 0.8.30 \
             0.8.31 0.8.32 0.8.33 0.8.34 0.8.35 0.8.36 0.8.37; do solc-select install $v; done
COPY detector /app/detector
COPY vendor/openzeppelin-contracts /app/vendor/openzeppelin-contracts

# --- noexit (Node) ---
COPY noexit/package.json noexit/package-lock.json /app/noexit/
RUN cd /app/noexit && npm ci --ignore-scripts
COPY noexit/tsconfig.json noexit/run.sh /app/noexit/
COPY noexit/src /app/noexit/src
RUN cd /app/noexit && npx tsc -p tsconfig.json && npm prune --omit=dev

COPY tools/ensemble.py /app/tools/ensemble.py
ENV DETECTOR_OZ_DIR=/app/vendor/openzeppelin-contracts PYTHONPATH=/app PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "/app/tools/ensemble.py"]
