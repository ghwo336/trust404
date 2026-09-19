FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir slither-analyzer solc-select
RUN for v in 0.4.26 0.5.17 0.6.12 0.7.6 0.8.20 0.8.24; do solc-select install $v; done
COPY tool.py /tool.py
ENTRYPOINT ["python","/tool.py","/input","/output/results.json"]
