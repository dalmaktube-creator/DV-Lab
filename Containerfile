FROM docker.io/library/python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iputils-ping iperf3 curl openssl procps ca-certificates && rm -rf /var/lib/apt/lists/*
COPY dvlab/__init__.py dvlab/common.py dvlab/runner.py dvlab/sampling.py /opt/dv-lab/dvlab/
ENV PYTHONPATH=/opt/dv-lab PYTHONDONTWRITEBYTECODE=1
WORKDIR /work
CMD ["python3", "-m", "dvlab.runner", "serve"]
