FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark suricata iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY idps/ ./idps/
COPY data/ ./data/

RUN mkdir -p /app/output

ENTRYPOINT ["python", "-m", "idps.cli"]
CMD ["--demo"]
