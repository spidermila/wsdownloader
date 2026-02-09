FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tini curl procps \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DATA_DIR=/data \
    DOWNLOADS_DIR=/downloads

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app.py downloader.py /app/
COPY templates/ /app/templates/

# Create download path and data path
RUN mkdir -p /downloads /data \
 && chmod 0777 /data

COPY entrypoint.sh /app/entrypoint.sh
COPY healthcheck.sh /usr/local/bin/healthcheck.sh
RUN chmod +x /app/entrypoint.sh /usr/local/bin/healthcheck.sh

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD /usr/local/bin/healthcheck.sh

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/app/entrypoint.sh"]
