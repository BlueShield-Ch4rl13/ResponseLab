# Motor de ResponseLab
#
#   docker build -t responselab .
#   docker run -p 8080:8080 -v ./clientes:/app/clientes:ro --env-file .env responselab
#
# La imagen lleva el motor, el catalogo compilado y los conectores
# declarativos. Los perfiles de cliente se montan desde fuera (cambian sin
# reconstruir) y el estado vive en un volumen. Sin TLS: va detras de un proxy
# (ver docker-compose.yml).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    RL_DATOS=/var/lib/responselab

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY responselab/ responselab/
COPY catalogo/ catalogo/
COPY conectores/ conectores/
COPY tools/ tools/
COPY escenarios/ escenarios/
COPY clientes/_plantilla.yml clientes/_plantilla.yml

RUN useradd --system --uid 10001 --home-dir /var/lib/responselab --shell /usr/sbin/nologin responselab \
    && mkdir -p /var/lib/responselab \
    && chown responselab /var/lib/responselab

USER responselab
VOLUME ["/var/lib/responselab"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/salud', timeout=4).status == 200 else 1)"]

CMD ["python", "-m", "responselab", "servir", "--puerto", "8080"]
