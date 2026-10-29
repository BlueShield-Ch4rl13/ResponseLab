# Caddy con el modulo de DNS de Cloudflare, para pedir el certificado del motor
# por DNS-01 (ver docker-compose.cloudflare.yml). Versiones fijadas.
FROM caddy:2.11.7-builder-alpine AS compilar
RUN xcaddy build v2.11.7 --with github.com/caddy-dns/cloudflare@v0.2.4

FROM caddy:2.11.7-alpine
COPY --from=compilar /usr/bin/caddy /usr/bin/caddy
