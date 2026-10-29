# Cambios

## 1.1.0 — 2026-10-25

Listo para el servidor del laboratorio.

### Despliegue
- `tools/preparar_servidor.py`: tokens y clave de la auditoría en `.env` (sin tocar
  los que ya existen) y la configuración rellena para el manager de Wazuh, las
  búsquedas de Splunk y las listas EDL de pfSense.
- `docker-compose.servidor.yml`: resolución de Wazuh y TheHive en otras VM,
  registros con rotación y un contenedor de copias.
- Certificado de Let's Encrypt por DNS en Cloudflare (`docker-compose.cloudflare.yml`),
  para que Wazuh, Splunk y el navegador confíen en el motor sin instalar una CA.
- Caddy fijado en 2.11.7; el proxy escucha en `RL_BIND`.
- `tools/comprobar_despliegue.py`: el motor desplegado visto desde fuera, con los
  escenarios y la conectividad con Wazuh y TheHive.
- `python -m responselab copia`: copia en caliente, verificada (integridad y
  cadena de auditoría) y con rotación. `make restaurar` para volver a una.
- Imágenes con versión: cada etiqueta `vX.Y.Z` publica `ghcr.io/...:X.Y.Z`.
- CI: el job *Despliegue de servidor* levanta los contenedores, comprueba por
  HTTPS, copia, restaura y vuelve a comprobar.
- `docs/SERVIDOR.md` para el HomeLab entero: direcciones, recursos, orden de
  despliegue con Infra-SocAnalyst y SplunkLab, cortafuegos y lista final.

### Ecosistema
- Sincronizado con DetectionLab tras la corrección de sus IDs de Wazuh (la
  sincronización fallaba desde el 23/10 porque 91 reglas habían cambiado de ID).
- 239 reglas. La pregunta de triaje de zta_vis_001 sigue a la regla nueva (sin
  apagados ni refrescos de GPO).

## 1.0.0 — 2026-10-02

Primera versión.

### Decisión y política
- Núcleo de decisión sin dependencias, compartido por el motor, Shuffle, Splunk SOAR
  y Cortex XSOAR.
- Política de radio × reversibilidad, con tres invariantes en el código.
- Evaluadores de tres valores (sí, no, no se sabe); lo desconocido lleva a aprobación.
- Siete secuencias de ataque que elevan la respuesta.

### Catálogo
- 235 reglas de DetectionLab, Infra-SocAnalyst y SplunkLab.
- 16 familias y 54 acciones ejecutables.

### Motor
- Multi-cliente, con tokens separados por función.
- Cola persistente y correlación de incidentes.
- Aprobaciones con caducidad, deshacer y auditoría encadenada.
- Plazos de RGPD, NIS2 y DORA.

### Conectores
- Wazuh, Defender for Endpoint, Entra ID, Exchange Online, CrowdStrike, SentinelOne,
  Palo Alto, FortiGate, Cloudflare, Kubernetes, Splunk, TheHive, MISP y listas EDL.
- Conectores declarativos en YAML y scripts para el resto.

### SIEM
- Integración con Wazuh: manager y agentes Linux y Windows con 14 acciones de active
  response.
- Splunk, Elastic Security y Microsoft Sentinel.

### SOAR
- Exportadores a Shuffle y TheHive, n8n, Splunk SOAR, Cortex XSOAR y Sentinel Logic
  Apps.

### Sincronización con el ecosistema
- Sincronización diaria con DetectionLab, Infra-SocAnalyst, SplunkLab, News CTI,
  FtriageDFIR y Malpipe.
- Validación, pruebas y escenarios antes de publicar.

### Calidad y despliegue
- 10 escenarios de ataque de extremo a extremo (176 comprobaciones) y 1183 pruebas.
- Imagen Docker sin privilegios y proxy TLS.
