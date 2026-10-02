# Cambios

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
