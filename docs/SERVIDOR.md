# Despliegue en el servidor del laboratorio

Esta guía despliega ResponseLab en el servidor propio del laboratorio, junto al
resto del ecosistema. Usa la misma arquitectura que
[Infra-SocAnalyst](https://github.com/BlueShield-Ch4rl13/Infra-SocAnalyst): Proxmox
VE, red segmentada por VLAN y pfSense entre zonas. El perfil `clientes/lab.yml` ya
está escrito para esa red: el manager de Wazuh en `10.0.30.10` y el motor en
`10.0.30.20`.

```
VLAN 40 Atacante ──► VLAN 20 DMZ (víctima, Suricata)
                        │ agentes Wazuh
VLAN 10 Endpoints ──────┤
                        ▼
VLAN 30 SOC:  Wazuh manager 10.0.30.10 ──► ResponseLab 10.0.30.20:8443 ──► TheHive, Discord
              Splunk (SplunkLab) ─────────►        │
              Shuffle, TheHive, MISP               └──► API de Wazuh: aislar, matar, triage...
VLAN 99 Gestión: Proxmox, pfSense, el panel de aprobaciones
```

## Recursos

El motor es un proceso de Python con SQLite. Medido con unas 80 alertas de los
escenarios del laboratorio: unos 60 MB de RAM y 5 MB de base de datos. En un host que comparte
memoria con Wazuh, Splunk y TheHive basta con una VM pequeña:

| Recurso | Para ResponseLab (motor y proxy) |
|---|---|
| vCPU | 1 |
| RAM | 1 GB |
| Disco | 10 GB (la base de datos crece con el histórico: unos pocos KB por alerta) |
| Sistema | Debian 12 con Docker, o un contenedor LXC con Docker |

## 1. La máquina

1. Crea la VM en Proxmox con la etiqueta de VLAN 30 y una IP fija: `10.0.30.20`.
2. Instala Docker con el repositorio oficial de Docker para Debian.
3. Clona el repositorio:

   ```bash
   git clone https://github.com/BlueShield-Ch4rl13/ResponseLab /opt/responselab
   cd /opt/responselab
   cp .env.example .env && chmod 600 .env
   ```

## 2. Tokens y configuración

En el laboratorio los tokens del cliente `lab` van en `.env`. Genera uno por función:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

| Variable | Para qué |
|---|---|
| `RL_LAB_TOKEN` | Ingesta: Wazuh, Splunk y Shuffle envían alertas con él |
| `RL_LAB_TOKEN_AGENTES` | Acuses de los agentes y subida de informes de FtriageDFIR |
| `RL_LAB_TOKEN_EDL` | pfSense lee las listas de bloqueo |
| `RL_LAB_TOKEN_APROBADOR` | Tu token en el panel |
| `RL_ADMIN_TOKEN` | Métricas y administración |
| `RL_LAB_WAZUH_USUARIO`, `RL_LAB_WAZUH_CLAVE` | Usuario de la API de Wazuh con permiso de active response |
| `RL_LAB_THEHIVE_KEY`, `RL_LAB_DISCORD_WEBHOOK` | Casos y avisos |

Y para el proxy:

```ini
RL_DOMINIO=10.0.30.20          # o el nombre interno, p. ej. motor.soc.lab
RL_TLS=internal                # CA propia de Caddy: el laboratorio no necesita un certificado público
RL_URL_PUBLICA=https://10.0.30.20:8443
```

Arranca:

```bash
docker compose up -d --build
curl -k https://10.0.30.20:8443/salud
```

La CA del proxy está dentro del volumen `caddy`. Cópiala a donde tenga que
confiarse en ella: el manager de Wazuh, Splunk y tu navegador.

```bash
docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt ./responselab-ca.pem
```

## 3. Cortafuegos (pfSense)

ResponseLab se coloca en la VLAN SOC y respeta su matriz: denegar por defecto y
abrir solo lo necesario.

| Origen | Destino | Puerto | Para qué |
|---|---|---|---|
| Wazuh manager (SOC) | Motor | 8443/tcp | Alertas y acuses (misma VLAN) |
| Splunk | Motor | 8443/tcp | Webhook de las alertas |
| Motor | Wazuh manager | 55000/tcp | API de active response |
| Motor | TheHive | 9000/tcp | Casos (misma VLAN) |
| Shuffle | Motor | 8443/tcp | `/decidir` y `/alertas`, si usas el workflow de Shuffle |
| Motor | Internet | 443/tcp | Catálogo y News CTI (`raw.githubusercontent.com`), avisos a Discord |
| pfSense | Motor | 8443/tcp | Lista EDL (alias *URL Table*) |
| Gestión (VLAN 99) | Motor | 8443/tcp | Panel de aprobaciones |
| Endpoints y DMZ | Motor | 8443/tcp | Solo si los agentes suben el informe completo de FtriageDFIR. Sin esta regla, el resumen vuelve por Wazuh |
| **Internet** | **Motor** | — | **Nunca.** El motor ejecuta acciones de contención: no se publica |

Un equipo aislado solo habla con el manager y con lo que esté en `permitidos`. En
`lab.yml` eso es el motor, `10.0.30.20`.

## 4. Conectar el laboratorio

1. **Wazuh manager.** Ejecuta `siem/wazuh/instalar-manager.sh` y rellena
   `/var/ossec/etc/responselab.json`:
   - `motor`: `https://10.0.30.20:8443`
   - `ca`: `/var/ossec/etc/responselab-ca.pem`
   - los tokens de ingesta y de agentes del cliente `lab`

   Detalle en [SIEM.md](SIEM.md#wazuh).
2. **Agentes.** Instala los scripts de active response:
   - en la víctima de la DMZ: `instalar-agente-linux.sh`;
   - en los endpoints Windows: `instalar-agente-windows.ps1`.
3. **TheHive.** Importa las plantillas de caso:
   `python tools/importar_thehive.py --url http://<thehive>:9000 --organizacion SOC`.
4. **Splunk (SplunkLab).** Copia las búsquedas con webhook y la lista de URL
   permitidas, con `MOTOR=10.0.30.20`. Detalle en [SIEM.md](SIEM.md#splunk).
5. **pfSense.** Crea un alias de tipo *URL Table (IPs)* con
   `https://10.0.30.20:8443/v1/lab/edl/ip?token=<RL_LAB_TOKEN_EDL>`, y una regla que
   bloquee ese alias como destino.

## 5. De simulación a producción

El laboratorio arranca en simulación por dos sitios: `RL_SIMULACION_GLOBAL=true` en
`.env` y `modo: simulacion` en `clientes/lab.yml`.

1. **Escenarios contra el motor desplegado.** Lanza los escenarios del cliente
   `lab` y revisa en el panel qué decidió el motor y qué habría ejecutado:

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.lab.yml run --rm escenarios
   ```

2. **El ataque de verdad.** Lanza la cadena de la demo de Infra-SocAnalyst desde la
   Kali de la VLAN 40: hydra, shell, `/etc/shadow` y cron. Comprueba que llegan las
   alertas de Wazuh, Falco y Tetragon y que la secuencia `intrusion_ssh` se detecta
   en la tercera.
3. **Actuar de verdad.** Pon `modo: produccion` en `lab.yml` y
   `RL_SIMULACION_GLOBAL=false` en `.env`, y reinicia con `docker compose up -d`.
   Repite el ataque: la víctima se aísla sola, el triage de FtriageDFIR vuelve al
   incidente y desde el panel se puede deshacer el aislamiento.

`RL_SIMULACION_GLOBAL=true` y reiniciar devuelve todo a simulación en el acto.

## 6. Copias y actualizaciones

| Qué | Cómo |
|---|---|
| Copia del estado | `docker compose exec motor python -c "import sqlite3; s=sqlite3.connect('/var/lib/responselab/responselab.db'); d=sqlite3.connect('/var/lib/responselab/copia.db'); s.backup(d)"` en un cron, más la copia de la VM en Proxmox (vzdump) |
| Catálogo | Se actualiza solo cada 30 minutos desde el repositorio (`RL_ACTUALIZACION_URL`), y solo si pasa la validación |
| Motor | `git pull && docker compose up -d --build` |
| Integridad | `curl -sk -H "Authorization: Bearer $RL_ADMIN_TOKEN" https://10.0.30.20:8443/v1/admin/auditoria/verificar` |

## Si quieres enseñar los datos en público

No publiques el motor ni su panel: el panel aprueba acciones de contención. Para
que se vean los datos desde un subdominio, publica una vista de solo lectura generada
a partir de la API. Por ejemplo, un JSON con incidentes, decisiones por familia y
resultados de los escenarios, sin nombres de equipo ni direcciones. Puedes servirla
como estática, igual que los paneles de News CTI y FtriageDFIR.
