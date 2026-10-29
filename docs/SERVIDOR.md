# Despliegue en el servidor del laboratorio

Esta guía deja ResponseLab funcionando en el servidor propio del laboratorio
(HomeLab), junto a [Infra-SocAnalyst](https://github.com/BlueShield-Ch4rl13/Infra-SocAnalyst)
y [SplunkLab](https://github.com/BlueShield-Ch4rl13/SplunkLab): las alertas de
Wazuh y de Splunk llegan al motor, el motor decide, contiene en los agentes, abre
el caso en TheHive y publica las listas de bloqueo que lee pfSense.

Todo lo que se puede automatizar está en tres órdenes:

```bash
python tools/preparar_servidor.py --motor 10.0.30.20 ...   # secretos y configuración de cada pieza
docker compose up -d --build --wait                         # motor, proxy TLS y copias
python tools/comprobar_despliegue.py --url ... --conectividad --escenarios
```

El CI de cada cambio hace lo mismo con `localhost` (job *Despliegue de servidor*):
prepara, levanta los tres contenedores, comprueba por HTTPS con la CA del proxy,
lanza los escenarios, hace una copia, la restaura y vuelve a comprobar.

## El laboratorio completo

Proxmox VE con el bridge VLAN-aware y pfSense entre zonas, como en
Infra-SocAnalyst. El direccionamiento es `10.0.<VLAN>.0/24`; el perfil
`clientes/lab.yml` ya está escrito para este plan (manager `10.0.30.10`, motor
`10.0.30.20`).

```
VLAN 40 Atacante (Kali 10.0.40.10) ──► VLAN 20 DMZ (víctima 10.0.20.10, Suricata)
                                          │ agentes Wazuh, Falco, Tetragon
VLAN 10 Endpoints (10.0.10.0/24) ─────────┤
                                          ▼
VLAN 30 SOC   Wazuh manager 10.0.30.10 ──► ResponseLab 10.0.30.20:8443 ──► TheHive (10.0.30.11), Discord
              Splunk 10.0.30.12 ─────────►        │        │
              Host SOAR 10.0.30.11               │        └──► listas EDL ──► pfSense
                                                  └──► API de Wazuh 55000: aislar, matar, triage…
VLAN 99 Gestión: Proxmox, pfSense, tu navegador (panel de aprobaciones)
```

| Máquina | VLAN | IP | Proyecto | vCPU | RAM | Disco |
|---|---|---|---|---|---|---|
| pfSense | todas | `.1` de cada una | Infra-SocAnalyst | 2 | 2 GB | 16 GB |
| Wazuh (manager, indexer y dashboard) | 30 | 10.0.30.10 | Infra-SocAnalyst | 4 | 8 GB | 80 GB |
| Host SOAR (Shuffle, TheHive, Cortex, MISP, Ollama) | 30 | 10.0.30.11 | Infra-SocAnalyst | 6 | 20 GB | 120 GB |
| Splunk | 30 | 10.0.30.12 | SplunkLab | 4 | 8 GB | 60 GB |
| **ResponseLab** | 30 | **10.0.30.20** | ResponseLab | 1 | 1 GB | 10 GB |
| Víctima SSH/Web | 20 | 10.0.20.10 | Infra-SocAnalyst | 2 | 2 GB | 20 GB |
| Endpoint Windows | 10 | 10.0.10.20 | — | 2 | 4 GB | 60 GB |
| Kali | 40 | 10.0.40.10 | — | 2 | 4 GB | 40 GB |
| **Total** | | | | 23 (Proxmox reparte) | **49 GB** | 406 GB |

Las cifras son un punto de partida, no una medida: en un mini PC de 64 GB quedan
unos 15 GB para Proxmox y para crecer. Lo que más varía es el host SOAR (el
modelo que cargue Ollama) y Splunk (el volumen que indexes). Del motor sí hay
medida: con las alertas de los escenarios usa unos 60 MB de RAM y 5 MB de base de
datos.

### Orden

1. Red: pfSense y VLAN (Infra-SocAnalyst, `docs/`).
2. Wazuh en 10.0.30.10 y las reglas de DetectionLab (`deploy/wazuh/INSTALAR.md`).
3. Host SOAR en 10.0.30.11 (`Infra-SocAnalyst/compose/soar-stack.yml`, con
   `SOC_BIND=10.0.30.11`).
4. SplunkLab en 10.0.30.12 (`make up` con `SPLUNK_BIND=10.0.30.12` en su `.env`).
5. **ResponseLab**: esta guía.
6. Agentes y active response en la víctima y en los endpoints.
7. Escenarios, ataque de verdad y paso a producción (apartado 7).

## 1. La máquina

1. VM Debian 12 en Proxmox con la etiqueta de VLAN 30 y la IP fija `10.0.30.20`.
2. Docker desde el repositorio oficial de Docker para Debian (con el plugin
   `compose`).
3. El repositorio:

   ```bash
   sudo git clone https://github.com/BlueShield-Ch4rl13/ResponseLab /opt/responselab
   cd /opt/responselab
   sudo apt install -y python3-yaml python3-httpx   # las dos herramientas de abajo
   ```

## 2. Preparar: secretos, certificado y configuración

### Elige el certificado

| | Cómo | Quién confía en él |
|---|---|---|
| **A. Let's Encrypt por DNS (recomendado)** | `--tls cloudflare --dominio motor.lab.carlosvillalbalagos.com`. Un registro A de ese nombre a `10.0.30.20` en Cloudflare (solo DNS, nube gris) o un *host override* en el DNS de pfSense. Let's Encrypt comprueba un TXT: el motor no se publica. | Todos: Wazuh, Splunk y el navegador, sin instalar nada |
| B. CA propia del proxy | `--tls internal` (por defecto) | Solo quien tenga la CA: hay que copiarla al manager y al navegador. La acción webhook de Splunk no tiene opción para indicar una CA, así que con SplunkLab conviene la A |

Para la A hace falta un token de Cloudflare con permiso *Zone → DNS → Edit*
limitado a tu zona, en `CLOUDFLARE_API_TOKEN` de `.env`.

### Ejecuta

```bash
# A (recomendado)
sudo python3 tools/preparar_servidor.py --motor 10.0.30.20 \
    --dominio motor.lab.carlosvillalbalagos.com --tls cloudflare
sudo nano .env        # CLOUDFLARE_API_TOKEN=...

# B
sudo python3 tools/preparar_servidor.py --motor 10.0.30.20
```

Qué deja hecho:

| Dónde | Qué |
|---|---|
| `.env` (0600) | Un token por función para el cliente `lab` (ingesta, agentes, EDL, aprobador), el de administración y la clave de la auditoría, generados con `secrets`. Los que ya tenían valor no se tocan: se puede repetir sin romper lo que ya usan Wazuh y Splunk. También la red: dominio, TLS, IP de escucha (`RL_BIND`), IP de Wazuh y del host SOAR, y `COMPOSE_FILE` para que `docker compose` use los ficheros del servidor. |
| `despliegue/generado/` (0700) | `wazuh/responselab.json` para el manager; las búsquedas de Splunk con la URL del motor y el token ya puestos y la lista de webhooks permitidos; las URL de las listas EDL; y un `LEEME.md` con dónde va cada fichero. Lleva tokens: no se sube (`.gitignore`). |
| `copias/` | Carpeta de las copias, propiedad del usuario del contenedor (10001). |

Si `clientes/lab.yml` apunta a otras IP que las del servidor (`managers`,
`permitidos`), lo avisa: un equipo aislado solo habla con esas direcciones.

## 3. Arrancar

```bash
sudo docker compose up -d --build --wait
```

Con `COMPOSE_FILE` de `.env` se levantan tres contenedores:

| Contenedor | Qué hace |
|---|---|
| `motor` | La API y la cola. Sin puerto propio, sistema de ficheros de solo lectura, usuario sin privilegios. Resuelve `wazuh-manager` y `thehive` (los nombres de `lab.yml`) a `RL_IP_WAZUH` y `RL_IP_SOAR`. |
| `proxy` | Caddy 2.11 con TLS en `RL_BIND:8443`. Con la opción A se construye con el módulo de DNS de Cloudflare (`despliegue/caddy-cloudflare/`). |
| `copias` | Una copia verificada del estado cada 6 horas; guarda las 14 últimas en `copias/` (`RL_COPIAS_CADA_S`, `RL_COPIAS_CONSERVAR`). |

Los registros de los tres rotan (5 × 10 MB por contenedor).

Con la opción B, saca la CA para los demás:

```bash
sudo docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt ./responselab-ca.pem
```

**Imagen.** Por defecto se construye en la VM. Para fijar una versión publicada
en vez de construir, pon `RL_IMAGEN=ghcr.io/blueshield-ch4rl13/responselab:1.1.0`
(cada etiqueta `vX.Y.Z` del repositorio publica esa imagen), y usa
`docker compose pull && docker compose up -d --wait`.

## 4. Comprobar

```bash
python3 tools/comprobar_despliegue.py --url https://motor.lab.carlosvillalbalagos.com:8443 --conectividad
# opción B: --url https://10.0.30.20:8443 --ca responselab-ca.pem
```

Sale una línea por comprobación (OK, AVISO o FALLO) y termina con error si algo
falla:

- el certificado es válido para esa URL;
- `/salud` responde y, sin token, no enseña los clientes;
- con el token de administración: catálogo cargado, perfiles sin errores, News
  CTI descargado y si el motor está en simulación;
- sin token no se ven los incidentes y con el del aprobador sí;
- la cadena de auditoría verifica entera;
- la lista EDL responde a su token;
- `--conectividad`: la VM abre conexión con la API de Wazuh (55000) y con
  TheHive (9000).

Repítela después de cada actualización.

## 5. Conectar el laboratorio

Todo lo que hay que copiar está en `despliegue/generado/`, con su `LEEME.md`.

1. **Wazuh manager** (10.0.30.10).

   ```bash
   sudo sh siem/wazuh/instalar-manager.sh
   sudo install -o root -g wazuh -m 640 despliegue/generado/wazuh/responselab.json /var/ossec/etc/
   # solo opción B:
   sudo install -o root -g wazuh -m 640 responselab-ca.pem /var/ossec/etc/
   sudo systemctl restart wazuh-manager
   ```

   Detalle en [SIEM.md](SIEM.md#wazuh).
2. **Agentes.** En la víctima de la DMZ, `siem/wazuh/instalar-agente-linux.sh`; en
   los endpoints Windows, `siem/wazuh/instalar-agente-windows.ps1`.
3. **TheHive** (host SOAR): las plantillas de caso.

   ```bash
   python3 tools/importar_thehive.py --url http://10.0.30.11:9000 --organizacion SOC
   ```

4. **SplunkLab** (10.0.30.12). La app `mi_indice` es una carpeta del host montada
   en el contenedor:

   ```bash
   cp despliegue/generado/splunk/savedsearches-splunklab.conf SplunkLab/splunk/apps/mi_indice/local/savedsearches.conf
   cp despliegue/generado/splunk/alert_actions.conf          SplunkLab/splunk/apps/mi_indice/local/alert_actions.conf
   (cd SplunkLab && docker compose restart splunk)
   ```

   Splunk 9 descarta sin avisar un webhook que no esté en la lista permitida; por
   eso va `alert_actions.conf`. Detalle en [SIEM.md](SIEM.md#splunk).
5. **pfSense.** `despliegue/generado/pfsense/edl.txt`: la lista de IP como alias
   *URL Table (IPs)* con una regla que la bloquee como destino en DMZ y
   Endpoints; la de dominios en pfBlockerNG (DNSBL); la de URL en el proxy web o
   el WAF.

## 6. Cortafuegos (pfSense)

ResponseLab va en la VLAN SOC y respeta su matriz: denegar por defecto y abrir
solo lo necesario.

| Origen | Destino | Puerto | Para qué |
|---|---|---|---|
| Wazuh manager (SOC) | Motor | 8443/tcp | Alertas y acuses (misma VLAN) |
| Splunk 10.0.30.12 | Motor | 8443/tcp | Webhook de las alertas (misma VLAN) |
| Motor | Wazuh manager | 55000/tcp | API de active response |
| Motor | TheHive 10.0.30.11 | 9000/tcp | Casos (misma VLAN) |
| Shuffle | Motor | 8443/tcp | `/decidir` y `/alertas`, si usas el workflow de Shuffle |
| Motor | Internet | 443/tcp | Catálogo y News CTI (`raw.githubusercontent.com`), avisos a Discord; con la opción A, `api.cloudflare.com` y Let's Encrypt |
| pfSense | Motor | 8443/tcp | Listas EDL |
| Gestión (VLAN 99) | Motor | 8443/tcp | Panel de aprobaciones |
| Endpoints y DMZ | Motor | 8443/tcp | Solo si los agentes suben el informe completo de FtriageDFIR. Sin esta regla, el resumen vuelve por Wazuh |
| **Internet** | **Motor** | — | **Nunca.** El motor ejecuta acciones de contención: no se publica |

Un equipo aislado solo habla con el manager y con lo que esté en `permitidos`. En
`lab.yml` eso es el motor, `10.0.30.20`.

## 7. De simulación a producción

El laboratorio arranca en simulación por dos sitios: `RL_SIMULACION_GLOBAL=true` en
`.env` y `modo: simulacion` en `clientes/lab.yml`.

1. **Escenarios contra el motor desplegado.** Los ataques de `escenarios/` del
   cliente `lab`, por HTTPS, como si llegaran de Wazuh y Splunk:

   ```bash
   python3 tools/comprobar_despliegue.py --url ... --escenarios
   ```

   En el panel (`/panel`, con el token de aprobador de `.env`) se ve qué decidió el
   motor y qué habría ejecutado.
2. **El ataque de verdad.** Lanza la cadena de la demo de Infra-SocAnalyst desde la
   Kali: hydra, shell, `/etc/shadow` y cron. Comprueba que llegan las alertas de
   Wazuh, Falco y Tetragon y que la secuencia `intrusion_ssh` se detecta en la
   tercera.
3. **Actuar de verdad.** `modo: produccion` en `lab.yml`,
   `RL_SIMULACION_GLOBAL=false` en `.env` y `docker compose up -d`. Repite el
   ataque: la víctima se aísla sola, el triage de FtriageDFIR vuelve al incidente y
   desde el panel se puede deshacer el aislamiento.

`RL_SIMULACION_GLOBAL=true` y `docker compose up -d` devuelven todo a simulación
en el acto.

## 8. Operación

| Qué | Cómo |
|---|---|
| Copias | Automáticas (contenedor `copias`). Cada copia se hace en caliente, se comprueba con `PRAGMA integrity_check` y verificando la cadena de auditoría con la clave del motor, y solo entonces sustituye a la más antigua. A mano: `make copia`. Saca `copias/` de la VM (y la copia de la VM con vzdump) |
| Restaurar | `make restaurar COPIA=responselab-AAAAMMDDTHHMMSSZ.db`: para el motor, pone la copia en el volumen y arranca. Luego `comprobar_despliegue.py` |
| La clave de la auditoría | Está en `.env` (`RL_CLAVE_AUDITORIA`), fuera del volumen de datos. Guarda `.env` aparte: sin esa clave, una copia restaurada no se puede verificar |
| Actualizar | `git pull && docker compose up -d --build --wait`, o sube `RL_IMAGEN` a la nueva versión. Volver atrás: la versión anterior en `RL_IMAGEN` |
| Catálogo | Se actualiza solo cada 30 minutos desde `RL_ACTUALIZACION_URL`, y solo si pasa la validación. Con `RL_CATALOGO_CLAVE`, además tiene que venir firmado (`tools/firmar_catalogo.py`) |
| Rotar un token | Vacía su variable en `.env`, repite `preparar_servidor.py` (solo genera los vacíos), vuelve a copiar lo de `despliegue/generado/` y `docker compose up -d` |
| Integridad | `comprobar_despliegue.py`, o `curl -H "Authorization: Bearer $RL_ADMIN_TOKEN" https://.../v1/admin/auditoria/verificar` |

## Lista para dar el despliegue por bueno

- [ ] `comprobar_despliegue.py --conectividad` sin ningún FALLO.
- [ ] Una alerta de prueba de Wazuh aparece en el panel (el manager llega al motor).
- [ ] Una búsqueda de SplunkLab con webhook aparece en el panel.
- [ ] pfSense lee la lista de IP (*Diagnostics → Tables*).
- [ ] `--escenarios` abre incidentes y el panel enseña qué habría ejecutado.
- [ ] Hay una copia en `copias/` y `make restaurar` con ella deja la auditoría íntegra.
- [ ] `.env` está guardado fuera de la VM.

## Si quieres enseñar los datos en público

No publiques el motor ni su panel: el panel aprueba acciones de contención. Para
que se vean los datos desde un subdominio, publica una vista de solo lectura generada
a partir de la API. Por ejemplo, un JSON con incidentes, decisiones por familia y
resultados de los escenarios, sin nombres de equipo ni direcciones. Puedes servirla
como estática, igual que los paneles de News CTI y FtriageDFIR.
