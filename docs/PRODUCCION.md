# Puesta en producción

## Requisitos

- Una máquina Linux con Docker (o Python 3.10+ y un proxy TLS propio).
- Conectividad del motor hacia las herramientas de cada cliente: EDR, identidad,
  cortafuegos, TheHive…
- Conectividad desde los SIEM y los agentes hacia el motor, por HTTPS.

Para el servidor propio del laboratorio (Proxmox, VLAN y pfSense, junto a
Infra-SocAnalyst), hay una guía paso a paso en [`SERVIDOR.md`](SERVIDOR.md).

## 1. Desplegar el motor

```bash
git clone https://github.com/BlueShield-Ch4rl13/ResponseLab && cd ResponseLab
cp .env.example .env
python -m responselab token        # una vez por token que vayas a necesitar
docker compose up -d --build
curl -k https://localhost:8443/salud
```

`docker-compose.yml` levanta dos servicios:

- **motor**: sin puerto publicado, sistema de ficheros en solo lectura, usuario sin
  privilegios, perfiles de cliente montados desde `./clientes` y estado en el
  volumen `datos`.
- **proxy**: Caddy en el puerto 8443. Con `RL_TLS=internal` usa su propia CA (para
  laboratorio; los clientes tienen que confiar en
  `/data/caddy/pki/authorities/local/root.crt` del volumen `caddy`). Con un correo
  y un dominio público, pide certificados a Let's Encrypt.

Sin Docker:

```bash
python -m pip install -r requirements.txt
RL_DATOS=/var/lib/responselab python -m responselab servir --host 127.0.0.1 --puerto 8080
```

En ese caso, pon delante un proxy TLS que pase `X-Forwarded-For`.

## 2. Dar de alta un cliente

1. Copia `clientes/_plantilla.yml` a `clientes/<id>.yml`.
2. Genera los tokens con `python -m responselab token`. Cada uno da el token, que se
   entrega una vez, y su huella, que va al perfil. Hacen falta:

   | Token | Lo usa | En el perfil |
   |---|---|---|
   | Ingesta | Los SIEM, para enviar alertas | `autenticacion.token_sha256` |
   | Agentes | Los acuses de active response y los informes de triage | `autenticacion.agentes.token_sha256` |
   | EDL | Los cortafuegos, para leer las listas de bloqueo | `autenticacion.edl.token_sha256` |
   | Aprobador | Cada persona que aprueba o deshace (uno por persona) | `aprobadores[].token_sha256` |

3. Declara las capacidades y sus conectores. Las credenciales se ponen como nombres
   de variables de entorno (`api_key_env: RL_<CLIENTE>_...`), y sus valores van en
   `.env`. La validación rechaza un perfil con secretos en claro.
4. Rellena el inventario, las listas y las ventanas. Cuanto más completo, más
   preguntas de triaje contesta la máquina. Lo que no declares es «no se sabe», no
   «no hay».
5. Guarda el fichero. El motor recarga el perfil solo. Si tiene errores, sigue con
   la versión anterior y los muestra en `/salud` (`perfiles_con_error`).

Los perfiles `lab`, `acme` y `norte` son ejemplos completos de tres pilas distintas:

- **lab**: Wazuh y TheHive (Infra-SocAnalyst);
- **acme**: Microsoft, Palo Alto, Cloudflare, Kubernetes y ServiceNow;
- **norte**: Elastic, CrowdStrike y FortiGate, con red OT.

## 3. Conectar los SIEM y los SOAR

[`SIEM.md`](SIEM.md) y [`SOAR.md`](SOAR.md).

## 4. De simulación a producción

Cada cliente empieza en `modo: simulacion`. El motor decide, abre casos, pide
aprobaciones y enseña en el panel las peticiones exactas que haría, pero no ejecuta
ninguna. El camino recomendado:

1. **Una semana en simulación** con tráfico real. Revisa en el panel, o en
   `GET /v1/<cliente>/ejecuciones`, qué habría ejecutado. Cada `simulada` que no
   tendría que haberse hecho se arregla en el perfil (protegidos, listas, ventanas)
   o en la capa ejecutable, nunca quitando la invariante.
2. **Prueba los conectores** con acciones a demanda sobre un equipo de prueba:
   `POST /v1/<cliente>/acciones/endpoint.aislar` con un token de aprobador.
   Comprueba también que se deshacen.
3. **Lanza los escenarios** contra el motor del cliente (purple team):

   ```bash
   python tools/simular.py --enviar https://motor:8443 --cliente <id> --token <ingesta> <escenario>
   ```

4. Cambia a `modo: produccion`. Si algo va mal,
   `RL_SIMULACION_GLOBAL=true` y reiniciar devuelve a todos los clientes a
   simulación.

## 5. Operación

| Qué | Cómo |
|---|---|
| Salud | `GET /salud`: catálogo en uso, CTI, clientes, perfiles con error, cola |
| Métricas | `GET /metricas` (Prometheus, token de administración) |
| Auditoría | `GET /v1/admin/auditoria/verificar` comprueba la cadena entera |
| Catálogo | Se actualiza solo desde `RL_ACTUALIZACION_URL`; `POST /v1/admin/catalogo/actualizar` lo fuerza |
| Copias | El estado entero es `responselab.db` en el volumen de datos. Haz la copia en caliente con `sqlite3 responselab.db ".backup copia.db"` |
| Rotar un token | Genera uno nuevo, cambia la huella en el perfil y guarda: vale al instante, y el anterior deja de valer |
| Dar de baja un cliente | `activo: false` o borrar el perfil: sus tokens dejan de valer al recargar |

## 6. Permisos mínimos por conector

Concede a cada conector solo lo que usan sus acciones. Las dos tablas que más se
consultan:

| Conector | Permisos |
|---|---|
| Defender for Endpoint | `Machine.Read.All`, `Machine.Isolate`, `Machine.StopAndQuarantine`, `Machine.CollectForensics` y `Ti.ReadWrite` (indicadores: hashes, URL y destinos) |
| Entra ID | `User.RevokeSessions.All`, `IdentityRiskyUser.ReadWrite.All`, `DelegatedPermissionGrant.ReadWrite.All` (retirar consentimientos) y `User.EnableDisableAccount.All` (solo si se aprueba deshabilitar cuentas) |
| Exchange Online | `Mail.ReadWrite` (retirar mensajes) y `MailboxSettings.ReadWrite` (reglas de buzón) |
| Wazuh | Un usuario de la API con permiso de `active-response:command` sobre los agentes del cliente |
| CrowdStrike | Cliente de API con `Hosts: Read/Write` e `IOC Management: Read/Write` |
| Palo Alto / FortiGate | Un administrador de API limitado a los objetos y grupos de ResponseLab |

Para Sentinel, `soar/sentinel/conceder-permisos.ps1` concede exactamente lo que usa
cada playbook.
