"""
Prepara un servidor para el motor: secretos en .env y la configuracion lista para
copiar en Wazuh, Splunk y pfSense.

    python tools/preparar_servidor.py --motor 10.0.30.20
    python tools/preparar_servidor.py --motor 10.0.30.20 --dominio motor.lab.ejemplo.com --tls cloudflare

Que hace:

1. .env. Si no existe, lo crea desde .env.example. Genera los secretos que esten
   vacios (token de administracion, los tokens del cliente que digan su perfil y
   la clave de la auditoria) y NUNCA cambia uno que ya tenga valor: se puede
   ejecutar otra vez sin romper lo que ya usan Wazuh y Splunk. Escribe la red
   del servidor (dominio, TLS, IP en la que escucha, IP de Wazuh y del host SOAR).
   Queda con permisos 0600.
2. despliegue/generado/ (0700, fuera del repositorio por .gitignore):
     wazuh/responselab.json          -> /var/ossec/etc/responselab.json del manager
     splunk/savedsearches-*.conf     -> apps de Splunk, con motor, cliente y token
     splunk/alert_actions.conf       -> lista de webhooks permitidos de Splunk 9
     pfsense/edl.txt                 -> URL de las listas de bloqueo para pfSense
     LEEME.md                        -> donde va cada cosa
3. La carpeta de copias, con el propietario del usuario del contenedor (10001)
   si se ejecuta como root.
4. Avisa si el perfil del cliente apunta a otras IP que las del servidor.

No muestra ningun secreto por pantalla: estan en .env y en despliegue/generado/.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parent.parent
UID_CONTENEDOR = 10001
MODOS_TLS = ("internal", "cloudflare")


def leer_env(ruta: Path) -> list[str]:
    return ruta.read_text(encoding="utf-8").splitlines()


def valor(lineas: list[str], clave: str) -> str | None:
    for linea in lineas:
        m = re.match(rf"^{re.escape(clave)}=(.*)$", linea)
        if m:
            return m.group(1).strip()
    return None


def poner(lineas: list[str], clave: str, nuevo: str) -> None:
    for i, linea in enumerate(lineas):
        if re.match(rf"^{re.escape(clave)}=", linea):
            lineas[i] = f"{clave}={nuevo}"
            return
    lineas.append(f"{clave}={nuevo}")


def tokens_del_perfil(perfil: dict) -> dict[str, str]:
    """Variables de entorno de los tokens que declara el perfil: {funcion: variable}."""
    aut = perfil.get("autenticacion") or {}
    salida = {}
    if aut.get("token_env"):
        salida["ingesta"] = aut["token_env"]
    for funcion in ("agentes", "edl"):
        if (aut.get(funcion) or {}).get("token_env"):
            salida[funcion] = aut[funcion]["token_env"]
    for n, ap in enumerate(perfil.get("aprobadores") or []):
        if ap.get("token_env"):
            salida[f"aprobador_{n + 1}"] = ap["token_env"]
    return salida


def regex_dominio(dominio: str) -> str:
    return re.sub(r"([.\-])", r"\\\1", dominio)


def escribir(ruta: Path, texto: str) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(ruta.parent, 0o700)
    ruta.write_text(texto, encoding="utf-8")
    os.chmod(ruta, 0o600)


def preparar(args: argparse.Namespace, raiz: Path = RAIZ) -> dict:
    env = raiz / args.env
    if not env.exists():
        env.write_text((raiz / ".env.example").read_text(encoding="utf-8"), encoding="utf-8")
    lineas = leer_env(env)

    perfil_ruta = raiz / "clientes" / f"{args.cliente}.yml"
    perfil = yaml.safe_load(perfil_ruta.read_text(encoding="utf-8"))
    tokens = tokens_del_perfil(perfil)
    if "ingesta" not in tokens:
        raise SystemExit(f"{perfil_ruta.name} no toma sus tokens de variables de entorno (token_env): "
                         "este script es para perfiles de laboratorio como lab.yml")

    generados = []
    for variable in ["RL_ADMIN_TOKEN", *tokens.values()]:
        if not valor(lineas, variable):
            poner(lineas, variable, secrets.token_urlsafe(32))
            generados.append(variable)
    if not valor(lineas, "RL_CLAVE_AUDITORIA"):
        poner(lineas, "RL_CLAVE_AUDITORIA", secrets.token_hex(32))
        generados.append("RL_CLAVE_AUDITORIA")

    dominio = args.dominio or args.motor
    puerto = 8443
    poner(lineas, "RL_DOMINIO", dominio)
    poner(lineas, "RL_URL_PUBLICA", f"https://{dominio}:{puerto}")
    poner(lineas, "RL_TLS", args.tls)
    poner(lineas, "RL_BIND", args.bind or args.motor)
    poner(lineas, "RL_IP_WAZUH", args.wazuh)
    poner(lineas, "RL_IP_SOAR", args.soar)
    # docker compose lee COMPOSE_FILE de .env: "docker compose up -d" ya usa los
    # ficheros del servidor sin tener que repetir los -f.
    ficheros = ["docker-compose.yml", "docker-compose.servidor.yml"]
    if args.tls == "cloudflare":
        ficheros.append("docker-compose.cloudflare.yml")
    poner(lineas, "COMPOSE_FILE", ":".join(ficheros))
    avisos = []
    if args.tls == "cloudflare" and not valor(lineas, "CLOUDFLARE_API_TOKEN"):
        avisos.append("--tls cloudflare: pon en .env CLOUDFLARE_API_TOKEN (token de Cloudflare con permiso "
                      "Zone > DNS > Edit solo sobre tu zona) antes de arrancar")
    env.write_text("\n".join(lineas) + "\n", encoding="utf-8")
    os.chmod(env, 0o600)

    def secreto(variable: str) -> str:
        return valor(lineas, variable) or ""

    salida = raiz / args.salida
    salida.mkdir(parents=True, exist_ok=True)
    os.chmod(salida, 0o700)
    motor_url = f"https://{dominio}:{puerto}"
    tls_interna = args.tls == "internal"

    # Wazuh manager
    ejemplo = json.loads((raiz / "siem/wazuh/responselab.json.ejemplo").read_text(encoding="utf-8"))
    ejemplo.pop("_comentario", None)
    ejemplo.pop("clientes_por_agente", None)
    ejemplo.update({
        "motor": motor_url,
        "verificar_tls": True,
        "ca": "/var/ossec/etc/responselab-ca.pem" if tls_interna else "",
        "cliente": args.cliente,
        "clientes": {args.cliente: {"token_ingesta": secreto(tokens["ingesta"]),
                                    "token_agentes": secreto(tokens.get("agentes", tokens["ingesta"]))}},
    })
    escribir(salida / "wazuh" / "responselab.json", json.dumps(ejemplo, indent=2, ensure_ascii=False) + "\n")

    # Splunk
    for nombre in ("savedsearches-detectionlab.conf", "savedsearches-splunklab.conf"):
        texto = (raiz / "siem" / "splunk" / nombre).read_text(encoding="utf-8")
        texto = (texto.replace("https://MOTOR:8443", motor_url)
                      .replace("/v1/CLIENTE/", f"/v1/{args.cliente}/")
                      .replace("TOKEN_DE_INGESTA", secreto(tokens["ingesta"])))
        escribir(salida / "splunk" / nombre, texto)
    permitidos = (raiz / "siem/splunk/alert_actions.conf").read_text(encoding="utf-8")
    escribir(salida / "splunk" / "alert_actions.conf", permitidos.replace("MOTOR", regex_dominio(dominio)))

    # pfSense
    edl = secreto(tokens["edl"]) if "edl" in tokens else ""
    base_edl = f"{motor_url}/v1/{args.cliente}/edl"
    lineas_edl = [
        "# Listas de bloqueo del motor. El token solo sirve para leerlas.",
        "#",
        "# IP -> pfSense: Firewall > Aliases > URLs, tipo URL Table (IPs), refresco 1 dia,",
        "#       y una regla que bloquee el alias como destino en DMZ y Endpoints.",
        f"RESPONSELAB_IP  {base_edl}/ip?token={edl}",
        "#",
        "# Dominios -> pfBlockerNG (DNSBL, feed propio) o cualquier resolver que lea listas.",
        f"RESPONSELAB_DOMINIO  {base_edl}/dominio?token={edl}",
        "#",
        "# URL -> el proxy web o el WAF (pfSense no filtra URL completas con un alias).",
        f"RESPONSELAB_URL  {base_edl}/url?token={edl}",
    ]
    escribir(salida / "pfsense" / "edl.txt", "\n".join(lineas_edl) + "\n")

    leeme = LEEME.format(motor=motor_url, cliente=args.cliente, wazuh=args.wazuh, soar=args.soar,
                         ca_paso=CA_INTERNA if tls_interna else CA_PUBLICA)
    escribir(salida / "LEEME.md", leeme)

    # Copias
    copias = raiz / (valor(lineas, "RL_COPIAS_DIR") or "copias")
    copias.mkdir(parents=True, exist_ok=True)
    aviso_copias = ""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(copias, UID_CONTENEDOR, UID_CONTENEDOR)
    elif hasattr(os, "geteuid"):
        aviso_copias = f"sudo chown {UID_CONTENEDOR}:{UID_CONTENEDOR} {copias}"
    os.chmod(copias, 0o700)

    # Coherencia con el perfil
    wazuh_cfg = (perfil.get("conectores") or {}).get("wazuh") or {}
    if wazuh_cfg:
        if args.wazuh not in (wazuh_cfg.get("managers") or []):
            avisos.append(f"clientes/{args.cliente}.yml: conectores.wazuh.managers es {wazuh_cfg.get('managers')}, "
                          f"pero el manager esta en {args.wazuh}. Un equipo aislado solo hablaria con esas IP.")
        if args.motor not in (wazuh_cfg.get("permitidos") or []):
            avisos.append(f"clientes/{args.cliente}.yml: conectores.wazuh.permitidos es {wazuh_cfg.get('permitidos')}, "
                          f"pero el motor esta en {args.motor}. Un equipo aislado no podria mandar sus acuses.")
    if aviso_copias:
        avisos.append(f"la carpeta de copias tiene que ser del usuario del contenedor: {aviso_copias}")

    return {"env": str(env), "generados": generados, "salida": str(salida), "copias": str(copias),
            "avisos": avisos}


CA_INTERNA = """\
El proxy usa su propia CA (RL_TLS=internal). Tras el primer `docker compose up`,
sacala y copiala a cada cliente del motor:

    docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt ./responselab-ca.pem

- Wazuh manager: /var/ossec/etc/responselab-ca.pem (root:wazuh 640). Ya lo
  espera wazuh/responselab.json.
- Tu navegador (panel): importala como autoridad de confianza.
- Splunk: la accion webhook no tiene opcion para indicar una CA propia; habria
  que tocar el almacen de certificados de Splunk. Para SplunkLab es mas sencillo
  `--tls cloudflare` (certificado de Let's Encrypt validado por DNS).
"""

CA_PUBLICA = """\
El proxy pide un certificado de Let's Encrypt (validacion por DNS en Cloudflare):
los clientes del motor no necesitan ninguna CA propia. wazuh/responselab.json
lleva `ca` vacio, que es la confianza del sistema.
"""

LEEME = """\
# Configuracion generada para el motor {motor}

Generada por tools/preparar_servidor.py. Contiene tokens: no la subas al
repositorio ni la mandes por correo. Copia cada fichero a su sitio y borra esta
carpeta cuando termines (se puede volver a generar: los tokens no cambian).

## 0. Certificado

{ca_paso}
## 1. Wazuh manager ({wazuh})

    sudo sh siem/wazuh/instalar-manager.sh
    sudo install -o root -g wazuh -m 640 wazuh/responselab.json /var/ossec/etc/responselab.json
    sudo systemctl restart wazuh-manager

## 2. Splunk (SplunkLab)

En SplunkLab la app mi_indice es una carpeta del host montada en el contenedor:

    savedsearches-splunklab.conf -> SplunkLab/splunk/apps/mi_indice/local/savedsearches.conf
    alert_actions.conf           -> SplunkLab/splunk/apps/mi_indice/local/alert_actions.conf
    cd SplunkLab && docker compose restart splunk

Si instalas tambien la app de DetectionLab (TA-detection-lab):

    savedsearches-detectionlab.conf -> $SPLUNK_HOME/etc/apps/TA-detection-lab/local/savedsearches.conf

Si ya tenias algo en esos local/, combina a mano: Splunk une local/ con default/
clave a clave.

## 3. TheHive (host SOAR, {soar})

    python tools/importar_thehive.py --url http://{soar}:9000 --organizacion SOC

## 4. pfSense

pfsense/edl.txt: la lista de IP va como alias *URL Table (IPs)* con una regla que
la bloquee como destino en DMZ y Endpoints; la de dominios, en pfBlockerNG
(DNSBL); la de URL, en el proxy web o el WAF.

## 5. Comprobar

    python tools/comprobar_despliegue.py --url {motor} --ca responselab-ca.pem --conectividad

y los escenarios del cliente {cliente} contra el motor desplegado:

    python tools/comprobar_despliegue.py --url {motor} --ca responselab-ca.pem --escenarios
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--motor", required=True, help="IP del motor en la VLAN SOC (p. ej. 10.0.30.20)")
    ap.add_argument("--dominio", help="nombre por el que se llega al motor (por defecto, la IP)")
    ap.add_argument("--tls", default="internal",
                    help="internal (CA propia), cloudflare (Let's Encrypt por DNS) o un correo (Let's Encrypt HTTP)")
    ap.add_argument("--bind", help="IP en la que escucha el proxy (por defecto, la del motor)")
    ap.add_argument("--wazuh", default="10.0.30.10", help="IP del manager de Wazuh")
    ap.add_argument("--soar", default="10.0.30.11", help="IP del host SOAR (TheHive)")
    ap.add_argument("--cliente", default="lab")
    ap.add_argument("--env", default=".env")
    ap.add_argument("--salida", default="despliegue/generado")
    args = ap.parse_args(argv)
    if args.tls not in MODOS_TLS and "@" not in args.tls:
        ap.error("--tls: internal, cloudflare o un correo")
    if args.tls == "cloudflare" and not args.dominio:
        ap.error("--tls cloudflare necesita --dominio: Let's Encrypt no emite certificados para una IP")

    r = preparar(args)
    print(f".env: {r['env']} (0600)")
    print(f"  secretos generados: {', '.join(r['generados']) or 'ninguno (ya estaban)'}")
    print(f"configuracion para Wazuh, Splunk y pfSense: {r['salida']}/ (lee LEEME.md)")
    print(f"copias: {r['copias']}")
    for a in r["avisos"]:
        print(f"AVISO: {a}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
