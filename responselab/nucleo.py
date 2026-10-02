"""
Nucleo de decision de ResponseLab.

Recibe una alerta de cualquier SIEM y devuelve un PLAN: que familia es, que
clase de automatizacion le toca, que preguntas de triaje se pueden contestar
solas, si se puede cerrar, que acciones de contencion se ejecutan sin persona,
cuales esperan aprobacion y a quien se escala.

No ejecuta nada. Ejecutar es cosa del motor (responselab.ejecutor) o del SOAR
que incruste este modulo.

Por que es Python puro y vive en un solo fichero
------------------------------------------------
Porque se copia literalmente dentro del nodo de Shuffle, del playbook de
Splunk SOAR y del script de Cortex XSOAR. Si cada SOAR llevara su propia
traduccion de la logica, en seis meses habria seis politicas distintas y nadie
sabria cual se aplico a un incidente concreto. Aqui hay una: la misma funcion
decide en el motor y en cualquier SOAR, y los tests la prueban una vez.

Restricciones que eso impone: solo biblioteca estandar, compatible con Python
3.8, sin estado global mutable y sin E/S. Todo lo que no se puede saber desde
la alerta (historico, inteligencia, DNS, plazos) llega en ``contexto``; si no
llega, los evaluadores que lo necesitan contestan "no lo se" (None) y la
pregunta queda para el analista. Nunca se inventa un si o un no.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import unicodedata
from datetime import datetime, timedelta, timezone

VERSION = "1.0.0"

NIVELES = ["informational", "low", "medium", "high", "critical"]
CLASES = ["auto_cierre", "auto_enriq", "auto_analisis", "auto_contener"]

# Mismo mapeo que DetectionLab. Cuanto mas grave la deteccion, mas cara una
# accion automatica equivocada: lo critico contiene SOLO lo reversible y de
# radio pequeno, y ademas despierta a una persona.
CLASE_POR_NIVEL = {
    "informational": "auto_cierre",
    "low": "auto_enriq",
    "medium": "auto_analisis",
    "high": "auto_analisis",
    "critical": "auto_contener",
}
SEVERIDAD_POR_NIVEL = {"informational": 1, "low": 1, "medium": 2, "high": 3, "critical": 4}

ORDEN_RADIO = ["proceso", "objeto", "sesion", "equipo", "cuenta", "organizacion"]
# Lo que afecta a gente que no es el atacante no lo decide una maquina.
RADIOS_AMPLIOS = ("cuenta", "organizacion")
ORDEN_ESCALADO = ["L1", "L2", "L3", "guardia"]
# Acciones cuyo objetivo es un fichero: nunca automaticas sobre rutas del
# sistema, venga lo que venga de configuracion.
ACCIONES_SOBRE_FICHERO = ("fichero.cuarentena", "flota.bloquear_hash")

# Sufijos de PTR de proveedores de CDN y nube publica reconocidos
SUFIJOS_CDN = (
    "cloudfront.net", "amazonaws.com", "akamaitechnologies.com", "akamai.net",
    "akamaiedge.net", "edgekey.net", "fastly.net", "cloudflare.com", "cloudflare.net",
    "googleusercontent.com", "1e100.net", "google.com", "azureedge.net",
    "cloudapp.azure.com", "cloudapp.net", "msedge.net", "microsoft.com",
    "edgecastcdn.net", "llnw.net", "cdn77.com", "stackpathdns.com", "bunnycdn.com",
)


# ════════════════════════════════════════════════════════════════════════════
# Utilidades
# ════════════════════════════════════════════════════════════════════════════

def norm(texto) -> str:
    """Minusculas, sin tildes ni puntuacion. Clave estable de un texto."""
    texto = unicodedata.normalize("NFKD", str(texto or "")).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", " ", texto.lower()).strip()


def leer(datos, ruta):
    """Lee 'a.b.c' de dicts anidados. Cadenas vacias cuentan como ausentes.

    Primero intenta la ruta completa como clave literal en cada nivel, porque
    Falco y otros sensores usan claves con puntos ('proc.name').
    """
    if datos is None or not ruta:
        return None
    actual = datos
    partes = ruta.split(".")
    i = 0
    while i < len(partes):
        if not isinstance(actual, dict):
            return None
        encontrado = False
        for j in range(len(partes), i, -1):
            clave = ".".join(partes[i:j])
            if clave in actual:
                actual = actual[clave]
                i = j
                encontrado = True
                break
        if not encontrado:
            return None
    if actual is None or (isinstance(actual, str) and not actual.strip()):
        return None
    if isinstance(actual, (list, dict)) and not actual:
        return None
    return actual


def poner(datos: dict, ruta: str, valor) -> None:
    if valor is None or (isinstance(valor, str) and not valor.strip()):
        return
    partes = ruta.split(".")
    actual = datos
    for p in partes[:-1]:
        actual = actual.setdefault(p, {})
    if isinstance(valor, str):
        valor = valor.strip()
    actual[partes[-1]] = valor


def primero(*valores):
    for v in valores:
        if v is None:
            continue
        if isinstance(v, str) and not v.strip():
            continue
        if isinstance(v, (list, dict)) and not v:
            continue
        return v
    return None


def a_fecha(valor):
    """ISO 8601, epoch en segundos o en milisegundos -> datetime UTC."""
    if valor is None or valor == "":
        return None
    if isinstance(valor, datetime):
        return valor if valor.tzinfo else valor.replace(tzinfo=timezone.utc)
    if isinstance(valor, (int, float)) or (isinstance(valor, str) and re.fullmatch(r"\d{9,13}(\.\d+)?", valor)):
        n = float(valor)
        if n > 1e11:
            n /= 1000.0
        return datetime.fromtimestamp(n, tz=timezone.utc)
    texto = str(valor).strip().replace(" UTC", "").replace("Z", "+00:00")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2}(\.\d+)?)?", texto):
        texto = texto.replace(" ", "T")
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?)(\.\d+)?([+-]\d{2}:?\d{2})?$", texto)
    if m:
        base, zona = m.group(1), m.group(3) or "+00:00"
        # Fraccion siempre de 6 cifras: Python 3.10 solo acepta 3 o 6
        frac = ("." + m.group(2)[1:7].ljust(6, "0")) if m.group(2) else ""
        if len(base) == 16:
            base += ":00"
        if len(zona) == 5:
            zona = zona[:3] + ":" + zona[3:]
        try:
            return datetime.fromisoformat(base + frac + zona).astimezone(timezone.utc)
        except ValueError:
            return None
    try:
        dt = datetime.fromisoformat(texto)
    except ValueError:
        return None
    # Sin zona es UTC, no la hora local de la maquina que ejecuta el nucleo
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def iso(dt) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else ""


def stem(clave) -> str:
    return str(clave or "").split(":", 1)[-1]


def nombre_base(ruta) -> str:
    if not ruta:
        return ""
    return re.split(r"[\\/]", str(ruta))[-1]


RE_RUTA_SISTEMA = re.compile(
    r"^(?:[a-z]:\\windows\\|\\\\\?\\[a-z]:\\windows\\|%systemroot%|%windir%"
    r"|/(?:usr/)?s?bin/|/usr/lib(?:64|32|exec)?/|/lib(?:64|32)?/|/system/|/usr/local/s?bin/)",
    re.I)


def ruta_sistema(ruta) -> bool:
    """Binario o libreria del sistema operativo."""
    return bool(ruta) and bool(RE_RUTA_SISTEMA.match(str(ruta).strip().strip('"')))


# Ficheros de configuracion sin los que el sistema no arranca o nadie entra:
# moverlos (cuarentena) deja el equipo inservible aunque el atacante los toque.
RE_FICHERO_CRITICO = re.compile(r"^/etc/(?:passwd|shadow|group|gshadow|sudoers|fstab|hosts)$")
# Almacenes de credenciales: copiarlos al almacen de evidencia multiplica el
# secreto; que se hayan leido ya consta en la alerta.
RE_ALMACEN_CREDENCIALES = re.compile(
    r"^(?:/etc/(?:g?shadow|security/opasswd)"
    r"|[a-z]:\\windows\\system32\\config\\(?:sam|security|system)"
    r"|[a-z]:\\windows\\ntds\\ntds\.dit)$", re.I)


def fichero_critico(ruta) -> bool:
    return bool(ruta) and bool(RE_FICHERO_CRITICO.match(str(ruta).strip().strip('"')))


def almacen_credenciales(ruta) -> bool:
    return bool(ruta) and bool(RE_ALMACEN_CREDENCIALES.match(str(ruta).strip().strip('"')))


def es_ip(valor) -> bool:
    try:
        ipaddress.ip_address(str(valor))
        return True
    except ValueError:
        return False


def ip_privada(valor) -> bool:
    try:
        ip = ipaddress.ip_address(str(valor))
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
    except ValueError:
        return False


# ════════════════════════════════════════════════════════════════════════════
# Normalizacion: la alerta de cada SIEM a un mismo esquema
# ════════════════════════════════════════════════════════════════════════════
#
# Esquema (todo opcional salvo id, siem y titulo):
#   regla_id, regla_nombre, regla_fichero, familia_pista, clase_pista,
#   severidad_pista (1-4), tecnicas[], titulo, descripcion, momento, cve[],
#   cti_tipo, equipo{nombre ip id_agente id_edr so}, usuario{nombre dominio
#   upn sid id_nube}, proceso{guid pid inicio imagen imagen_nombre linea
#   padre_imagen padre_nombre padre_linea sha256 sha1 md5 team_id},
#   fichero{ruta nombre sha256 sha1 md5}, persistencia{tipo nombre ruta},
#   red{ip_origen ip_destino puerto_destino dominio url}, http{metodo uri
#   estado user_agent}, correo{message_id remitente dominio_remitente buzon
#   asunto regla_buzon reenvio_a}, nube{app_id app_nombre consentimiento_id sp_id},
#   k8s{namespace pod nodo sujeto rolebinding imagen workload},
#   dispositivo{serie}, objeto_ad, clave_ssh, sesion{id}, observables[]

RE_RUTA_ABSOLUTA = re.compile(r'^"?(?:[a-zA-Z]:[\\/]|\\\\|/)')
RE_GUID = re.compile(r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$")
RE_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
RE_SHA1 = re.compile(r"^[0-9a-fA-F]{40}$")
RE_MD5 = re.compile(r"^[0-9a-fA-F]{32}$")
RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def parsear_hashes(texto) -> dict:
    """'SHA1=..,MD5=..,SHA256=..' de Sysmon, o un hash suelto."""
    salida = {}
    if not texto:
        return salida
    if isinstance(texto, dict):
        for k, v in texto.items():
            k2 = norm(k).replace(" ", "")
            if k2 in ("sha256", "sha1", "md5"):
                salida[k2] = str(v).lower()
        return salida
    for parte in re.split(r"[,;\s]+", str(texto)):
        if "=" in parte:
            k, v = parte.split("=", 1)
            k = k.strip().lower()
            if k in ("sha256", "sha1", "md5"):
                salida[k] = v.strip().lower()
        else:
            v = parte.strip()
            if RE_SHA256.match(v):
                salida["sha256"] = v.lower()
            elif RE_SHA1.match(v):
                salida["sha1"] = v.lower()
            elif RE_MD5.match(v):
                salida["md5"] = v.lower()
    return salida


def partir_usuario(valor):
    """'DOMINIO\\usuario' o 'usuario@dominio' -> (usuario, dominio, upn)."""
    if not valor:
        return None, None, None
    v = str(valor).strip()
    if "\\" in v:
        dom, usr = v.split("\\", 1)
        return usr, dom, None
    if "@" in v:
        return v.split("@", 1)[0], v.split("@", 1)[1], v
    return v, None, None


def alerta_vacia(siem: str, cliente: str = "") -> dict:
    return {
        "id": "", "siem": siem, "cliente": cliente, "titulo": "", "descripcion": "",
        "momento": "", "regla_id": "", "regla_nombre": "", "regla_fichero": "",
        "familia_pista": "", "clase_pista": "", "severidad_pista": 0,
        "tecnicas": [], "cve": [], "cti_tipo": "",
        "equipo": {}, "usuario": {}, "proceso": {}, "fichero": {}, "persistencia": {},
        "red": {}, "http": {}, "correo": {}, "nube": {}, "k8s": {}, "dispositivo": {},
        "sesion": {}, "objeto_ad": "", "clave_ssh": "", "observables": [], "bruto": {},
    }


def _completar(a: dict) -> dict:
    """Campos derivados y lista de observables, comunes a todos los SIEM."""
    p = a["proceso"]
    if p.get("imagen") and not p.get("imagen_nombre"):
        p["imagen_nombre"] = nombre_base(p["imagen"]).lower()
    if p.get("padre_imagen") and not p.get("padre_nombre"):
        p["padre_nombre"] = nombre_base(p["padre_imagen"]).lower()
    if p.get("guid") and RE_GUID.match(str(p["guid"])):
        # Solo los GUID de Windows se normalizan; el exec_id de Tetragon es
        # base64 y cambiarle las mayusculas lo convierte en otro.
        p["guid"] = str(p["guid"]).strip("{}").lower()
    if p.get("pid") is not None:
        try:
            p["pid"] = int(str(p["pid"]).strip())
        except ValueError:
            p.pop("pid", None)
    f = a["fichero"]
    # El binario del proceso es el fichero sobre el que actuar SOLO si no es del
    # sistema. Con "vssadmin delete shadows" el proceso es vssadmin.exe de
    # System32: ponerlo en cuarentena o bloquear su hash en la flota romperia
    # el equipo y no tocaria al atacante, que es quien lo lanzo.
    if not f.get("ruta") and p.get("imagen") and RE_RUTA_ABSOLUTA.match(str(p["imagen"])) \
            and not ruta_sistema(p["imagen"]):
        f["ruta"] = p["imagen"]
        for h in ("sha256", "sha1", "md5"):
            if p.get(h) and not f.get(h):
                f[h] = p[h]
    if f.get("ruta") and not f.get("nombre"):
        f["nombre"] = nombre_base(f["ruta"])
    u = a["usuario"]
    if u.get("nombre") and ("\\" in u["nombre"] or "@" in u["nombre"]):
        usr, dom, upn = partir_usuario(u["nombre"])
        u["nombre"] = usr
        if dom and not u.get("dominio"):
            u["dominio"] = dom
        if upn and not u.get("upn"):
            u["upn"] = upn
    c = a["correo"]
    if c.get("remitente") and "@" in c["remitente"] and not c.get("dominio_remitente"):
        c["dominio_remitente"] = c["remitente"].split("@", 1)[1].lower()
    r = a["red"]
    if r.get("url") and not r.get("dominio"):
        m = re.match(r"^[a-z][a-z0-9+.-]*://([^/:?#]+)", str(r["url"]), re.I)
        if m and not es_ip(m.group(1)):
            r["dominio"] = m.group(1).lower()
    texto = " ".join(str(x) for x in (a.get("titulo"), a.get("descripcion")))
    a["cve"] = sorted(set(a.get("cve") or []) | {x.upper() for x in RE_CVE.findall(texto)})
    a["tecnicas"] = sorted({str(t).upper() for t in a.get("tecnicas") or [] if t})

    obs = []

    def anadir(tipo, valor):
        if valor and {"tipo": tipo, "valor": str(valor)} not in obs:
            obs.append({"tipo": tipo, "valor": str(valor)})

    for ip in (r.get("ip_destino"), r.get("ip_origen")):
        if ip and es_ip(ip) and not ip_privada(ip):
            anadir("ip", ip)
    anadir("dominio", r.get("dominio"))
    anadir("url", r.get("url"))
    for h in ("sha256", "sha1", "md5"):
        anadir("hash", f.get(h))
        if p.get(h) != f.get(h):
            anadir("hash", p.get(h))
    anadir("correo", c.get("remitente"))
    a["observables"] = obs
    if not a.get("id"):
        huella = json.dumps(a.get("bruto", {}), sort_keys=True, default=str).encode("utf-8")
        a["id"] = "rl-" + hashlib.sha1(huella).hexdigest()[:20]
    return a


def _parametros_o365(valor) -> dict:
    """Parameters de la auditoria de Exchange Online en cualquiera de sus formas.

    El registro original es una lista [{Name, Value}]; Elastic la aplana en un
    objeto y Splunk la parte en dos multivalor (Parameters{}.Name/.Value).
    """
    if isinstance(valor, str):
        try:
            valor = json.loads(valor)
        except ValueError:
            return {}
    if isinstance(valor, dict):
        return {str(k): v for k, v in valor.items()}
    if isinstance(valor, list):
        return {str(x.get("Name")): x.get("Value") for x in valor if isinstance(x, dict) and x.get("Name")}
    return {}


def _auditoria_exchange(a: dict, operacion, parametros, objeto=None, actor=None) -> None:
    """Regla de buzon y destino de reenvio de un registro New/Set-InboxRule o Set-Mailbox.

    El registro trae el NOMBRE de la regla (o "buzon\\nombre" en ObjectId); el
    conector de Exchange la busca por ese nombre y solo actua si casa una.
    """
    if not operacion or not re.search(r"InboxRule|Set-Mailbox|TransportRule", str(operacion), re.I):
        return
    p = _parametros_o365(parametros)
    destino = primero(*(p.get(k) for k in ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo",
                                          "ForwardingSmtpAddress", "ForwardingAddress")))
    if destino:
        poner(a, "correo.reenvio_a", re.sub(r"^smtp:", "", str(destino), flags=re.I))
    objeto = str(objeto or "")
    if re.search(r"InboxRule", str(operacion), re.I):
        nombre = p.get("Name") or (str(p.get("Identity") or "").rsplit("\\", 1)[-1] or None) \
            or (objeto.rsplit("\\", 1)[1] if "\\" in objeto else None)
        poner(a, "correo.regla_buzon", nombre)
    buzon = p.get("Mailbox") or (objeto.split("\\", 1)[0] if "\\" in objeto else None)
    if not (buzon and "@" in str(buzon)):
        buzon = actor if actor and "@" in str(actor) else None
    poner(a, "correo.buzon", buzon)


def _wazuh(carga: dict, a: dict) -> dict:
    # Compatibilidad: la carga reducida que mandaba custom-detectionlab.py
    if carga.get("origen") == "detection-lab" and "rule" not in carga:
        a["id"] = str(carga.get("wazuh_id") or "")
        a["regla_id"] = str(carga.get("regla_id") or "")
        a["regla_fichero"] = carga.get("regla_sigma") or ""
        a["familia_pista"] = carga.get("playbook") or ""
        a["clase_pista"] = carga.get("clase_automatizacion") or ""
        a["severidad_pista"] = int(carga.get("severidad") or 0)
        a["titulo"] = carga.get("descripcion") or ""
        a["tecnicas"] = carga.get("mitre") or []
        a["momento"] = carga.get("marca_tiempo") or ""
        poner(a, "equipo.nombre", carga.get("agente"))
        poner(a, "equipo.ip", carga.get("agente_ip"))
        o = carga.get("observables") or {}
        poner(a, "red.ip_origen", o.get("ip"))
        poner(a, "red.dominio", o.get("dominio"))
        poner(a, "red.url", o.get("url"))
        a["proceso"].update({k: v for k, v in parsear_hashes(o.get("hash")).items()})
        poner(a, "usuario.nombre", o.get("usuario"))
        return a

    regla = carga.get("rule") or {}
    datos = carga.get("data") or {}
    ev = leer(datos, "win.eventdata") or {}
    a["id"] = str(carga.get("id") or "")
    a["momento"] = carga.get("timestamp") or ""
    a["regla_id"] = str(regla.get("id") or "")
    a["titulo"] = regla.get("description") or ""
    a["descripcion"] = (carga.get("full_log") or "")[:4000]
    a["tecnicas"] = (regla.get("mitre") or {}).get("id") or []
    grupos = regla.get("groups") or []
    a["clase_pista"] = next((g for g in grupos if str(g).startswith("auto_")), "")
    info = str(regla.get("info") or "")
    m = re.search(r"playbook=([\w-]+)", info)
    if m:
        a["familia_pista"] = m.group(1)
    else:
        fam = next((g[4:] for g in grupos if str(g).startswith("soc_") and g[4:] in (
            "ad", "cloud", "contenedores", "correo", "credenciales", "endpoint", "exfiltracion",
            "linux", "macos", "red", "web", "xdr", "zta")), "")
        a["familia_pista"] = fam
    m = re.search(r"severidad_thehive=(\d)", info)
    nivel = int(regla.get("level") or 0)
    a["severidad_pista"] = int(m.group(1)) if m else (4 if nivel >= 14 else 3 if nivel >= 12 else 2 if nivel >= 8 else 1)
    m = re.search(r"origen=([\w.-]+\.yml)", info)
    if m:
        a["regla_fichero"] = m.group(1)
    for g in grupos:
        if g in ("cti_hash", "cti_ip", "cti_dominio", "cti_url"):
            a["cti_tipo"] = g[4:]

    ag = carga.get("agent") or {}
    poner(a, "equipo.nombre", ag.get("name"))
    poner(a, "equipo.ip", ag.get("ip"))
    poner(a, "equipo.id_agente", ag.get("id"))
    poner(a, "equipo.so", leer(carga, "agent.os.platform") or leer(datos, "win.system.computer") and "windows")

    # Windows / Sysmon / canal Security
    poner(a, "proceso.guid", primero(ev.get("processGuid"), ev.get("sourceProcessGuid")))
    poner(a, "proceso.pid", primero(ev.get("processId"), ev.get("sourceProcessId"), ev.get("newProcessId")))
    poner(a, "proceso.imagen", primero(ev.get("image"), ev.get("sourceImage"), ev.get("newProcessName"), ev.get("processName")))
    poner(a, "proceso.linea", ev.get("commandLine"))
    poner(a, "proceso.padre_imagen", primero(ev.get("parentImage"), ev.get("parentProcessName")))
    poner(a, "proceso.padre_linea", ev.get("parentCommandLine"))
    if leer(datos, "win.system.eventID") == "1" or ev.get("commandLine"):
        poner(a, "proceso.inicio", ev.get("utcTime"))
    a["proceso"].update(parsear_hashes(ev.get("hashes")))
    poner(a, "proceso.firmante", ev.get("signature"))
    poner(a, "fichero.ruta", primero(ev.get("targetFilename"), ev.get("imageLoaded"), leer(carga, "syscheck.path")))
    if ev.get("imageLoaded") or ev.get("targetFilename"):
        h = parsear_hashes(ev.get("hashes"))
        if h:
            a["fichero"].update(h)
    poner(a, "fichero.sha256", leer(carga, "syscheck.sha256_after"))
    poner(a, "fichero.sha1", leer(carga, "syscheck.sha1_after"))
    poner(a, "fichero.md5", leer(carga, "syscheck.md5_after"))
    usuario = primero(ev.get("targetUserName") if leer(datos, "win.system.eventID") in ("4720", "4726", "4738", "4724", "4723", "4768", "4769") else None,
                      ev.get("user"), ev.get("subjectUserName"), ev.get("targetUserName"),
                      datos.get("srcuser"), datos.get("dstuser"), leer(datos, "audit.auid"))
    poner(a, "usuario.nombre", usuario)
    poner(a, "usuario.dominio", primero(ev.get("targetDomainName"), ev.get("subjectDomainName")))
    poner(a, "objeto_ad", primero(ev.get("objectDN"), ev.get("objectName") if "CN=" in str(ev.get("objectName") or "") else None,
                                  ev.get("serviceName") if leer(datos, "win.system.eventID") in ("4769",) else None))
    poner(a, "persistencia.nombre", primero(ev.get("taskName"), ev.get("serviceName") if leer(datos, "win.system.eventID") in ("7045", "4697") else None))
    if ev.get("targetObject") and re.search(r"\\(Run|RunOnce)\\", str(ev.get("targetObject")), re.I):
        poner(a, "persistencia.tipo", "run")
        poner(a, "persistencia.ruta", ev.get("targetObject"))
    elif ev.get("taskName"):
        poner(a, "persistencia.tipo", "tarea")
    poner(a, "red.ip_destino", primero(ev.get("destinationIp"), datos.get("dstip")))
    poner(a, "red.ip_origen", primero(ev.get("sourceIp") if ev.get("destinationIp") else None, datos.get("srcip"), ev.get("ipAddress")))
    poner(a, "red.puerto_destino", primero(ev.get("destinationPort"), datos.get("dstport")))
    poner(a, "red.dominio", primero(ev.get("queryName"), ev.get("destinationHostname"), leer(datos, "dns.rrname"), datos.get("hostname")))
    poner(a, "red.url", primero(datos.get("url") if str(datos.get("url") or "").startswith("http") else None, leer(datos, "http.url")))
    poner(a, "http.uri", primero(datos.get("url") if not str(datos.get("url") or "").startswith("http") else None, leer(datos, "http.url")))
    poner(a, "http.metodo", primero(datos.get("protocol") if str(datos.get("protocol") or "").isalpha() else None, leer(datos, "http.http_method")))
    estado = primero(leer(datos, "http.status"), datos.get("id") if re.fullmatch(r"[1-5]\d\d", str(datos.get("id") or "")) else None)
    poner(a, "http.estado", str(estado) if estado else None)

    # Falco (output_fields con claves con punto) y Tetragon
    of = datos.get("output_fields") or {}
    if of:
        poner(a, "proceso.pid", of.get("proc.pid"))
        poner(a, "proceso.imagen", primero(of.get("proc.exepath"), of.get("proc.exe"), of.get("proc.name")))
        poner(a, "proceso.linea", of.get("proc.cmdline"))
        poner(a, "proceso.padre_imagen", primero(of.get("proc.pexepath"), of.get("proc.pname")))
        poner(a, "usuario.nombre", of.get("user.name"))
        poner(a, "fichero.ruta", of.get("fd.name") if str(of.get("fd.name") or "").startswith("/") else None)
        poner(a, "k8s.namespace", of.get("k8s.ns.name"))
        poner(a, "k8s.pod", of.get("k8s.pod.name"))
        poner(a, "k8s.imagen", of.get("container.image.repository"))
        if of.get("evt.time") and of.get("proc.pid") and of.get("proc.start_ts"):
            poner(a, "proceso.inicio", of.get("proc.start_ts"))
    for clave in ("process_exec", "process_kprobe"):
        pr = leer(datos, clave + ".process")
        if isinstance(pr, dict):
            poner(a, "proceso.pid", pr.get("pid"))
            poner(a, "proceso.inicio", pr.get("start_time"))
            poner(a, "proceso.imagen", pr.get("binary"))
            poner(a, "proceso.linea", " ".join(x for x in (pr.get("binary"), pr.get("arguments")) if x))
            poner(a, "proceso.guid", pr.get("exec_id"))
            pa = leer(datos, clave + ".parent") or {}
            poner(a, "proceso.padre_imagen", pa.get("binary"))
            args = leer(datos, clave + ".args")
            if isinstance(args, list):
                for x in args:
                    ruta = leer(x, "file_arg.path") if isinstance(x, dict) else None
                    poner(a, "fichero.ruta", ruta)
    # auditd
    poner(a, "proceso.pid", leer(datos, "audit.pid"))
    poner(a, "proceso.imagen", leer(datos, "audit.exe"))
    poner(a, "proceso.linea", leer(datos, "audit.execve.a0") and " ".join(
        str(leer(datos, "audit.execve." + k)) for k in ("a0", "a1", "a2", "a3") if leer(datos, "audit.execve." + k)))
    # Microsoft 365 (modulo office365 de Wazuh)
    o365 = datos.get("office365") or {}
    if o365:
        poner(a, "usuario.nombre", o365.get("UserId"))
        poner(a, "red.ip_origen", o365.get("ClientIP"))
        _auditoria_exchange(a, o365.get("Operation"), o365.get("Parameters"), o365.get("ObjectId"), o365.get("UserId"))
    # Kubernetes (auditoria del API server)
    poner(a, "k8s.namespace", primero(leer(datos, "k8s.objectRef.namespace"), leer(datos, "objectRef.namespace")))
    poner(a, "k8s.pod", primero(leer(datos, "objectRef.name") if leer(datos, "objectRef.resource") == "pods" else None))
    poner(a, "k8s.sujeto", primero(leer(datos, "user.username"), leer(datos, "k8s.user.username")))
    if leer(datos, "objectRef.resource") in ("rolebindings", "clusterrolebindings"):
        poner(a, "k8s.rolebinding", "/".join(x for x in (leer(datos, "objectRef.resource"), leer(datos, "objectRef.namespace"), leer(datos, "objectRef.name")) if x))
    a["bruto"] = carga
    return a


def _campo_splunk(r: dict, *nombres):
    for n in nombres:
        v = r.get(n)
        if isinstance(v, list):
            v = v[0] if v else None
        if v not in (None, "", "-", "unknown"):
            return v
    return None


def _splunk(carga: dict, a: dict) -> dict:
    """Webhook de alerta de Splunk: {search_name, sid, result{...}, results_link}.

    Tambien acepta un notable de Splunk ES tal como lo trae un SOAR (XSOAR,
    Splunk SOAR): un diccionario plano con search_name y los campos del evento.
    """
    plano = "result" not in carga and ("search_name" in carga or "rule_name" in carga or "event_id" in carga)
    r = carga if plano else (carga.get("result") or {})
    if plano:
        a["id"] = str(carga.get("event_id") or carga.get("notable_id") or "")
    else:
        partes = [str(x) for x in (carga.get("sid"), _campo_splunk(r, "_cd", "_serial")) if x not in (None, "")]
        a["id"] = ":".join(partes)       # vacio: _completar le da uno derivado del contenido
    a["regla_nombre"] = carga.get("search_name") or carga.get("rule_name") or ""
    a["titulo"] = carga.get("rule_title") or carga.get("search_name") or carga.get("rule_name") or ""
    a["descripcion"] = str(_campo_splunk(r, "_raw") or "")[:4000]
    a["momento"] = _campo_splunk(r, "_time", "time") or ""
    sev = _campo_splunk(r, "severity", "urgency")
    a["severidad_pista"] = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 1}.get(str(sev).lower(), 0)
    poner(a, "equipo.nombre", _campo_splunk(r, "dest", "host", "Computer", "dvc", "ComputerName"))
    poner(a, "equipo.ip", _campo_splunk(r, "dest_ip") if not _campo_splunk(r, "DestinationIp") else None)
    poner(a, "usuario.nombre", _campo_splunk(r, "user", "User", "TargetUserName", "SubjectUserName", "src_user", "UserPrincipalName"))
    poner(a, "usuario.upn", _campo_splunk(r, "UserPrincipalName", "userPrincipalName"))
    poner(a, "proceso.guid", _campo_splunk(r, "ProcessGuid", "process_guid"))
    poner(a, "proceso.pid", _campo_splunk(r, "ProcessId", "process_id", "pid"))
    poner(a, "proceso.inicio", _campo_splunk(r, "UtcTime"))
    poner(a, "proceso.imagen", _campo_splunk(r, "Image", "process_path", "NewProcessName"))
    poner(a, "proceso.linea", _campo_splunk(r, "CommandLine", "process", "cmdline"))
    poner(a, "proceso.padre_imagen", _campo_splunk(r, "ParentImage", "parent_process_path", "parent_process"))
    a["proceso"].update(parsear_hashes(_campo_splunk(r, "Hashes", "hashes", "file_hash")))
    poner(a, "fichero.ruta", _campo_splunk(r, "TargetFilename", "file_path"))
    poner(a, "red.ip_origen", _campo_splunk(r, "src_ip", "src", "SourceIp", "ip", "IPAddress", "clientip"))
    poner(a, "red.ip_destino", _campo_splunk(r, "dest_ip", "DestinationIp"))
    poner(a, "red.puerto_destino", _campo_splunk(r, "dest_port", "DestinationPort"))
    poner(a, "red.dominio", _campo_splunk(r, "query", "QueryName", "dest_host", "domain"))
    poner(a, "red.url", _campo_splunk(r, "url"))
    poner(a, "http.uri", _campo_splunk(r, "uri_path", "uri", "cs_uri_stem"))
    poner(a, "http.estado", _campo_splunk(r, "status", "sc_status"))
    poner(a, "http.user_agent", _campo_splunk(r, "http_user_agent", "useragent"))
    poner(a, "correo.message_id", _campo_splunk(r, "message_id", "internet_message_id"))
    poner(a, "correo.remitente", _campo_splunk(r, "src_user", "sender"))
    poner(a, "correo.buzon", _campo_splunk(r, "recipient", "MailboxOwnerUPN"))
    poner(a, "k8s.namespace", _campo_splunk(r, "namespace", "objectRef.namespace"))
    poner(a, "k8s.pod", _campo_splunk(r, "pod", "pod_name"))
    nombres, valores = r.get("Parameters{}.Name"), r.get("Parameters{}.Value")
    if isinstance(nombres, list) and isinstance(valores, list):
        parametros = [{"Name": n, "Value": v} for n, v in zip(nombres, valores)]
    elif nombres is not None and valores is not None:
        parametros = [{"Name": nombres, "Value": valores}]
    else:
        parametros = r.get("Parameters")
    _auditoria_exchange(a, _campo_splunk(r, "Operation", "operation"), parametros, _campo_splunk(r, "ObjectId"),
                        _campo_splunk(r, "UserId", "user"))
    tec = _campo_splunk(r, "tecnica", "technique", "mitre_technique_id")
    if tec:
        a["tecnicas"] = re.findall(r"T\d{4}(?:\.\d{3})?", str(tec))
    a["bruto"] = carga
    return a


def _sentinel(carga: dict, a: dict) -> dict:
    """Incidente de Sentinel (cuerpo del disparador de Logic Apps o de la API)."""
    obj = carga.get("object") or carga
    props = obj.get("properties") or {}
    a["id"] = str(obj.get("name") or obj.get("id") or props.get("incidentNumber") or "")
    a["titulo"] = props.get("title") or ""
    # El nombre de la regla de analitica viaja en las alertas del incidente. El
    # titulo del incidente puede cambiar (el portal de Defender lo reescribe al
    # correlar), el nombre de la alerta no.
    nombres = [leer(x, "properties.alertDisplayName") for x in props.get("alerts") or props.get("Alerts") or []
               if isinstance(x, dict)]
    a["regla_nombre"] = primero(*nombres, props.get("title")) or ""
    a["descripcion"] = (props.get("description") or "")[:4000]
    a["momento"] = props.get("firstActivityTimeUtc") or props.get("createdTimeUtc") or ""
    a["severidad_pista"] = {"high": 3, "medium": 2, "low": 1, "informational": 1}.get(str(props.get("severity")).lower(), 0)
    adicional = props.get("additionalData") or {}
    a["tecnicas"] = adicional.get("techniques") or []
    for e in props.get("relatedEntities") or carga.get("entities") or []:
        tipo = str(e.get("kind") or e.get("Type") or e.get("type") or "").lower()
        p = e.get("properties") or e
        if tipo == "host":
            poner(a, "equipo.nombre", primero(p.get("hostName"), p.get("HostName"), p.get("netBiosName")))
            poner(a, "equipo.id_edr", primero(leer(p, "additionalData.MdatpDeviceId"), p.get("MdatpDeviceId")))
            poner(a, "equipo.so", p.get("osFamily"))
        elif tipo == "account":
            nombre = primero(p.get("accountName"), p.get("Name"))
            sufijo = primero(p.get("upnSuffix"), p.get("UPNSuffix"))
            poner(a, "usuario.nombre", nombre)
            poner(a, "usuario.dominio", primero(p.get("ntDomain"), p.get("NTDomain")))
            if nombre and sufijo:
                poner(a, "usuario.upn", nombre + "@" + sufijo)
            poner(a, "usuario.id_nube", primero(p.get("aadUserId"), p.get("AadUserId")))
            poner(a, "usuario.sid", p.get("sid"))
        elif tipo == "ip":
            ip = primero(p.get("address"), p.get("Address"))
            if ip and not a["red"].get("ip_origen"):
                poner(a, "red.ip_origen", ip)
            elif ip:
                poner(a, "red.ip_destino", ip)
        elif tipo == "filehash":
            alg = str(primero(p.get("algorithm"), p.get("Algorithm")) or "").lower()
            val = primero(p.get("hashValue"), p.get("Value"))
            if alg in ("sha256", "sha1", "md5") and val:
                poner(a, "fichero." + alg, str(val).lower())
        elif tipo == "file":
            poner(a, "fichero.nombre", p.get("fileName"))
            if p.get("directory") and p.get("fileName"):
                poner(a, "fichero.ruta", str(p["directory"]).rstrip("\\/") + "\\" + p["fileName"])
        elif tipo == "process":
            poner(a, "proceso.pid", p.get("processId"))
            poner(a, "proceso.linea", p.get("commandLine"))
            poner(a, "proceso.inicio", p.get("creationTimeUtc"))
        elif tipo == "url":
            poner(a, "red.url", p.get("url"))
        elif tipo == "dns":
            poner(a, "red.dominio", p.get("domainName"))
        elif tipo == "mailmessage":
            poner(a, "correo.message_id", p.get("internetMessageId"))
            poner(a, "correo.remitente", p.get("p1Sender") or p.get("p2Sender"))
            poner(a, "correo.buzon", p.get("recipient"))
            poner(a, "correo.asunto", p.get("subject"))
        elif tipo == "mailbox":
            poner(a, "correo.buzon", p.get("mailboxPrimaryAddress"))
        elif tipo == "cloudapplication":
            poner(a, "nube.app_id", p.get("appId"))
            poner(a, "nube.app_nombre", p.get("appName"))
    a["bruto"] = carga
    return a


def _elastic(carga: dict, a: dict) -> dict:
    """Alerta de Elastic Security (documento ECS o carga del conector webhook)."""
    al = carga
    if isinstance(carga.get("alerts"), list) and carga["alerts"]:
        al = dict(carga["alerts"][0])
        al.setdefault("rule", carga.get("rule") or {})
    a["id"] = str(primero(al.get("_id"), leer(al, "kibana.alert.uuid"), al.get("id")) or "")
    a["titulo"] = str(primero(leer(al, "kibana.alert.rule.name"), leer(al, "rule.name"), leer(carga, "rule.name")) or "")
    a["regla_nombre"] = a["titulo"]
    a["regla_id"] = str(primero(leer(al, "kibana.alert.rule.rule_id"), leer(al, "rule.id"), leer(carga, "rule.id")) or "")
    a["momento"] = primero(al.get("@timestamp"), leer(al, "kibana.alert.original_time")) or ""
    sev = primero(leer(al, "kibana.alert.severity"), leer(carga, "rule.severity"))
    a["severidad_pista"] = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(sev).lower(), 0)
    poner(a, "equipo.nombre", primero(leer(al, "host.name"), leer(al, "host.hostname"), leer(al, "winlog.computer_name")))
    ip = leer(al, "host.ip")
    poner(a, "equipo.ip", ip[0] if isinstance(ip, list) else ip)
    poner(a, "usuario.nombre", primero(leer(al, "user.name"), leer(al, "winlog.event_data.TargetUserName"),
                                       leer(al, "user.email"), leer(al, "o365.audit.UserId")))
    poner(a, "usuario.dominio", leer(al, "user.domain"))
    poner(a, "proceso.guid", primero(leer(al, "process.entity_id"), leer(al, "winlog.event_data.ProcessGuid")))
    poner(a, "proceso.pid", primero(leer(al, "process.pid"), leer(al, "winlog.event_data.ProcessId")))
    poner(a, "proceso.inicio", primero(leer(al, "process.start"), leer(al, "winlog.event_data.UtcTime")))
    poner(a, "proceso.imagen", primero(leer(al, "process.executable"), leer(al, "winlog.event_data.Image")))
    poner(a, "proceso.linea", primero(leer(al, "process.command_line"), leer(al, "winlog.event_data.CommandLine")))
    poner(a, "proceso.padre_imagen", primero(leer(al, "process.parent.executable"), leer(al, "winlog.event_data.ParentImage")))
    poner(a, "proceso.sha256", leer(al, "process.hash.sha256"))
    poner(a, "proceso.sha1", leer(al, "process.hash.sha1"))
    poner(a, "proceso.md5", leer(al, "process.hash.md5"))
    a["proceso"].update(parsear_hashes(leer(al, "winlog.event_data.Hashes")))
    poner(a, "fichero.ruta", primero(leer(al, "file.path"), leer(al, "winlog.event_data.TargetFilename")))
    poner(a, "fichero.sha256", leer(al, "file.hash.sha256"))
    poner(a, "fichero.sha1", leer(al, "file.hash.sha1"))
    poner(a, "red.ip_origen", leer(al, "source.ip"))
    poner(a, "red.ip_destino", leer(al, "destination.ip"))
    poner(a, "red.puerto_destino", leer(al, "destination.port"))
    poner(a, "red.dominio", primero(leer(al, "dns.question.name"), leer(al, "destination.domain"), leer(al, "url.domain")))
    poner(a, "red.url", leer(al, "url.full"))
    poner(a, "http.estado", leer(al, "http.response.status_code") and str(leer(al, "http.response.status_code")))
    poner(a, "http.metodo", leer(al, "http.request.method"))
    poner(a, "http.user_agent", leer(al, "user_agent.original"))
    poner(a, "k8s.namespace", primero(leer(al, "orchestrator.namespace"), leer(al, "kubernetes.namespace")))
    poner(a, "k8s.pod", primero(leer(al, "orchestrator.resource.name"), leer(al, "kubernetes.pod.name")))
    poner(a, "k8s.nodo", leer(al, "kubernetes.node.name"))
    _auditoria_exchange(a, primero(leer(al, "o365.audit.Operation"), leer(al, "event.action")),
                        leer(al, "o365.audit.Parameters"), leer(al, "o365.audit.ObjectId"), leer(al, "o365.audit.UserId"))
    amenazas = leer(al, "kibana.alert.rule.threat") or []
    tec = []
    for t in amenazas if isinstance(amenazas, list) else []:
        for x in t.get("technique") or []:
            tec.append(x.get("id"))
            for s in x.get("subtechnique") or []:
                tec.append(s.get("id"))
    a["tecnicas"] = [t for t in tec if t]
    a["bruto"] = carga
    return a


def _generico(carga: dict, a: dict) -> dict:
    """El propio esquema normalizado, para SIEM sin normalizador o pruebas."""
    for clave, valor in carga.items():
        if clave in a and isinstance(a[clave], dict) and isinstance(valor, dict):
            a[clave].update({k: v for k, v in valor.items() if v not in (None, "")})
        elif clave in a and valor not in (None, ""):
            a[clave] = valor
    a["bruto"] = carga
    return a


NORMALIZADORES = {
    "wazuh": _wazuh,
    "splunk": _splunk,
    "sentinel": _sentinel,
    "elastic": _elastic,
    "generico": _generico,
}


def normalizar(siem: str, carga: dict, cliente: str = "") -> dict:
    siem = (siem or "generico").lower()
    if siem not in NORMALIZADORES:
        raise ValueError("SIEM no soportado: %s (validos: %s)" % (siem, ", ".join(sorted(NORMALIZADORES))))
    a = alerta_vacia(siem, cliente)
    NORMALIZADORES[siem](carga or {}, a)
    return _completar(a)


# ════════════════════════════════════════════════════════════════════════════
# Catalogo
# ════════════════════════════════════════════════════════════════════════════

def limpiar_nombre_regla(nombre) -> str:
    """Quita lo que cada plataforma anade al nombre de la regla al desplegarla:
    prefijos de laboratorio ("DL - ", "RL - ") y la convencion de Splunk ES
    para busquedas de correlacion ("Threat - <nombre> - Rule")."""
    t = str(nombre or "").strip()
    t = re.sub(r"\s*-\s*rule\s*$", "", t, flags=re.I)
    t = re.sub(r"^\s*(access|endpoint|network|threat|identity|audit)\s*-\s*", "", t, flags=re.I)
    t = re.sub(r"^\s*(dl|rl|responselab)\s*-\s*", "", t, flags=re.I)
    return t


class Catalogo:
    """Indice de solo lectura sobre catalogo.json."""

    def __init__(self, datos: dict):
        self.datos = datos
        self.version = datos.get("version", "")
        self.familias = datos.get("familias", {})
        self.acciones = datos.get("acciones", {})
        self.reglas = datos.get("reglas", [])
        self.secuencias = datos.get("secuencias", [])
        self.por_clave, self.por_wazuh, self.por_stem = {}, {}, {}
        self.por_titulo, self.por_splunk, self.por_sigma = {}, {}, {}
        for r in self.reglas:
            self.por_clave[r["clave"]] = r
            self.por_stem.setdefault(stem(r["clave"]).lower(), r)
            for w in r.get("wazuh_ids") or []:
                self.por_wazuh[str(w)] = r
            for t in [r.get("titulo")] + list(r.get("titulos") or []):
                if t:
                    self.por_titulo.setdefault(norm(t), r)
            if r.get("splunk"):
                self.por_splunk[norm(r["splunk"])] = r
            if r.get("sigma_id"):
                self.por_sigma[str(r["sigma_id"]).lower()] = r

    def buscar_regla(self, alerta: dict):
        """Devuelve (regla, via). Orden: identificadores exactos antes que titulos."""
        siem = alerta.get("siem")
        rid = str(alerta.get("regla_id") or "")
        if siem == "wazuh" and rid in self.por_wazuh:
            return self.por_wazuh[rid], "id de regla de Wazuh"
        fichero = alerta.get("regla_fichero")
        if fichero:
            s = re.sub(r"\.ya?ml$", "", nombre_base(fichero)).lower()
            if s in self.por_stem:
                return self.por_stem[s], "fichero de origen"
        if rid.lower() in self.por_sigma:
            return self.por_sigma[rid.lower()], "id Sigma"
        nombre = alerta.get("regla_nombre") or ""
        if nombre and norm(nombre) in self.por_splunk:
            return self.por_splunk[norm(nombre)], "busqueda guardada de Splunk"
        for t in (nombre, alerta.get("titulo")):
            if not t:
                continue
            limpio = limpiar_nombre_regla(t)
            if norm(limpio) in self.por_splunk:
                return self.por_splunk[norm(limpio)], "busqueda guardada de Splunk"
            if norm(limpio) in self.por_titulo:
                return self.por_titulo[norm(limpio)], "titulo"
        if rid and rid in self.por_wazuh:
            return self.por_wazuh[rid], "id de regla"
        return None, ""

    def familia(self, nombre: str) -> dict:
        return self.familias.get(nombre) or self.familias.get("_generico") or {}


# ════════════════════════════════════════════════════════════════════════════
# Evaluadores: preguntas de triaje, cierres y excepciones
# ════════════════════════════════════════════════════════════════════════════
#
# Cada evaluador contesta True, False o None. None significa "no tengo datos
# para saberlo" y es una respuesta legitima: la pregunta pasa al analista. Un
# evaluador que convirtiera la falta de datos en un no estaria cerrando
# alertas con la informacion que le falta.

EVALUADORES = {}


def evaluador(nombre):
    def registrar(fn):
        EVALUADORES[nombre] = fn
        return fn
    return registrar


def evaluar(spec, ctx):
    if spec is None:
        return None
    if isinstance(spec, list):
        spec = {"todos": spec}
    if not isinstance(spec, dict) or len(spec) != 1:
        raise ValueError("evaluador mal formado: %r" % (spec,))
    nombre, arg = next(iter(spec.items()))
    if nombre == "todos":
        rs = [evaluar(x, ctx) for x in arg]
        if any(r is False for r in rs):
            return False
        return None if any(r is None for r in rs) else True
    if nombre == "alguno":
        rs = [evaluar(x, ctx) for x in arg]
        if any(r is True for r in rs):
            return True
        return None if any(r is None for r in rs) else False
    # "negar" y no "no": en YAML, una clave `no:` sin comillas es el booleano
    # False. Es el mismo detalle que muerde a los playbooks de DetectionLab.
    if nombre == "negar":
        r = evaluar(arg, ctx)
        return None if r is None else (not r)
    fn = EVALUADORES.get(nombre)
    if fn is None:
        raise ValueError("evaluador desconocido: %s" % nombre)
    return fn(arg if arg is not None else {}, ctx)


def _al(ctx):
    return ctx["alerta"]


def _identificadores_regla(ctx) -> set:
    regla = ctx.get("regla") or {}
    a = _al(ctx)
    ids = {str(regla.get("clave", "")).lower(), stem(regla.get("clave", "")).lower()}
    ids |= {str(w) for w in regla.get("wazuh_ids") or []}
    ids.add(str(a.get("regla_id") or "").lower())
    if a.get("regla_fichero"):
        ids.add(re.sub(r"\.ya?ml$", "", nombre_base(a["regla_fichero"])).lower())
    ids.discard("")
    return ids


@evaluador("evento.regla_en")
def _ev_regla_en(arg, ctx):
    return bool({str(x).lower() for x in arg or []} & _identificadores_regla(ctx))


@evaluador("evento.campo_contiene")
def _ev_campo_contiene(arg, ctx):
    v = leer(_al(ctx), arg["campo"])
    if v is None:
        return None
    t = str(v).lower()
    return any(str(x).lower() in t for x in arg.get("valores") or [])


@evaluador("evento.campo_valor")
def _ev_campo_valor(arg, ctx):
    v = leer(_al(ctx), arg["campo"])
    if v is None:
        return None
    return str(v).lower() in {str(x).lower() for x in arg.get("valores") or []}


@evaluador("evento.campo_existe")
def _ev_campo_existe(arg, ctx):
    campo = arg if isinstance(arg, str) else arg.get("campo")
    return leer(_al(ctx), campo) is not None


@evaluador("evento.texto_contiene")
def _ev_texto_contiene(arg, ctx):
    a = _al(ctx)
    blob = " ".join([str(a.get("titulo", "")), str(a.get("descripcion", "")),
                     json.dumps(a.get("bruto", {}), default=str, ensure_ascii=False)]).lower()
    return any(str(x).lower() in blob for x in arg.get("valores") or [])


# ── Inventario del cliente ──────────────────────────────────────────────────

def _valor_objetivo(ctx, objetivo):
    a = _al(ctx)
    if not objetivo or objetivo == "equipo":
        return leer(a, "equipo.nombre"), leer(a, "equipo.ip")
    if objetivo == "destino":
        return leer(a, "red.dominio"), leer(a, "red.ip_destino")
    v = leer(a, objetivo)
    return (None, v) if es_ip(v) else (v, None)


def _casa_activo(entrada: dict, nombre, ip) -> bool:
    if nombre:
        n = str(nombre).lower()
        if entrada.get("nombre") and str(entrada["nombre"]).lower() in (n, n.split(".")[0]):
            return True
        if entrada.get("patron") and re.search(entrada["patron"], str(nombre), re.I):
            return True
    if ip and entrada.get("ip"):
        try:
            return ipaddress.ip_address(str(ip)) in ipaddress.ip_network(str(entrada["ip"]), strict=False)
        except ValueError:
            return False
    return False


def activos_de(cliente: dict, nombre, ip) -> list:
    inv = (cliente or {}).get("inventario") or {}
    return [e for e in inv.get("activos") or [] if _casa_activo(e, nombre, ip)]


@evaluador("inventario.etiqueta")
def _ev_inventario_etiqueta(arg, ctx):
    nombre, ip = _valor_objetivo(ctx, arg.get("objetivo"))
    if not nombre and not ip:
        return None
    cliente = ctx.get("cliente") or {}
    entradas = activos_de(cliente, nombre, ip)
    etiquetas = {str(t) for e in entradas for t in e.get("etiquetas") or []}
    if etiquetas & {str(t) for t in arg.get("etiquetas") or []}:
        return True
    if entradas or ((cliente.get("inventario") or {}).get("completo")):
        return False
    return None


def _hhmm(valor) -> str:
    """'HH:MM' normalizado, o '' si no es una hora.

    Acepta el entero en que YAML 1.1 convierte una hora sin comillas (14:00 es
    840, base 60): validar_perfil lo rechaza, pero un perfil que llegue por otra
    via no debe tumbar la decision.
    """
    if isinstance(valor, bool):
        return ""
    if isinstance(valor, int):
        return "%02d:%02d" % divmod(valor, 60) if 0 <= valor < 24 * 60 else ""
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", str(valor or "").strip())
    if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
        return ""
    return "%02d:%02d" % (int(m.group(1)), int(m.group(2)))


def _ventana_activa(v: dict, momento: datetime, zona) -> bool:
    if v.get("inicio") and v.get("fin"):
        ini, fin = a_fecha(v["inicio"]), a_fecha(v["fin"])
        return bool(ini and fin and ini <= momento <= fin)
    desde, hasta = _hhmm(v.get("desde")), _hhmm(v.get("hasta"))
    if not (v.get("dias") and desde and hasta):
        return False
    local = momento.astimezone(zona) if zona else momento
    dias = {str(d).lower()[:2] for d in v["dias"]}
    nombres = ["lu", "ma", "mi", "ju", "vi", "sa", "do"]

    def listado(fecha) -> bool:
        return nombres[fecha.weekday()] in dias or str(fecha.weekday()) in dias

    hhmm = local.strftime("%H:%M")
    if desde <= hasta:
        return listado(local) and desde <= hhmm <= hasta
    # Cruza la medianoche: la ventana es del dia en que empieza. "vi 22:00-06:00"
    # cubre la madrugada del sabado, no la del viernes.
    if hhmm >= desde:
        return listado(local)
    if hhmm <= hasta:
        return listado(local - timedelta(days=1))
    return False


def _zona(cliente):
    nombre = (cliente or {}).get("zona_horaria")
    if not nombre:
        return timezone.utc
    try:
        from zoneinfo import ZoneInfo  # Python 3.9+
        return ZoneInfo(nombre)
    except Exception:
        return timezone.utc


@evaluador("inventario.ventana_abierta")
def _ev_ventana_abierta(arg, ctx):
    cliente = ctx.get("cliente") or {}
    momento = ctx["momento"]
    zona = _zona(cliente)
    nombre = leer(_al(ctx), "equipo.nombre")
    for v in cliente.get("ventanas") or []:
        if arg.get("tipo") and v.get("tipo") != arg["tipo"]:
            continue
        if not _ventana_activa(v, momento, zona):
            continue
        if arg.get("objetivo") == "ninguno" or not v.get("equipos"):
            return True
        if nombre and any(re.search(p, str(nombre), re.I) for p in v["equipos"]):
            return True
    # Sin ventana declarada no hay ventana abierta: es un no, no un "no se".
    return False


def _excepciones_que_casan(ctx, arg):
    cliente = ctx.get("cliente") or {}
    nombre, ip = _valor_objetivo(ctx, arg.get("objetivo"))
    ids = _identificadores_regla(ctx)
    salida = []
    for e in cliente.get("excepciones") or []:
        if not _casa_activo({"nombre": e.get("activo"), "patron": e.get("patron"), "ip": e.get("ip")}, nombre, ip):
            continue
        if e.get("reglas") and not ({str(x).lower() for x in e["reglas"]} & ids):
            continue
        if arg.get("segmento") and e.get("segmento"):
            origen = leer(_al(ctx), arg["segmento"])
            try:
                if not origen or ipaddress.ip_address(str(origen)) not in ipaddress.ip_network(str(e["segmento"]), strict=False):
                    continue
            except ValueError:
                continue
        salida.append(e)
    return salida


@evaluador("inventario.excepcion_vigente")
def _ev_excepcion_vigente(arg, ctx):
    for e in _excepciones_que_casan(ctx, arg):
        vence = a_fecha(e.get("vence"))
        if vence is None or vence >= ctx["momento"]:
            return True
    return False


@evaluador("inventario.excepcion_caducada")
def _ev_excepcion_caducada(arg, ctx):
    hay = _excepciones_que_casan(ctx, arg)
    if not hay:
        return False
    return all(a_fecha(e.get("vence")) and a_fecha(e.get("vence")) < ctx["momento"] for e in hay)


# ── Listas del cliente ──────────────────────────────────────────────────────

def _lista(ctx, nombre):
    listas = (ctx.get("cliente") or {}).get("listas") or {}
    return listas.get(nombre)  # None = la lista no esta declarada: no se sabe


@evaluador("directorio.cuenta_en_lista")
def _ev_cuenta_en_lista(arg, ctx):
    lista = _lista(ctx, arg["lista"])
    if lista is None:
        return None
    v = leer(_al(ctx), arg.get("campo", "usuario.nombre"))
    if v is None:
        return None
    v = str(v).lower()
    candidatos = {v, v.split("\\")[-1], v.split("@")[0]}
    return any(str(x).lower() in candidatos or str(x).lower().split("@")[0] in candidatos for x in lista)


@evaluador("lista.valor_en")
def _ev_valor_en(arg, ctx):
    lista = _lista(ctx, arg["lista"])
    if lista is None:
        return None
    v = leer(_al(ctx), arg["campo"])
    if v is None:
        return None
    return str(v).lower() in {str(x).lower() for x in lista}


@evaluador("lista.ip_en_rango")
def _ev_ip_en_rango(arg, ctx):
    lista = _lista(ctx, arg["lista"])
    if lista is None:
        return None
    v = leer(_al(ctx), arg["campo"])
    if v is None or not es_ip(v):
        return None
    ip = ipaddress.ip_address(str(v))
    for red in lista:
        try:
            if ip in ipaddress.ip_network(str(red), strict=False):
                return True
        except ValueError:
            continue
    return False


@evaluador("lista.prefijo_en")
def _ev_prefijo_en(arg, ctx):
    lista = _lista(ctx, arg["lista"])
    if lista is None:
        return None
    v = leer(_al(ctx), arg["campo"])
    if v is None:
        return None
    return any(str(v).lower().startswith(str(p).lower()) for p in lista)


@evaluador("lista.prefijo_no_en")
def _ev_prefijo_no_en(arg, ctx):
    r = _ev_prefijo_en(arg, ctx)
    return None if r is None else (not r)


@evaluador("lista.par_en")
def _ev_par_en(arg, ctx):
    lista = _lista(ctx, arg["lista"])
    if lista is None:
        return None
    valores = {}
    for clave, campo in (arg.get("campos") or {}).items():
        v = leer(_al(ctx), campo)
        if v is None:
            return None
        valores[clave] = str(v).lower()
    return any(all(str(e.get(k, "")).lower() == v for k, v in valores.items())
               for e in lista if isinstance(e, dict))


# ── Correlacion (necesita el historico que aporta el motor) ─────────────────

def _recientes(ctx):
    c = (ctx.get("contexto") or {}).get("correlacion")
    if c is None:
        return None
    return c.get("recientes") or []


def _dentro(r, ctx, minutos):
    t = a_fecha(r.get("momento"))
    return bool(t) and abs((ctx["momento"] - t).total_seconds()) <= minutos * 60


def _no_soy_yo(r, ctx):
    return str(r.get("id")) != str(_al(ctx).get("id"))


def _misma_entidad(r, ctx, objetivo="equipo"):
    a = _al(ctx)
    if objetivo == "usuario":
        u = (leer(a, "usuario.nombre") or "").lower()
        return bool(u) and str(r.get("usuario") or "").lower() == u
    e = (leer(a, "equipo.nombre") or "").lower()
    return bool(e) and str(r.get("equipo") or "").lower() == e


@evaluador("correlacion.otras_familias")
def _ev_otras_familias(arg, ctx):
    rec = _recientes(ctx)
    objetivo = arg.get("objetivo", "equipo")
    clave = leer(_al(ctx), "usuario.nombre" if objetivo == "usuario" else "equipo.nombre")
    if rec is None or not clave:
        return None
    fams = {r.get("familia") for r in rec
            if _no_soy_yo(r, ctx) and _misma_entidad(r, ctx, objetivo)
            and r.get("familia") != ctx.get("familia") and _dentro(r, ctx, arg.get("horas", 24) * 60)}
    return len(fams - {None, ""}) >= int(arg.get("minimo", 1))


@evaluador("correlacion.misma_regla_en_equipos")
def _ev_misma_regla_en_equipos(arg, ctx):
    rec = _recientes(ctx)
    if rec is None:
        return None
    clave = (ctx.get("regla") or {}).get("clave")
    if not clave:
        return None
    equipos = {str(r.get("equipo") or "").lower() for r in rec
               if r.get("regla_clave") == clave and _dentro(r, ctx, arg.get("minutos", 60))}
    propio = leer(_al(ctx), "equipo.nombre")
    if propio:
        equipos.add(str(propio).lower())
    equipos.discard("")
    if "maximo" in arg:
        return len(equipos) <= int(arg["maximo"])
    return len(equipos) >= int(arg.get("minimo", 2))


@evaluador("correlacion.unico_equipo")
def _ev_unico_equipo(arg, ctx):
    return _ev_misma_regla_en_equipos({"minutos": arg.get("horas", 24) * 60, "maximo": 1}, ctx)


@evaluador("correlacion.regla_en_equipo")
def _ev_regla_en_equipo(arg, ctx):
    rec = _recientes(ctx)
    if rec is None or not leer(_al(ctx), "equipo.nombre"):
        return None
    reglas = {str(x).lower() for x in arg.get("reglas") or []}
    for r in rec:
        if not (_no_soy_yo(r, ctx) and _misma_entidad(r, ctx) and _dentro(r, ctx, arg.get("minutos", 10))):
            continue
        rc = str(r.get("regla_clave") or "").lower()
        if rc in reglas or stem(rc) in reglas:
            return True
    return False


@evaluador("correlacion.familia_en_usuario")
def _ev_familia_en_usuario(arg, ctx):
    rec = _recientes(ctx)
    if rec is None or not leer(_al(ctx), "usuario.nombre"):
        return None
    fams = set(arg.get("familias") or [])
    return any(_no_soy_yo(r, ctx) and _misma_entidad(r, ctx, "usuario") and r.get("familia") in fams
               and _dentro(r, ctx, arg.get("minutos", 60)) for r in rec)


@evaluador("correlacion.primera_vez")
def _ev_primera_vez(arg, ctx):
    c = (ctx.get("contexto") or {}).get("correlacion")
    if c is None or leer(_al(ctx), arg["campo"]) is None:
        return None
    visto = (c.get("visto") or {}).get(arg["campo"])
    return None if visto is None else (not visto)


@evaluador("correlacion.mismo_observable_en_equipos")
def _ev_mismo_observable_en_equipos(arg, ctx):
    rec = _recientes(ctx)
    if rec is None:
        return None
    valores = {str(leer(_al(ctx), c)).lower() for c in arg.get("campos") or [] if leer(_al(ctx), c)}
    if not valores:
        return None
    minutos = arg.get("horas", 24) * 60
    equipos = set()
    for r in rec:
        if _dentro(r, ctx, minutos) and valores & {str(x).lower() for x in r.get("observables") or []}:
            equipos.add(str(r.get("equipo") or "").lower())
    propio = leer(_al(ctx), "equipo.nombre")
    if propio:
        equipos.add(str(propio).lower())
    equipos.discard("")
    if len(equipos) < int(arg.get("minimo", 2)):
        return False
    if arg.get("sin_otras_alertas"):
        for r in rec:
            if (str(r.get("equipo") or "").lower() in equipos and _dentro(r, ctx, minutos)
                    and not (valores & {str(x).lower() for x in r.get("observables") or []})):
                return False
    return True


@evaluador("correlacion.observables_distintos_en_equipo")
def _ev_observables_distintos(arg, ctx):
    rec = _recientes(ctx)
    if rec is None or not leer(_al(ctx), "equipo.nombre"):
        return None
    vistos = {str(x).lower() for r in rec if _misma_entidad(r, ctx) and _dentro(r, ctx, arg.get("horas", 24) * 60)
              for x in r.get("cti") or []}
    vistos |= {str(c.get("valor")).lower() for c in _coincidencias(ctx) or []}
    return len(vistos) >= int(arg.get("minimo", 3))


# ── Inteligencia (News CTI y MISP, resuelta por el motor) ───────────────────

def _cti(ctx):
    return (ctx.get("contexto") or {}).get("cti")


def _coincidencias(ctx):
    c = _cti(ctx)
    return None if c is None else (c.get("coincidencias") or [])


NIVEL_CTI = {"baja": 0, "media": 1, "alta": 2}


@evaluador("cti.coincidencia")
def _ev_cti_coincidencia(arg, ctx):
    co = _coincidencias(ctx)
    if co is None:
        return None
    minimo = NIVEL_CTI.get(arg.get("nivel_minimo", "media"), 1)
    return any(NIVEL_CTI.get(c.get("nivel"), 0) >= minimo for c in co)


@evaluador("cti.tipo_coincidencia")
def _ev_cti_tipo(arg, ctx):
    tipos = set(arg if isinstance(arg, list) else arg.get("tipos") or [])
    if _al(ctx).get("cti_tipo"):
        return _al(ctx)["cti_tipo"] in tipos
    co = _coincidencias(ctx)
    if co is None:
        return None
    if not co:
        return False
    return any(c.get("tipo") in tipos for c in co)


@evaluador("cti.nivel_en")
def _ev_cti_nivel_en(arg, ctx):
    co = _coincidencias(ctx)
    if not co:
        return None
    maximo = max(co, key=lambda c: NIVEL_CTI.get(c.get("nivel"), 0))
    return maximo.get("nivel") in set(arg if isinstance(arg, list) else arg.get("niveles") or [])


@evaluador("cti.antiguedad_mayor")
def _ev_cti_antiguedad(arg, ctx):
    co = _coincidencias(ctx)
    if not co:
        return None
    edades = [c.get("edad_dias") for c in co if c.get("edad_dias") is not None]
    if not edades:
        return None
    return min(edades) > int(arg.get("dias", 30))


@evaluador("cti.una_sola_fuente")
def _ev_cti_una_fuente(arg, ctx):
    co = _coincidencias(ctx)
    if not co:
        return None
    return all(len(c.get("fuentes") or [1]) <= 1 for c in co)


@evaluador("cti.retirado_del_feed")
def _ev_cti_retirado(arg, ctx):
    c = _cti(ctx)
    if c is None:
        return None
    valores = {str(o["valor"]).lower() for o in _al(ctx).get("observables") or []}
    for r in c.get("retirados") or []:
        if str(r.get("valor")).lower() in valores and int(r.get("primera_vez_dias", 0)) >= int(arg.get("dias_minimos", 25)):
            return True
    return False


@evaluador("cti.kev")
def _ev_cti_kev(arg, ctx):
    cves = _al(ctx).get("cve") or []
    c = _cti(ctx)
    if not cves or c is None:
        return None
    return bool({x.upper() for x in cves} & {str(k).upper() for k in c.get("kev") or []})


@evaluador("dns.proveedor_cdn")
def _ev_dns_cdn(arg, ctx):
    ip = leer(_al(ctx), "red.ip_destino")
    dns = (ctx.get("contexto") or {}).get("dns") or {}
    info = dns.get(str(ip)) if ip else None
    if info is None:
        dom = leer(_al(ctx), "red.dominio")
        info = dns.get(str(dom)) if dom else None
    if not info:
        return None
    if "cdn" in info:
        return bool(info["cdn"])
    ptr = str(info.get("ptr") or "").lower().rstrip(".")
    return any(ptr.endswith(s) for s in SUFIJOS_CDN) if ptr else None


@evaluador("regulatorio.plazo_menor_horas")
def _ev_plazo(arg, ctx):
    plazos = (ctx.get("contexto") or {}).get("plazos")
    if plazos is None:
        return None
    return any(float(p.get("horas_restantes", 1e9)) < float(arg.get("horas", 24)) for p in plazos)


# ════════════════════════════════════════════════════════════════════════════
# Politica: radio x reversibilidad
# ════════════════════════════════════════════════════════════════════════════

def radio_efectivo(*radios) -> str:
    """El mas amplio de los declarados. Lo desconocido, o no declarar ninguno,
    cuenta como organizacion: lo que no dice a quien afecta se trata como lo peor."""
    declarados = [r for r in radios if r]
    if not declarados:
        return ORDEN_RADIO[-1]
    return ORDEN_RADIO[max(ORDEN_RADIO.index(r) if r in ORDEN_RADIO else len(ORDEN_RADIO) - 1 for r in declarados)]


def reversible_efectivo(*valores) -> str:
    """'si' solo si todos dicen 'si'. Cualquier otra cosa (incluido el booleano
    False que YAML hace de un `no` sin comillas) cuenta como irreversible."""
    vals = [v for v in valores if v is not None]
    return "si" if vals and all(str(v).strip().lower() == "si" for v in vals) else "no"


def requisito(alerta: dict, requiere: list):
    """Comprueba los campos que necesita una accion. Devuelve (ok, objetivo, falta)."""
    objetivo, falta = {}, []
    for req in requiere or []:
        cumplido = False
        for alternativa in str(req).split("|"):
            campos = [c.strip() for c in alternativa.split("+") if c.strip()]
            valores = {c: leer(alerta, c) for c in campos}
            if campos and all(v is not None for v in valores.values()):
                objetivo.update(valores)
                cumplido = True
                break
        if not cumplido:
            falta.append(req)
    return (not falta), objetivo, falta


def activo_protegido(cliente: dict, alerta: dict) -> bool:
    inv = (cliente or {}).get("inventario") or {}
    nombre, ip = leer(alerta, "equipo.nombre"), leer(alerta, "equipo.ip")
    for patron in inv.get("protegidos") or []:
        if nombre and re.search(str(patron), str(nombre), re.I):
            return True
    return any("protegido" in (e.get("etiquetas") or []) for e in activos_de(cliente, nombre, ip))


def decidir_modo(paso: dict, clase: str, escalada: bool, cliente: dict,
                 capacidades, ctx: dict, acciones_disponibles=None):
    """Decide si una accion se ejecuta sola. Devuelve (modo, motivo).

    Modos: automatica | aprobacion | manual | no_aplicable | prohibida.
    El orden de las comprobaciones importa: las invariantes van antes que
    cualquier cosa que venga de configuracion, para que ningun perfil de
    cliente ni ningun catalogo pueda autorizar lo que el codigo prohibe.
    """
    politica = (cliente or {}).get("politica") or {}
    accion = paso["accion"]
    radio, rev = paso["radio"], paso["reversible"]

    if paso.get("solo_reglas") and not ({str(x).lower() for x in paso["solo_reglas"]} & _identificadores_regla(ctx)):
        return "no_aplicable", "solo aplica a las reglas %s" % ", ".join(paso["solo_reglas"])
    if not paso.get("objetivo_ok"):
        return "no_aplicable", "la alerta no trae %s; no hay objetivo inequivoco" % " / ".join(paso.get("falta") or [])
    if accion in (politica.get("acciones_prohibidas") or []):
        return "prohibida", "el perfil del cliente no permite esta accion"
    if capacidades is not None and paso.get("capacidad") not in capacidades and paso.get("capacidad") != "interno":
        return "manual", "el cliente no tiene conector de %s" % paso.get("capacidad")
    if acciones_disponibles is not None and accion not in acciones_disponibles:
        return "manual", "ningun conector del cliente sabe hacer %s" % accion

    # Las invariantes de radio y reversibilidad valen para todo, tambien para lo
    # que el catalogo marque como registro o evidencia: una marca en un fichero
    # de configuracion no convierte en inocua una accion de radio organizacion.
    if paso.get("registro") or paso.get("es_evidencia"):
        if radio in RADIOS_AMPLIOS:
            return "aprobacion", "radio %s: afecta a quien no es el atacante" % radio
        if rev != "si" and radio != "proceso":
            return "aprobacion", "irreversible con radio %s" % radio

    if paso.get("registro"):
        # Anotar, abrir tareas o fijar retencion no corta nada a nadie.
        return "automatica", "accion de registro"

    if paso.get("es_evidencia"):
        if accion in ACCIONES_SOBRE_FICHERO:
            return "aprobacion", "%s no es recogida de evidencia" % accion
        if not (clase in (paso.get("clases") or ["auto_contener"]) or escalada):
            return "aprobacion", "recogida de evidencia disponible a demanda en esta clase"
        # En un activo protegido (DC, HMI de planta) ni siquiera la recogida es
        # automatica: un colector en un sistema fragil tambien es tocarlo.
        if activo_protegido(cliente, _al(ctx)):
            return "aprobacion", "activo protegido en el inventario del cliente: la recogida la decide una persona"
        objetivo = paso.get("objetivo") or {}
        if almacen_credenciales(objetivo.get("persistencia.ruta") or objetivo.get("fichero.ruta")):
            return "aprobacion", "es un almacen de credenciales: copiarlo multiplica el secreto"
        return "automatica", "recogida de evidencia: el peor caso es disco ocupado"

    if clase != "auto_contener" and not escalada:
        return "aprobacion", "la clase %s no autoriza contencion automatica: se prepara" % clase
    # ── Invariantes. No dependen de ningun dato configurable. ──
    if radio in RADIOS_AMPLIOS:
        return "aprobacion", "radio %s: afecta a quien no es el atacante" % radio
    if rev != "si" and radio != "proceso":
        return "aprobacion", "irreversible con radio %s" % radio
    if rev != "si" and not paso.get("objetivo_ok"):
        return "aprobacion", "irreversible sin objetivo identificado sin ambiguedad"
    if accion in ACCIONES_SOBRE_FICHERO and ruta_sistema(leer(_al(ctx), "fichero.ruta")):
        return "aprobacion", "el fichero esta en una ruta del sistema operativo"
    if accion in ACCIONES_SOBRE_FICHERO and fichero_critico(leer(_al(ctx), "fichero.ruta")):
        return "aprobacion", "el fichero es configuracion critica del sistema"
    # ── Lo que decide DetectionLab y el cliente ──
    if str(paso.get("requiere_aprobacion_origen", "no")).lower() == "si":
        return "aprobacion", "DetectionLab la marca con aprobacion"
    if politica.get("contencion_automatica") is False:
        return "aprobacion", "el cliente no admite contencion automatica"
    if accion in (politica.get("acciones_siempre_aprobacion") or []):
        return "aprobacion", "el cliente exige aprobacion para esta accion"
    if activo_protegido(cliente, _al(ctx)):
        return "aprobacion", "activo protegido en el inventario del cliente"
    sin_datos = politica.get("excepcion_sin_datos", "aprobacion")
    for exc in paso.get("excepciones") or []:
        r = evaluar(exc, ctx)
        if r is True:
            return "aprobacion", "se cumple una excepcion: %s" % describir_evaluador(exc)
        if r is None and sin_datos == "aprobacion":
            return "aprobacion", "no hay datos para descartar la excepcion: %s" % describir_evaluador(exc)
    return "automatica", "radio %s, %s" % (radio, "reversible" if rev == "si" else "proceso identificado")


def describir_evaluador(spec) -> str:
    if not isinstance(spec, dict) or len(spec) != 1:
        return str(spec)
    nombre, arg = next(iter(spec.items()))
    if nombre in ("todos", "alguno"):
        return (" y " if nombre == "todos" else " o ").join(describir_evaluador(x) for x in arg)
    if nombre == "negar":
        return "no (" + describir_evaluador(arg) + ")"
    if isinstance(arg, dict):
        detalle = ", ".join("%s=%s" % (k, v) for k, v in arg.items())
    else:
        detalle = ", ".join(str(x) for x in arg) if isinstance(arg, list) else str(arg)
    return "%s(%s)" % (nombre, detalle)


def verificar_invariantes(plan: dict, alerta=None) -> list:
    """Defensa en profundidad: lo que el ejecutor comprueba antes de actuar."""
    fallos = []
    for p in plan.get("acciones") or []:
        # Sin excepciones para registro ni evidencia: la marca viene del catalogo
        if p.get("modo") != "automatica":
            continue
        if p.get("accion") in ACCIONES_SOBRE_FICHERO and alerta is not None \
                and (ruta_sistema(leer(alerta, "fichero.ruta")) or fichero_critico(leer(alerta, "fichero.ruta"))):
            fallos.append("%s automatica sobre una ruta del sistema" % p["accion"])
        if p.get("radio") in RADIOS_AMPLIOS:
            fallos.append("%s automatica con radio %s" % (p["accion"], p["radio"]))
        if p.get("reversible") != "si" and p.get("radio") != "proceso":
            fallos.append("%s irreversible con radio %s" % (p["accion"], p["radio"]))
        if not p.get("objetivo") and not p.get("registro"):
            # Las de registro (nota, tarea, retencion) actuan sobre el caso, no
            # sobre un objetivo de la alerta; el resto necesita uno inequivoco.
            fallos.append("%s automatica sin objetivo" % p["accion"])
    return fallos


# ════════════════════════════════════════════════════════════════════════════
# Secuencias: cuando varias alertas son un mismo ataque
# ════════════════════════════════════════════════════════════════════════════

def _casa_paso(item: str, r: dict) -> bool:
    item = str(item)
    if item.startswith("familia:"):
        return r.get("familia") == item.split(":", 1)[1]
    if item.startswith("tecnica:"):
        pref = item.split(":", 1)[1].upper().rstrip("*")
        return any(str(t).upper().startswith(pref) for t in r.get("tecnicas") or [])
    clave = str(r.get("regla_clave") or "").lower()
    return item.lower() in (clave, stem(clave))


def evaluar_secuencias(alerta: dict, regla: dict, familia: str, secuencias: list, recientes):
    if recientes is None:
        return []
    actual = {"id": alerta.get("id"), "momento": alerta.get("momento"),
              "regla_clave": (regla or {}).get("clave", ""), "familia": familia,
              "tecnicas": alerta.get("tecnicas") or [],
              "equipo": leer(alerta, "equipo.nombre"), "usuario": leer(alerta, "usuario.nombre")}
    momento = a_fecha(alerta.get("momento")) or datetime.now(timezone.utc)
    activadas = []
    for s in secuencias or []:
        objetivo = s.get("objetivo", "equipo")
        clave = actual.get(objetivo)
        if not clave:
            continue
        ventana = timedelta(minutes=int(s.get("ventana_min", 60)))
        candidatas = [actual] + [r for r in recientes
                                 if str(r.get(objetivo) or "").lower() == str(clave).lower()
                                 and a_fecha(r.get("momento")) and abs(momento - a_fecha(r["momento"])) <= ventana]
        casados = []
        for i, paso in enumerate(s.get("pasos") or []):
            if any(_casa_paso(item, r) for r in candidatas for item in paso):
                casados.append(i)
        # La alerta actual tiene que formar parte de la secuencia: si no, la
        # secuencia ya se activo con otra y no es esta la que la completa.
        participa = any(_casa_paso(item, actual) for paso in s.get("pasos") or [] for item in paso)
        if participa and len(casados) >= int(s.get("minimo", len(s.get("pasos") or []))):
            activadas.append({"id": s["id"], "nombre": s.get("nombre", s["id"]),
                              "pasos_casados": len(casados), "pasos": len(s.get("pasos") or []),
                              "efecto": s.get("efecto") or {}})
    return activadas


# ════════════════════════════════════════════════════════════════════════════
# Decision
# ════════════════════════════════════════════════════════════════════════════

def _clase_por_severidad(sev: int) -> str:
    return {4: "auto_analisis", 3: "auto_analisis", 2: "auto_analisis", 1: "auto_enriq"}.get(int(sev or 0), "auto_analisis")


def _subir_escalado(actual: str, nuevo: str) -> str:
    if nuevo not in ORDEN_ESCALADO:
        return actual
    return nuevo if ORDEN_ESCALADO.index(nuevo) > ORDEN_ESCALADO.index(actual if actual in ORDEN_ESCALADO else "L2") else actual


def decidir(alerta: dict, catalogo, cliente=None, contexto=None, capacidades=None,
            acciones_disponibles=None) -> dict:
    """Alerta normalizada -> plan. Determinista y sin efectos."""
    if not isinstance(catalogo, Catalogo):
        catalogo = Catalogo(catalogo)
    cliente = cliente or {}
    contexto = contexto or {}
    politica = cliente.get("politica") or {}

    regla, via = catalogo.buscar_regla(alerta)
    avisos = []
    if regla:
        familia = regla.get("familia") or "_generico"
        nivel = regla.get("nivel", "medium")
        clase = regla.get("clase") or CLASE_POR_NIVEL.get(nivel, "auto_analisis")
        severidad = SEVERIDAD_POR_NIVEL.get(nivel, 2)
        if familia not in catalogo.familias:
            avisos.append("la familia %s no tiene playbook: se usa el generico" % familia)
            familia = "_generico"
    else:
        pista = alerta.get("familia_pista")
        familia = pista if pista in catalogo.familias else "_generico"
        severidad = int(alerta.get("severidad_pista") or 2)
        clase = alerta.get("clase_pista") if alerta.get("clase_pista") in CLASES else _clase_por_severidad(severidad)
        if clase == "auto_contener":
            # Una regla que el catalogo no conoce nunca contiene sola.
            clase = "auto_analisis"
            avisos.append("regla desconocida: la clase se limita a auto_analisis")
        avisos.append("regla no encontrada en el catalogo (%s)" % (alerta.get("regla_id") or alerta.get("titulo") or "sin id"))
    fam = catalogo.familia(familia)
    momento = a_fecha(alerta.get("momento")) or a_fecha(contexto.get("ahora")) or datetime.now(timezone.utc)

    plan = {
        "version_nucleo": VERSION,
        "version_catalogo": catalogo.version,
        "alerta_id": alerta.get("id", ""),
        "cliente": alerta.get("cliente", ""),
        "siem": alerta.get("siem", ""),
        "titulo": alerta.get("titulo", ""),
        "momento": iso(momento),
        "regla": {"clave": (regla or {}).get("clave", ""), "titulo": (regla or {}).get("titulo", alerta.get("titulo", "")),
                  "nivel": (regla or {}).get("nivel", ""), "origen": (regla or {}).get("origen", ""),
                  "conocida": bool(regla), "via": via, "tecnicas": (regla or {}).get("tecnicas") or alerta.get("tecnicas") or []},
        "familia": familia,
        "playbook": fam.get("nombre", familia),
        "plantilla_caso": fam.get("plantilla_caso", "ResponseLab - %s" % familia),
        "clase_origen": clase,
        "clase": clase,
        "severidad_inicial": severidad,
        "severidad": severidad,
        "estado": "en_curso",
        "triaje": [], "cierre": None, "cierres_propuestos": [], "secuencias": [],
        "acciones": [], "evidencia": [], "requiere_persona": [],
        "escalado": {}, "crear_caso": False, "notificar": False, "usar_llm": False,
        "enriquecimiento": [e.get("fuente") for e in fam.get("enriquecimiento") or []],
        "avisos": avisos, "modos": {},
    }

    if clase == "auto_cierre":
        plan["estado"] = "descartada"
        plan["resumen"] = "Regla base de correlacion (informational): se registra y se descarta."
        return plan

    ctx = {"alerta": alerta, "regla": regla or {}, "cliente": cliente, "contexto": contexto,
           "momento": momento, "familia": familia}

    # ── Triaje ──
    subir = bajar = 0
    for t in fam.get("triaje") or []:
        r = evaluar(t["evaluador"], ctx) if t.get("evaluador") else None
        plan["triaje"].append({"pregunta": t["pregunta"], "fuente": t.get("fuente", ""),
                               "efecto": t.get("efecto", ""), "automatica": bool(t.get("evaluador")),
                               "resultado": "pendiente" if r is None else ("si" if r else "no"),
                               "nota": t.get("nota", "")})
        if r is True and t.get("efecto") == "subir_severidad":
            subir += 1
        elif r is True and t.get("efecto") == "bajar_severidad":
            bajar += 1
    # Bajar reduce un escalon como mucho: reduce, no descarta.
    plan["severidad"] = max(1, min(4, severidad + subir - min(bajar, 1)))

    # ── Secuencias ──
    recientes = _recientes(ctx)
    secuencias = evaluar_secuencias(alerta, regla, familia, catalogo.secuencias, recientes)
    plan["secuencias"] = secuencias
    escalada = False
    for s in secuencias:
        ef = s["efecto"]
        plan["severidad"] = max(plan["severidad"], int(ef.get("severidad", 0) or 0))
        if ef.get("clase") == "auto_contener" and clase in ("auto_enriq", "auto_analisis") \
                and politica.get("escalado_por_correlacion", True):
            if regla:
                escalada = True
            else:
                avisos.append("la secuencia %s no eleva la clase: la regla no esta en el catalogo" % s["id"])
    if escalada:
        plan["clase"] = "auto_contener"
        avisos.append("clase elevada a auto_contener por la secuencia %s" % ", ".join(s["id"] for s in secuencias))

    # ── Cierre automatico ──
    for c in fam.get("cierre") or []:
        r = evaluar(c["evaluador"], ctx) if c.get("evaluador") else None
        if r is True and not secuencias:
            plan["cierre"] = {"condicion": c["condicion"], "justificacion": c.get("justificacion", "")}
            plan["estado"] = "cerrada_auto"
            break
        if r is None or (r is True and secuencias):
            plan["cierres_propuestos"].append({
                "condicion": c["condicion"],
                "motivo": "forma parte de una secuencia de ataque" if r else
                          ("faltan datos para comprobarla" if c.get("evaluador") else "no hay evaluador automatico")})

    # ── Acciones de contencion y evidencia ──
    clase_ef = plan["clase"]
    if plan["estado"] != "cerrada_auto" and clase_ef in ("auto_analisis", "auto_contener"):
        for i, c in enumerate(fam.get("contencion") or [], 1):
            plan["acciones"].append(_paso(i, c, catalogo, alerta, clase_ef, escalada, cliente, capacidades, ctx,
                                          acciones_disponibles))
    if plan["estado"] != "cerrada_auto":
        for j, e in enumerate(fam.get("evidencia_automatica") or [], 1):
            if clase_ef in ("auto_analisis", "auto_contener"):
                c = dict(e)
                c.setdefault("texto", catalogo.acciones.get(e["accion"], {}).get("nombre", e["accion"]))
                c["es_evidencia"] = True
                plan["acciones"].append(_paso("e%d" % j, c, catalogo, alerta, clase_ef, escalada, cliente, capacidades,
                                              ctx, acciones_disponibles))
    for p in plan["acciones"]:
        plan["modos"][p["id"]] = p["modo"]

    plan["evidencia"] = [dict(e) for e in fam.get("evidencia") or []]
    plan["requiere_persona"] = [dict(r) for r in fam.get("requiere_persona") or []]

    # ── Escalado ──
    esc = dict(fam.get("escalado") or {})
    destino = esc.get("a", "L2")
    motivos, pendientes = [], []
    for nivel_esc, clave in (("L3", "a_L3_si"), ("guardia", "a_guardia_si")):
        texto = esc.get(clave)
        ev = (fam.get("escalado_evaluadores") or {}).get(clave)
        if not texto and not ev:
            continue
        r = evaluar(ev, ctx) if ev else None
        if r is True:
            destino = _subir_escalado(destino, nivel_esc)
            motivos.append(texto or describir_evaluador(ev))
        elif r is None and texto:
            pendientes.append({"a": nivel_esc, "si": " ".join(str(texto).split())})
    for s in secuencias:
        if s["efecto"].get("escalar_a"):
            nuevo = _subir_escalado(destino, s["efecto"]["escalar_a"])
            if nuevo != destino:
                motivos.append("secuencia %s" % s["nombre"])
            destino = nuevo
    plan["escalado"] = {"a": destino, "plazo_min": int(esc.get("plazo_min", 30)),
                        "motivos": motivos, "comprobar": pendientes,
                        "avisar_ademas": sorted(set((esc.get("ademas_avisar_a") or [])
                                                    + [x for s in secuencias for x in s["efecto"].get("avisar") or []])),
                        "nota_plazo": " ".join(str(esc.get("nota_plazo", "")).split())}
    if destino == "guardia":
        plan["escalado"]["plazo_min"] = min(plan["escalado"]["plazo_min"], 10)

    # ── Que hace el flujo con todo esto ──
    cerrada = plan["estado"] == "cerrada_auto"
    plan["crear_caso"] = (not cerrada) and (clase_ef in ("auto_analisis", "auto_contener") or bool(secuencias))
    plan["notificar"] = (not cerrada) and (clase_ef == "auto_contener" or plan["severidad"] >= 3 or bool(secuencias))
    plan["usar_llm"] = (not cerrada) and clase_ef in ("auto_analisis", "auto_contener")
    plan["resumen"] = resumen(plan)
    return plan


def _paso(ident, c: dict, catalogo, alerta, clase, escalada, cliente, capacidades, ctx,
          acciones_disponibles=None) -> dict:
    accion = c.get("accion")
    meta = catalogo.acciones.get(accion) if accion else None
    paso = {
        "id": "c%s" % ident if not str(ident).startswith("e") else str(ident),
        "origen": " ".join(str(c.get("texto", "")).split()),
        "accion": accion or "",
        "nombre": (meta or {}).get("nombre", c.get("texto", "")),
        "justificacion": " ".join(str(c.get("justificacion", "")).split()),
        "excepcion_origen": " ".join(str(c.get("excepcion", "")).split()),
    }
    if not meta:
        paso.update({"modo": "manual", "motivo": "accion sin mapear a nada ejecutable: tarea del analista",
                     "radio": c.get("radio", "organizacion"), "reversible": "no", "objetivo": {},
                     "capacidad": "", "deshacer": ""})
        return paso
    ok, objetivo, falta = requisito(alerta, meta.get("requiere"))
    paso.update({
        "radio": radio_efectivo(c.get("radio"), meta.get("radio")),
        "reversible": reversible_efectivo(c.get("reversible", "si"), meta.get("reversible")),
        "requiere_aprobacion_origen": str(c.get("requiere_aprobacion", "no")),
        "capacidad": meta.get("capacidad", ""),
        "deshacer": meta.get("deshacer", ""),
        "objetivo_ok": ok, "objetivo": objetivo, "falta": falta,
        "solo_reglas": c.get("solo_reglas") or [],
        "excepciones": c.get("excepciones") or [],
        "registro": bool(meta.get("registro")),
        "es_evidencia": bool(c.get("es_evidencia")) or str(accion).startswith("evidencia."),
        "clases": c.get("clases") or [],
        "parametros": c.get("parametros") or {},
    })
    modo, motivo = decidir_modo(paso, clase, escalada, cliente, capacidades, ctx, acciones_disponibles)
    paso["modo"], paso["motivo"] = modo, motivo
    for k in ("objetivo_ok", "falta", "excepciones", "clases"):
        paso.pop(k, None)
    return paso


def resumen(plan: dict) -> str:
    if plan["estado"] == "descartada":
        return "Descartada (regla base de correlacion)."
    auto = [p["nombre"] for p in plan["acciones"] if p["modo"] == "automatica"]
    espera = [p["nombre"] for p in plan["acciones"] if p["modo"] == "aprobacion"]
    partes = ["%s | %s | %s | severidad %d" % (plan["regla"]["titulo"] or plan["titulo"], plan["familia"],
                                                plan["clase"], plan["severidad"])]
    if plan["estado"] == "cerrada_auto":
        partes.append("cerrada sola: " + plan["cierre"]["condicion"][:160])
    if plan["secuencias"]:
        partes.append("secuencia: " + ", ".join(s["nombre"] for s in plan["secuencias"]))
    if auto:
        partes.append("automatico: " + "; ".join(auto))
    if espera:
        partes.append("espera aprobacion: " + "; ".join(espera))
    partes.append("escalar a %s en %d min" % (plan["escalado"].get("a", "L2"), plan["escalado"].get("plazo_min", 30)))
    return " | ".join(partes)
