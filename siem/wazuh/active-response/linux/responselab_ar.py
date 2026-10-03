#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
responselab_ar.py: active response de ResponseLab para agentes Wazuh en Linux.

Lo invocan los lanzadores responselab-<accion> de active-response/bin cuando
el motor pide una accion (PUT /active-response con "!responselab-<accion>").

Protocolo de Wazuh 4.2+ (src/active-response/active_responses.c):
  1. execd escribe una linea JSON en stdin:
       {"version":1,"origin":{...},"command":"add",
        "parameters":{"extra_args":[],"alert":{"data":{"responselab":{...}}},"program":"..."}}
  2. el script contesta check_keys y lee "continue" o "abort"
  3. execd ESPERA a que el script termine (wpclose -> waitpid): todo lo que
     tarde mas de unos segundos (el triage forense) se lanza en segundo plano.

El acuse vuelve por el propio Wazuh: una linea JSON en logs/active-responses.log
({"responselab_ar": {...}}) que el agente ya envia al manager, donde la regla
109900 la convierte en alerta y la integracion custom-responselab se la pasa
al motor. Ventajas: no hace falta ningun secreto en el equipo y el acuse llega
aunque el equipo este aislado (el manager sigue siendo alcanzable).

Cada accion comprueba su objetivo antes de tocar nada y guarda lo necesario
para deshacerla en <wazuh>/var/responselab. Solo biblioteca estandar, Python 3.6+.
"""
import hashlib
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "1.0"
AQUI = Path(__file__).resolve().parent                        # <wazuh>/active-response/bin
WAZUH = Path(os.environ.get("RL_WAZUH_DIR") or AQUI.parent.parent)
ESTADO = WAZUH / "var" / "responselab"
CUSTODIA = ESTADO / "custodia"
REGISTRO = WAZUH / "logs" / "active-responses.log"
CONFIGURACIONES = [WAZUH / "etc" / "shared" / "responselab.conf", WAZUH / "etc" / "responselab.conf"]
SIMULACION = os.environ.get("RL_AR_SIMULACION") == "1"        # pruebas: registra comandos, no los ejecuta
MAX_ACUSE = 6000                                               # una linea de log razonable para Wazuh

TABLA_AISLAR = "responselab_aislamiento"
TABLA_DESTINOS = "responselab_destinos"
CADENAS_IPT = {"entrada": "RL_AISLAR_IN", "salida": "RL_AISLAR_OUT", "reenvio": "RL_AISLAR_FWD"}
CADENA_DESTINOS = "RL_DESTINOS"

# Lo mismo que nucleo.RE_RUTA_SISTEMA, mas ficheros que no se tocan nunca
RE_RUTA_SISTEMA = re.compile(
    r"^(?:/(?:usr/)?s?bin/|/usr/lib(?:exec)?/|/lib(?:64)?/|/system/|/usr/local/s?bin/|/boot/"
    r"|/etc/(?:passwd|shadow|group|gshadow|sudoers|fstab|hosts)$)")
# Lo mismo que nucleo.RE_ALMACEN_CREDENCIALES: no se copian a custodia
RE_CREDENCIALES = re.compile(r"^/etc/(?:g?shadow|security/opasswd)$")
RE_DESTINO = re.compile(r"^[A-Za-z0-9.:_-]{1,253}$")
DIRS_SYSTEMD = ("/etc/systemd/", "/lib/systemd/", "/usr/lib/systemd/", "/run/systemd/")
DIRS_CRON = ("/etc/cron", "/var/spool/cron/")
COMANDOS_EJECUTADOS = []


class Fallo(Exception):
    """La accion no se hace: el motivo vuelve al motor en el acuse."""


# ═══ Utilidades ══════════════════════════════════════════════════════════════

def ahora() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def acuse(accion: str, estado: str, detalle: str, ejecucion: str = "", datos=None):
    """Una linea JSON en active-responses.log. "datos" va como texto JSON para
    que el decodificador de Wazuh no aplane listas ni objetos anidados."""
    cuerpo = {"v": 1, "accion": accion, "estado": estado, "ejecucion_id": ejecucion,
              "detalle": str(detalle)[:500], "equipo": socket.gethostname()}
    if datos:
        texto = json.dumps(datos, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        if len(texto) > MAX_ACUSE:
            texto = json.dumps({"recortado": True, "claves": sorted(datos)[:20]})
        cuerpo["datos"] = texto
    linea = json.dumps({"responselab_ar": cuerpo}, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    try:
        REGISTRO.parent.mkdir(parents=True, exist_ok=True)
        with open(str(REGISTRO), "a") as f:
            f.write(linea + "\n")
    except OSError:
        pass
    return cuerpo


def configuracion() -> dict:
    for ruta in CONFIGURACIONES:
        try:
            return json.loads(ruta.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
    return {}


def ejecutar(cmd, entrada=None, comprobar=True, tiempo=60) -> subprocess.CompletedProcess:
    COMANDOS_EJECUTADOS.append({"cmd": cmd, "entrada": entrada})
    if SIMULACION:
        return subprocess.CompletedProcess(cmd, 0, "", "")
    r = subprocess.run(cmd, input=entrada, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True, timeout=tiempo)
    if comprobar and r.returncode != 0:
        raise Fallo("%s fallo (%d): %s" % (" ".join(cmd[:3]), r.returncode, (r.stderr or r.stdout).strip()[:200]))
    return r


def hay(binario: str) -> bool:
    if SIMULACION:
        return binario in (os.environ.get("RL_AR_BINARIOS") or "nft").split(",")
    return shutil.which(binario) is not None


def sha256(ruta: Path) -> str:
    h = hashlib.sha256()
    with open(str(ruta), "rb") as f:
        for bloque in iter(lambda: f.read(1 << 20), b""):
            h.update(bloque)
    return h.hexdigest()


def md5(ruta: Path) -> str:
    h = hashlib.md5()
    with open(str(ruta), "rb") as f:
        for bloque in iter(lambda: f.read(1 << 20), b""):
            h.update(bloque)
    return h.hexdigest()


def guardar(nombre: str, datos: dict):
    ESTADO.mkdir(parents=True, exist_ok=True)
    os.chmod(str(ESTADO), 0o700)
    (ESTADO / nombre).write_text(json.dumps(datos, indent=1, sort_keys=True), encoding="utf-8")


def leer(nombre: str) -> dict:
    try:
        return json.loads((ESTADO / nombre).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _formas(ruta) -> list:
    """La ruta tal cual llega, normalizada y resuelta (enlaces simbolicos).

    normpath conserva una // inicial (POSIX la permite) y no resuelve enlaces:
    "//usr/bin/ls" o un directorio enlazado a /usr/bin pasarian por un fichero
    cualquiera si solo se mirara el texto.
    """
    normal = os.path.normpath(str(ruta))
    if normal.startswith("//"):
        normal = "/" + normal.lstrip("/")
    formas = [normal]
    try:
        real = os.path.realpath(str(ruta))
        if real not in formas:
            formas.append(real)
    except (OSError, ValueError):
        pass
    return formas


def ruta_sistema(ruta) -> bool:
    return any(RE_RUTA_SISTEMA.match(r) for r in _formas(ruta))


def almacen_credenciales(ruta) -> bool:
    return any(RE_CREDENCIALES.match(r) for r in _formas(ruta))


def paquete_de(ruta) -> str:
    """El paquete del sistema que instalo el fichero, o "" si no es de ninguno."""
    for orden in (["dpkg", "-S"], ["rpm", "-qf"]):
        if not hay(orden[0]):
            continue
        try:
            r = subprocess.run(orden + [str(ruta)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               universal_newlines=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip().split(":")[0].split()[0]
    return ""


def ips_validas(valores) -> list:
    salida = []
    for v in valores or []:
        try:
            salida.append(str(ipaddress.ip_address(str(v).strip())))
        except ValueError:
            continue
    return sorted(set(salida))


def resolver(nombre: str) -> list:
    try:
        return ips_validas({x[4][0] for x in socket.getaddrinfo(nombre, None)})
    except (socket.gaierror, UnicodeError):
        return []


def managers_del_agente() -> list:
    """Las direcciones del manager en ossec.conf: aislar sin ellas dejaria el
    equipo sin Wazuh, y con el, sin forma de deshacer el aislamiento."""
    try:
        texto = (WAZUH / "etc" / "ossec.conf").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    ips = []
    for direccion in re.findall(r"<address>\s*([^<\s]+)\s*</address>", texto):
        ips += ips_validas([direccion]) or resolver(direccion)
    return sorted(set(ips))


RE_MOMENTO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$", re.I)


def momento_epoch(valor: str) -> float:
    """ISO 8601 -> epoch. El desplazamiento se aplica (12:00+02:00 son las 10:00 UTC);
    sin zona es UTC, que es como lo dan Sysmon, Tetragon y Falco."""
    m = RE_MOMENTO.match(str(valor).strip())
    if not m:
        raise Fallo("hora de arranque del proceso ilegible: %r" % valor)
    a, mes, d, h, mi, s, frac, zona = m.groups()
    dt = datetime(int(a), int(mes), int(d), int(h), int(mi), int(s), int((frac or "0")[:6].ljust(6, "0")),
                  tzinfo=timezone.utc)
    if zona and zona.upper() != "Z":
        signo = 1 if zona[0] == "+" else -1
        horas, minutos = int(zona[1:3]), int(zona[-2:])
        dt -= signo * timedelta(hours=horas, minutes=minutos)
    return dt.timestamp()


# ═══ Aislamiento de red ══════════════════════════════════════════════════════

def _nft_aislar(permitidos: list) -> str:
    v4 = [i for i in permitidos if ":" not in i]
    v6 = [i for i in permitidos if ":" in i]
    lineas = ["table inet %s" % TABLA_AISLAR, "delete table inet %s" % TABLA_AISLAR,
              "table inet %s {" % TABLA_AISLAR]
    for nombre, gancho, dir_ip, dir_if in (("entrada", "input", "saddr", "iif"),
                                           ("salida", "output", "daddr", "oif"),
                                           ("reenvio", "forward", None, None)):
        lineas.append("  chain %s {" % nombre)
        lineas.append("    type filter hook %s priority -300; policy drop;" % gancho)
        if dir_ip:
            lineas.append('    %s "lo" accept' % dir_if)
            if v4:
                lineas.append("    ip %s { %s } accept" % (dir_ip, ", ".join(v4)))
            if v6:
                lineas.append("    ip6 %s { %s } accept" % (dir_ip, ", ".join(v6)))
        lineas.append("  }")
    lineas.append("}")
    return "\n".join(lineas) + "\n"


def _ipt_quitar(binario: str, cadenas: dict):
    for padre, hija in (("INPUT", cadenas["entrada"]), ("OUTPUT", cadenas["salida"]), ("FORWARD", cadenas["reenvio"])):
        for _ in range(10):
            if ejecutar([binario, "-w", "-D", padre, "-j", hija], comprobar=False).returncode != 0 or SIMULACION:
                break
        ejecutar([binario, "-w", "-F", hija], comprobar=False)
        ejecutar([binario, "-w", "-X", hija], comprobar=False)


def _ipt_aislar(binario: str, permitidos: list):
    _ipt_quitar(binario, CADENAS_IPT)
    for nombre, cadena in CADENAS_IPT.items():
        ejecutar([binario, "-w", "-N", cadena])
        if nombre != "reenvio":
            ejecutar([binario, "-w", "-A", cadena, "-i" if nombre == "entrada" else "-o", "lo", "-j", "ACCEPT"])
            for ip in permitidos:
                ejecutar([binario, "-w", "-A", cadena, "-s" if nombre == "entrada" else "-d", ip, "-j", "ACCEPT"])
        ejecutar([binario, "-w", "-A", cadena, "-j", "DROP"])
    ejecutar([binario, "-w", "-I", "INPUT", "1", "-j", CADENAS_IPT["entrada"]])
    ejecutar([binario, "-w", "-I", "OUTPUT", "1", "-j", CADENAS_IPT["salida"]])
    ejecutar([binario, "-w", "-I", "FORWARD", "1", "-j", CADENAS_IPT["reenvio"]])


def aislar(p: dict) -> tuple:
    permitidos = sorted(set(ips_validas(p.get("permitidos"))) | set(managers_del_agente()))
    if not permitidos:
        raise Fallo("sin IPs permitidas (manager y motor): el equipo perderia Wazuh y no se podria deshacer")
    if hay("nft"):
        ejecutar(["nft", "-f", "-"], entrada=_nft_aislar(permitidos))
        metodo = "nftables"
    elif hay("iptables"):
        _ipt_aislar("iptables", [i for i in permitidos if ":" not in i])
        if hay("ip6tables"):
            _ipt_aislar("ip6tables", [i for i in permitidos if ":" in i])
        metodo = "iptables"
    else:
        raise Fallo("ni nft ni iptables en el equipo")
    guardar("aislamiento.json", {"metodo": metodo, "permitidos": permitidos, "desde": ahora(),
                                 "ejecucion": p.get("ejecucion_id", "")})
    return "equipo aislado con %s; solo habla con %s" % (metodo, ", ".join(permitidos)), {"metodo": metodo, "permitidos": permitidos}


def liberar(p: dict) -> tuple:
    estado = leer("aislamiento.json")
    hecho = []
    if hay("nft"):
        if ejecutar(["nft", "delete", "table", "inet", TABLA_AISLAR], comprobar=False).returncode == 0:
            hecho.append("nftables")
    for binario in ("iptables", "ip6tables"):
        if hay(binario):
            _ipt_quitar(binario, CADENAS_IPT)
            hecho.append(binario)
    try:
        (ESTADO / "aislamiento.json").unlink()
    except OSError:
        pass
    if not hecho:
        raise Fallo("no habia aislamiento que levantar ni herramientas para comprobarlo")
    return "aislamiento levantado (%s)" % ", ".join(hecho), {"previo": estado}


# ═══ Procesos ════════════════════════════════════════════════════════════════

def _arranque_proceso(pid: int) -> float:
    texto = Path("/proc/%d/stat" % pid).read_text()
    campos = texto[texto.rindex(")") + 2:].split()
    ticks = int(campos[19])        # campo 22 de stat: starttime, contando desde el estado (campo 3)
    for linea in Path("/proc/stat").read_text().splitlines():
        if linea.startswith("btime "):
            return int(linea.split()[1]) + ticks / os.sysconf("SC_CLK_TCK")
    raise Fallo("no se pudo leer btime de /proc/stat")


def matar(p: dict) -> tuple:
    try:
        pid = int(p.get("pid"))
    except (TypeError, ValueError):
        raise Fallo("PID no valido: %r" % p.get("pid")) from None
    if pid <= 1 or pid == os.getpid():
        raise Fallo("PID %d protegido" % pid)
    if not Path("/proc/%d" % pid).exists():
        raise Fallo("el proceso %d ya no existe" % pid)
    real = _arranque_proceso(pid)
    esperado = momento_epoch(p.get("inicio", ""))
    if abs(real - esperado) > 2.0:
        raise Fallo("el PID %d se ha reutilizado: arranco %ds despues de lo que dice la alerta; no se mata"
                    % (pid, int(real - esperado)))
    try:
        exe = os.readlink("/proc/%d/exe" % pid)
    except OSError:
        exe = ""
    imagen = str(p.get("imagen") or "")
    if imagen and exe and os.path.basename(imagen) != os.path.basename(exe.replace(" (deleted)", "")):
        raise Fallo("el PID %d es %s, no %s; no se mata" % (pid, exe, imagen))
    datos = {"pid": pid, "exe": exe}
    try:
        datos["linea"] = Path("/proc/%d/cmdline" % pid).read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")[:300]
        if exe and os.path.isfile(exe.replace(" (deleted)", "")):
            datos["sha256"] = sha256(Path(exe.replace(" (deleted)", "")))
    except OSError:
        pass
    COMANDOS_EJECUTADOS.append({"cmd": ["kill", "-9", str(pid)]})
    if not SIMULACION:
        os.kill(pid, signal.SIGKILL)
    return "proceso %d (%s) terminado" % (pid, exe or imagen), datos


# ═══ Ficheros: cuarentena, restauracion y conservacion ═══════════════════════

def _fichero_objetivo(ruta_txt: str, sha_esperado: str) -> tuple:
    if not ruta_txt:
        raise Fallo("sin ruta de fichero")
    ruta = Path(ruta_txt)
    if not ruta.is_absolute():
        raise Fallo("ruta relativa: %s" % ruta_txt)
    if ruta_sistema(ruta):
        raise Fallo("%s es del sistema operativo: no se toca sin una persona" % ruta)
    if ruta.is_symlink() or not ruta.is_file():
        raise Fallo("%s no es un fichero regular (o ya no esta)" % ruta)
    sha = sha256(ruta)
    if sha_esperado and sha != sha_esperado.lower():
        raise Fallo("el contenido de %s ha cambiado desde la alerta (sha256 %s)" % (ruta, sha[:16]))
    return ruta, sha


def _carpeta_custodia(sha: str, ruta: Path) -> Path:
    """Una carpeta por fichero puesto en cuarentena: hash del contenido y de la
    ruta, y nunca una que ya guarde algo. Dos copias identicas en dos rutas no
    se pisan, y cada una se restaura a su sitio."""
    base = "%s-%s" % (sha, hashlib.sha256(str(ruta).encode("utf-8")).hexdigest()[:12])
    n = 1
    destino = CUSTODIA / base
    while (destino / "fichero").exists():
        n += 1
        destino = CUSTODIA / ("%s-%d" % (base, n))
    return destino


def cuarentena(p: dict) -> tuple:
    ruta, sha = _fichero_objetivo(str(p.get("ruta") or ""), str(p.get("sha256") or ""))
    st = ruta.stat()
    destino = _carpeta_custodia(sha, ruta)
    destino.mkdir(parents=True, exist_ok=True)
    os.chmod(str(CUSTODIA), 0o700)
    meta = {"ruta": str(ruta), "sha256": sha, "md5": md5(ruta), "tamano": st.st_size, "modo": st.st_mode & 0o7777,
            "uid": st.st_uid, "gid": st.st_gid, "mtime": st.st_mtime, "cuarentena": ahora(),
            "ejecucion": p.get("ejecucion_id", ""), "caso": p.get("caso", "")}
    shutil.move(str(ruta), str(destino / "fichero"))
    os.chmod(str(destino / "fichero"), 0)
    (destino / "meta.json").write_text(json.dumps(meta, indent=1, sort_keys=True), encoding="utf-8")
    return "%s en cuarentena (sha256 %s)" % (ruta, sha[:16]), {"custodia": str(destino), "sha256": sha, "ruta": str(ruta)}


def restaurar(p: dict) -> tuple:
    sha = str(p.get("sha256") or "").lower()
    ruta = str(p.get("ruta") or "")
    candidatos = []
    for meta in sorted(CUSTODIA.glob("*/meta.json")) if CUSTODIA.is_dir() else []:
        try:
            m = json.loads(meta.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not (meta.parent / "fichero").is_file():
            continue                      # ya restaurado
        if (sha and m.get("sha256") != sha) or (ruta and m.get("ruta") != ruta) or not (sha or ruta):
            continue
        candidatos.append(meta.parent)
    if len({json.loads((c / "meta.json").read_text(encoding="utf-8")).get("ruta") for c in candidatos}) > 1:
        raise Fallo("el sha256 %s esta en custodia desde varias rutas: indica la ruta a restaurar" % sha)
    for carpeta in candidatos[-1:]:
        if (carpeta / "fichero").is_file():
            meta = json.loads((carpeta / "meta.json").read_text(encoding="utf-8"))
            original = Path(meta["ruta"])
            if original.exists():
                raise Fallo("ya hay un fichero en %s: no se sobrescribe" % original)
            original.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(carpeta / "fichero"), str(original))
            os.chmod(str(original), int(meta.get("modo", 0o644)))
            try:
                os.chown(str(original), int(meta["uid"]), int(meta["gid"]))
            except (OSError, KeyError):
                pass
            meta["restaurado"] = ahora()
            (carpeta / "meta.json").write_text(json.dumps(meta, indent=1, sort_keys=True), encoding="utf-8")
            return "%s restaurado desde la custodia" % original, {"ruta": str(original), "sha256": meta["sha256"]}
    raise Fallo("no hay nada en custodia para %s" % (sha or p.get("ruta")))


def conservar(p: dict) -> tuple:
    ruta = Path(str(p.get("ruta") or ""))
    if not ruta.is_absolute() or not ruta.is_file():
        raise Fallo("no hay fichero que conservar en %s" % ruta)
    if almacen_credenciales(ruta):
        raise Fallo("%s es un almacen de credenciales: no se copia a custodia" % ruta)
    sha = sha256(ruta)
    destino = CUSTODIA / "conservados" / sha
    destino.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(ruta), str(destino / "fichero"))
    os.chmod(str(destino / "fichero"), 0o400)
    meta = {"ruta": str(ruta), "sha256": sha, "md5": md5(ruta), "copiado": ahora(), "ejecucion": p.get("ejecucion_id", ""),
            "caso": p.get("caso", "")}
    (destino / "meta.json").write_text(json.dumps(meta, indent=1, sort_keys=True), encoding="utf-8")
    return "copia de %s conservada (sha256 %s)" % (ruta, sha[:16]), {"custodia": str(destino), "sha256": sha}


# ═══ Persistencia ════════════════════════════════════════════════════════════

def persistencia(p: dict) -> tuple:
    ruta_txt = str(p.get("ruta") or "")
    nombre = str(p.get("nombre") or "")
    if not ruta_txt and nombre.endswith((".service", ".timer")):
        for base in ("/etc/systemd/system/", "/lib/systemd/system/", "/usr/lib/systemd/system/"):
            if os.path.isfile(base + nombre):
                ruta_txt = base + nombre
                break
    if not ruta_txt:
        raise Fallo("sin ruta del elemento de persistencia")
    ruta = Path(ruta_txt)
    if not ruta.is_absolute():
        raise Fallo("ruta relativa: %s" % ruta_txt)
    if ruta.is_symlink() or not ruta.is_file():
        raise Fallo("%s no es un fichero regular" % ruta)
    if ruta_sistema(ruta):
        raise Fallo("%s es del sistema operativo: no se toca sin una persona" % ruta)
    linea_a_linea = ruta_txt.startswith(DIRS_CRON) or str(ruta) == "/etc/ld.so.preload"
    if linea_a_linea and not nombre:
        # /etc/crontab, /etc/cron.d/* o ld.so.preload enteros llevan tareas
        # legitimas: sin el patron de la linea maliciosa no se retira nada.
        raise Fallo("%s se limpia linea a linea y la alerta no dice cual: lo decide una persona" % ruta)
    if not linea_a_linea:
        paquete = paquete_de(ruta)
        if paquete:
            raise Fallo("%s es del paquete %s: retirarlo romperia el sistema, lo decide una persona" % (ruta, paquete))
    destino = CUSTODIA / "persistencia" / hashlib.sha256(str(ruta).encode()).hexdigest()[:24]
    destino.mkdir(parents=True, exist_ok=True)
    st = ruta.stat()
    meta = {"ruta": str(ruta), "modo": st.st_mode & 0o7777, "uid": st.st_uid, "gid": st.st_gid,
            "sha256": sha256(ruta), "momento": ahora(), "ejecucion": p.get("ejecucion_id", "")}
    shutil.copy2(str(ruta), str(destino / "original"))
    if ruta_txt.startswith(DIRS_SYSTEMD) and ruta.suffix in (".service", ".timer", ".socket", ".path"):
        meta["tipo"] = "systemd"
        ejecutar(["systemctl", "disable", "--now", ruta.name], comprobar=False)
        ruta.unlink()
        ejecutar(["systemctl", "daemon-reload"], comprobar=False)
        detalle = "unidad %s parada, deshabilitada y retirada" % ruta.name
    elif ruta_txt.startswith(DIRS_CRON):
        # crontab (de usuario, /etc/crontab o /etc/cron.d): solo las lineas que
        # casan, no todas las tareas del equipo o del usuario
        lineas = ruta.read_text(encoding="utf-8", errors="replace").splitlines(True)
        quitadas = [l for l in lineas if nombre in l]
        if not quitadas:
            raise Fallo("ninguna linea de %s contiene %r" % (ruta, nombre))
        ruta.write_text("".join(l for l in lineas if nombre not in l), encoding="utf-8")
        meta.update(tipo="crontab", lineas=quitadas)
        detalle = "%d linea(s) retiradas de %s" % (len(quitadas), ruta)
    elif str(ruta) == "/etc/ld.so.preload" and nombre:
        lineas = ruta.read_text(encoding="utf-8", errors="replace").splitlines(True)
        quitadas = [l for l in lineas if nombre in l]
        if not quitadas:
            raise Fallo("ninguna linea de %s contiene %r" % (ruta, nombre))
        ruta.write_text("".join(l for l in lineas if nombre not in l), encoding="utf-8")
        meta.update(tipo="ld_preload", lineas=quitadas)
        detalle = "entrada %s retirada de /etc/ld.so.preload" % nombre
    else:
        meta["tipo"] = "fichero"
        ruta.unlink()
        detalle = "%s retirado (copia en custodia)" % ruta
    (destino / "meta.json").write_text(json.dumps(meta, indent=1, sort_keys=True), encoding="utf-8")
    return detalle, {"custodia": str(destino), "tipo": meta["tipo"], "ruta": str(ruta)}


def persistencia_restaurar(p: dict) -> tuple:
    ruta = Path(str(p.get("ruta") or ""))
    destino = CUSTODIA / "persistencia" / hashlib.sha256(str(ruta).encode()).hexdigest()[:24]
    try:
        meta = json.loads((destino / "meta.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise Fallo("no hay copia de %s en custodia" % ruta) from None
    if meta["tipo"] in ("crontab", "ld_preload"):
        with open(str(ruta), "a", encoding="utf-8") as f:
            f.writelines(meta.get("lineas") or [])
        detalle = "%d linea(s) devueltas a %s" % (len(meta.get("lineas") or []), ruta)
    else:
        if ruta.exists():
            raise Fallo("ya existe %s: no se sobrescribe" % ruta)
        shutil.copy2(str(destino / "original"), str(ruta))
        os.chmod(str(ruta), int(meta.get("modo", 0o644)))
        try:
            os.chown(str(ruta), int(meta["uid"]), int(meta["gid"]))
        except (OSError, KeyError):
            pass
        detalle = "%s restaurado" % ruta
        if meta["tipo"] == "systemd":
            ejecutar(["systemctl", "daemon-reload"], comprobar=False)
            ejecutar(["systemctl", "enable", ruta.name], comprobar=False)
            detalle += " y habilitado de nuevo (no se arranca: decide la persona)"
    return detalle, {"ruta": str(ruta)}


# ═══ Bloqueo de destinos en este equipo ══════════════════════════════════════

def _destinos(p: dict) -> list:
    destino = str(p.get("destino") or "")
    if not RE_DESTINO.match(destino):
        raise Fallo("destino no valido: %r" % destino)
    ips = ips_validas([destino]) or resolver(destino)
    if not ips:
        raise Fallo("%s no resuelve a ninguna IP" % destino)
    publicas = [i for i in ips if not ipaddress.ip_address(i).is_private and not ipaddress.ip_address(i).is_loopback]
    if not publicas:
        raise Fallo("%s solo resuelve a IPs internas (%s): bloquearlas en el equipo necesita una persona"
                    % (destino, ", ".join(ips)))
    return publicas


def bloquear_destino(p: dict) -> tuple:
    ips = _destinos(p)
    if hay("nft"):
        v4 = [i for i in ips if ":" not in i]
        v6 = [i for i in ips if ":" in i]
        script = ["table inet %s {" % TABLA_DESTINOS,
                  "  set v4 { type ipv4_addr; }", "  set v6 { type ipv6_addr; }",
                  "  chain salida { type filter hook output priority -290; policy accept;",
                  "    ip daddr @v4 drop", "    ip6 daddr @v6 drop", "  }", "}"]
        if v4:
            script.append("add element inet %s v4 { %s }" % (TABLA_DESTINOS, ", ".join(v4)))
        if v6:
            script.append("add element inet %s v6 { %s }" % (TABLA_DESTINOS, ", ".join(v6)))
        ejecutar(["nft", "-f", "-"], entrada="\n".join(script) + "\n")
        metodo = "nftables"
    elif hay("iptables"):
        for binario, familia in (("iptables", 4), ("ip6tables", 6)):
            propias = [i for i in ips if ipaddress.ip_address(i).version == familia]
            if not propias or not hay(binario):
                continue
            ejecutar([binario, "-w", "-N", CADENA_DESTINOS], comprobar=False)
            if ejecutar([binario, "-w", "-C", "OUTPUT", "-j", CADENA_DESTINOS], comprobar=False).returncode != 0:
                ejecutar([binario, "-w", "-I", "OUTPUT", "1", "-j", CADENA_DESTINOS])
            for ip in propias:
                ejecutar([binario, "-w", "-A", CADENA_DESTINOS, "-d", ip, "-j", "DROP"])
        metodo = "iptables"
    else:
        raise Fallo("ni nft ni iptables en el equipo")
    bloqueos = leer("destinos.json")
    bloqueos[str(p.get("destino"))] = {"ips": ips, "metodo": metodo, "desde": ahora()}
    guardar("destinos.json", bloqueos)
    return "salida bloqueada hacia %s (%s)" % (p.get("destino"), ", ".join(ips)), {"ips": ips, "metodo": metodo}


def desbloquear_destino(p: dict) -> tuple:
    bloqueos = leer("destinos.json")
    previo = bloqueos.pop(str(p.get("destino")), None)
    if not previo:
        raise Fallo("no consta ningun bloqueo de %s en este equipo" % p.get("destino"))
    for ip in previo["ips"]:
        if previo["metodo"] == "nftables":
            familia = "v6" if ":" in ip else "v4"
            ejecutar(["nft", "delete", "element", "inet", TABLA_DESTINOS, familia, "{ %s }" % ip], comprobar=False)
        else:
            binario = "ip6tables" if ":" in ip else "iptables"
            ejecutar([binario, "-w", "-D", CADENA_DESTINOS, "-d", ip, "-j", "DROP"], comprobar=False)
    guardar("destinos.json", bloqueos)
    return "salida hacia %s desbloqueada" % p.get("destino"), {"ips": previo["ips"]}


# ═══ Claves SSH ══════════════════════════════════════════════════════════════

def _authorized_keys(p: dict) -> Path:
    if p.get("ruta"):
        return Path(str(p["ruta"]))
    import pwd
    try:
        return Path(pwd.getpwnam(str(p.get("usuario") or "")).pw_dir) / ".ssh" / "authorized_keys"
    except KeyError:
        raise Fallo("usuario desconocido: %r" % p.get("usuario")) from None


def ssh_clave(p: dict) -> tuple:
    ruta = _authorized_keys(p)
    clave = str(p.get("clave") or "").split()
    material = clave[1] if len(clave) > 1 else (clave[0] if clave else "")
    if len(material) < 40:
        raise Fallo("clave SSH no identificada sin ambiguedad")
    lineas = ruta.read_text(encoding="utf-8", errors="replace").splitlines(True)
    quitadas = [l for l in lineas if material in l]
    if not quitadas:
        raise Fallo("la clave no esta en %s" % ruta)
    destino = CUSTODIA / "ssh" / hashlib.sha256(str(ruta).encode()).hexdigest()[:24]
    destino.mkdir(parents=True, exist_ok=True)
    previas = leer_json(destino / "quitadas.json", [])
    (destino / "quitadas.json").write_text(json.dumps(previas + quitadas, indent=1), encoding="utf-8")
    (destino / "ruta.txt").write_text(str(ruta), encoding="utf-8")
    ruta.write_text("".join(l for l in lineas if material not in l), encoding="utf-8")
    return "%d clave(s) retiradas de %s" % (len(quitadas), ruta), {"ruta": str(ruta), "claves": len(quitadas)}


def ssh_clave_restaurar(p: dict) -> tuple:
    ruta = _authorized_keys(p)
    destino = CUSTODIA / "ssh" / hashlib.sha256(str(ruta).encode()).hexdigest()[:24]
    quitadas = leer_json(destino / "quitadas.json", [])
    if not quitadas:
        raise Fallo("no hay claves retiradas de %s" % ruta)
    with open(str(ruta), "a", encoding="utf-8") as f:
        f.writelines(quitadas)
    (destino / "quitadas.json").write_text("[]", encoding="utf-8")
    return "%d clave(s) devueltas a %s" % (len(quitadas), ruta), {"ruta": str(ruta)}


def leer_json(ruta: Path, defecto):
    try:
        return json.loads(ruta.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return defecto


# ═══ Triage forense (FtriageDFIR), en segundo plano ═════════════════════════

def _ftriage(conf: dict) -> tuple:
    script = Path(conf.get("ftriage") or "/opt/ftriage/triage.py")
    python = conf.get("python_ftriage") or sys.executable
    if not script.is_file():
        raise Fallo("FtriageDFIR no esta instalado en %s (clave 'ftriage' de responselab.conf)" % script)
    return python, script


def triage(p: dict) -> tuple:
    conf = configuracion()
    python, script = _ftriage(conf)
    caso = re.sub(r"[^A-Za-z0-9_.-]", "_", str(p.get("caso") or p.get("ejecucion_id") or "responselab"))[:60]
    salida = ESTADO / "triage" / ("%s_%s" % (caso, time.strftime("%Y%m%dT%H%M%S")))
    salida.parent.mkdir(parents=True, exist_ok=True)
    argumentos = json.dumps({"python": str(python), "script": str(script), "salida": str(salida), "caso": caso,
                             "ejecucion_id": p.get("ejecucion_id", "")})
    COMANDOS_EJECUTADOS.append({"cmd": [sys.executable, __file__, "_triage_en_segundo_plano", argumentos]})
    if not SIMULACION:
        registro = open(str(salida) + ".log", "a")
        subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "_triage_en_segundo_plano", argumentos],
                         stdin=subprocess.DEVNULL, stdout=registro, stderr=registro, close_fds=True,
                         start_new_session=True)
    return "triage forense lanzado en segundo plano (%s)" % salida, {"salida": str(salida), "estado": "en_curso"}


def resumen_ftriage(informe: dict) -> dict:
    """Lo que cabe en un acuse: veredicto, tecnicas, IOCs publicos, hallazgos criticos."""
    ev = informe.get("assessment") or {}
    evaluacion = {k: ev.get(k) for k in ("verdict", "verdict_key", "risk_score", "confidence")}
    evaluacion["attack_techniques"] = [{"attack": t.get("attack"), "tactic": t.get("tactic")}
                                       for t in (ev.get("attack_techniques") or [])[:20]]
    return {
        "host": {"hostname": (informe.get("host") or {}).get("hostname", "")},
        "case": {"name": (informe.get("case") or {}).get("name", "")},
        "assessment": evaluacion,
        "iocs": [{"type": i.get("type"), "value": i.get("value"), "defanged": i.get("defanged")}
                 for i in (informe.get("iocs") or []) if not i.get("private")][:30],
        "findings": [{"level": f.get("level"), "text": str(f.get("text", ""))[:200]}
                     for f in (informe.get("findings") or []) if f.get("level") == "crit"][:10],
    }


def _triage_en_segundo_plano(argumentos: str):
    a = json.loads(argumentos)
    salida = Path(a["salida"])
    try:
        r = subprocess.run([a["python"], a["script"], "triage", "--case", a["caso"], "--examiner", "ResponseLab",
                            "--output", str(salida)], stdin=subprocess.DEVNULL, timeout=4 * 3600)
        informe_ruta = salida / "report.json"
        if r.returncode != 0 or not informe_ruta.is_file():
            raise Fallo("ftriage termino con codigo %d sin report.json" % r.returncode)
        informe = json.loads(informe_ruta.read_text(encoding="utf-8"))
        datos = {"salida": str(salida), "sha256_informe": sha256(informe_ruta),
                 "sha256_manifiesto": sha256(salida / "manifest.json") if (salida / "manifest.json").is_file() else "",
                 "informe_ftriage": resumen_ftriage(informe)}
        conf = configuracion()
        if conf.get("motor") and conf.get("token_agentes") and conf.get("cliente"):
            try:
                _subir(conf, "/v1/%s/evidencias/ftriage" % conf["cliente"], informe)
                datos["subido"] = True
                datos.pop("informe_ftriage")      # el motor ya tiene el informe entero
            except Exception as e:  # el resumen sigue llegando por Wazuh
                datos["subido"] = False
                datos["error_subida"] = str(e)[:200]
        acuse("triage", "aplicada", "triage terminado: %s" % ((informe.get("assessment") or {}).get("verdict") or "sin veredicto"),
              a.get("ejecucion_id", ""), datos)
    except Exception as e:
        acuse("triage", "fallida", "el triage no termino: %s" % e, a.get("ejecucion_id", ""), {"salida": str(salida)})


def _subir(conf: dict, ruta: str, cuerpo: dict):
    import ssl
    contexto = ssl.create_default_context(cafile=conf.get("ca") or None)
    peticion = urllib.request.Request(conf["motor"].rstrip("/") + ruta, method="POST",
                                      data=json.dumps(cuerpo).encode("utf-8"),
                                      headers={"Authorization": "Bearer " + conf["token_agentes"],
                                               "Content-Type": "application/json"})
    with urllib.request.urlopen(peticion, context=contexto, timeout=60) as r:
        if r.status >= 300:
            raise Fallo("el motor respondio %d" % r.status)


def instantanea_ad(p: dict) -> tuple:
    raise Fallo("la instantanea de un objeto de AD se hace desde un equipo Windows con RSAT")


ACCIONES = {
    "aislar": aislar, "liberar": liberar, "matar": matar, "cuarentena": cuarentena, "restaurar": restaurar,
    "persistencia": persistencia, "persistencia-restaurar": persistencia_restaurar,
    "bloquear-destino": bloquear_destino, "desbloquear-destino": desbloquear_destino,
    "triage": triage, "conservar": conservar, "ssh-clave": ssh_clave, "ssh-clave-restaurar": ssh_clave_restaurar,
    "instantanea-ad": instantanea_ad,
}


# ═══ Protocolo de Wazuh ══════════════════════════════════════════════════════

def leer_mensaje() -> dict:
    linea = sys.stdin.readline()
    if not linea:
        raise Fallo("execd no envio nada por stdin")
    mensaje = json.loads(linea)
    if mensaje.get("command") not in ("add", "delete"):
        raise Fallo("comando de execd no reconocido: %r" % mensaje.get("command"))
    return mensaje


def pedir_permiso(accion: str, claves: list) -> bool:
    """check_keys: execd contesta continue o abort. Con '!' no hay lista de
    tiempos y siempre contesta continue, pero se respeta el protocolo."""
    mensaje = {"version": 1, "origin": {"name": "responselab-" + accion, "module": "active-response"},
               "command": "check_keys", "parameters": {"keys": claves}}
    sys.stdout.write(json.dumps(mensaje, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    respuesta = sys.stdin.readline()
    if not respuesta:
        return True
    try:
        return json.loads(respuesta).get("command") != "abort"
    except ValueError:
        return True


def main(argv) -> int:
    if len(argv) > 2 and argv[1] == "_triage_en_segundo_plano":
        _triage_en_segundo_plano(argv[2])
        return 0
    accion = argv[1] if len(argv) > 1 else ""
    if accion not in ACCIONES:
        acuse(accion or "?", "fallida", "accion desconocida")
        return 1
    ejecucion = ""
    try:
        mensaje = leer_mensaje()
        alerta = (mensaje.get("parameters") or {}).get("alert") or {}
        p = ((alerta.get("data") or {}).get("responselab")) or {}
        if not isinstance(p, dict):
            raise Fallo("parametros de ResponseLab ausentes en la orden")
        ejecucion = str(p.get("ejecucion_id") or "")
        if mensaje["command"] == "delete":
            return 0                      # ResponseLab deshace con su accion inversa, no con timeouts
        if not pedir_permiso(accion, [ejecucion or accion]):
            acuse(accion, "rechazada", "execd aborto la orden (repetida)", ejecucion)
            return 0
        detalle, datos = ACCIONES[accion](p)
        estado = (datos or {}).pop("estado", "aplicada") if isinstance(datos, dict) else "aplicada"
        acuse(accion, estado, detalle, ejecucion, datos)
        return 0
    except Fallo as e:
        acuse(accion, "fallida", str(e), ejecucion)
        return 1
    except Exception as e:  # nunca dejar a execd sin acuse
        acuse(accion, "fallida", "error inesperado: %s: %s" % (type(e).__name__, e), ejecucion)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
