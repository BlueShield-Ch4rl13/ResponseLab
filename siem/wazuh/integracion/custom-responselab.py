#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
custom-responselab.py: integracion Wazuh -> motor de ResponseLab.

La ejecuta wazuh-integratord por cada alerta que pasa los filtros de un bloque
<integration> con <name>custom-responselab</name> (ver ossec-responselab.conf,
que se genera con la lista exacta de reglas que el catalogo conoce). Dos casos:

  * acuse de un script de active response (regla 109900, grupo
    responselab_acuse)     -> POST /v1/<cliente>/acuses
  * cualquier otra alerta  -> POST /v1/<cliente>/alertas/wazuh

Si el motor no contesta, la alerta se guarda en <wazuh>/var/responselab/pendientes
y se reenvia con la siguiente: integratord no reintenta por su cuenta y una
alerta critica no se puede perder porque el motor se estuviera reiniciando.
El motor descarta duplicados por id de alerta.

Configuracion: <wazuh>/etc/responselab.json (root:wazuh, 640). Ver
responselab.json.ejemplo. Los tokens viven ahi y no en ossec.conf, que leen
mas procesos y se copia en mas sitios.

Argumentos de integratord (src/os_integrator/integrator.c, Wazuh 4.x):
  1 fichero con la alerta   2 api_key   3 hook_url   4 "debug" o ""
  5 fichero de opciones     6 timeout   7 reintentos
Con argumentos vacios las posiciones pueden correrse: se buscan por forma.

Solo biblioteca estandar (corre con el Python que trae el manager).
"""
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

AQUI = Path(__file__).resolve().parent                      # <wazuh>/integrations
WAZUH = Path(os.environ.get("RL_WAZUH_DIR") or AQUI.parent)
CONFIG = WAZUH / "etc" / "responselab.json"
PENDIENTES = WAZUH / "var" / "responselab" / "pendientes"
REGISTRO = WAZUH / "logs" / "integrations.log"
MAX_PENDIENTES = 5000
GRUPO_ACUSE = "responselab_acuse"


def registrar(mensaje: str):
    try:
        with open(str(REGISTRO), "a") as f:
            f.write("%s custom-responselab: %s\n" % (time.strftime("%Y/%m/%d %H:%M:%S"), mensaje))
    except OSError:
        pass


def argumentos(argv: list) -> dict:
    a = {"alerta": argv[1] if len(argv) > 1 else "", "hook": "", "api_key": "", "opciones": "", "debug": False}
    for x in argv[2:]:
        if x.startswith(("http://", "https://")):
            a["hook"] = x
        elif x.endswith(".options") and os.path.isfile(x):
            a["opciones"] = x
        elif x == "debug":
            a["debug"] = True
    # Integratord pasa: alerta, api_key, hook_url, "debug", fichero .options,
    # timeout y reintentos. Con api_key y hook_url vacios la linea se desplaza:
    # un .options o un numero en la segunda posicion no son una clave.
    if len(argv) > 2:
        candidata = argv[2]
        if candidata and not candidata.startswith(("http://", "https://")) and candidata != "debug" \
                and not candidata.endswith(".options") and not candidata.isdigit():
            a["api_key"] = candidata
    return a


def cargar_config(a: dict) -> dict:
    conf = {}
    try:
        conf = json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        if not a["hook"]:
            raise SystemExit("sin %s ni hook_url: %s" % (CONFIG, e)) from None
    if a["opciones"]:
        try:
            conf.update(json.loads(Path(a["opciones"]).read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass
    if a["hook"] and not conf.get("motor"):
        conf["motor"] = a["hook"]
    if a["api_key"] and conf.get("cliente"):
        conf.setdefault("clientes", {}).setdefault(conf["cliente"], {}).setdefault("token_ingesta", a["api_key"])
    if not conf.get("motor") or not conf.get("cliente"):
        raise SystemExit("responselab.json necesita 'motor' y 'cliente'")
    return conf


def cliente_de(alerta: dict, conf: dict) -> str:
    agente = str((alerta.get("agent") or {}).get("name") or "")
    for regla in conf.get("clientes_por_agente") or []:
        try:
            if re.search(regla["patron"], agente):
                return regla["cliente"]
        except (KeyError, re.error):
            continue
    return conf["cliente"]


def es_acuse(alerta: dict) -> bool:
    return GRUPO_ACUSE in ((alerta.get("rule") or {}).get("groups") or []) and \
        isinstance((alerta.get("data") or {}).get("responselab_ar"), dict)


def peticion(alerta: dict, conf: dict) -> tuple:
    cliente = cliente_de(alerta, conf)
    tokens = (conf.get("clientes") or {}).get(cliente) or {}
    if es_acuse(alerta):
        d = alerta["data"]["responselab_ar"]
        detalle = {"detalle": d.get("detalle", ""), "accion": d.get("accion", ""), "equipo": d.get("equipo", ""),
                   "agente": (alerta.get("agent") or {}).get("name", ""), "alerta_wazuh": alerta.get("id", "")}
        datos = d.get("datos")
        if isinstance(datos, str) and datos:
            try:
                datos = json.loads(datos)
            except ValueError:
                datos = {"texto": datos[:2000]}
        if isinstance(datos, dict):
            detalle.update(datos)
        cuerpo = {"ejecucion_id": d.get("ejecucion_id", ""), "estado": d.get("estado", ""), "detalle": detalle}
        return "/v1/%s/acuses" % cliente, cuerpo, tokens.get("token_agentes", "")
    return "/v1/%s/alertas/wazuh" % cliente, alerta, tokens.get("token_ingesta", "")


def enviar(conf: dict, ruta: str, cuerpo: dict, token: str) -> int:
    if not token:
        raise ValueError("no hay token para %s en responselab.json" % ruta)
    if conf.get("verificar_tls", True):
        contexto = ssl.create_default_context(cafile=conf.get("ca") or None)
    else:
        contexto = ssl._create_unverified_context()   # solo laboratorio: lo dice la configuracion
    req = urllib.request.Request(conf["motor"].rstrip("/") + ruta, method="POST",
                                 data=json.dumps(cuerpo).encode("utf-8"),
                                 headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                                          "User-Agent": "wazuh-custom-responselab/1.0"})
    try:
        with urllib.request.urlopen(req, context=contexto, timeout=float(conf.get("timeout", 10))) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def guardar_pendiente(ruta: str, cuerpo: dict, token_de: str):
    PENDIENTES.mkdir(parents=True, exist_ok=True)
    if len(list(PENDIENTES.iterdir())) >= MAX_PENDIENTES:
        registrar("cola de pendientes llena (%d): se descarta una alerta" % MAX_PENDIENTES)
        return
    nombre = "%d-%d.json" % (time.time() * 1000, os.getpid())
    (PENDIENTES / nombre).write_text(json.dumps({"ruta": ruta, "cuerpo": cuerpo, "token_de": token_de}), encoding="utf-8")


def vaciar_pendientes(conf: dict, limite: int = 50):
    if not PENDIENTES.is_dir():
        return
    for f in sorted(PENDIENTES.iterdir())[:limite]:
        # Leer y entender el fichero: si esta roto, se descarta (nunca se arreglara)
        try:
            p = json.loads(f.read_text(encoding="utf-8"))
            cliente = p["ruta"].split("/")[2]
            token = ((conf.get("clientes") or {}).get(cliente) or {}).get(p["token_de"], "")
        except (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError):
            registrar("pendiente %s ilegible: se descarta" % f.name)
            f.unlink()
            continue
        # Enviarlo: si falla la red (URLError es un OSError) se conserva para la
        # siguiente vez. Antes se confundia con un fichero roto y se borraba.
        try:
            estado = enviar(conf, p["ruta"], p["cuerpo"], token)
        except ValueError as e:
            registrar("pendiente %s sin token (%s): se conserva" % (f.name, e))
            continue
        except Exception:
            return                     # el motor sigue sin contestar: se reintenta con la siguiente alerta
        if estado < 500:
            f.unlink()                 # 2xx entregada; 4xx no mejorara reintentando (se registra)
            if estado >= 400:
                registrar("pendiente %s rechazado por el motor (%d)" % (f.name, estado))
        else:
            return


def main(argv: list) -> int:
    a = argumentos(argv)
    try:
        alerta = json.loads(Path(a["alerta"]).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        registrar("alerta ilegible %s: %s" % (a["alerta"], e))
        return 1
    try:
        conf = cargar_config(a)
    except SystemExit as e:
        registrar(str(e))
        return 1
    ruta, cuerpo, token = peticion(alerta, conf)
    token_de = "token_agentes" if ruta.endswith("/acuses") else "token_ingesta"
    vaciar_pendientes(conf)
    ultimo = ""
    for intento in range(int(conf.get("reintentos", 2)) + 1):
        try:
            estado = enviar(conf, ruta, cuerpo, token)
        except ValueError as e:
            registrar(str(e))
            return 1
        except Exception as e:  # red, TLS, DNS: se reintenta y, si no, a la cola
            estado, ultimo = 0, "%s: %s" % (type(e).__name__, e)
        if 200 <= estado < 300:
            if a["debug"]:
                registrar("enviada %s (%d)" % (ruta, estado))
            return 0
        if 400 <= estado < 500:
            registrar("el motor rechazo %s con %d (revisa token y cliente)" % (ruta, estado))
            return 1
        time.sleep(1 + intento)
    guardar_pendiente(ruta, cuerpo, token_de)
    registrar("motor no disponible (%s): %s queda en pendientes" % (ultimo or "HTTP %d" % estado, ruta))
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
