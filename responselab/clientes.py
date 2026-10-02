"""
Perfiles de cliente (MSSP): uno por fichero en clientes/<id>.yml.

Que hay en un perfil y por que
------------------------------
* Que herramienta hace cada capacidad (edr: defender, perimetro: [paloalto, edl]).
* La politica: que se le permite al motor en automatico con ESE cliente.
* El inventario y las listas con las que se contestan las preguntas de triaje.
* Quien aprueba, a quien se escala y por que canal.

Lo que NO hay: secretos. Cada clave es el NOMBRE de una variable de entorno
(``api_key_env: RL_ACME_THEHIVE_KEY``) y los tokens de acceso se guardan como
su huella SHA-256. Un perfil se puede versionar en git y revisar en un pull
request sin exponer nada.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
from pathlib import Path

import yaml

from . import nucleo

log = logging.getLogger("responselab.clientes")

MODOS = ("simulacion", "produccion")


def huella(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def iguales(a: str, b: str) -> bool:
    """Comparacion en tiempo constante que no revienta con texto no ASCII."""
    return hmac.compare_digest(str(a).encode("utf-8"), str(b).encode("utf-8"))


def secreto(cfg: dict, clave: str) -> str:
    """Lee el valor de `clave_env` del entorno. Nunca lee `clave` en claro."""
    nombre = (cfg or {}).get(f"{clave}_env")
    return os.environ.get(nombre, "") if nombre else ""


# Claves que son secretos. En un perfil solo pueden aparecer como <clave>_env
# (el nombre de una variable de entorno) o, los tokens de acceso, como
# token_sha256. Se buscan en todo el perfil, no solo en conectores.
CLAVES_SECRETAS = {"api_key", "api_token", "apikey", "clave", "clave_privada", "client_secret", "contrasena",
                   "password", "private_key", "secret", "secreto", "token", "webhook", "webhook_url"}
RE_URL_CON_CREDENCIALES = re.compile(r"^[a-z][a-z0-9+.-]*://[^/@\s]+:[^/@\s]+@", re.I)
RE_HORA = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")
DIAS = {"lu", "ma", "mi", "ju", "vi", "sa", "do", "0", "1", "2", "3", "4", "5", "6"}


def _secretos_en_claro(nodo, ruta: str = "") -> list[str]:
    errores = []
    if isinstance(nodo, dict):
        for k, v in nodo.items():
            r = f"{ruta}.{k}" if ruta else str(k)
            if str(k).lower() in CLAVES_SECRETAS and isinstance(v, (str, int, float)) and str(v).strip():
                errores.append(f"{r}: secreto en claro; usa {k}_env con el nombre de una variable")
            else:
                errores += _secretos_en_claro(v, r)
    elif isinstance(nodo, list):
        for i, v in enumerate(nodo):
            errores += _secretos_en_claro(v, f"{ruta}[{i}]")
    elif isinstance(nodo, str) and RE_URL_CON_CREDENCIALES.match(nodo.strip()):
        errores.append(f"{ruta}: URL con usuario y contrasena en claro")
    return errores


def _regex_invalida(patron) -> str:
    try:
        re.compile(str(patron))
        return ""
    except re.error as e:
        return str(e)


def validar_perfil(p: dict) -> list[str]:
    errores = []
    if not p.get("id"):
        errores.append("falta id")
    if p.get("modo", "simulacion") not in MODOS:
        errores.append(f"modo '{p.get('modo')}' no valido ({', '.join(MODOS)})")
    errores += _secretos_en_claro(p)
    inv = p.get("inventario") or {}
    patrones = [("inventario.protegidos", x) for x in inv.get("protegidos") or []]
    patrones += [("inventario.activos.patron", a.get("patron")) for a in inv.get("activos") or []
                 if isinstance(a, dict) and a.get("patron")]
    for i, v in enumerate(p.get("ventanas") or []):
        if not isinstance(v, dict):
            errores.append(f"ventanas[{i}]: debe ser un diccionario")
            continue
        patrones += [(f"ventanas[{i}].equipos", x) for x in v.get("equipos") or []]
        if v.get("inicio") or v.get("fin"):
            for k in ("inicio", "fin"):
                if not nucleo.a_fecha(v.get(k)):
                    errores.append(f"ventanas[{i}].{k}: fecha ISO 8601 no valida ({v.get(k)!r})")
            continue
        for k in ("desde", "hasta"):
            if not (isinstance(v.get(k), str) and RE_HORA.match(v[k].strip())):
                errores.append(f"ventanas[{i}].{k}: hora no valida ({v.get(k)!r}); escribela entre comillas, "
                               f"p.ej. \"06:00\" (sin comillas YAML la convierte en un numero)")
        dias = v.get("dias") or []
        if not dias or any(str(d).lower()[:2] not in DIAS for d in dias):
            errores.append(f"ventanas[{i}].dias: usa lu, ma, mi, ju, vi, sa, do ({dias!r})")
    for donde, patron in patrones:
        fallo = _regex_invalida(patron)
        if fallo:
            errores.append(f"{donde}: expresion regular no valida {patron!r} ({fallo})")
    pol = p.get("politica") or {}
    if pol.get("excepcion_sin_datos", "aprobacion") not in ("aprobacion", "ignorar"):
        errores.append("politica.excepcion_sin_datos debe ser 'aprobacion' o 'ignorar'")
    for ap in p.get("aprobadores") or []:
        if not (ap.get("token_sha256") or ap.get("token_env")):
            errores.append(f"aprobador {ap.get('nombre')}: sin token_sha256 ni token_env")
    return errores


class Clientes:
    def __init__(self, carpeta: Path):
        self.carpeta = carpeta
        self.perfiles: dict[str, dict] = {}
        self._mtimes: dict[str, float] = {}
        self._ids: dict[str, str] = {}          # fichero -> id del cliente que define
        self.errores: dict[str, list[str]] = {}
        self.recargar()

    def recargar(self) -> bool:
        """Relee los perfiles si alguno cambio. Un perfil invalido no sustituye al bueno."""
        cambio = False
        vistos = set()
        if not self.carpeta.is_dir():
            return False
        for f in sorted(self.carpeta.glob("*.yml")):
            if f.name.startswith("_"):
                continue                     # _plantilla.yml no es un cliente
            vistos.add(f.name)
            mtime = f.stat().st_mtime
            if self._mtimes.get(f.name) == mtime:
                continue
            try:
                p = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as e:
                self.errores[f.name] = [f"YAML invalido: {e}"]
                log.error("perfil %s invalido: %s", f.name, e)
                continue
            errores = validar_perfil(p)
            if errores:
                self.errores[f.name] = errores
                log.error("perfil %s con errores: %s", f.name, errores)
                continue
            self.errores.pop(f.name, None)
            anterior = self._ids.get(f.name)
            if anterior and anterior != p["id"]:
                self.perfiles.pop(anterior, None)   # el fichero ha cambiado de id
            self.perfiles[p["id"]] = p
            self._ids[f.name] = p["id"]
            self._mtimes[f.name] = mtime
            cambio = True
        # Un perfil borrado deja de existir en el acto: sus tokens dejan de valer.
        for nombre in list(self._ids):
            if nombre not in vistos:
                self.perfiles.pop(self._ids.pop(nombre), None)
                self._mtimes.pop(nombre, None)
                self.errores.pop(nombre, None)
                cambio = True
        return cambio

    def get(self, cliente_id: str) -> dict | None:
        p = self.perfiles.get(cliente_id)
        return p if p and p.get("activo", True) else None

    def todos(self) -> list[dict]:
        return [p for p in self.perfiles.values() if p.get("activo", True)]

    # ── autenticacion ──
    @staticmethod
    def _casa_token(token: str, cfg: dict) -> bool:
        if not token or not cfg:
            return False
        if cfg.get("token_sha256"):
            return iguales(huella(token), str(cfg["token_sha256"]).lower())
        esperado = secreto(cfg, "token")
        return bool(esperado) and iguales(token, esperado)

    def token_ingesta_valido(self, cliente_id: str, token: str) -> bool:
        p = self.get(cliente_id)
        return bool(p) and self._casa_token(token, p.get("autenticacion") or {})

    def token_agente_valido(self, cliente_id: str, token: str) -> bool:
        """Token de los agentes (acuses de active response, informes de triage)."""
        p = self.get(cliente_id)
        if not p:
            return False
        # Sin recurrir al token de ingesta: ese viaja en ?token= (webhook de
        # Splunk) y acaba en los registros de los proxies. Con el, cualquiera
        # podria confirmar acciones o inyectar informes de triage.
        agentes = (p.get("autenticacion") or {}).get("agentes") or {}
        return self._casa_token(token, agentes)

    def token_edl_valido(self, cliente_id: str, token: str) -> bool:
        p = self.get(cliente_id)
        if not p:
            return False
        return self._casa_token(token, (p.get("autenticacion") or {}).get("edl") or {})

    def aprobador(self, cliente_id: str, token: str) -> dict | None:
        p = self.get(cliente_id)
        if not p or not token:
            return None
        for ap in p.get("aprobadores") or []:
            if self._casa_token(token, ap):
                return ap
        return None

    # ── vistas utiles para el nucleo y el ejecutor ──
    @staticmethod
    def modo(p: dict, simulacion_global: bool) -> str:
        if simulacion_global:
            return "simulacion"
        return p.get("modo", "simulacion")

    @staticmethod
    def capacidades(p: dict) -> dict[str, list[str]]:
        salida = {}
        for cap, con in (p.get("capacidades") or {}).items():
            salida[cap] = con if isinstance(con, list) else [con]
        salida.setdefault("interno", ["interno"])
        return salida
