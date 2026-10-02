"""
Base de los conectores: cliente HTTP con modo simulacion, reintentos y registro
de cada peticion sin secretos.

Un mismo codigo para simular y para ejecutar
--------------------------------------------
En simulacion, el cliente HTTP no sale a la red: registra la peticion exacta que
habria hecho (metodo, URL, cuerpo, sin cabeceras de autenticacion) y devuelve
una respuesta simulada. Asi el laboratorio ensena exactamente lo que se
ejecutaria en produccion, y produccion ejecuta el mismo camino de codigo que se
ha probado en el laboratorio. Un modo "de prueba" con su propio codigo acaba
probando otra cosa.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..clientes import secreto

log = logging.getLogger("responselab.conectores")

SENSIBLES = re.compile(r"(authorization|api[-_]?key|apikey|token|secret|password|clave|key|x-api)", re.I)


class ErrorConector(Exception):
    """Fallo de la herramienta (no de ResponseLab). Se reintenta si es transitorio."""

    def __init__(self, mensaje: str, transitorio: bool = False, estado: int | None = None):
        super().__init__(mensaje)
        self.transitorio = transitorio
        self.estado = estado


class NoSoportada(Exception):
    """El conector no sabe hacer esta accion con este objetivo (se registra como omitida)."""


@dataclass
class Resultado:
    estado: str                      # ok | error | simulada | omitida
    detalle: str = ""
    datos: dict = field(default_factory=dict)        # lo necesario para deshacer
    peticiones: list = field(default_factory=list)   # registro saneado


class Respuesta:
    def __init__(self, estado: int, cuerpo: Any, texto: str = ""):
        self.status_code = estado
        self._cuerpo = cuerpo
        self.text = texto or (json.dumps(cuerpo) if cuerpo is not None else "")

    def json(self):
        return self._cuerpo


def _sanear_url(url: str) -> str:
    return re.sub(r"([?&](?:key|token|api_key|apikey|password)=)[^&]+", r"\1***", url, flags=re.I)


def _sanear(obj):
    if isinstance(obj, dict):
        return {k: ("***" if SENSIBLES.search(str(k)) else _sanear(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanear(x) for x in obj]
    if isinstance(obj, str) and len(obj) > 4000:
        return obj[:4000] + "...(recortado)"
    return obj


class ClienteHttp:
    """httpx con reintentos, simulacion y registro. Uno por ejecucion."""

    def __init__(self, simulacion: bool, verificar_tls: bool | str = True, timeout: float = 20.0,
                 reintentos: int = 2, transporte: httpx.AsyncBaseTransport | None = None):
        self.simulacion = simulacion
        self.verificar = verificar_tls
        self.timeout = timeout
        self.reintentos = reintentos
        self.transporte = transporte
        self.registro: list[dict] = []

    async def peticion(self, metodo: str, url: str, *, cabeceras: dict | None = None, json_: Any = None,
                       datos: Any = None, params: dict | None = None, auth: tuple | None = None,
                       esperado: tuple = (200, 201, 202, 204), simulada: Any = None,
                       contenido: str | None = None) -> Respuesta:
        entrada = {"metodo": metodo.upper(), "url": _sanear_url(url)}
        if params:
            entrada["params"] = _sanear(params)
        if json_ is not None:
            entrada["cuerpo"] = _sanear(json_)
        elif datos is not None:
            entrada["cuerpo"] = _sanear(datos) if isinstance(datos, dict) else "(formulario)"
        elif contenido is not None:
            entrada["cuerpo"] = contenido[:2000]
        if self.simulacion:
            entrada["simulada"] = True
            self.registro.append(entrada)
            return Respuesta(200, simulada if simulada is not None else {})

        ultimo_error = None
        for intento in range(self.reintentos + 1):
            t0 = time.monotonic()
            try:
                async with httpx.AsyncClient(verify=self.verificar, timeout=self.timeout,
                                             transport=self.transporte, follow_redirects=False) as c:
                    r = await c.request(metodo, url, headers=cabeceras, json=json_, data=datos,
                                        params=params, auth=auth, content=contenido)
                entrada["estado"] = r.status_code
                entrada["ms"] = int((time.monotonic() - t0) * 1000)
                if r.status_code in esperado:
                    self.registro.append(dict(entrada))
                    try:
                        cuerpo = r.json() if r.content else {}
                    except ValueError:
                        cuerpo = {"texto": r.text[:2000]}
                    return Respuesta(r.status_code, cuerpo, r.text)
                transitorio = r.status_code in (408, 425, 429, 500, 502, 503, 504)
                ultimo_error = ErrorConector(f"{metodo} {_sanear_url(url)} -> HTTP {r.status_code}: {r.text[:300]}",
                                             transitorio=transitorio, estado=r.status_code)
                if not transitorio:
                    break
            except httpx.TimeoutException as e:
                ultimo_error = ErrorConector(f"{metodo} {_sanear_url(url)}: tiempo agotado ({e})", transitorio=True)
            except httpx.TransportError as e:
                ultimo_error = ErrorConector(f"{metodo} {_sanear_url(url)}: {e}", transitorio=True)
            if intento < self.reintentos:
                await asyncio.sleep(min(2 ** intento, 8))
        entrada["error"] = str(ultimo_error)[:500]
        self.registro.append(entrada)
        raise ultimo_error


class TokenCache:
    """Tokens OAuth2 en memoria por (url, cliente, ambito). Se renuevan antes de caducar."""

    _tokens: dict[tuple, tuple[str, float]] = {}

    @classmethod
    async def obtener(cls, http: ClienteHttp, url: str, datos: dict, clave: tuple) -> str:
        if http.simulacion:
            return "token-simulado"
        t = cls._tokens.get(clave)
        if t and t[1] > time.time() + 60:
            return t[0]
        r = await http.peticion("POST", url, datos=datos, esperado=(200, 201))
        cuerpo = r.json()
        token = cuerpo.get("access_token")
        if not token:
            raise ErrorConector(f"sin access_token en la respuesta de {url}")
        cls._tokens[clave] = (token, time.time() + int(cuerpo.get("expires_in", 1800)))
        return token


class Conector:
    """Base de los conectores. Cada subclase declara que acciones sabe hacer."""

    nombre = ""
    # accion del catalogo -> nombre del metodo
    acciones: dict[str, str] = {}
    # claves de configuracion obligatorias (sin _env) y secretos obligatorios
    requiere_cfg: tuple = ()
    requiere_secretos: tuple = ()

    def __init__(self, cliente: dict, cfg: dict, simulacion: bool, transporte=None, motor=None):
        self.cliente = cliente
        self.cfg = cfg or {}
        self.simulacion = simulacion
        self.transporte = transporte
        self.motor = motor               # acceso al almacen para conectores internos (edl, interno)

    def secreto(self, clave: str) -> str:
        return secreto(self.cfg, clave)

    def configurado(self) -> tuple[bool, str]:
        faltan = [k for k in self.requiere_cfg if not self.cfg.get(k)]
        faltan += [f"{k}_env" for k in self.requiere_secretos if not self.secreto(k)]
        if faltan:
            return False, f"falta configuracion: {', '.join(faltan)}"
        return True, ""

    def http(self) -> ClienteHttp:
        verificar = self.cfg.get("ca") or self.cfg.get("verificar_tls", True)
        return ClienteHttp(self.simulacion, verificar_tls=verificar,
                           timeout=float(self.cfg.get("timeout", 20)),
                           reintentos=int(self.cfg.get("reintentos", 2)), transporte=self.transporte)

    def sabe(self, accion: str) -> bool:
        return accion in self.acciones

    async def ejecutar(self, accion: str, objetivo: dict, parametros: dict, contexto: dict) -> Resultado:
        metodo = getattr(self, self.acciones[accion])
        http = self.http()
        try:
            r = await metodo(http, objetivo, parametros or {}, contexto or {})
        except NoSoportada as e:
            return Resultado("omitida", str(e), peticiones=http.registro)
        except ErrorConector as e:
            return Resultado("error", str(e), peticiones=http.registro)
        r.peticiones = http.registro
        if self.simulacion and r.estado == "ok":
            r.estado = "simulada"
        return r

    async def probar(self) -> Resultado:
        ok, motivo = self.configurado()
        return Resultado("ok" if ok else "error", motivo or "configurado")


def objetivo_valor(objetivo: dict, *campos):
    for c in campos:
        v = objetivo.get(c)
        if v not in (None, ""):
            return v
    return None
