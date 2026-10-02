"""
Conectores para cualquier herramienta: declarativos (HTTP descrito en YAML) y
de script (un ejecutable en una carpeta permitida).

Declarativo
-----------
Cualquier herramienta con API HTTP se integra escribiendo conectores/<nombre>.yml,
sin tocar el codigo del motor. Plantillas con {{ ruta.al.campo }} sobre el
contexto (alerta, objetivo, plan, cliente, parametros, deshacer), sin
expresiones: una plantilla que pudiera ejecutar codigo convertiria cada perfil
de cliente en una via de ejecucion remota.

    nombre: servicenow
    autenticacion: {tipo: basica, usuario_env: SNOW_USER, clave_env: SNOW_PASS}
    base_url_env: SNOW_URL
    acciones:
      itsm.ticket:
        metodo: POST
        ruta: /api/now/table/incident
        cuerpo: {short_description: "[ResponseLab] {{ alerta.titulo }}"}
        guardar: {sys_id: result.sys_id}

Script
------
Para lo que no tiene API HTTP (un appliance con CLI, una herramienta interna):
un ejecutable en conectores/scripts/ que recibe un JSON por la entrada estandar
y contesta otro por la salida. Solo se ejecutan ficheros de esa carpeta, con
argumentos en lista (nunca a traves de una shell) y con tiempo maximo.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from pathlib import Path

import yaml

from .base import Conector, ErrorConector, NoSoportada, Resultado, TokenCache

RE_PLANTILLA = re.compile(r"\{\{\s*([a-zA-Z0-9_.]+)\s*(?:\|\s*(json|urlencode|minusculas|default:[^}]*))?\s*\}\}")


def renderizar(valor, contexto: dict):
    """Sustituye {{ a.b.c }} en cadenas, listas y diccionarios. Nada mas."""
    from urllib.parse import quote
    from ..nucleo import leer
    if isinstance(valor, dict):
        return {k: renderizar(v, contexto) for k, v in valor.items()}
    if isinstance(valor, list):
        return [renderizar(v, contexto) for v in valor]
    if not isinstance(valor, str):
        return valor
    completo = RE_PLANTILLA.fullmatch(valor.strip())
    if completo and completo.group(2) == "json":
        return leer(contexto, completo.group(1))

    def sustituir(m):
        v = leer(contexto, m.group(1))
        filtro = m.group(2) or ""
        if v is None and filtro.startswith("default:"):
            v = filtro.split(":", 1)[1].strip()
        if v is None:
            return ""
        if filtro == "json":
            return json.dumps(v, ensure_ascii=False)
        if filtro == "urlencode":
            return quote(str(v), safe="")
        if filtro == "minusculas":
            return str(v).lower()
        return str(v)
    return RE_PLANTILLA.sub(sustituir, valor)


_CACHE: dict[str, tuple[tuple, dict]] = {}


def cargar_declarativos(carpeta: Path) -> dict[str, dict]:
    """Definiciones de conectores/*.yml, releidas solo si algun fichero cambio."""
    if not carpeta.is_dir():
        return {}
    ficheros = sorted(carpeta.glob("*.yml"))
    huella = tuple((f.name, f.stat().st_mtime) for f in ficheros)
    previo = _CACHE.get(str(carpeta))
    if previo and previo[0] == huella:
        return previo[1]
    salida = {}
    for f in ficheros:
        d = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        if d.get("nombre") and d.get("acciones"):
            salida[d["nombre"]] = d
    _CACHE[str(carpeta)] = (huella, salida)
    return salida


class Declarativo(Conector):
    nombre = "declarativo"

    def __init__(self, cliente, cfg, simulacion, transporte=None, motor=None, definicion: dict | None = None):
        super().__init__(cliente, cfg, simulacion, transporte, motor)
        self.definicion = definicion or {}
        self.nombre = self.definicion.get("nombre", "declarativo")
        self.acciones = {a: "_ejecutar_def" for a in self.definicion.get("acciones") or {}}

    def _base(self):
        d = self.definicion
        variable = self.cfg.get("base_url_env") or d.get("base_url_env")
        return (self.cfg.get("base_url") or (os.environ.get(variable) if variable else None)
                or d.get("base_url") or "").rstrip("/")

    def configurado(self):
        if not self._base():
            return False, f"{self.nombre}: falta base_url"
        aut = self.definicion.get("autenticacion") or {}
        for k, v in aut.items():
            if k.endswith("_env") and not os.environ.get(self.cfg.get(k, v) or ""):
                return False, f"{self.nombre}: falta la variable {self.cfg.get(k, v)}"
        return True, ""

    async def _cabeceras(self, http) -> tuple[dict, tuple | None]:
        aut = dict(self.definicion.get("autenticacion") or {})
        aut.update({k: v for k, v in self.cfg.items() if k.endswith("_env")})
        env = lambda k: os.environ.get(aut.get(k, ""), "")  # noqa: E731
        tipo = aut.get("tipo", "ninguna")
        cab = dict(self.definicion.get("cabeceras") or {})
        if tipo == "bearer":
            cab["Authorization"] = f"Bearer {env('token_env')}"
        elif tipo == "cabecera":
            cab[aut.get("nombre", "X-API-Key")] = env("valor_env")
        elif tipo == "basica":
            return cab, (env("usuario_env"), env("clave_env"))
        elif tipo == "oauth2_cc":
            datos = {"grant_type": "client_credentials", "client_id": env("client_id_env"),
                     "client_secret": env("client_secret_env")}
            if aut.get("ambito"):
                datos["scope"] = aut["ambito"]
            token = await TokenCache.obtener(http, aut["url_token"], datos, (aut["url_token"], datos["client_id"], aut.get("ambito")))
            cab["Authorization"] = f"Bearer {token}"
        return cab, None

    async def _ejecutar_def(self, http, objetivo, parametros, contexto, accion=None):
        accion = accion or contexto.get("accion")
        definicion = (self.definicion.get("acciones") or {}).get(accion)
        if not definicion:
            raise NoSoportada(f"{self.nombre} no define {accion}")
        ctx = {"alerta": contexto.get("alerta") or {}, "objetivo": objetivo, "plan": contexto.get("plan") or {},
               "cliente": {"id": self.cliente.get("id"), "nombre": self.cliente.get("nombre")},
               "parametros": parametros, "deshacer": contexto.get("datos_deshacer") or {},
               "incidente": {"id": contexto.get("incidente_id", "")}, "ejecucion": {"id": contexto.get("ejecucion_id", "")}}
        cab, auth = await self._cabeceras(http)
        pasos = definicion if isinstance(definicion, list) else [definicion]
        guardado = {}
        for paso in pasos:
            ctx["guardado"] = guardado
            url = self._base() + renderizar(paso.get("ruta", ""), ctx)
            cuerpo = renderizar(paso.get("cuerpo"), ctx) if "cuerpo" in paso else None
            params = renderizar(paso.get("params"), ctx) if "params" in paso else None
            r = await http.peticion(paso.get("metodo", "POST"), url, cabeceras=cab, auth=auth, json_=cuerpo,
                                    params=params, esperado=tuple(paso.get("exito", (200, 201, 202, 204))),
                                    simulada=paso.get("simulada", {}))
            from ..nucleo import leer
            for nombre, ruta in (paso.get("guardar") or {}).items():
                guardado[nombre] = leer(r.json() if isinstance(r.json(), dict) else {}, ruta)
        return Resultado("ok", renderizar(pasos[-1].get("detalle", f"{accion} via {self.nombre}"), ctx), guardado)

    async def ejecutar(self, accion, objetivo, parametros, contexto):
        contexto = dict(contexto or {}, accion=accion)
        return await super().ejecutar(accion, objetivo, parametros, contexto)


class Script(Conector):
    nombre = "script"

    def __init__(self, cliente, cfg, simulacion, transporte=None, motor=None, carpeta: Path | None = None):
        super().__init__(cliente, cfg, simulacion, transporte, motor)
        self.carpeta = (carpeta or Path("conectores/scripts")).resolve()
        self.acciones = {a: "_lanzar" for a in (cfg or {}).get("acciones") or {}}

    def _ruta(self, nombre: str) -> Path:
        ruta = (self.carpeta / nombre).resolve()
        if self.carpeta not in ruta.parents or not ruta.is_file():
            raise NoSoportada(f"script '{nombre}' fuera de {self.carpeta} o inexistente")
        if not os.access(ruta, os.X_OK) and not ruta.suffix == ".py":
            raise NoSoportada(f"script '{nombre}' no es ejecutable")
        return ruta

    async def _lanzar(self, http, objetivo, parametros, contexto):
        accion = contexto.get("accion")
        nombre = (self.cfg.get("acciones") or {}).get(accion)
        ruta = self._ruta(nombre)
        entrada = json.dumps({"accion": accion, "objetivo": objetivo, "parametros": parametros,
                              "cliente": self.cliente.get("id"), "incidente": contexto.get("incidente_id"),
                              "deshacer": contexto.get("datos_deshacer") or {}, "simulacion": self.simulacion},
                             ensure_ascii=False, default=str)
        http.registro.append({"script": str(ruta.name), "entrada": json.loads(entrada), "simulada": self.simulacion})
        if self.simulacion:
            return Resultado("ok", f"se lanzaria {ruta.name}")
        argv = [sys.executable, str(ruta)] if ruta.suffix == ".py" else [str(ruta)]
        proc = await asyncio.create_subprocess_exec(*argv, stdin=asyncio.subprocess.PIPE,
                                                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            salida, error = await asyncio.wait_for(proc.communicate(entrada.encode()), timeout=float(self.cfg.get("timeout", 60)))
        except asyncio.TimeoutError:
            proc.kill()
            raise ErrorConector(f"{ruta.name}: tiempo agotado") from None
        if proc.returncode != 0:
            raise ErrorConector(f"{ruta.name} salio con {proc.returncode}: {error.decode(errors='replace')[:400]}")
        try:
            r = json.loads(salida.decode() or "{}")
        except ValueError:
            r = {"detalle": salida.decode(errors="replace")[:400]}
        return Resultado("ok" if r.get("ok", True) else "error", str(r.get("detalle", ruta.name)), r.get("datos") or {})

    async def ejecutar(self, accion, objetivo, parametros, contexto):
        contexto = dict(contexto or {}, accion=accion)
        return await super().ejecutar(accion, objetivo, parametros, contexto)

