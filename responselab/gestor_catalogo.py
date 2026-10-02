"""
Carga del catalogo en el motor y actualizacion en caliente desde el repositorio.

Como se actualiza solo sin poner en riesgo la produccion
--------------------------------------------------------
1. Cada RL_ACTUALIZACION_MIN minutos se pide catalogo/catalogo.json al
   repositorio (con ETag: si no cambio, no se descarga).
2. El catalogo nuevo se VALIDA entero antes de usarlo, incluida la simulacion
   de todas las reglas contra las invariantes de radio y reversibilidad.
3. Solo si pasa se escribe en disco (de forma atomica) y se cambia de golpe.
   Si no pasa, se sigue con el anterior y se avisa en /salud y en la auditoria.

Y aunque un catalogo malicioso pasara la validacion, las invariantes estan en
el codigo (responselab/nucleo.py), no en los datos: ningun catalogo puede hacer
automatica una accion de radio cuenta u organizacion.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import httpx

from . import nucleo, validacion

log = logging.getLogger("responselab.catalogo")


class GestorCatalogo:
    def __init__(self, ruta_local: Path, carpeta_datos: Path, url_remota: str = ""):
        self.ruta_local = ruta_local
        self.descargado = carpeta_datos / "catalogo" / "catalogo.json"
        self.url = url_remota
        self.actual: nucleo.Catalogo | None = None
        self.origen = ""
        self.etag = ""
        self.ultimo_error = ""
        self._mtime_local = 0.0

    @staticmethod
    def validar(datos: dict) -> list[str]:
        if not isinstance(datos, dict) or "familias" not in datos or "reglas" not in datos:
            return ["no parece un catalogo de ResponseLab"]
        try:
            errores, _, _ = validacion.validar(datos, None)
        except Exception as e:  # noqa: BLE001 - un catalogo roto se rechaza, nunca tumba el motor
            return [f"el catalogo no se puede validar: {type(e).__name__}: {e}"]
        return errores

    def _usar(self, datos: dict, origen: str):
        self.actual = nucleo.Catalogo(datos)
        self.origen = origen
        log.info("catalogo %s cargado desde %s (%d reglas)", self.actual.version, origen, len(self.actual.reglas))

    def cargar(self) -> None:
        candidatos = []
        if self.descargado.exists():
            candidatos.append((self.descargado, "repositorio (descargado)"))
        candidatos.append((self.ruta_local, "imagen"))
        for ruta, origen in candidatos:
            try:
                datos = json.loads(ruta.read_text(encoding="utf-8"))
            except (OSError, ValueError) as e:
                self.ultimo_error = f"{ruta}: {e}"
                continue
            errores = self.validar(datos)
            if errores:
                self.ultimo_error = f"{ruta}: {errores[:3]}"
                log.error("catalogo %s rechazado: %s", ruta, errores[:5])
                continue
            self._usar(datos, origen)
            if ruta == self.ruta_local:
                self._mtime_local = ruta.stat().st_mtime
            return
        raise RuntimeError(f"no hay ningun catalogo valido: {self.ultimo_error}")

    def recargar_local(self) -> bool:
        """Para desarrollo y despliegues sin actualizacion remota."""
        try:
            mtime = self.ruta_local.stat().st_mtime
        except OSError:
            return False
        if mtime == self._mtime_local or self.origen.startswith("repositorio"):
            return False
        datos = json.loads(self.ruta_local.read_text(encoding="utf-8"))
        errores = self.validar(datos)
        self._mtime_local = mtime
        if errores:
            self.ultimo_error = f"catalogo local rechazado: {errores[:3]}"
            return False
        self._usar(datos, "imagen")
        return True

    async def actualizar_remoto(self, transporte=None) -> dict:
        if not self.url:
            return {"estado": "desactivado"}
        cab = {"If-None-Match": self.etag} if self.etag else {}
        try:
            async with httpx.AsyncClient(timeout=60, transport=transporte) as c:
                r = await c.get(self.url, headers=cab)
            if r.status_code == 304:
                return {"estado": "sin cambios", "version": self.actual.version if self.actual else ""}
            r.raise_for_status()
            datos = r.json()
        except (httpx.HTTPError, ValueError) as e:
            self.ultimo_error = f"descarga: {e}"
            return {"estado": "error", "error": self.ultimo_error}
        if self.actual and datos.get("version") == self.actual.version:
            self.etag = r.headers.get("etag", "")
            return {"estado": "sin cambios", "version": self.actual.version}
        errores = self.validar(datos)
        if errores:
            self.ultimo_error = f"catalogo remoto {datos.get('version')} rechazado: {errores[:3]}"
            log.error(self.ultimo_error)
            return {"estado": "rechazado", "errores": errores[:20]}
        self.descargado.parent.mkdir(parents=True, exist_ok=True)
        temporal = self.descargado.with_suffix(".tmp")
        temporal.write_text(json.dumps(datos, ensure_ascii=False), encoding="utf-8")
        os.replace(temporal, self.descargado)
        anterior = self.actual.version if self.actual else ""
        self._usar(datos, "repositorio (descargado)")
        self.etag = r.headers.get("etag", "")
        self.ultimo_error = ""
        return {"estado": "actualizado", "anterior": anterior, "version": self.actual.version}

    def estado(self) -> dict:
        return {"version": self.actual.version if self.actual else "", "origen": self.origen,
                "reglas": len(self.actual.reglas) if self.actual else 0,
                "familias": len(self.actual.familias) if self.actual else 0,
                "actualizacion_remota": bool(self.url), "ultimo_error": self.ultimo_error}
