"""
Inteligencia en caliente: el feed de News CTI, filtrado como lo filtra
DetectionLab, y MISP si el cliente lo tiene.

Mismas tres decisiones que tools/sync_cti.py de DetectionLab, por las mismas
razones: se filtra por nivel (los de nivel bajo viven horas), los hashes entran
siempre (un hash no caduca como una IP) y cada indicador lleva su edad.

Ademas, el motor guarda cuando vio cada indicador por primera vez. Es lo que
permite contestar "el indicador ya no figura en el feed y tenia mas de 25
dias", que es una de las condiciones de cierre del playbook de inteligencia.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx

log = logging.getLogger("responselab.cti")

NIVELES = {"baja": 0, "media": 1, "alta": 2}
TIPOS = {
    "ipv4": "ip", "ip:port": "ip", "ip": "ip",
    "domain": "dominio", "hostname": "dominio",
    "url": "url",
    "filehash-sha256": "hash", "filehash-sha1": "hash", "filehash-md5": "hash",
    "sha256_hash": "hash", "md5_hash": "hash", "sha1_hash": "hash",
}


def normalizar_valor(tipo: str, valor: str) -> str:
    v = str(valor or "").strip()
    if tipo == "ip":
        v = re.sub(r":\d+$", "", v)          # el feed pega el puerto: 1.2.3.4:443
    if tipo in ("dominio", "hash"):
        v = v.lower().rstrip(".")
    return v


class Inteligencia:
    def __init__(self, url: str, carpeta: Path, almacen=None, nivel_minimo: str = "media", max_dias: int = 30):
        self.url = url
        self.cache = carpeta / "cti" / "iocs_latest.json"
        self.almacen = almacen
        self.nivel_minimo = NIVELES.get(nivel_minimo, 1)
        self.max_dias = max_dias
        self.indice: dict[str, dict] = {}
        self.kev: set[str] = set()
        self.generado = ""
        self.etag = ""
        self.actualizado: datetime | None = None
        self.error = ""

    @property
    def disponible(self) -> bool:
        return bool(self.indice)

    def cargar_disco(self) -> bool:
        if self.cache.exists():
            try:
                self._procesar(json.loads(self.cache.read_text(encoding="utf-8")), registrar=False)
                return True
            except (ValueError, OSError) as e:
                log.warning("cache de CTI ilegible: %s", e)
        return False

    async def refrescar(self, transporte=None) -> dict:
        if not self.url:
            return {"estado": "desactivado"}
        cab = {"If-None-Match": self.etag} if self.etag else {}
        try:
            async with httpx.AsyncClient(timeout=60, transport=transporte) as c:
                r = await c.get(self.url, headers=cab)
            if r.status_code == 304:
                self.actualizado = datetime.now(timezone.utc)
                return {"estado": "sin cambios"}
            r.raise_for_status()
            datos = r.json()
        except (httpx.HTTPError, ValueError) as e:
            # Sin red se sigue con lo ultimo bueno: perder la inteligencia por
            # un fallo de descarga seria peor que usarla con unas horas de mas.
            self.error = str(e)[:300]
            log.warning("no se pudo refrescar News CTI: %s", e)
            return {"estado": "error", "error": self.error}
        self.etag = r.headers.get("etag", "")
        self._procesar(datos, registrar=True)
        self.cache.parent.mkdir(parents=True, exist_ok=True)
        self.cache.write_text(json.dumps(datos), encoding="utf-8")
        self.error = ""
        return {"estado": "actualizado", "indicadores": len(self.indice), "generado": self.generado}

    def _procesar(self, datos: dict, registrar: bool):
        indice = {}
        for ioc in datos.get("iocs") or []:
            tipo = TIPOS.get(str(ioc.get("type", "")).lower())
            if not tipo:
                continue
            nivel = str(ioc.get("level", "baja")).lower()
            edad = ioc.get("age_days")
            if tipo != "hash":
                if NIVELES.get(nivel, 0) < self.nivel_minimo:
                    continue
                if edad is not None and int(edad) > self.max_dias:
                    continue
            valor = normalizar_valor(tipo, ioc.get("value", ""))
            if not valor:
                continue
            indice[valor.lower()] = {
                "tipo": tipo, "valor": valor, "nivel": nivel, "score": ioc.get("score"),
                "edad_dias": edad, "fuentes": ioc.get("sources") or [ioc.get("source")],
                "amenaza": ioc.get("threat", ""), "gravedad": ioc.get("severity", ""),
                "pais": ioc.get("country", ""), "origen": "newscti",
            }
        self.indice = indice
        self.kev = {str(k.get("cve", "")).upper() for k in datos.get("cisa_kev_recent") or [] if k.get("cve")}
        self.generado = str(datos.get("generated_utc", ""))
        self.actualizado = datetime.now(timezone.utc)
        if registrar and self.almacen is not None:
            self.almacen.cti_registrar([(v["valor"], v["tipo"]) for v in indice.values()])
        log.info("News CTI: %d indicadores utiles, %d CVE de KEV", len(indice), len(self.kev))

    def buscar(self, observables: list[dict]) -> list[dict]:
        salida = []
        for o in observables or []:
            tipo = o.get("tipo")
            valor = normalizar_valor(tipo, o.get("valor", "")).lower()
            hit = self.indice.get(valor)
            if hit:
                salida.append(dict(hit))
        return salida

    def retirados(self, observables: list[dict]) -> list[dict]:
        """Observables que estuvieron en el feed y ya no estan, con su antiguedad."""
        if self.almacen is None:
            return []
        valores = [normalizar_valor(o.get("tipo"), o.get("valor", "")).lower() for o in observables or []]
        valores = [v for v in valores if v and v not in self.indice]
        ahora = datetime.now(timezone.utc)
        salida = []
        for f in self.almacen.cti_historial(valores):
            primera = datetime.fromisoformat(f["primera_vez"].replace("Z", "+00:00"))
            salida.append({"valor": f["valor"], "tipo": f["tipo"], "primera_vez_dias": (ahora - primera).days})
        return salida

    def estado(self) -> dict:
        return {"disponible": self.disponible, "indicadores": len(self.indice), "kev": len(self.kev),
                "generado": self.generado, "error": self.error,
                "actualizado": self.actualizado.isoformat() if self.actualizado else ""}
