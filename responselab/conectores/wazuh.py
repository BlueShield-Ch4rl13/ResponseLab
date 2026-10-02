"""
Wazuh: contencion en el propio equipo mediante active response.

El motor llama a la API del manager (PUT /active-response) y el agente ejecuta
el script de ResponseLab correspondiente (siem/wazuh/active-response/). Los
scripts validan sus entradas, guardan lo necesario para deshacer y, si el
agente tiene configurado el motor, devuelven un acuse a /v1/acuses: asi
"orden enviada" y "accion aplicada" son dos estados distintos, que en un
incidente real no es un matiz.
"""
from __future__ import annotations

import re

from .base import Conector, ErrorConector, NoSoportada, Resultado


def _campo(objetivo, contexto, ruta):
    from ..nucleo import leer
    return objetivo.get(ruta) or leer(contexto.get("alerta") or {}, ruta)


class Wazuh(Conector):
    nombre = "wazuh"
    requiere_cfg = ("url",)
    requiere_secretos = ("usuario", "clave")
    acciones = {
        "endpoint.aislar": "aislar",
        "endpoint.liberar": "liberar",
        "proceso.matar": "matar",
        "fichero.cuarentena": "cuarentena",
        "fichero.restaurar": "restaurar",
        "persistencia.deshabilitar": "persistencia",
        "persistencia.restaurar": "persistencia_restaurar",
        "red.bloquear_destino_equipo": "bloquear_destino",
        "red.desbloquear_destino_equipo": "desbloquear_destino",
        "evidencia.triage_forense": "triage",
        "evidencia.conservar_fichero": "conservar",
        "evidencia.instantanea_ad": "instantanea_ad",
        "cuenta.retirar_clave_ssh": "retirar_clave",
        "cuenta.restaurar_clave_ssh": "restaurar_clave",
    }

    async def _token(self, http) -> str:
        if http.simulacion:
            return "jwt-simulado"
        r = await http.peticion("POST", self.cfg["url"].rstrip("/") + "/security/user/authenticate",
                                auth=(self.secreto("usuario"), self.secreto("clave")))
        token = (r.json().get("data") or {}).get("token")
        if not token:
            raise ErrorConector("la API de Wazuh no devolvio token")
        return token

    async def _agente(self, http, cab, objetivo, contexto) -> tuple[str, str]:
        ident = _campo(objetivo, contexto, "equipo.id_agente")
        nombre = _campo(objetivo, contexto, "equipo.nombre")
        so = (_campo(objetivo, contexto, "equipo.so") or "").lower()
        if ident and so:
            return str(ident).zfill(3), so
        params = {"select": "id,name,os.platform", "limit": 2}
        if ident:
            params["agents_list"] = str(ident).zfill(3)
        else:
            params["name"] = nombre
        r = await http.peticion("GET", self.cfg["url"].rstrip("/") + "/agents", cabeceras=cab, params=params,
                                simulada={"data": {"affected_items": [{"id": "001", "name": nombre, "os": {"platform": "windows"}}]}})
        items = (r.json().get("data") or {}).get("affected_items") or []
        if not items:
            raise ErrorConector(f"no hay agente de Wazuh para '{nombre or ident}'")
        if len(items) > 1:
            raise ErrorConector(f"el nombre '{nombre}' casa con varios agentes: no se actua sobre un objetivo ambiguo")
        return items[0]["id"], str((items[0].get("os") or {}).get("platform", "")).lower()

    async def _ar(self, http, objetivo, contexto, script: str, params: dict) -> Resultado:
        token = await self._token(http)
        cab = {"Authorization": f"Bearer {token}"}
        agente, so = await self._agente(http, cab, objetivo, contexto)
        windows = "windows" in so
        comando = f"!responselab-{script}" + (".cmd" if windows else "")
        params = dict(params, ejecucion_id=contexto.get("ejecucion_id", ""), caso=contexto.get("incidente_id", ""))
        cuerpo = {"command": comando, "arguments": [], "alert": {"data": {"responselab": params}}}
        r = await http.peticion("PUT", self.cfg["url"].rstrip("/") + "/active-response", cabeceras=cab,
                                params={"agents_list": agente}, json_=cuerpo,
                                simulada={"data": {"total_affected_items": 1, "failed_items": []}, "error": 0})
        datos = r.json().get("data") or {}
        if int(datos.get("total_affected_items", 0)) < 1:
            raise ErrorConector(f"Wazuh no entrego la orden al agente {agente}: {datos.get('failed_items')}")
        return Resultado("ok", f"orden {comando} entregada al agente {agente} (pendiente de acuse)",
                         {"agente": agente, "so": so, "params": params})

    # ── acciones ──
    async def aislar(self, http, objetivo, parametros, contexto):
        managers = self.cfg.get("managers") or []
        if not managers:
            raise NoSoportada("conectores.wazuh.managers vacio: sin la IP del manager el equipo se quedaria incomunicado")
        return await self._ar(http, objetivo, contexto, "aislar", {"permitidos": managers + list(self.cfg.get("permitidos") or [])})

    async def liberar(self, http, objetivo, parametros, contexto):
        return await self._ar(http, objetivo, contexto, "liberar", {})

    async def matar(self, http, objetivo, parametros, contexto):
        pid = _campo(objetivo, contexto, "proceso.pid")
        inicio = _campo(objetivo, contexto, "proceso.inicio")
        if not pid or not inicio:
            raise NoSoportada("sin PID y hora de arranque el script no puede comprobar que mata el proceso correcto")
        return await self._ar(http, objetivo, contexto, "matar", {
            "pid": int(pid), "inicio": str(inicio), "imagen": _campo(objetivo, contexto, "proceso.imagen") or "",
            "guid": _campo(objetivo, contexto, "proceso.guid") or ""})

    async def cuarentena(self, http, objetivo, parametros, contexto):
        ruta = _campo(objetivo, contexto, "fichero.ruta")
        if not ruta:
            raise NoSoportada("Wazuh necesita la ruta del fichero (el hash solo no basta)")
        return await self._ar(http, objetivo, contexto, "cuarentena", {
            "ruta": ruta, "sha256": _campo(objetivo, contexto, "fichero.sha256") or ""})

    async def restaurar(self, http, objetivo, parametros, contexto):
        return await self._ar(http, objetivo, contexto, "restaurar", {
            "ruta": _campo(objetivo, contexto, "fichero.ruta") or "",
            "sha256": _campo(objetivo, contexto, "fichero.sha256") or ""})

    async def persistencia(self, http, objetivo, parametros, contexto):
        return await self._ar(http, objetivo, contexto, "persistencia", {
            "tipo": _campo(objetivo, contexto, "persistencia.tipo") or "",
            "nombre": _campo(objetivo, contexto, "persistencia.nombre") or "",
            "ruta": _campo(objetivo, contexto, "persistencia.ruta") or ""})

    async def persistencia_restaurar(self, http, objetivo, parametros, contexto):
        return await self._ar(http, objetivo, contexto, "persistencia-restaurar", {
            "tipo": _campo(objetivo, contexto, "persistencia.tipo") or "",
            "nombre": _campo(objetivo, contexto, "persistencia.nombre") or "",
            "ruta": _campo(objetivo, contexto, "persistencia.ruta") or ""})

    async def bloquear_destino(self, http, objetivo, parametros, contexto):
        destino = _campo(objetivo, contexto, "red.ip_destino") or _campo(objetivo, contexto, "red.dominio")
        if not destino or not re.fullmatch(r"[A-Za-z0-9.:_-]{1,253}", str(destino)):
            raise NoSoportada(f"destino no valido: {destino!r}")
        return await self._ar(http, objetivo, contexto, "bloquear-destino", {"destino": str(destino)})

    async def desbloquear_destino(self, http, objetivo, parametros, contexto):
        destino = _campo(objetivo, contexto, "red.ip_destino") or _campo(objetivo, contexto, "red.dominio")
        return await self._ar(http, objetivo, contexto, "desbloquear-destino", {"destino": str(destino or "")})

    async def triage(self, http, objetivo, parametros, contexto):
        return await self._ar(http, objetivo, contexto, "triage", {"caso": contexto.get("incidente_id", "")})

    async def conservar(self, http, objetivo, parametros, contexto):
        ruta = _campo(objetivo, contexto, "persistencia.ruta") or _campo(objetivo, contexto, "fichero.ruta")
        return await self._ar(http, objetivo, contexto, "conservar", {"ruta": ruta})

    async def instantanea_ad(self, http, objetivo, parametros, contexto):
        return await self._ar(http, objetivo, contexto, "instantanea-ad", {"dn": _campo(objetivo, contexto, "objeto_ad")})

    async def retirar_clave(self, http, objetivo, parametros, contexto):
        return await self._ar(http, objetivo, contexto, "ssh-clave", {
            "usuario": _campo(objetivo, contexto, "usuario.nombre"),
            "clave": _campo(objetivo, contexto, "clave_ssh") or "",
            "ruta": _campo(objetivo, contexto, "fichero.ruta") or ""})

    async def restaurar_clave(self, http, objetivo, parametros, contexto):
        return await self._ar(http, objetivo, contexto, "ssh-clave-restaurar", {
            "usuario": _campo(objetivo, contexto, "usuario.nombre")})

    async def probar(self):
        ok, motivo = self.configurado()
        if not ok or self.simulacion:
            return Resultado("ok" if ok else "error", motivo or "configurado (simulacion)")
        http = self.http()
        try:
            await self._token(http)
            return Resultado("ok", "autenticado en la API de Wazuh")
        except ErrorConector as e:
            return Resultado("error", str(e))
