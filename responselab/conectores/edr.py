"""
EDR de terceros: CrowdStrike Falcon y SentinelOne.

Los dos resuelven el equipo por nombre y se niegan a actuar si el nombre casa
con mas de un dispositivo: aislar "el equipo que se llama PC-01" cuando hay
dos con ese nombre es exactamente el tipo de accion que no tiene que hacer una
maquina sola.
"""
from __future__ import annotations

from .base import Conector, ErrorConector, NoSoportada, Resultado, TokenCache


def _campo(objetivo, contexto, ruta):
    from ..nucleo import leer
    return objetivo.get(ruta) or leer(contexto.get("alerta") or {}, ruta)


class CrowdStrike(Conector):
    nombre = "crowdstrike"
    requiere_secretos = ("client_id", "client_secret")
    acciones = {
        "endpoint.aislar": "contener",
        "endpoint.liberar": "liberar",
        "proceso.matar": "matar",
        "flota.bloquear_hash": "bloquear_hash",
        "flota.desbloquear_hash": "desbloquear_hash",
    }

    @property
    def base(self):
        return self.cfg.get("url", "https://api.crowdstrike.com").rstrip("/")

    async def _cab(self, http):
        url = f"{self.base}/oauth2/token"
        datos = {"client_id": self.secreto("client_id"), "client_secret": self.secreto("client_secret")}
        token = await TokenCache.obtener(http, url, datos, (url, datos["client_id"], "falcon"))
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async def _dispositivo(self, http, cab, objetivo, contexto) -> str:
        ident = _campo(objetivo, contexto, "equipo.id_edr")
        if ident:
            return ident
        nombre = str(_campo(objetivo, contexto, "equipo.nombre") or "").replace("'", "")
        if not nombre:
            raise NoSoportada("sin id de Falcon ni nombre de equipo")
        r = await http.peticion("GET", f"{self.base}/devices/queries/devices/v1", cabeceras=cab,
                                params={"filter": f"hostname:'{nombre}'"}, simulada={"resources": ["aid-simulado"]})
        ids = r.json().get("resources") or []
        if len(ids) != 1:
            raise ErrorConector(f"'{nombre}' casa con {len(ids)} dispositivos en Falcon: no se actua")
        return ids[0]

    async def _accion(self, http, objetivo, contexto, accion):
        cab = await self._cab(http)
        aid = await self._dispositivo(http, cab, objetivo, contexto)
        await http.peticion("POST", f"{self.base}/devices/entities/devices-actions/v2", cabeceras=cab,
                            params={"action_name": accion}, json_={"ids": [aid]})
        return aid

    async def contener(self, http, objetivo, parametros, contexto):
        aid = await self._accion(http, objetivo, contexto, "contain")
        return Resultado("ok", f"contencion de red solicitada para {aid}", {"aid": aid})

    async def liberar(self, http, objetivo, parametros, contexto):
        aid = await self._accion(http, objetivo, contexto, "lift_containment")
        return Resultado("ok", f"contencion levantada para {aid}")

    async def matar(self, http, objetivo, parametros, contexto):
        pid = _campo(objetivo, contexto, "proceso.pid")
        if not pid:
            raise NoSoportada("sin PID")
        cab = await self._cab(http)
        aid = await self._dispositivo(http, cab, objetivo, contexto)
        r = await http.peticion("POST", f"{self.base}/real-time-response/entities/sessions/v1", cabeceras=cab,
                                json_={"device_id": aid, "origin": "responselab"},
                                simulada={"resources": [{"session_id": "sesion-simulada"}]})
        sesion = (r.json().get("resources") or [{}])[0].get("session_id")
        if not sesion:
            raise ErrorConector("Falcon no abrio sesion de RTR")
        await http.peticion("POST", f"{self.base}/real-time-response/entities/active-responder-command/v1",
                            cabeceras=cab, json_={"base_command": "kill", "command_string": f"kill {int(pid)}",
                                                  "session_id": sesion})
        return Resultado("ok", f"kill {pid} enviado por RTR a {aid}. Falcon no comprueba la hora de arranque: "
                         "revisa el acuse en la consola", {"aid": aid})

    async def bloquear_hash(self, http, objetivo, parametros, contexto):
        h = _campo(objetivo, contexto, "fichero.sha256")
        if not h:
            raise NoSoportada("Falcon bloquea por SHA-256 y la alerta no lo trae")
        cab = await self._cab(http)
        r = await http.peticion("POST", f"{self.base}/iocs/entities/indicators/v1", cabeceras=cab, json_={
            "indicators": [{"type": "sha256", "value": h, "action": "prevent", "severity": "high",
                            "platforms": ["windows", "mac", "linux"], "applied_globally": True,
                            "description": f"ResponseLab {contexto.get('incidente_id', '')}"}]},
            simulada={"resources": [{"id": "ioc-simulado"}]})
        ioc = (r.json().get("resources") or [{}])[0].get("id")
        return Resultado("ok", f"IOC {h} en prevencion en toda la flota", {"ioc": ioc})

    async def desbloquear_hash(self, http, objetivo, parametros, contexto):
        ioc = (contexto.get("datos_deshacer") or {}).get("ioc")
        if not ioc:
            raise NoSoportada("no se guardo el id del IOC")
        cab = await self._cab(http)
        await http.peticion("DELETE", f"{self.base}/iocs/entities/indicators/v1", cabeceras=cab, params={"ids": ioc})
        return Resultado("ok", f"IOC {ioc} retirado")


class SentinelOne(Conector):
    nombre = "sentinelone"
    requiere_cfg = ("url",)
    requiere_secretos = ("api_token",)
    acciones = {
        "endpoint.aislar": "desconectar",
        "endpoint.liberar": "conectar",
        "flota.bloquear_hash": "bloquear_hash",
        "flota.desbloquear_hash": "desbloquear_hash",
    }

    @property
    def base(self):
        return self.cfg["url"].rstrip("/") + "/web/api/v2.1"

    def _cab(self):
        return {"Authorization": f"ApiToken {self.secreto('api_token')}", "Content-Type": "application/json"}

    async def _agente(self, http, objetivo, contexto) -> str:
        ident = _campo(objetivo, contexto, "equipo.id_edr")
        if ident:
            return ident
        nombre = _campo(objetivo, contexto, "equipo.nombre")
        if not nombre:
            raise NoSoportada("sin id de agente ni nombre de equipo")
        r = await http.peticion("GET", f"{self.base}/agents", cabeceras=self._cab(),
                                params={"computerName": nombre, "limit": 2}, simulada={"data": [{"id": "agente-simulado"}]})
        datos = r.json().get("data") or []
        if len(datos) != 1:
            raise ErrorConector(f"'{nombre}' casa con {len(datos)} agentes en SentinelOne: no se actua")
        return datos[0]["id"]

    async def desconectar(self, http, objetivo, parametros, contexto):
        aid = await self._agente(http, objetivo, contexto)
        await http.peticion("POST", f"{self.base}/agents/actions/disconnect", cabeceras=self._cab(),
                            json_={"filter": {"ids": [aid]}})
        return Resultado("ok", f"agente {aid} desconectado de la red", {"agente": aid})

    async def conectar(self, http, objetivo, parametros, contexto):
        aid = (contexto.get("datos_deshacer") or {}).get("agente") or await self._agente(http, objetivo, contexto)
        await http.peticion("POST", f"{self.base}/agents/actions/connect", cabeceras=self._cab(),
                            json_={"filter": {"ids": [aid]}})
        return Resultado("ok", f"agente {aid} reconectado")

    async def bloquear_hash(self, http, objetivo, parametros, contexto):
        h = _campo(objetivo, contexto, "fichero.sha1")
        if not h:
            raise NoSoportada("la lista de bloqueo de SentinelOne usa SHA-1 y la alerta no lo trae")
        r = await http.peticion("POST", f"{self.base}/restrictions", cabeceras=self._cab(), json_={
            "data": {"type": "black_hash", "value": h, "osType": self.cfg.get("so", "windows"),
                     "description": f"ResponseLab {contexto.get('incidente_id', '')}"},
            "filter": {"tenant": True}}, simulada={"data": [{"id": "restriccion-simulada"}]})
        rid = (r.json().get("data") or [{}])[0].get("id")
        return Resultado("ok", f"SHA-1 {h} en la lista de bloqueo global", {"restriccion": rid})

    async def desbloquear_hash(self, http, objetivo, parametros, contexto):
        rid = (contexto.get("datos_deshacer") or {}).get("restriccion")
        if not rid:
            raise NoSoportada("no se guardo el id de la restriccion")
        await http.peticion("DELETE", f"{self.base}/restrictions", cabeceras=self._cab(),
                            json_={"data": {"type": "black_hash", "ids": [rid]}})
        return Resultado("ok", f"restriccion {rid} retirada")
