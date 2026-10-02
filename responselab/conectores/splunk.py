"""
Splunk como destino de evidencia: copia los eventos de la ventana del hecho a
un indice de retencion larga con `collect`, para que la retencion normal del
indice de origen no se los lleve antes de que acabe la investigacion.
"""
from __future__ import annotations

import re
from datetime import timedelta

from .base import Conector, NoSoportada, Resultado


class Splunk(Conector):
    nombre = "splunk"
    requiere_cfg = ("url",)
    requiere_secretos = ("token",)
    acciones = {"evidencia.retener": "retener"}

    async def retener(self, http, objetivo, parametros, contexto):
        from ..nucleo import a_fecha, leer
        alerta = contexto.get("alerta") or {}
        momento = a_fecha(alerta.get("momento"))
        if not momento:
            raise NoSoportada("la alerta no trae momento")
        equipo = leer(alerta, "equipo.nombre") or ""
        if equipo and not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", equipo):
            raise NoSoportada(f"nombre de equipo no valido para la busqueda: {equipo!r}")
        horas = int(self.cfg.get("ventana_horas", 24))
        indice = self.cfg.get("indice_evidencias", "rl_evidencias")
        if not re.fullmatch(r"[a-z0-9_-]+", indice):
            raise NoSoportada("indice de evidencias no valido")
        filtro = f'host="{equipo}"' if equipo else ""
        busqueda = (f"search index=* {filtro} earliest={int((momento - timedelta(hours=horas)).timestamp())} "
                    f"latest={int((momento + timedelta(hours=1)).timestamp())} "
                    f"| eval rl_incidente=\"{contexto.get('incidente_id', '')}\" | collect index={indice}")
        r = await http.peticion("POST", self.cfg["url"].rstrip("/") + "/services/search/jobs",
                                cabeceras={"Authorization": f"Bearer {self.secreto('token')}"},
                                datos={"search": busqueda, "exec_mode": "normal", "output_mode": "json"},
                                simulada={"sid": "sid-simulado"})
        return Resultado("ok", f"copia a {indice} lanzada (sid {r.json().get('sid')})", {"sid": r.json().get("sid")})
