"""
TheHive 5 (casos) y Cortex (a traves de TheHive), y MISP (enriquecimiento).

El caso se abre con la plantilla de su familia (soar/thehive/plantillas/), que
ya trae las tareas de evidencia, triaje y contencion del playbook. Encima, el
motor anade lo que solo se sabe en tiempo real: observables, TTPs, las
acciones que ejecuto, las que esperan aprobacion y las preguntas de triaje que
no pudo contestar.

En un MSSP cada cliente es una organizacion de TheHive: la cabecera
X-Organisation sale del perfil del cliente.
"""
from __future__ import annotations

from .base import Conector, ErrorConector, Resultado

TIPOS_OBSERVABLE = {"ip": "ip", "dominio": "domain", "url": "url", "hash": "hash", "correo": "mail"}


class TheHive(Conector):
    nombre = "thehive"
    requiere_cfg = ("url",)
    requiere_secretos = ("api_key",)
    acciones = {"caso.nota": "nota"}

    def _cab(self) -> dict:
        cab = {"Authorization": f"Bearer {self.secreto('api_key')}", "Content-Type": "application/json"}
        if self.cfg.get("organizacion"):
            cab["X-Organisation"] = self.cfg["organizacion"]
        return cab

    def _url(self, ruta: str) -> str:
        return self.cfg["url"].rstrip("/") + ruta

    async def abrir_caso(self, plan: dict, alerta: dict, incidente: dict) -> Resultado:
        """Alerta con la plantilla de su familia y, si el plan lo pide, caso."""
        http = self.http()
        tlp = int(self.cfg.get("tlp", 2))
        pap = int(self.cfg.get("pap", 2))
        observables = [{"dataType": TIPOS_OBSERVABLE.get(o["tipo"], "other"), "data": o["valor"],
                        "message": "ResponseLab", "ioc": o["tipo"] in ("hash",), "tags": ["responselab"]}
                       for o in alerta.get("observables") or []]
        equipo = (alerta.get("equipo") or {}).get("nombre")
        if equipo:
            observables.append({"dataType": "hostname", "data": equipo, "message": "Equipo afectado"})
        from ..nucleo import a_fecha
        momento = a_fecha(alerta.get("momento"))
        epoch_ms = int(momento.timestamp() * 1000) if momento else None
        # Los procedimientos (TTP) solo se envian si el perfil lo activa: TheHive
        # rechaza la alerta entera si no tiene cargado el patron ATT&CK citado.
        procedimientos = [{"patternId": t, "occurDate": epoch_ms, "description": "ResponseLab"}
                          for t in plan["regla"].get("tecnicas") or [] if str(t).startswith("T")]
        cuerpo = {
            "type": "responselab",
            "source": f"responselab-{alerta.get('siem', '')}",
            "sourceRef": f"{alerta.get('cliente')}-{alerta.get('id')}"[:128],
            "title": f"[{plan['familia']}] {plan['regla']['titulo'] or plan['titulo']}"[:512],
            "description": descripcion_markdown(plan, alerta, incidente),
            "severity": int(plan["severidad"]),
            "tlp": tlp, "pap": pap,
            "tags": [f"rl:familia={plan['familia']}", f"rl:clase={plan['clase']}",
                     f"rl:incidente={incidente.get('id', '')}", f"rl:regla={plan['regla']['clave']}"],
            "observables": observables,
        }
        if self.cfg.get("plantillas", True):
            cuerpo["caseTemplate"] = plan.get("plantilla_caso")
        if procedimientos and epoch_ms and self.cfg.get("procedimientos", False):
            cuerpo["procedures"] = procedimientos
        try:
            r = await http.peticion("POST", self._url("/api/v1/alert"), cabeceras=self._cab(), json_=cuerpo,
                                    simulada={"_id": "~alerta-simulada"})
            alerta_id = r.json().get("_id")
            caso_id = None
            if plan.get("crear_caso") and alerta_id:
                r2 = await http.peticion("POST", self._url(f"/api/v1/alert/{alerta_id}/case"), cabeceras=self._cab(),
                                         json_={}, simulada={"_id": "~caso-simulado", "number": 0})
                caso_id = r2.json().get("_id")
                await self._tareas_dinamicas(http, caso_id, plan)
                await self._analizadores(http, caso_id)
            res = Resultado("ok", f"alerta {alerta_id}" + (f", caso {caso_id}" if caso_id else ""),
                            {"alerta": alerta_id, "caso": caso_id})
        except ErrorConector as e:
            res = Resultado("error", str(e))
        res.peticiones = http.registro
        if self.simulacion and res.estado == "ok":
            res.estado = "simulada"
        return res

    async def _tareas_dinamicas(self, http, caso_id, plan):
        """Lo que la plantilla no puede saber: aprobaciones y triaje pendientes."""
        tareas = []
        for p in plan["acciones"]:
            if p["modo"] == "aprobacion":
                tareas.append(("Aprobar", f"Aprobar: {p['nombre']}",
                               f"{p['motivo']}. Objetivo: {p.get('objetivo')}. Se aprueba en el panel de ResponseLab "
                               f"o con POST /v1/aprobaciones/<id>/aprobar."))
            elif p["modo"] == "manual":
                tareas.append(("Contencion", p["nombre"] or p["origen"], p["motivo"]))
        for t in plan["triaje"]:
            if t["resultado"] == "pendiente":
                tareas.append(("Triaje", t["pregunta"][:250], f"Fuente: {t['fuente']}. Efecto si es afirmativa: {t['efecto']}."))
        for c in plan.get("escalado", {}).get("comprobar") or []:
            tareas.append(("Escalado", f"Comprobar si hay que escalar a {c['a']}", c["si"]))
        for grupo, titulo, desc in tareas:
            await http.peticion("POST", self._url(f"/api/v1/case/{caso_id}/task"), cabeceras=self._cab(),
                                json_={"title": titulo[:250], "group": grupo, "description": desc[:4000]},
                                simulada={"_id": "~tarea"})

    async def _analizadores(self, http, caso_id):
        cortex = self.cfg.get("cortex") or {}
        if not cortex.get("id") or not cortex.get("analizadores"):
            return
        r = await http.peticion("POST", self._url("/api/v1/query"), cabeceras=self._cab(),
                                json_={"query": [{"_name": "getCase", "idOrName": caso_id}, {"_name": "observables"}]},
                                simulada=[])
        for obs in r.json() or []:
            for analizador in cortex["analizadores"].get(obs.get("dataType"), []):
                await http.peticion("POST", self._url("/api/connector/cortex/job"), cabeceras=self._cab(),
                                    json_={"analyzerId": analizador, "cortexId": cortex["id"], "artifactId": obs.get("_id")})

    async def comentar(self, caso_id: str, texto: str) -> Resultado:
        http = self.http()
        try:
            await http.peticion("POST", self._url(f"/api/v1/case/{caso_id}/comment"), cabeceras=self._cab(),
                                json_={"message": texto[:8000]})
            return Resultado("simulada" if self.simulacion else "ok", "comentario anadido", peticiones=http.registro)
        except ErrorConector as e:
            return Resultado("error", str(e), peticiones=http.registro)

    async def nota(self, http, objetivo, parametros, contexto):
        caso = contexto.get("caso_externo")
        paso = contexto.get("paso") or {}
        if not caso:
            return Resultado("ok", "sin caso externo todavia: queda en las tareas del motor")
        await http.peticion("POST", self._url(f"/api/v1/case/{caso}/comment"), cabeceras=self._cab(),
                            json_={"message": f"{paso.get('nombre', '')}: {paso.get('origen', '')}"})
        return Resultado("ok", "nota anadida al caso")

    async def probar(self):
        ok, motivo = self.configurado()
        if not ok or self.simulacion:
            return Resultado("ok" if ok else "error", motivo or "configurado (simulacion)")
        http = self.http()
        try:
            await http.peticion("GET", self._url("/api/v1/user/current"), cabeceras=self._cab())
            return Resultado("ok", "autenticado en TheHive")
        except ErrorConector as e:
            return Resultado("error", str(e))


class Misp(Conector):
    """Solo enriquecimiento: no contiene nada, contesta si un observable es conocido."""
    nombre = "misp"
    requiere_cfg = ("url",)
    requiere_secretos = ("api_key",)
    acciones = {}

    async def buscar(self, valores: list[str]) -> list[dict]:
        if self.simulacion or not valores:
            return []
        http = self.http()
        try:
            r = await http.peticion("POST", self.cfg["url"].rstrip("/") + "/attributes/restSearch",
                                    cabeceras={"Authorization": self.secreto("api_key"), "Accept": "application/json",
                                               "Content-Type": "application/json"},
                                    json_={"returnFormat": "json", "value": valores, "limit": 100,
                                           "to_ids": True, "includeEventTags": False})
        except ErrorConector:
            return []
        atributos = ((r.json() or {}).get("response") or {}).get("Attribute") or []
        return [{"valor": a.get("value"), "tipo": a.get("type"), "evento": a.get("event_id"),
                 "categoria": a.get("category")} for a in atributos]


def descripcion_markdown(plan: dict, alerta: dict, incidente: dict) -> str:
    l = [f"**{plan['playbook']}** · clase `{plan['clase']}` · severidad {plan['severidad']}/4",
         f"Regla: `{plan['regla']['clave'] or 'desconocida'}` ({plan['regla'].get('via') or 'sin catalogo'})",
         f"Incidente ResponseLab: `{incidente.get('id', '')}` · escalar a **{plan['escalado'].get('a')}** "
         f"en {plan['escalado'].get('plazo_min')} min", ""]
    if plan.get("secuencias"):
        l.append("**Secuencia de ataque:** " + ", ".join(s["nombre"] for s in plan["secuencias"]))
    l.append("### Acciones")
    for p in plan["acciones"]:
        l.append(f"- `{p['modo']}` {p['nombre']} — {p['motivo']}")
    l.append("### Triaje")
    for t in plan["triaje"]:
        l.append(f"- [{t['resultado']}] {t['pregunta']}")
    if plan.get("cierres_propuestos"):
        l.append("### Cierres posibles que no se han podido comprobar")
        for c in plan["cierres_propuestos"]:
            l.append(f"- {c['condicion'][:300]} ({c['motivo']})")
    if plan["escalado"].get("nota_plazo"):
        l.append("")
        l.append(f"> {plan['escalado']['nota_plazo']}")
    return "\n".join(l)[:30000]
