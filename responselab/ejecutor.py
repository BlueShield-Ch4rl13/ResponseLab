"""
El motor: recibe alertas, decide con el nucleo y ejecuta con los conectores.

    alerta ──► normalizar ──► cola persistente ──► trabajador
                                                    │
                       contexto (historico, CTI, DNS, plazos)
                                                    │
                                     nucleo.decidir  (el mismo de los SOAR)
                                                    │
               ┌──────────────┬────────────────┬────┴─────────┬─────────────┐
           automatica      aprobacion         manual        caso          aviso
           conector        se guarda y se     tarea del     TheHive o     Discord, Teams,
           (o simulacion)  avisa con enlace   analista      interno       Slack, correo

Garantias
---------
* Idempotencia: la misma alerta no se procesa dos veces y el mismo paso no se
  ejecuta dos veces (un reenvio del SIEM no aisla dos veces).
* Defensa en profundidad: antes de ejecutar se vuelven a comprobar las
  invariantes del plan. Si alguna fallara (no deberia: el nucleo ya lo impide),
  la accion pasa a aprobacion y queda en la auditoria.
* Simulacion: por cliente o global. En simulacion los conectores registran la
  peticion exacta que harian y no salen a la red.
* Todo lo que se hace queda en la auditoria encadenada.
"""
from __future__ import annotations

import asyncio
import collections
import json
import logging
import socket
import time
from datetime import datetime, timedelta, timezone

from . import avisos, conectores, nucleo, regulatorio
from .almacen import Almacen, iso
from .clientes import Clientes
from .config import Config
from .cti import Inteligencia
from .gestor_catalogo import GestorCatalogo

log = logging.getLogger("responselab.motor")


class AlertaRechazada(Exception):
    pass


class Motor:
    def __init__(self, config: Config, transporte=None):
        self.config = config
        self.transporte = transporte          # para pruebas: httpx.MockTransport
        config.datos.mkdir(parents=True, exist_ok=True)
        self.almacen = Almacen(config.base_datos)
        self.clientes = Clientes(config.clientes)
        self.catalogo = GestorCatalogo(config.catalogo, config.datos, config.actualizacion_url)
        self.catalogo.cargar()
        self.cti = Inteligencia(config.cti_url, config.datos, self.almacen, config.cti_nivel_minimo, config.cti_max_dias)
        self.cti.cargar_disco()
        self._hay_trabajo = asyncio.Event()
        self._cerrojo_decision = asyncio.Lock()
        self._limites: dict[tuple, collections.deque] = {}
        self._recientes_ids: collections.OrderedDict = collections.OrderedDict()
        self._tareas: list[asyncio.Task] = []
        self._parando = False
        self._marcas = {"catalogo": 0.0, "cti": 0.0, "vigilancia": 0.0}
        self.contadores = collections.Counter()

    # ════════════════════════════════════════════════════════════════════
    # Entrada
    # ════════════════════════════════════════════════════════════════════

    def _limitada(self, alerta: dict) -> bool:
        clave = (alerta["cliente"], alerta.get("regla_id") or alerta.get("titulo"),
                 (alerta.get("equipo") or {}).get("nombre", ""))
        ahora = time.monotonic()
        marcas = self._limites.setdefault(clave, collections.deque())
        while marcas and ahora - marcas[0] > self.config.limite_ventana_seg:
            marcas.popleft()
        if len(marcas) >= self.config.limite_por_clave:
            return True
        marcas.append(ahora)
        return False

    def recibir(self, cliente_id: str, siem: str, carga: dict) -> dict:
        """Normaliza y encola. Rapido: el SIEM no espera a que se ejecute nada."""
        cliente = self.clientes.get(cliente_id)
        if not cliente:
            raise AlertaRechazada(f"cliente desconocido o inactivo: {cliente_id}")
        alerta = nucleo.normalizar(siem, carga, cliente_id)
        # Los reintentos del SIEM son duplicados, no alertas nuevas: se miran
        # antes que el limitador para que no le gasten el cupo a las de verdad.
        # La clave lleva el cliente: dos clientes pueden repetir un id.
        clave = (cliente_id, alerta["id"])
        if clave in self._recientes_ids or self.almacen.existe_alerta(cliente_id, alerta["id"]):
            self.contadores["duplicadas"] += 1
            return {"alerta_id": alerta["id"], "estado": "duplicada"}
        if self._limitada(alerta):
            self.contadores["limitadas"] += 1
            self.almacen.auditar(cliente_id, "sistema", "alerta.limitada",
                                 {"alerta": alerta["id"], "regla": alerta.get("regla_id") or alerta.get("titulo")})
            return {"alerta_id": alerta["id"], "estado": "limitada"}
        self._recientes_ids[clave] = time.monotonic()
        while len(self._recientes_ids) > 10000:
            self._recientes_ids.popitem(last=False)
        if len(str(alerta.get("bruto"))) > self.config.tamano_maximo:
            alerta["bruto"] = {"recortado": True}
        n = self.almacen.encolar("alerta", {"alerta": alerta})
        self.contadores[f"recibidas_{siem}"] += 1
        self._hay_trabajo.set()
        return {"alerta_id": alerta["id"], "estado": "encolada", "trabajo": n}

    # ════════════════════════════════════════════════════════════════════
    # Contexto para el nucleo
    # ════════════════════════════════════════════════════════════════════

    async def _dns(self, alerta: dict) -> dict:
        if not self.config.dns_ptr:
            return {}
        ip = nucleo.leer(alerta, "red.ip_destino")
        if not ip or not nucleo.es_ip(ip) or nucleo.ip_privada(ip):
            return {}
        loop = asyncio.get_running_loop()
        try:
            nombre = await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout=2.0)
            return {ip: {"ptr": nombre[0]}}
        except (asyncio.TimeoutError, OSError):
            return {}

    async def _cti_cliente(self, cliente: dict, alerta: dict, simulacion: bool) -> list[dict]:
        coincidencias = self.cti.buscar(alerta.get("observables") or [])
        if "misp" in (cliente.get("conectores") or {}):
            misp = conectores.construir("misp", cliente, simulacion, self.config.conectores, self.transporte, self)
            valores = [o["valor"] for o in alerta.get("observables") or []]
            for m in await misp.buscar(valores):
                tipo = next((o["tipo"] for o in alerta["observables"] if o["valor"].lower() == str(m["valor"]).lower()), "")
                coincidencias.append({"tipo": tipo, "valor": m["valor"], "nivel": "alta", "fuentes": ["misp"],
                                      "edad_dias": None, "amenaza": f"MISP evento {m.get('evento')}", "origen": "misp"})
        return coincidencias

    def _contexto(self, cliente: dict, alerta: dict, cti: list, dns: dict, registrar: bool) -> dict:
        momento = nucleo.a_fecha(alerta.get("momento")) or datetime.now(timezone.utc)
        recientes = self.almacen.recientes(cliente["id"], momento - timedelta(days=7))
        visto = {}
        for campo in ("proceso.sha256", "proceso.imagen", "fichero.sha256"):
            valor = nucleo.leer(alerta, campo)
            if valor:
                visto[campo] = self.almacen.visto(cliente["id"], campo, str(valor)) if registrar else \
                    any(str(valor).lower() in [str(x).lower() for x in r.get("observables") or []] for r in recientes)
        plazos = []
        equipo = nucleo.leer(alerta, "equipo.nombre")
        if equipo:
            inc = self.almacen.incidente_abierto(cliente["id"], "equipo", equipo, momento - timedelta(hours=24))
            if inc:
                plazos = regulatorio.horas_restantes(inc.get("plazos_regulatorios") or [])
        return {
            "ahora": iso(),
            "correlacion": {"recientes": recientes, "visto": visto},
            "cti": {"disponible": self.cti.disponible or bool(cti), "coincidencias": cti,
                    "retirados": self.cti.retirados(alerta.get("observables") or []), "kev": sorted(self.cti.kev)},
            "dns": dns,
            "plazos": plazos,
        }

    def acciones_disponibles(self, cliente: dict) -> set[str]:
        """Acciones que algun conector configurado del cliente sabe hacer."""
        disponibles = set()
        for nombres in Clientes.capacidades(cliente).values():
            for n in nombres:
                con = conectores.construir(n, cliente, True, self.config.conectores, None, self)
                if con is not None:
                    disponibles |= set(con.acciones)
        return disponibles

    def modo(self, cliente: dict) -> bool:
        """True si este cliente esta en simulacion."""
        return Clientes.modo(cliente, self.config.simulacion_global) == "simulacion"

    def decidir(self, cliente_id: str, siem: str, carga: dict) -> dict:
        """Plan sin ejecutar nada ni guardar estado. Para SOAR que solo piden la decision."""
        cliente = self.clientes.get(cliente_id)
        if not cliente:
            raise AlertaRechazada(f"cliente desconocido o inactivo: {cliente_id}")
        alerta = nucleo.normalizar(siem, carga, cliente_id)
        cti = self.cti.buscar(alerta.get("observables") or [])
        contexto = self._contexto(cliente, alerta, cti, {}, registrar=False)
        caps = set(Clientes.capacidades(cliente))
        return nucleo.decidir(alerta, self.catalogo.actual, cliente, contexto, capacidades=caps,
                              acciones_disponibles=self.acciones_disponibles(cliente))

    # ════════════════════════════════════════════════════════════════════
    # Procesar una alerta
    # ════════════════════════════════════════════════════════════════════

    async def procesar_alerta(self, alerta: dict) -> dict:
        cliente = self.clientes.get(alerta["cliente"])
        if not cliente:
            raise AlertaRechazada(f"cliente {alerta['cliente']} ya no esta activo")
        simulacion = self.modo(cliente)
        dns = await self._dns(alerta)
        cti = await self._cti_cliente(cliente, alerta, simulacion)
        caps = Clientes.capacidades(cliente)

        # Decision, correlacion y guardado van en serie: dos alertas del mismo
        # ataque procesadas a la vez tienen que verse la una a la otra, o la
        # secuencia no se detecta nunca.
        async with self._cerrojo_decision:
            if self.almacen.existe_alerta(cliente["id"], alerta["id"]):
                return {"estado": "duplicada"}
            contexto = self._contexto(cliente, alerta, cti, dns, registrar=True)
            plan = nucleo.decidir(alerta, self.catalogo.actual, cliente, contexto, capacidades=set(caps),
                                  acciones_disponibles=self.acciones_disponibles(cliente))
            fallos = nucleo.verificar_invariantes(plan, alerta)
            if fallos:
                # No deberia pasar nunca: el nucleo ya lo impide. Si pasa, se
                # degrada a aprobacion y se deja rastro.
                for p in plan["acciones"]:
                    if p["modo"] == "automatica" and not p.get("registro") and not p.get("es_evidencia"):
                        p["modo"], p["motivo"] = "aprobacion", "invariante: " + "; ".join(fallos)
                self.almacen.auditar(cliente["id"], "sistema", "invariante.rota", {"alerta": alerta["id"], "fallos": fallos})
            incidente = self._correlacionar(cliente, alerta, plan)
            self.almacen.guardar_alerta(alerta, plan, incidente["id"] if incidente else "", cti)

        self.almacen.auditar(cliente["id"], "sistema", "alerta.decidida", {
            "alerta": alerta["id"], "regla": plan["regla"]["clave"], "familia": plan["familia"], "clase": plan["clase"],
            "estado": plan["estado"], "modos": plan["modos"], "incidente": incidente["id"] if incidente else "",
            "catalogo": plan["version_catalogo"], "simulacion": simulacion})
        self.contadores[f"plan_{plan['estado']}"] += 1
        if plan["estado"] in ("descartada", "cerrada_auto") or not incidente:
            return {"plan": plan, "incidente": None}

        # Plazos regulatorios: corren desde que se abrio el incidente, y se anaden
        # los marcos que una alerta posterior haga aplicables (la exfiltracion
        # que llega despues del ransomware anade el RGPD a lo que ya corria).
        etiquetas = {e for a in nucleo.activos_de(cliente, nucleo.leer(alerta, "equipo.nombre"), nucleo.leer(alerta, "equipo.ip"))
                     for e in a.get("etiquetas") or []}
        marcos = regulatorio.aplica(cliente, plan, etiquetas)
        previos = incidente.get("plazos_regulatorios") or []
        if isinstance(previos, str):
            previos = json.loads(previos or "[]")
        if marcos:
            ya = {str(p.get("marco", "")).lower() for p in previos}
            conocido = nucleo.a_fecha(incidente["abierto"]) or datetime.now(timezone.utc)
            nuevos = [p for p in regulatorio.plazos_para(cliente, plan, conocido, etiquetas=etiquetas)
                      if str(p["marco"]).lower() not in ya]
            if nuevos:
                self.almacen.modificar_incidente(incidente["id"], plazos_regulatorios=previos + nuevos)
                self.almacen.auditar(cliente["id"], "sistema", "plazos.iniciados",
                                     {"incidente": incidente["id"], "marcos": sorted({p["marco"] for p in nuevos})})

        # Acciones
        resultados = []
        for paso in plan["acciones"]:
            if paso["modo"] == "automatica":
                resultados += await self.ejecutar_paso(cliente, incidente, alerta, plan, paso, origen="automatica")
            elif paso["modo"] == "aprobacion":
                self._pedir_aprobacion(cliente, incidente, alerta, plan, paso)
            elif paso["modo"] == "manual":
                self.almacen.crear_tarea(cliente["id"], incidente["id"], "Contencion", paso["nombre"] or paso["origen"],
                                         paso["motivo"])

        # Caso externo y aviso
        await self._caso(cliente, incidente, alerta, plan, simulacion)
        if plan["notificar"]:
            await self._avisar_plan(cliente, incidente, plan, resultados, simulacion)
        return {"plan": plan, "incidente": incidente["id"], "ejecuciones": resultados}

    def _correlacionar(self, cliente, alerta, plan):
        if plan["estado"] in ("descartada", "cerrada_auto"):
            return None
        momento = nucleo.a_fecha(alerta.get("momento")) or datetime.now(timezone.utc)
        for tipo, valor in (("equipo", nucleo.leer(alerta, "equipo.nombre")), ("usuario", nucleo.leer(alerta, "usuario.nombre"))):
            if not valor:
                continue
            inc = self.almacen.incidente_abierto(cliente["id"], tipo, valor, momento - timedelta(hours=24))
            if inc:
                return self.almacen.actualizar_incidente(inc["id"], plan)
        tipo, valor = ("equipo", nucleo.leer(alerta, "equipo.nombre")) if nucleo.leer(alerta, "equipo.nombre") else \
            ("usuario", nucleo.leer(alerta, "usuario.nombre") or "") if nucleo.leer(alerta, "usuario.nombre") else ("alerta", alerta["id"])
        inc = self.almacen.crear_incidente(cliente["id"], tipo, valor, plan)
        self.almacen.auditar(cliente["id"], "sistema", "incidente.abierto", {"incidente": inc["id"], "entidad": f"{tipo}:{valor}"})
        return inc

    # ════════════════════════════════════════════════════════════════════
    # Ejecutar un paso
    # ════════════════════════════════════════════════════════════════════

    def _conectores_de(self, cliente: dict, paso: dict) -> list[str]:
        return Clientes.capacidades(cliente).get(paso.get("capacidad"), [])

    async def ejecutar_paso(self, cliente: dict, incidente: dict, alerta: dict, plan: dict, paso: dict,
                            origen: str, actor: str = "sistema", deshace: str | None = None,
                            datos_deshacer: dict | None = None) -> list[dict]:
        if origen == "automatica" and self.almacen.ejecucion_previa(cliente["id"], alerta.get("id", ""), paso["id"]):
            return []
        if origen == "automatica":
            previa = self.almacen.accion_vigente(cliente["id"], (incidente or {}).get("id", ""), paso["accion"],
                                                 paso.get("objetivo") or {})
            if previa:
                ej = self.almacen.crear_ejecucion(
                    cliente=cliente["id"], incidente_id=incidente["id"], alerta_id=alerta.get("id", ""),
                    paso_id=paso.get("id", ""), accion=paso["accion"], conector="", origen=origen, estado="omitida",
                    objetivo=paso.get("objetivo") or {}, parametros=paso.get("parametros") or {}, actor=actor,
                    resultado={"detalle": f"ya aplicada en este incidente ({previa['id']})"})
                return [dict(ej, detalle=f"ya aplicada en este incidente ({previa['id']})")]
        simulacion = self.modo(cliente)
        nombres = self._conectores_de(cliente, paso)
        if not nombres:
            nombres = ["interno"] if paso.get("capacidad") == "interno" else []
        salida = []
        caso_externo = (incidente or {}).get("caso_externo", "")
        for nombre in nombres:
            con = conectores.construir(nombre, cliente, simulacion, self.config.conectores, self.transporte, self)
            ej = self.almacen.crear_ejecucion(
                cliente=cliente["id"], incidente_id=(incidente or {}).get("id", ""), alerta_id=alerta.get("id", ""),
                paso_id=paso.get("id", ""), accion=paso["accion"], conector=nombre, origen=origen, estado="en_curso",
                objetivo=paso.get("objetivo") or {}, parametros=paso.get("parametros") or {}, deshace=deshace, actor=actor)
            if con is None or not con.sabe(paso["accion"]):
                motivo = f"el conector {nombre} no existe" if con is None else f"{nombre} no implementa {paso['accion']}"
                self.almacen.terminar_ejecucion(ej["id"], "omitida", {"detalle": motivo}, [])
                salida.append(dict(ej, estado="omitida", detalle=motivo))
                continue
            ok, motivo = con.configurado()
            if not ok and not simulacion:
                self.almacen.terminar_ejecucion(ej["id"], "error", {"detalle": motivo}, [])
                salida.append(dict(ej, estado="error", detalle=motivo))
                continue
            contexto = {"alerta": alerta, "plan": plan, "paso": paso, "incidente_id": (incidente or {}).get("id", ""),
                        "ejecucion_id": ej["id"], "caso_externo": caso_externo, "datos_deshacer": datos_deshacer or {}}
            try:
                res = await con.ejecutar(paso["accion"], paso.get("objetivo") or {}, paso.get("parametros") or {}, contexto)
            except Exception as e:  # un conector roto no tumba el motor
                log.exception("conector %s fallo", nombre)
                res = conectores.Resultado("error", f"{type(e).__name__}: {e}")
            self.almacen.terminar_ejecucion(ej["id"], res.estado, {"detalle": res.detalle}, res.peticiones, res.datos)
            self.almacen.auditar(cliente["id"], actor, "accion." + res.estado, {
                "ejecucion": ej["id"], "accion": paso["accion"], "conector": nombre, "origen": origen,
                "objetivo": paso.get("objetivo"), "detalle": res.detalle[:500], "incidente": (incidente or {}).get("id", "")})
            self.contadores[f"accion_{res.estado}"] += 1
            salida.append(dict(ej, estado=res.estado, detalle=res.detalle))
            if res.estado == "error" and origen != "deshacer":
                await avisos.enviar(cliente, "error", f"Fallo al ejecutar {paso['nombre']}",
                                    f"{nombre}: {res.detalle}", 3, {"Incidente": (incidente or {}).get("id", "")},
                                    self._enlace(cliente, (incidente or {}).get("id", "")), simulacion, self.transporte)
        return salida

    def _pedir_aprobacion(self, cliente, incidente, alerta, plan, paso):
        minutos = int((cliente.get("politica") or {}).get("caducidad_aprobacion_min", 240))
        ap = self.almacen.crear_aprobacion(cliente["id"], incidente["id"], alerta["id"], paso, paso["motivo"],
                                           datetime.now(timezone.utc) + timedelta(minutes=minutos))
        self.almacen.auditar(cliente["id"], "sistema", "aprobacion.pedida", {
            "aprobacion": ap["id"], "accion": paso["accion"], "motivo": paso["motivo"], "incidente": incidente["id"]})
        return ap

    async def aprobar(self, cliente_id: str, ap_id: str, quien: str, comentario: str = "") -> dict:
        cliente = self.clientes.get(cliente_id)
        ap = self.almacen.aprobacion(ap_id)
        if not cliente or not ap or ap["cliente"] != cliente_id:
            raise AlertaRechazada("aprobacion no encontrada")
        if not self.almacen.decidir_aprobacion(ap_id, "aprobada", quien, comentario):
            actual = self.almacen.aprobacion(ap_id) or ap
            if actual["estado"] == "pendiente":
                # Caducada pero aun sin marcar: la vigilancia periodica no ha pasado
                for v in self.almacen.caducar_aprobaciones():
                    self.almacen.auditar(v["cliente"], "sistema", "aprobacion.caducada", {"aprobacion": v["id"]})
                raise AlertaRechazada(f"la aprobacion caduco el {actual.get('caduca')}: la accion ya no se ejecuta")
            raise AlertaRechazada(f"la aprobacion ya no esta pendiente ({actual['estado']})")
        self.almacen.auditar(cliente_id, quien, "aprobacion.aprobada", {"aprobacion": ap_id, "accion": ap["paso"].get("accion"),
                                                                        "comentario": comentario})
        incidente = self.almacen.incidente(ap["incidente_id"]) or {}
        alerta = self._alerta_guardada(cliente_id, ap["alerta_id"])
        plan = alerta.pop("_plan", {}) if alerta else {}
        resultados = await self.ejecutar_paso(cliente, incidente, alerta or {"id": ap["alerta_id"]}, plan, ap["paso"],
                                              origen="aprobada", actor=quien)
        estado = "ejecutada" if any(r["estado"] in ("ok", "simulada") for r in resultados) else "fallida"
        self.almacen.anotar_ejecuciones_aprobacion(ap_id, [r["id"] for r in resultados], estado)
        return {"aprobacion": ap_id, "estado": estado, "ejecuciones": resultados}

    def rechazar(self, cliente_id: str, ap_id: str, quien: str, comentario: str = "") -> dict:
        ap = self.almacen.aprobacion(ap_id)
        if not ap or ap["cliente"] != cliente_id:
            raise AlertaRechazada("aprobacion no encontrada")
        if not self.almacen.decidir_aprobacion(ap_id, "rechazada", quien, comentario):
            raise AlertaRechazada(f"la aprobacion ya no esta pendiente ({ap['estado']})")
        self.almacen.auditar(cliente_id, quien, "aprobacion.rechazada", {"aprobacion": ap_id, "comentario": comentario})
        return {"aprobacion": ap_id, "estado": "rechazada"}

    def _alerta_guardada(self, cliente_id: str, alerta_id: str) -> dict | None:
        import json
        f = self.almacen._uno("SELECT alerta, plan FROM alertas WHERE cliente=? AND id=?", (cliente_id, alerta_id))
        if not f:
            return None
        a = json.loads(f["alerta"])
        a["_plan"] = json.loads(f["plan"])
        return a

    async def deshacer(self, cliente_id: str, ej_id: str, quien: str) -> list[dict]:
        cliente = self.clientes.get(cliente_id)
        ej = self.almacen.ejecucion(ej_id)
        if not cliente or not ej or ej["cliente"] != cliente_id:
            raise AlertaRechazada("ejecucion no encontrada")
        if ej["estado"] not in ("ok", "simulada", "confirmada"):
            raise AlertaRechazada(f"solo se deshace lo ejecutado (estado actual: {ej['estado']})")
        previa = self.almacen.deshecha_por(ej_id)
        if previa:
            raise AlertaRechazada(f"ya se deshizo ({previa['id']}, {previa['estado']}): repetir la inversa "
                                  "desharia lo que se haya hecho despues")
        meta = self.catalogo.actual.acciones.get(ej["accion"]) or {}
        inversa = meta.get("deshacer")
        if not inversa:
            raise AlertaRechazada(f"{ej['accion']} no tiene accion inversa (radio {meta.get('radio')}, "
                                  f"reversible {meta.get('reversible')})")
        meta_inv = self.catalogo.actual.acciones[inversa]
        alerta = self._alerta_guardada(cliente_id, ej["alerta_id"]) or {"id": ej["alerta_id"]}
        plan = alerta.pop("_plan", {})
        paso = {"id": f"deshacer-{ej_id}", "accion": inversa, "nombre": meta_inv.get("nombre", inversa),
                "capacidad": meta_inv.get("capacidad"), "objetivo": ej.get("objetivo") or {}, "parametros": {}}
        # Se deshace con el MISMO conector que ejecuto, no con todos los de la capacidad.
        cliente_un = dict(cliente, capacidades=dict(cliente.get("capacidades") or {}, **{meta_inv.get("capacidad"): [ej["conector"]]}))
        incidente = self.almacen.incidente(ej["incidente_id"]) or {}
        return await self.ejecutar_paso(cliente_un, incidente, alerta, plan, paso, origen="deshacer", actor=quien,
                                        deshace=ej_id, datos_deshacer=ej.get("datos_deshacer") or {})

    async def accion_a_demanda(self, cliente_id: str, accion: str, objetivo: dict, quien: str,
                               incidente_id: str = "", comentario: str = "") -> list[dict]:
        """Una persona autorizada ordena una accion del catalogo. Es su decision: se ejecuta y se audita."""
        cliente = self.clientes.get(cliente_id)
        meta = self.catalogo.actual.acciones.get(accion)
        if not cliente or not meta:
            raise AlertaRechazada("cliente o accion desconocidos")
        if accion in ((cliente.get("politica") or {}).get("acciones_prohibidas") or []):
            raise AlertaRechazada("el perfil del cliente prohibe esta accion")
        alerta = nucleo.alerta_vacia("generico", cliente_id)
        for ruta, valor in (objetivo or {}).items():
            nucleo.poner(alerta, ruta, valor)
        alerta["id"] = f"demanda-{int(time.time() * 1000)}"
        ok, obj, falta = nucleo.requisito(alerta, meta.get("requiere"))
        if not ok:
            raise AlertaRechazada(f"faltan campos del objetivo: {falta}")
        paso = {"id": alerta["id"], "accion": accion, "nombre": meta.get("nombre", accion), "capacidad": meta.get("capacidad"),
                "objetivo": obj, "parametros": {}, "origen": comentario}
        incidente = self.almacen.incidente(incidente_id) if incidente_id else {}
        if incidente_id and (not incidente or incidente["cliente"] != cliente_id):
            raise AlertaRechazada("incidente no encontrado")
        self.almacen.auditar(cliente_id, quien, "accion.demanda", {"accion": accion, "objetivo": obj, "comentario": comentario})
        return await self.ejecutar_paso(cliente, incidente or {}, alerta, {}, paso, origen="demanda", actor=quien)

    # ════════════════════════════════════════════════════════════════════
    # Caso y avisos
    # ════════════════════════════════════════════════════════════════════

    def _enlace(self, cliente: dict, incidente_id: str) -> str:
        return f"{self.config.url_publica.rstrip('/')}/panel#{cliente['id']}/{incidente_id}" if incidente_id else ""

    async def _caso(self, cliente, incidente, alerta, plan, simulacion):
        if not plan.get("crear_caso") and plan["clase"] != "auto_enriq":
            return
        for nombre in Clientes.capacidades(cliente).get("casos", []):
            if nombre != "thehive":
                continue
            con = conectores.construir("thehive", cliente, simulacion, self.config.conectores, self.transporte, self)
            ok, motivo = con.configurado()
            if not ok and not simulacion:
                self.almacen.auditar(cliente["id"], "sistema", "caso.error", {"incidente": incidente["id"], "detalle": motivo})
                continue
            if incidente.get("caso_externo"):
                res = await con.comentar(incidente["caso_externo"], plan["resumen"])
            else:
                res = await con.abrir_caso(plan, alerta, incidente)
                caso = (res.datos or {}).get("caso")
                if caso:
                    self.almacen.modificar_incidente(incidente["id"], caso_externo=caso)
            self.almacen.auditar(cliente["id"], "sistema", "caso." + res.estado, {
                "incidente": incidente["id"], "detalle": res.detalle, "peticiones": len(res.peticiones)})

    async def _avisar_plan(self, cliente, incidente, plan, resultados, simulacion):
        auto = [f"{r['accion']} ({r['estado']})" for r in resultados]
        espera = [p["nombre"] for p in plan["acciones"] if p["modo"] == "aprobacion"]
        campos = {"Familia": plan["familia"], "Clase": plan["clase"], "Severidad": plan["severidad"],
                  "Escalar a": f"{plan['escalado']['a']} en {plan['escalado']['plazo_min']} min",
                  "Equipo": incidente.get("entidad", ""), "Incidente": incidente["id"]}
        if auto:
            campos["Ejecutado"] = "; ".join(auto)[:900]
        if espera:
            campos["Espera aprobacion"] = "; ".join(espera)[:900]
        if plan.get("secuencias"):
            campos["Secuencia"] = ", ".join(s["nombre"] for s in plan["secuencias"])
        titulo = ("[SIMULACION] " if simulacion else "") + f"{plan['regla']['titulo'] or plan['titulo']}"
        r = await avisos.enviar(cliente, "incidente", titulo[:200], plan["resumen"][:1500], plan["severidad"], campos,
                                self._enlace(cliente, incidente["id"]), simulacion, self.transporte)
        self.almacen.auditar(cliente["id"], "sistema", "aviso.enviado", {"incidente": incidente["id"], "canales": r})

    # ════════════════════════════════════════════════════════════════════
    # Evidencias que vuelven: acuses, FtriageDFIR y Malpipe
    # ════════════════════════════════════════════════════════════════════

    ESTADOS_ACUSE = {"ok": "confirmada", "aplicada": "confirmada", "confirmada": "confirmada",
                     "fallida": "fallida", "error": "fallida", "rechazada": "fallida"}

    def acuse(self, cliente_id: str, ej_id: str, estado: str, detalle: dict) -> dict:
        """Lo que el script del equipo dice que paso de verdad.

        "en_curso" o "lanzada" (un triage que tarda minutos) solo se audita: la
        ejecucion sigue pendiente hasta el acuse final. Si el acuse trae el
        resumen de un triage de FtriageDFIR (cuando el equipo no puede subir el
        informe entero al motor), se incorpora al incidente como evidencia.
        """
        ej = self.almacen.ejecucion(ej_id)
        if not ej or ej["cliente"] != cliente_id:
            raise AlertaRechazada("ejecucion no encontrada")
        nuevo = self.ESTADOS_ACUSE.get(str(estado).lower())
        if nuevo is None:
            self.almacen.auditar(cliente_id, "agente", "accion.progreso",
                                 {"ejecucion": ej_id, "estado": estado, "detalle": detalle})
            return {"ejecucion": ej_id, "estado": ej["estado"], "progreso": estado}
        self.almacen.confirmar_ejecucion(ej_id, nuevo, detalle)
        self.almacen.auditar(cliente_id, "agente", "accion." + nuevo, {"ejecucion": ej_id, "detalle": detalle})
        salida = {"ejecucion": ej_id, "estado": nuevo}
        informe = (detalle or {}).get("informe_ftriage")
        if nuevo == "confirmada" and isinstance(informe, dict):
            informe.setdefault("case", {}).setdefault("name", ej.get("incidente_id") or "")
            salida["evidencia"] = self.ingerir_ftriage(cliente_id, informe)
        return salida

    def ingerir_ftriage(self, cliente_id: str, informe: dict) -> dict:
        """Informe de FtriageDFIR -> IOCs y tecnicas al incidente del equipo."""
        host = (informe.get("host") or {}).get("hostname", "")
        caso = (informe.get("case") or {}).get("name", "")
        evaluacion = informe.get("assessment") or {}
        inc = self.almacen.incidente(caso) if caso.startswith("inc-") else None
        if inc is not None and inc["cliente"] != cliente_id:
            inc = None                       # el caso es de otro cliente: no se toca
        if inc is None and host:
            inc = self.almacen.incidente_abierto(cliente_id, "equipo", host, datetime.now(timezone.utc) - timedelta(days=7))
        iocs = [i for i in informe.get("iocs") or [] if not i.get("private")]
        tecnicas = sorted({t.get("attack") for t in evaluacion.get("attack_techniques") or [] if t.get("attack")})
        resumen = {"equipo": host, "veredicto": evaluacion.get("verdict"), "riesgo": evaluacion.get("risk_score"),
                   "confianza": evaluacion.get("confidence"), "iocs": len(iocs), "tecnicas": tecnicas,
                   "hallazgos_criticos": [f["text"] for f in informe.get("findings") or [] if f.get("level") == "crit"][:10]}
        if inc:
            self.almacen.crear_tarea(cliente_id, inc["id"], "Evidencia", f"Triage forense de {host}: {evaluacion.get('verdict', '')}",
                                     f"Riesgo {evaluacion.get('risk_score')}/100. Tecnicas: {', '.join(tecnicas)}. "
                                     f"IOCs: {', '.join(i.get('defanged') or i.get('value', '') for i in iocs[:30])}")
            if evaluacion.get("verdict_key") == "critico":
                self.almacen.modificar_incidente(inc["id"], severidad=4)
        self.almacen.auditar(cliente_id, "agente", "evidencia.ftriage", dict(resumen, incidente=(inc or {}).get("id", "")))
        return dict(resumen, incidente=(inc or {}).get("id", ""))

    def ingerir_malpipe(self, cliente_id: str, informe: dict, incidente_id: str = "") -> dict:
        """Veredicto de Malpipe -> si es malicioso, propone bloquear el hash en la flota (con aprobacion)."""
        estatico = informe.get("static") or {}
        hashes = estatico.get("hashes") or {}
        ind = estatico.get("indicators") or {}
        veredicto = informe.get("verdict", "desconocido")
        resumen = {"fichero": estatico.get("filename"), "sha256": hashes.get("sha256"), "veredicto": veredicto,
                   "puntuacion": informe.get("score"), "familia": (informe.get("dynamic") or {}).get("family", ""),
                   "tecnicas": sorted({a.get("id") for a in informe.get("attack") or [] if a.get("id")}),
                   "iocs": {"ips": ind.get("ips") or [], "dominios": ind.get("domains") or [], "urls": ind.get("urls") or []}}
        inc = self.almacen.incidente(incidente_id) if incidente_id else None
        if inc is not None and inc["cliente"] != cliente_id:
            inc, incidente_id = None, ""     # el incidente es de otro cliente: no se toca
        cliente = self.clientes.get(cliente_id)
        if inc and cliente and veredicto == "malicioso" and hashes.get("sha256"):
            meta = self.catalogo.actual.acciones["flota.bloquear_hash"]
            paso = {"id": f"malpipe-{hashes['sha256'][:12]}", "accion": "flota.bloquear_hash", "nombre": meta["nombre"],
                    "capacidad": meta["capacidad"], "radio": meta["radio"], "reversible": meta["reversible"],
                    "objetivo": {"fichero.sha256": hashes["sha256"]}, "parametros": {},
                    "motivo": f"Malpipe: {veredicto} ({informe.get('score')}/100) {resumen['familia']}".strip(),
                    "modo": "aprobacion", "origen": "Veredicto de Malpipe"}
            alerta = {"id": f"malpipe-{hashes['sha256'][:16]}", "cliente": cliente_id}
            self._pedir_aprobacion(cliente, inc, alerta, {}, paso)
        self.almacen.auditar(cliente_id, "agente", "evidencia.malpipe", dict(resumen, incidente=incidente_id))
        return resumen

    # ════════════════════════════════════════════════════════════════════
    # Trabajadores y tareas periodicas
    # ════════════════════════════════════════════════════════════════════

    async def _esperar_trabajo(self, segundos: float):
        # asyncio.wait y no wait_for: hasta Python 3.11, wait_for se puede tragar
        # la cancelacion si el evento llega a la vez, y parar() no volveria nunca.
        espera = asyncio.ensure_future(self._hay_trabajo.wait())
        try:
            await asyncio.wait({espera}, timeout=segundos)
        finally:
            if not espera.done():
                espera.cancel()

    async def _trabajador(self, n: int):
        while not self._parando:
            trabajo = self.almacen.tomar_trabajo()
            if trabajo is None:
                self._hay_trabajo.clear()
                await self._esperar_trabajo(1.0)
                continue
            try:
                if trabajo["tipo"] == "alerta":
                    await self.procesar_alerta(trabajo["carga"]["alerta"])
                self.almacen.terminar_trabajo(trabajo["n"])
            except Exception as e:
                log.exception("trabajo %s fallo", trabajo["n"])
                self.almacen.terminar_trabajo(trabajo["n"], f"{type(e).__name__}: {e}")
                self.almacen.auditar(trabajo["carga"].get("alerta", {}).get("cliente", ""), "sistema", "trabajo.error",
                                     {"trabajo": trabajo["n"], "error": str(e)[:500]})

    async def vigilar_una_vez(self):
        """Caducidades, vencimientos, refrescos. Se llama en bucle y en las pruebas."""
        for ap in self.almacen.caducar_aprobaciones():
            self.almacen.auditar(ap["cliente"], "sistema", "aprobacion.caducada", {"aprobacion": ap["id"]})
        for inc in self.almacen.incidentes_vencidos():
            cliente = self.clientes.get(inc["cliente"])
            if not cliente:
                continue
            siguiente = {"L1": "L2", "L2": "L3", "L3": "guardia"}.get(inc["escalado_a"], "guardia")
            await avisos.enviar(cliente, "vencimiento", f"Incidente sin asumir: {inc['titulo']}"[:200],
                                f"Vencio el plazo de {inc['escalado_a']} sin que nadie lo asumiera. Escalar a {siguiente}.",
                                4, {"Incidente": inc["id"], "Entidad": inc["entidad"]},
                                self._enlace(cliente, inc["id"]), self.modo(cliente), self.transporte)
            self.almacen.modificar_incidente(inc["id"], vencimiento_avisado=1, escalado_a=siguiente)
            self.almacen.auditar(inc["cliente"], "sistema", "incidente.vencido", {"incidente": inc["id"], "escalado_a": siguiente})
        self.almacen.edl_purgar()
        self.clientes.recargar()
        ahora = time.monotonic()
        if ahora - self._marcas["catalogo"] > self.config.actualizacion_min * 60:
            self._marcas["catalogo"] = ahora
            if self.config.actualizacion_url:
                r = await self.catalogo.actualizar_remoto(self.transporte)
                if r.get("estado") in ("actualizado", "rechazado"):
                    self.almacen.auditar("", "sistema", "catalogo." + r["estado"], r)
            else:
                self.catalogo.recargar_local()
        if ahora - self._marcas["cti"] > self.config.cti_min * 60:
            self._marcas["cti"] = ahora
            await self.cti.refrescar(self.transporte)

    async def _vigilante(self):
        while True:
            try:
                await self.vigilar_una_vez()
            except Exception:
                log.exception("vigilancia")
            await asyncio.sleep(self.config.vigilancia_seg)

    async def arrancar(self, vigilante: bool = True):
        self._parando = False
        n = self.almacen.reencolar_huerfanos()
        if n:
            log.warning("%d trabajo(s) interrumpidos vuelven a la cola", n)
        for i in range(max(1, self.config.trabajadores)):
            self._tareas.append(asyncio.create_task(self._trabajador(i)))
        if vigilante:
            self._tareas.append(asyncio.create_task(self._vigilante()))
        self._hay_trabajo.set()

    async def parar(self, limite_seg: float = 10.0):
        self._parando = True
        self._hay_trabajo.set()
        for t in self._tareas:
            t.cancel()
        if self._tareas:
            _, colgadas = await asyncio.wait(self._tareas, timeout=limite_seg)
            if colgadas:
                log.warning("%d tarea(s) no terminaron en %s s al parar", len(colgadas), limite_seg)
        self._tareas.clear()

    async def drenar(self, limite_seg: float = 30.0):
        """Espera a que la cola se vacie (pruebas y simulador)."""
        fin = time.monotonic() + limite_seg
        while self.almacen.pendientes() and time.monotonic() < fin:
            await asyncio.sleep(0.05)
