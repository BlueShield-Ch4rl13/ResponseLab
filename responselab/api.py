"""
API HTTP del motor.

Autenticacion, por quien llama
------------------------------
* SIEM -> motor (alertas): token de ingesta del cliente. Cabecera
  ``Authorization: Bearer <token>``, Basic con el token como contrasena (el
  conector Webhook de Kibana) o, para la accion webhook de Splunk que no
  admite cabeceras, ``?token=``. Solo sirve para enviar alertas de su cliente.
* Agentes (acuses de active response, informes de FtriageDFIR y Malpipe):
  token de agentes del cliente.
* Personas (aprobar, rechazar, deshacer, acciones a demanda, ver incidentes):
  token personal del aprobador, guardado como huella en el perfil.
* Administracion (recargar catalogo, metricas, auditoria): RL_ADMIN_TOKEN.

Ningun token sirve para otro cliente ni para otro papel.
"""
from __future__ import annotations

import base64
import binascii
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from . import __version__
from .clientes import iguales
from .config import Config
from .ejecutor import AlertaRechazada, Motor

log = logging.getLogger("responselab.api")
PANEL = Path(__file__).resolve().parent / "panel.html"


class LimiteCuerpo:
    """Corta en 413 cualquier peticion cuyo cuerpo supere el limite.

    No basta con mirar Content-Length: un cuerpo enviado por trozos (chunked)
    no lo lleva. Se cuentan los bytes segun llegan.
    """

    def __init__(self, app, config: Config):
        self.app, self.config = app, config

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limite = self.config.tamano_maximo
        longitud = dict(scope.get("headers") or []).get(b"content-length", b"")
        if longitud.isdigit() and int(longitud) > limite:
            respuesta = JSONResponse({"error": "alerta demasiado grande"}, status_code=413)
            return await respuesta(scope, receive, send)
        recibido = 0

        async def recibir():
            nonlocal recibido
            mensaje = await receive()
            if mensaje["type"] == "http.request":
                recibido += len(mensaje.get("body") or b"")
                if recibido > limite:
                    raise HTTPException(413, "alerta demasiado grande")
            return mensaje

        await self.app(scope, recibir, send)


def _token(authorization: str | None, token_qs: str | None) -> str:
    """Bearer, Basic (usuario cualquiera, el token como contrasena) o ?token=.

    Basic existe para los SIEM cuyo webhook solo sabe guardar credenciales
    asi (el conector Webhook de Kibana las cifra; una cabecera Authorization
    escrita a mano quedaria en claro). ?token= es para el webhook de Splunk,
    que no admite cabeceras: va en el registro de accesos del proxy, asi que
    ese token solo debe servir para ingerir.
    """
    if authorization:
        tipo, _, valor = authorization.strip().partition(" ")
        if tipo.lower() == "bearer":
            return valor.strip()
        if tipo.lower() == "basic":
            try:
                usuario_clave = base64.b64decode(valor.strip(), validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                return ""
            return usuario_clave.partition(":")[2].strip()
    return (token_qs or "").strip()


def crear_app(config: Config | None = None, motor: Motor | None = None, arrancar: bool = True) -> FastAPI:
    config = config or Config()

    @asynccontextmanager
    async def ciclo(app: FastAPI):
        app.state.motor = motor or Motor(config)
        if arrancar:
            await app.state.motor.arrancar()
        yield
        await app.state.motor.parar()

    app = FastAPI(title="ResponseLab", version=__version__, lifespan=ciclo,
                  description="Motor de respuesta a incidentes multi-SIEM y multi-SOAR")
    app.add_middleware(LimiteCuerpo, config=config)

    def m(request: Request) -> Motor:
        return request.app.state.motor

    # ── dependencias de autenticacion ──
    # ?token= solo vale para ingerir y para las listas EDL (lo que no sabe
    # mandar cabeceras); administracion, aprobadores y agentes van por cabecera.
    def admin(request: Request, authorization: str | None = Header(None)):
        t = _token(authorization, None)
        if not config.token_admin or not t or not iguales(t, config.token_admin):
            raise HTTPException(401, "token de administracion no valido")
        return "admin"

    def ingesta(cliente: str, request: Request, authorization: str | None = Header(None), token: str | None = Query(None)):
        if not m(request).clientes.token_ingesta_valido(cliente, _token(authorization, token)):
            raise HTTPException(401, "token de ingesta no valido para este cliente")
        return cliente

    def agente(cliente: str, request: Request, authorization: str | None = Header(None)):
        if not m(request).clientes.token_agente_valido(cliente, _token(authorization, None)):
            raise HTTPException(401, "token de agente no valido para este cliente")
        return cliente

    def persona(cliente: str, request: Request, authorization: str | None = Header(None)):
        t = _token(authorization, None)
        if config.token_admin and t and iguales(t, config.token_admin):
            return "admin"
        ap = m(request).clientes.aprobador(cliente, t)
        if not ap:
            raise HTTPException(401, "token de aprobador no valido para este cliente")
        return ap.get("email") or ap.get("nombre") or "aprobador"

    def _err(e: Exception):
        raise HTTPException(409 if isinstance(e, AlertaRechazada) else 400, str(e))

    # ── salud y metricas ──
    @app.get("/salud")
    async def salud(request: Request):
        mo = m(request)
        cat = mo.catalogo.estado()
        return {"estado": "ok" if cat["version"] else "degradado", "version": __version__,
                "catalogo": {"version": cat["version"], "origen": cat["origen"], "error": cat["ultimo_error"]},
                "cti": {"disponible": mo.cti.disponible, "generado": mo.cti.generado},
                "clientes": len(mo.clientes.todos()), "perfiles_con_error": sorted(mo.clientes.errores),
                "cola": mo.almacen.pendientes(), "simulacion_global": config.simulacion_global}

    @app.get("/metricas", response_class=PlainTextResponse)
    async def metricas(request: Request, _=Depends(admin)):
        mo = m(request)
        c = mo.almacen.contar()
        l = ["# TYPE responselab_alertas_total counter", f"responselab_alertas_total {c['alertas']}",
             "# TYPE responselab_incidentes_abiertos gauge", f"responselab_incidentes_abiertos {c['incidentes_abiertos']}",
             "# TYPE responselab_aprobaciones_pendientes gauge",
             f"responselab_aprobaciones_pendientes {c['aprobaciones_pendientes']}",
             "# TYPE responselab_cola gauge", f"responselab_cola {c['trabajos_pendientes']}"]
        l.append("# TYPE responselab_ejecuciones gauge")
        for estado, n in sorted(c["ejecuciones_por_estado"].items()):
            l.append(f'responselab_ejecuciones{{estado="{estado}"}} {n}')
        l.append("# TYPE responselab_alertas_por_clase gauge")
        for clase, n in sorted(c["alertas_por_clase"].items()):
            l.append(f'responselab_alertas_por_clase{{clase="{clase}"}} {n}')
        l.append("# TYPE responselab_eventos counter")
        for k, n in sorted(mo.contadores.items()):
            l.append(f'responselab_eventos{{tipo="{k}"}} {n}')
        l.append(f'responselab_catalogo_info{{version="{mo.catalogo.estado()["version"]}"}} 1')
        l.append(f"responselab_cti_indicadores {len(mo.cti.indice)}")
        return "\n".join(l) + "\n"

    # ── entrada de alertas ──
    @app.post("/v1/{cliente}/alertas/{siem}", status_code=202)
    async def alerta(cliente: str, siem: str, request: Request, _=Depends(ingesta)):
        try:
            carga = await request.json()
        except ValueError:
            raise HTTPException(400, "el cuerpo no es JSON") from None
        if not isinstance(carga, (dict, list)):
            raise HTTPException(400, "se espera una alerta (objeto JSON) o una lista de alertas")
        cargas = carga if isinstance(carga, list) else [carga]
        if siem == "elastic":
            # Una accion de regla de Kibana puede traer varias alertas juntas
            cargas = [dict(c, alerts=[a]) for c in cargas if isinstance(c, dict)
                      for a in (c.get("alerts") or [None]) if a is not None] or cargas
        salida = []
        for c in cargas[:500]:
            if not isinstance(c, dict):
                salida.append({"estado": "rechazada", "motivo": "cada alerta tiene que ser un objeto JSON"})
                continue
            try:
                salida.append(m(request).recibir(cliente, siem, c))
            except (AlertaRechazada, ValueError, TypeError, AttributeError, KeyError) as e:
                salida.append({"estado": "rechazada", "motivo": f"{type(e).__name__}: {e}"[:300]})
        return salida if isinstance(carga, list) or len(salida) != 1 else salida[0]

    @app.post("/v1/{cliente}/decidir/{siem}")
    async def decidir(cliente: str, siem: str, request: Request, carga: dict = Body(...), _=Depends(ingesta)):
        try:
            return m(request).decidir(cliente, siem, carga)
        except (AlertaRechazada, ValueError) as e:
            _err(e)

    # ── incidentes ──
    @app.get("/v1/{cliente}/incidentes")
    async def incidentes(cliente: str, request: Request, estado: str | None = None, limite: int = 100,
                         _=Depends(persona)):
        return m(request).almacen.incidentes(cliente, estado, min(limite, 500))

    @app.get("/v1/{cliente}/incidentes/{inc_id}")
    async def incidente(cliente: str, inc_id: str, request: Request, _=Depends(persona)):
        al = m(request).almacen
        inc = al.incidente(inc_id)
        if not inc or inc["cliente"] != cliente:
            raise HTTPException(404, "incidente no encontrado")
        return {"incidente": inc, "alertas": al.alertas(cliente, inc_id), "ejecuciones": al.ejecuciones(cliente, inc_id),
                "aprobaciones": [a for a in al.aprobaciones(cliente) if a["incidente_id"] == inc_id],
                "tareas": al.tareas(inc_id)}

    @app.post("/v1/{cliente}/incidentes/{inc_id}/{operacion}")
    async def operar_incidente(cliente: str, inc_id: str, operacion: str, request: Request,
                               cuerpo: dict = Body(default={}), quien=Depends(persona)):
        al = m(request).almacen
        inc = al.incidente(inc_id)
        if not inc or inc["cliente"] != cliente:
            raise HTTPException(404, "incidente no encontrado")
        if operacion == "asumir":
            al.modificar_incidente(inc_id, estado="asumido", asumido_por=quien)
        elif operacion == "cerrar":
            al.modificar_incidente(inc_id, estado="cerrado")
        else:
            raise HTTPException(404, "operacion desconocida (asumir | cerrar)")
        al.auditar(cliente, quien, f"incidente.{operacion}", {"incidente": inc_id, "comentario": cuerpo.get("comentario", "")})
        return al.incidente(inc_id)

    # ── aprobaciones ──
    @app.get("/v1/{cliente}/aprobaciones")
    async def aprobaciones(cliente: str, request: Request, estado: str | None = "pendiente", _=Depends(persona)):
        return m(request).almacen.aprobaciones(cliente, estado)

    @app.post("/v1/{cliente}/aprobaciones/{ap_id}/aprobar")
    async def aprobar(cliente: str, ap_id: str, request: Request, cuerpo: dict = Body(default={}), quien=Depends(persona)):
        try:
            return await m(request).aprobar(cliente, ap_id, quien, cuerpo.get("comentario", ""))
        except AlertaRechazada as e:
            _err(e)

    @app.post("/v1/{cliente}/aprobaciones/{ap_id}/rechazar")
    async def rechazar(cliente: str, ap_id: str, request: Request, cuerpo: dict = Body(default={}), quien=Depends(persona)):
        try:
            return m(request).rechazar(cliente, ap_id, quien, cuerpo.get("comentario", ""))
        except AlertaRechazada as e:
            _err(e)

    # ── ejecuciones ──
    @app.get("/v1/{cliente}/ejecuciones")
    async def ejecuciones(cliente: str, request: Request, incidente: str | None = None, _=Depends(persona)):
        return m(request).almacen.ejecuciones(cliente, incidente)

    @app.post("/v1/{cliente}/ejecuciones/{ej_id}/deshacer")
    async def deshacer(cliente: str, ej_id: str, request: Request, quien=Depends(persona)):
        try:
            return await m(request).deshacer(cliente, ej_id, quien)
        except AlertaRechazada as e:
            _err(e)

    @app.post("/v1/{cliente}/acciones/{accion}")
    async def accion_demanda(cliente: str, accion: str, request: Request, cuerpo: dict = Body(...), quien=Depends(persona)):
        try:
            return await m(request).accion_a_demanda(cliente, accion, cuerpo.get("objetivo") or {}, quien,
                                                     cuerpo.get("incidente", ""), cuerpo.get("comentario", ""))
        except AlertaRechazada as e:
            _err(e)

    # ── lo que vuelve de los agentes y de los proyectos vecinos ──
    @app.post("/v1/{cliente}/acuses")
    async def acuse(cliente: str, request: Request, cuerpo: dict = Body(...), _=Depends(agente)):
        try:
            return m(request).acuse(cliente, str(cuerpo.get("ejecucion_id", "")), str(cuerpo.get("estado", "")),
                                    cuerpo.get("detalle") or {})
        except AlertaRechazada as e:
            _err(e)

    @app.post("/v1/{cliente}/evidencias/ftriage")
    async def evidencia_ftriage(cliente: str, request: Request, informe: dict = Body(...), _=Depends(agente)):
        return m(request).ingerir_ftriage(cliente, informe)

    @app.post("/v1/{cliente}/evidencias/malpipe")
    async def evidencia_malpipe(cliente: str, request: Request, informe: dict = Body(...),
                                incidente: str = Query(""), _=Depends(agente)):
        return m(request).ingerir_malpipe(cliente, informe, incidente)

    # ── EDL para el perimetro ──
    @app.get("/v1/{cliente}/edl/{tipo}", response_class=PlainTextResponse)
    async def edl(cliente: str, tipo: str, request: Request, authorization: str | None = Header(None),
                  token: str | None = Query(None)):
        if not m(request).clientes.token_edl_valido(cliente, _token(authorization, token)):
            raise HTTPException(401, "token de EDL no valido")
        if tipo not in ("ip", "dominio", "url"):
            raise HTTPException(404, "tipo de lista: ip | dominio | url")
        return "\n".join(m(request).almacen.edl(cliente, tipo)) + "\n"

    # ── administracion ──
    @app.get("/v1/admin/catalogo")
    async def catalogo(request: Request, _=Depends(admin)):
        return m(request).catalogo.estado()

    @app.post("/v1/admin/catalogo/actualizar")
    async def catalogo_actualizar(request: Request, _=Depends(admin)):
        mo = m(request)
        r = await mo.catalogo.actualizar_remoto(mo.transporte) if mo.catalogo.url else \
            {"estado": "recargado" if mo.catalogo.recargar_local() else "sin cambios"}
        mo.almacen.auditar("", "admin", "catalogo.actualizar", r)
        return r

    @app.post("/v1/admin/cti/actualizar")
    async def cti_actualizar(request: Request, _=Depends(admin)):
        return await m(request).cti.refrescar(m(request).transporte)

    @app.get("/v1/admin/auditoria/verificar")
    async def auditoria_verificar(request: Request, _=Depends(admin)):
        return m(request).almacen.verificar_auditoria()

    @app.get("/v1/{cliente}/auditoria")
    async def auditoria(cliente: str, request: Request, limite: int = 200, _=Depends(persona)):
        return m(request).almacen.auditoria(cliente, min(limite, 1000))

    @app.get("/v1/{cliente}/conectores")
    async def conectores_estado(cliente: str, request: Request, _=Depends(persona)):
        from . import conectores
        mo = m(request)
        p = mo.clientes.get(cliente)
        if not p:
            raise HTTPException(404, "cliente desconocido o inactivo")
        salida = {}
        for cap, nombres in (p.get("capacidades") or {}).items():
            for n in nombres if isinstance(nombres, list) else [nombres]:
                con = conectores.construir(n, p, mo.modo(p), config.conectores, mo.transporte, mo)
                if con is None:
                    salida[n] = {"capacidad": cap, "estado": "no existe"}
                    continue
                r = await con.probar()
                salida[n] = {"capacidad": cap, "estado": r.estado, "detalle": r.detalle,
                             "acciones": sorted(con.acciones)}
        return {"modo": "simulacion" if mo.modo(p) else "produccion", "conectores": salida}

    # ── panel ──
    @app.get("/panel", response_class=HTMLResponse)
    async def panel():
        return HTMLResponse(PANEL.read_text(encoding="utf-8"),
                            headers={"Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'; "
                                     "script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
                                     "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"})

    @app.exception_handler(HTTPException)
    async def errores(request: Request, exc: HTTPException):
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    return app


def app_desde_entorno() -> FastAPI:
    logging.basicConfig(level=Config().log_nivel, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    return crear_app()
