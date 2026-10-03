"""
Pruebas de la API HTTP (responselab.api).

La app se sirve con httpx.ASGITransport y su propio ciclo de vida
(app.router.lifespan_context), en el mismo bucle que el motor de la prueba.
raise_app_exceptions=False para ver el codigo que recibiria el cliente (un 500
es un fallo, no una excepcion en la prueba).

Papeles y tokens (conftest y clientes/lab.yml): ingesta, agentes, EDL,
aprobador y administracion. Ningun token sirve para otro cliente ni para otro
papel.
"""
from __future__ import annotations

import base64
import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import yaml

from responselab import simulador
from responselab.api import crear_app
from responselab.clientes import huella
from responselab.ejecutor import Motor

ESCENARIOS = {e["id"]: e for e in simulador.cargar()}
FUTURO = datetime.now(timezone.utc) + timedelta(hours=2)

ING = {"Authorization": "Bearer token-ingesta-lab"}
AGE = {"Authorization": "Bearer token-agentes-lab"}
EDL = {"Authorization": "Bearer token-edl-lab"}
APR = {"Authorization": "Bearer token-aprobador-lab"}
ADM = {"Authorization": "Bearer token-admin"}

ACME = {"ingesta": "token-ingesta-acme", "agentes": "token-agentes-acme", "edl": "token-edl-acme",
        "aprobador": "token-aprobador-acme"}


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def basic(usuario: str, clave: str) -> dict:
    return {"Authorization": "Basic " + base64.b64encode(f"{usuario}:{clave}".encode()).decode()}


def escribir_perfil(ruta, datos: dict):
    ruta.write_text(yaml.safe_dump(datos, allow_unicode=True, sort_keys=False), encoding="utf-8")
    st = ruta.stat()
    os.utime(ruta, (st.st_atime, st.st_mtime + 5))


def alerta_local(regla: str = "100950", equipo: str = "PC-0042", nivel: int = 8) -> dict:
    """Alerta de Wazuh de una regla local: abre un incidente y no contiene nada."""
    return {
        "id": f"api-{regla}-{equipo}-{uuid.uuid4().hex[:8]}",
        "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "rule": {"id": regla, "level": nivel, "description": f"Local: regla {regla}", "groups": ["local"]},
        "agent": {"id": "042", "name": equipo, "ip": "10.0.20.42"},
        "data": {"win": {"system": {"eventID": "1", "computer": f"{equipo}.lab.test"},
                         "eventdata": {"image": "C:\\Users\\Public\\svc.exe", "processId": "3300"}}},
    }


def carga_de(escenario: str, n: int) -> tuple[str, dict]:
    a = ESCENARIOS[escenario]["alertas"][n - 1]
    base = datetime.now(timezone.utc) - timedelta(minutes=40)
    return a["siem"], simulador.preparar(a["siem"], a["carga"], base + timedelta(minutes=a.get("minuto", 0)),
                                         f"api-{escenario}-{n}-{uuid.uuid4().hex[:8]}")


def cliente_http(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                             base_url="http://responselab.test")


@pytest.fixture
async def api(motor, config):
    """La app con el motor de la prueba. Antes de apagar se vacia la cola."""
    app = crear_app(config, motor=motor, arrancar=False)
    async with app.router.lifespan_context(app):
        assert app.state.motor is motor
        async with cliente_http(app) as c:
            yield c
        await motor.drenar()


@pytest.fixture
def acme_con_tokens(motor, carpeta_clientes):
    """acme con huellas de tokens conocidos (el perfil de ejemplo trae huellas de ceros)."""
    ruta = carpeta_clientes / "acme.yml"
    datos = yaml.safe_load(ruta.read_text(encoding="utf-8"))
    datos["autenticacion"] = {"token_sha256": huella(ACME["ingesta"]),
                              "agentes": {"token_sha256": huella(ACME["agentes"])},
                              "edl": {"token_sha256": huella(ACME["edl"])}}
    datos["aprobadores"] = [{"nombre": "Guardia SOC ACME", "email": "soc-guardia@acme.test",
                             "token_sha256": huella(ACME["aprobador"])}]
    escribir_perfil(ruta, datos)
    assert motor.clientes.recargar() is True
    return ACME


async def enviar(api, motor, cliente: str, siem: str, carga, cabeceras=ING) -> httpx.Response:
    r = await api.post(f"/v1/{cliente}/alertas/{siem}", headers=cabeceras, json=carga)
    await motor.drenar()
    return r


# ====================================================================
# Salud y panel
# ====================================================================

async def test_salud_responde_sin_autenticacion(api):
    r = await api.get("/salud")
    assert r.status_code == 200
    s = r.json()
    assert s["estado"] == "ok" and s["catalogo"]["version"]
    assert s["clientes"] == 3 and s["perfiles_con_error"] == []
    assert s["simulacion_global"] is True and s["cola"] == 0


async def test_panel_con_cabeceras_de_seguridad(api):
    r = await api.get("/panel")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "no-referrer"


# ====================================================================
# Autenticacion de la ingesta
# ====================================================================

@pytest.mark.parametrize("cabeceras, params", [
    (ING, {}),
    (basic("kibana", "token-ingesta-lab"), {}),
    (basic("", "token-ingesta-lab"), {}),
    ({}, {"token": "token-ingesta-lab"}),
], ids=["bearer", "basic", "basic-sin-usuario", "query"])
async def test_ingesta_acepta_bearer_basic_y_query(api, motor, cabeceras, params):
    r = await api.post("/v1/lab/alertas/wazuh", headers=cabeceras, params=params, json=alerta_local())
    await motor.drenar()
    assert r.status_code == 202
    assert r.json()["estado"] == "encolada"


@pytest.mark.parametrize("cabeceras, params", [
    ({}, {}),
    (bearer("token-equivocado"), {}),
    ({"Authorization": "Bearer "}, {}),
    (basic("kibana", "token-equivocado"), {}),
    ({"Authorization": "Basic esto-no-es-base64!"}, {}),
    ({"Authorization": "Basic " + base64.b64encode(b"token-ingesta-lab").decode()}, {}),
    ({"Authorization": "Token token-ingesta-lab"}, {}),
    ({}, {"token": "token-equivocado"}),
], ids=["sin-token", "bearer-erroneo", "bearer-vacio", "basic-erroneo", "basic-roto", "basic-sin-dos-puntos",
        "esquema-desconocido", "query-erroneo"])
async def test_ingesta_rechaza_credenciales_no_validas(api, motor, cabeceras, params):
    r = await api.post("/v1/lab/alertas/wazuh", headers=cabeceras, params=params, json=alerta_local())
    assert r.status_code == 401
    assert r.json() == {"error": "token de ingesta no valido para este cliente"}
    assert motor.almacen.pendientes() == 0


@pytest.mark.parametrize("cabeceras", [AGE, EDL, APR, ADM], ids=["agentes", "edl", "aprobador", "admin"])
async def test_ingesta_rechaza_tokens_de_otros_papeles(api, motor, cabeceras):
    r = await api.post("/v1/lab/alertas/wazuh", headers=cabeceras, json=alerta_local())
    assert r.status_code == 401
    assert motor.almacen.pendientes() == 0


async def test_cliente_desconocido_responde_401(api):
    r = await api.post("/v1/no-existe/alertas/wazuh", headers=ING, json=alerta_local())
    assert r.status_code == 401


@pytest.mark.parametrize("ruta", ["/v1/lab/acuses", "/v1/lab/evidencias/ftriage", "/v1/lab/evidencias/malpipe"])
async def test_el_token_de_ingesta_no_sirve_para_los_agentes(api, ruta):
    r = await api.post(ruta, headers=ING, json={"ejecucion_id": "ej-x", "estado": "ok", "host": {"hostname": "PC-0042"}})
    assert r.status_code == 401


@pytest.mark.parametrize("metodo, ruta, cabeceras, params", [
    ("GET", "/v1/admin/catalogo", {}, {"token": "contrase\u00f1a"}),
    ("POST", "/v1/lab/alertas/wazuh", {}, {"token": "contrase\u00f1a"}),
    ("POST", "/v1/lab/alertas/wazuh", basic("splunk", "contrase\u00f1a"), {}),
    ("GET", "/v1/lab/aprobaciones", {}, {"token": "contrase\u00f1a"}),
    ("GET", "/v1/lab/edl/ip", {}, {"token": "contrase\u00f1a"}),
], ids=["admin", "ingesta-query", "ingesta-basic", "aprobador", "edl"])
async def test_un_token_no_ascii_da_401_y_no_500(api, metodo, ruta, cabeceras, params):
    r = await api.request(metodo, ruta, headers=cabeceras, params=params, json={})
    assert r.status_code == 401


# ====================================================================
# Aislamiento entre clientes
# ====================================================================

async def test_el_token_de_un_cliente_no_vale_para_otro(api, motor, acme_con_tokens):
    assert (await api.post("/v1/acme/alertas/wazuh", headers=ING, json=alerta_local())).status_code == 401
    assert (await api.post("/v1/lab/alertas/wazuh", headers=bearer(ACME["ingesta"]),
                           json=alerta_local())).status_code == 401
    assert motor.almacen.pendientes() == 0
    propia = await enviar(api, motor, "acme", "wazuh", alerta_local(equipo="SRV-ACME-01"), bearer(ACME["ingesta"]))
    assert propia.status_code == 202
    assert [a["cliente"] for a in motor.almacen.alertas()] == ["acme"]


@pytest.mark.parametrize("metodo, ruta, papel_lab, papel_acme", [
    ("POST", "/v1/{c}/acuses", AGE, "agentes"),
    ("POST", "/v1/{c}/evidencias/ftriage", AGE, "agentes"),
    ("GET", "/v1/{c}/edl/ip", EDL, "edl"),
    ("GET", "/v1/{c}/aprobaciones", APR, "aprobador"),
    ("GET", "/v1/{c}/incidentes", APR, "aprobador"),
    ("GET", "/v1/{c}/auditoria", APR, "aprobador"),
    ("POST", "/v1/{c}/acciones/endpoint.aislar", APR, "aprobador"),
])
async def test_aislamiento_entre_clientes_en_todos_los_papeles(api, acme_con_tokens, metodo, ruta, papel_lab, papel_acme):
    cuerpo = {"ejecucion_id": "ej-x", "estado": "ok", "objetivo": {"equipo.nombre": "PC-0042"}}
    lab_en_acme = await api.request(metodo, ruta.format(c="acme"), headers=papel_lab, json=cuerpo)
    acme_en_lab = await api.request(metodo, ruta.format(c="lab"), headers=bearer(ACME[papel_acme]), json=cuerpo)
    assert lab_en_acme.status_code == 401
    assert acme_en_lab.status_code == 401


# ====================================================================
# Cuerpo de la peticion: tamano, JSON y SIEM
# ====================================================================

async def test_413_si_el_cuerpo_supera_el_tamano_maximo(api, motor, config):
    config.tamano_maximo = 500
    r = await api.post("/v1/lab/alertas/wazuh", headers=ING, json=dict(alerta_local(), relleno="x" * 1000))
    assert r.status_code == 413
    assert r.json() == {"error": "alerta demasiado grande"}
    assert motor.almacen.pendientes() == 0


async def test_413_tambien_sin_content_length(api, motor, config):
    config.tamano_maximo = 500
    cuerpo = json.dumps(dict(alerta_local(), relleno="x" * 5000)).encode()

    async def trozos():
        for i in range(0, len(cuerpo), 256):
            yield cuerpo[i:i + 256]

    r = await api.post("/v1/lab/alertas/wazuh", headers=ING, content=trozos())
    await motor.drenar()
    assert r.status_code == 413


async def test_400_si_el_cuerpo_no_es_json(api, motor):
    r = await api.post("/v1/lab/alertas/wazuh", headers={**ING, "Content-Type": "application/json"},
                       content=b'{"rule": {"id": "100950"')
    assert r.status_code == 400
    assert r.json() == {"error": "el cuerpo no es JSON"}
    assert motor.almacen.pendientes() == 0


@pytest.mark.parametrize("siem, cuerpo", [
    ("wazuh", "una cadena"),
    ("wazuh", [1, 2]),
    ("elastic", [1, 2]),
], ids=["cadena", "lista-de-numeros", "elastic-lista-de-numeros"])
async def test_un_json_que_no_es_un_objeto_no_da_500(api, motor, siem, cuerpo):
    r = await api.post(f"/v1/lab/alertas/{siem}", headers=ING, json=cuerpo)
    await motor.drenar()
    assert r.status_code in (400, 202)
    if r.status_code == 202:
        items = r.json() if isinstance(r.json(), list) else [r.json()]
        assert all(i["estado"] == "rechazada" for i in items)


async def test_siem_no_soportado_se_rechaza_alerta_a_alerta(api, motor):
    r = await api.post("/v1/lab/alertas/qradar", headers=ING, json={"id": "q-1"})
    assert r.status_code == 202
    assert r.json()["estado"] == "rechazada" and "SIEM no soportado" in r.json()["motivo"]
    assert motor.almacen.pendientes() == 0


async def test_elastic_con_varias_alertas_se_separa_en_una_por_alerta(api, motor):
    _, plantilla = carga_de("credenciales-movimiento-ot", 1)
    ing07 = dict(plantilla["alerts"][0], _id=f"el-{uuid.uuid4().hex[:8]}")
    hmi02 = dict(ing07, _id=f"el-{uuid.uuid4().hex[:8]}", host={"name": "HMI-02", "ip": ["10.50.1.12"]})
    r = await enviar(api, motor, "lab", "elastic", dict(plantilla, alerts=[ing07, hmi02]))
    assert r.status_code == 202
    cuerpo = r.json()
    assert [x["estado"] for x in cuerpo] == ["encolada", "encolada"]
    assert {x["alerta_id"] for x in cuerpo} == {ing07["_id"], hmi02["_id"]}
    assert sorted(a["equipo"] for a in motor.almacen.alertas("lab")) == ["HMI-02", "ING-07"]


async def test_una_lista_de_cargas_devuelve_una_lista(api, motor):
    r = await enviar(api, motor, "lab", "wazuh", [alerta_local()])
    assert r.status_code == 202
    assert isinstance(r.json(), list) and r.json()[0]["estado"] == "encolada"
    sola = await enviar(api, motor, "lab", "wazuh", alerta_local(equipo="PC-0043"))
    assert isinstance(sola.json(), dict)


async def test_decidir_devuelve_el_plan_sin_guardar_nada(api, motor):
    siem, carga = carga_de("ransomware-puesto", 2)
    r = await api.post(f"/v1/lab/decidir/{siem}", headers=ING, json=carga)
    assert r.status_code == 200
    assert r.json()["familia"] == "endpoint" and r.json()["alerta_id"] == carga["id"]
    assert motor.almacen.contar()["alertas"] == 0 and motor.almacen.pendientes() == 0
    assert (await api.post(f"/v1/lab/decidir/{siem}", headers=APR, json=carga)).status_code == 401


# ====================================================================
# Listas EDL
# ====================================================================

async def test_edl_contenido_y_autenticacion(api, motor):
    al = motor.almacen
    al.edl_anadir("lab", "ip", "8.8.8.8", "C2", FUTURO, "ej-1")
    al.edl_anadir("lab", "ip", "1.0.0.1", "C2", FUTURO, "ej-2")
    al.edl_anadir("lab", "ip", "9.9.9.9", "caducada", datetime.now(timezone.utc) - timedelta(hours=1), "ej-3")
    al.edl_anadir("lab", "dominio", "Malo.Example", "phishing", FUTURO, "ej-4")
    al.edl_anadir("acme", "ip", "4.4.4.4", "de otro cliente", FUTURO, "ej-5")
    r = await api.get("/v1/lab/edl/ip", headers=EDL)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert r.text == "1.0.0.1\n8.8.8.8\n"
    por_query = await api.get("/v1/lab/edl/dominio", params={"token": "token-edl-lab"})   # asi lo piden los cortafuegos
    assert por_query.text == "malo.example\n"
    assert (await api.get("/v1/lab/edl/url", headers=EDL)).text == "\n"
    assert (await api.get("/v1/lab/edl/hash", headers=EDL)).status_code == 404
    for otro in (ING, AGE, APR, ADM, {}):
        assert (await api.get("/v1/lab/edl/ip", headers=otro)).status_code == 401
    assert (await api.get("/v1/acme/edl/ip", headers=EDL)).status_code == 401


@pytest.fixture
async def api_produccion(config, carpeta_clientes, entorno_tokens):
    """lab en produccion (sin el interruptor global): la EDL la escribe el conector de verdad."""
    ruta = carpeta_clientes / "lab.yml"
    datos = yaml.safe_load(ruta.read_text(encoding="utf-8"))
    datos["modo"] = "produccion"
    escribir_perfil(ruta, datos)
    config.simulacion_global = False
    m = Motor(config)
    await m.arrancar(vigilante=False)
    app = crear_app(config, motor=m, arrancar=False)
    try:
        async with app.router.lifespan_context(app):
            async with cliente_http(app) as c:
                yield c, m
            await m.drenar()
    finally:
        m.almacen.cerrar()


async def test_edl_de_extremo_a_extremo_bloquear_y_deshacer(api_produccion):
    api, motor = api_produccion
    r = await api.post("/v1/lab/acciones/perimetro.bloquear_destino", headers=APR,
                       json={"objetivo": {"red.ip_destino": "8.8.8.8"}, "comentario": "C2 confirmado"})
    assert r.status_code == 200
    [ej] = r.json()
    assert (ej["conector"], ej["estado"], ej["actor"]) == ("edl", "ok", "analista@lab.test")
    assert (await api.get("/v1/lab/edl/ip", headers=EDL)).text == "8.8.8.8\n"
    # Una IP interna nunca entra en la lista del perimetro, ni ordenada por una persona
    interna = await api.post("/v1/lab/acciones/perimetro.bloquear_destino", headers=APR,
                             json={"objetivo": {"red.ip_destino": "10.1.2.3"}})
    assert interna.json()[0]["estado"] == "omitida" and "interna" in interna.json()[0]["detalle"]
    assert (await api.get("/v1/lab/edl/ip", headers=EDL)).text == "8.8.8.8\n"
    deshecha = await api.post(f"/v1/lab/ejecuciones/{ej['id']}/deshacer", headers=APR)
    assert deshecha.status_code == 200
    assert [(d["accion"], d["estado"], d["deshace"]) for d in deshecha.json()] == [
        ("perimetro.desbloquear_destino", "ok", ej["id"])]
    assert (await api.get("/v1/lab/edl/ip", headers=EDL)).text == "\n"
    assert motor.almacen.verificar_auditoria()["integra"] is True


# ====================================================================
# Administracion
# ====================================================================

@pytest.mark.parametrize("metodo, ruta", [
    ("GET", "/metricas"),
    ("GET", "/v1/admin/catalogo"),
    ("GET", "/v1/admin/auditoria/verificar"),
    ("POST", "/v1/admin/catalogo/actualizar"),
    ("POST", "/v1/admin/cti/actualizar"),
])
async def test_la_administracion_exige_el_token_de_administracion(api, metodo, ruta):
    assert (await api.request(metodo, ruta, headers=ADM)).status_code == 200
    for otro in (ING, AGE, EDL, APR, {}, bearer("token-admin-falso")):
        r = await api.request(metodo, ruta, headers=otro)
        assert r.status_code == 401
        assert r.json() == {"error": "token de administracion no valido"}


async def test_sin_token_de_administracion_configurado_no_hay_administracion(api, config):
    config.token_admin = ""
    for cabeceras, params in (({"Authorization": "Bearer "}, {}), ({}, {"token": ""}), (ADM, {})):
        assert (await api.get("/v1/admin/catalogo", headers=cabeceras, params=params)).status_code == 401
    assert (await api.get("/v1/lab/aprobaciones", headers={"Authorization": "Bearer "})).status_code == 401


async def test_metricas_en_formato_prometheus(api, motor):
    await enviar(api, motor, "lab", "wazuh", alerta_local())
    r = await api.get("/metricas", headers=ADM)
    assert r.headers["content-type"].startswith("text/plain")
    lineas = r.text.splitlines()
    assert "responselab_alertas_total 1" in lineas
    assert "responselab_incidentes_abiertos 1" in lineas
    assert any(x.startswith('responselab_catalogo_info{version="') for x in lineas)


async def test_admin_verifica_la_auditoria_y_actualiza_sin_red(api, motor):
    await enviar(api, motor, "lab", "wazuh", alerta_local())
    v = (await api.get("/v1/admin/auditoria/verificar", headers=ADM)).json()
    assert v["integra"] is True and v["registros"] >= 2
    assert (await api.post("/v1/admin/cti/actualizar", headers=ADM)).json() == {"estado": "desactivado"}
    assert (await api.post("/v1/admin/catalogo/actualizar", headers=ADM)).json() == {"estado": "sin cambios"}
    assert "catalogo.actualizar" in [f["evento"] for f in motor.almacen.auditoria(limite=50)]


# ====================================================================
# Personas: aprobaciones, incidentes, ejecuciones
# ====================================================================

async def test_el_aprobador_solo_actua_en_su_cliente(api):
    assert (await api.get("/v1/lab/aprobaciones", headers=APR)).status_code == 200
    assert (await api.get("/v1/acme/aprobaciones", headers=APR)).status_code == 401
    for otro in (ING, AGE, EDL, basic("x", "token-ingesta-lab")):
        assert (await api.get("/v1/lab/aprobaciones", headers=otro)).status_code == 401
    # La administracion ve todos los clientes
    assert (await api.get("/v1/acme/aprobaciones", headers=ADM)).status_code == 200


async def test_aprobar_y_rechazar_por_la_api(api, motor):
    siem, carga = carga_de("ransomware-puesto", 1)
    await enviar(api, motor, "lab", siem, carga)
    pendientes = {a["paso"]["accion"]: a for a in (await api.get("/v1/lab/aprobaciones", headers=APR)).json()}
    aislar, matar = pendientes["endpoint.aislar"], pendientes["proceso.matar"]

    r = await api.post(f"/v1/lab/aprobaciones/{aislar['id']}/aprobar", headers=APR, json={"comentario": "adelante"})
    assert r.status_code == 200
    assert r.json()["estado"] == "ejecutada" and r.json()["ejecuciones"][0]["estado"] == "simulada"
    otra_vez = await api.post(f"/v1/lab/aprobaciones/{aislar['id']}/aprobar", headers=APR)
    assert otra_vez.status_code == 409 and "ya no esta pendiente" in otra_vez.json()["error"]

    r = await api.post(f"/v1/lab/aprobaciones/{matar['id']}/rechazar", headers=APR, json={"comentario": "no"})
    assert r.status_code == 200 and r.json() == {"aprobacion": matar["id"], "estado": "rechazada"}

    decididas = {a["id"]: a for a in (await api.get("/v1/lab/aprobaciones", headers=APR,
                                                    params={"estado": ""})).json()}
    assert decididas[aislar["id"]]["decidida_por"] == "analista@lab.test"
    assert decididas[matar["id"]]["decidida_por"] == "analista@lab.test"
    assert (await api.post(f"/v1/lab/aprobaciones/{matar['id']}/aprobar", headers=ING)).status_code == 401


async def test_no_se_decide_lo_de_otro_cliente_desde_la_url_propia(api, motor):
    ajena = motor.almacen.crear_aprobacion("acme", "inc-acme", "al-acme", {"accion": "endpoint.aislar"}, "m", FUTURO)
    for op in ("aprobar", "rechazar"):
        r = await api.post(f"/v1/lab/aprobaciones/{ajena['id']}/{op}", headers=APR)
        assert r.status_code == 409 and r.json() == {"error": "aprobacion no encontrada"}
    assert motor.almacen.aprobacion(ajena["id"])["estado"] == "pendiente"


async def test_incidentes_de_otro_cliente_dan_404(api, motor):
    plan = {"severidad": 2, "titulo": "t", "familia": "endpoint", "regla": {"titulo": "r", "clave": "k"},
            "escalado": {"a": "L2", "plazo_min": 30}}
    ajeno = motor.almacen.crear_incidente("acme", "equipo", "SRV-ACME-01", plan)
    assert (await api.get(f"/v1/lab/incidentes/{ajeno['id']}", headers=APR)).status_code == 404
    assert (await api.post(f"/v1/lab/incidentes/{ajeno['id']}/cerrar", headers=APR)).status_code == 404
    assert motor.almacen.incidente(ajeno["id"])["estado"] == "abierto"
    assert ajeno["id"] not in [i["id"] for i in (await api.get("/v1/lab/incidentes", headers=APR)).json()]
    assert (await api.get("/v1/lab/incidentes/inc-no-existe", headers=APR)).status_code == 404


async def test_detalle_asumir_y_cerrar_un_incidente(api, motor):
    await enviar(api, motor, "lab", "wazuh", alerta_local())
    [inc] = (await api.get("/v1/lab/incidentes", headers=APR)).json()
    detalle = (await api.get(f"/v1/lab/incidentes/{inc['id']}", headers=APR)).json()
    assert set(detalle) == {"incidente", "alertas", "ejecuciones", "aprobaciones", "tareas"}
    assert len(detalle["alertas"]) == 1
    asumido = (await api.post(f"/v1/lab/incidentes/{inc['id']}/asumir", headers=APR, json={"comentario": "mio"})).json()
    assert asumido["estado"] == "asumido" and asumido["asumido_por"] == "analista@lab.test"
    assert (await api.post(f"/v1/lab/incidentes/{inc['id']}/cerrar", headers=APR)).json()["estado"] == "cerrado"
    assert (await api.post(f"/v1/lab/incidentes/{inc['id']}/borrar", headers=APR)).status_code == 404
    auditoria = (await api.get("/v1/lab/auditoria", headers=APR)).json()
    assert {"incidente.asumir", "incidente.cerrar"} <= {f["evento"] for f in auditoria}


async def test_acuses_y_deshacer_por_la_api(api, motor):
    for n in (1, 2):
        siem, carga = carga_de("ransomware-puesto", n)
        await enviar(api, motor, "lab", siem, carga)
    ejs = (await api.get("/v1/lab/ejecuciones", headers=APR)).json()
    aislar = next(e for e in ejs if e["accion"] == "endpoint.aislar" and e["estado"] == "simulada")

    assert (await api.post("/v1/lab/acuses", headers=APR, json={"ejecucion_id": aislar["id"], "estado": "ok"})
            ).status_code == 401
    r = await api.post("/v1/lab/acuses", headers=basic("agente", "token-agentes-lab"),
                       json={"ejecucion_id": aislar["id"], "estado": "ok", "detalle": {"reglas": 2}})
    assert r.status_code == 200 and r.json() == {"ejecucion": aislar["id"], "estado": "confirmada"}
    desconocida = await api.post("/v1/lab/acuses", headers=AGE, json={"ejecucion_id": "ej-no", "estado": "ok"})
    assert desconocida.status_code == 409

    assert (await api.post(f"/v1/lab/ejecuciones/{aislar['id']}/deshacer", headers=ING)).status_code == 401
    r = await api.post(f"/v1/lab/ejecuciones/{aislar['id']}/deshacer", headers=APR)
    assert r.status_code == 200
    assert [(d["accion"], d["deshace"]) for d in r.json()] == [("endpoint.liberar", aislar["id"])]


async def test_evidencias_de_ftriage_y_malpipe_con_token_de_agente(api, motor):
    await enviar(api, motor, "lab", "wazuh", alerta_local(equipo="PC-0042"))
    [inc] = motor.almacen.incidentes("lab")
    informe = {"host": {"hostname": "PC-0042"}, "assessment": {"verdict": "Sospechoso", "risk_score": 55}}
    r = await api.post("/v1/lab/evidencias/ftriage", headers=AGE, json=informe)
    assert r.status_code == 200 and r.json()["incidente"] == inc["id"]
    malpipe = {"verdict": "malicioso", "score": 90, "static": {"filename": "x.exe", "hashes": {"sha256": "cd" * 32}}}
    r = await api.post("/v1/lab/evidencias/malpipe", headers=AGE, params={"incidente": inc["id"]}, json=malpipe)
    assert r.status_code == 200 and r.json()["sha256"] == "cd" * 32
    assert any(a["paso"]["accion"] == "flota.bloquear_hash" for a in motor.almacen.aprobaciones("lab"))
    assert (await api.post("/v1/lab/evidencias/ftriage", headers=APR, json=informe)).status_code == 401


async def test_accion_a_demanda_por_la_api(api, acme_con_tokens):
    r = await api.post("/v1/lab/acciones/endpoint.aislar", headers=APR,
                       json={"objetivo": {"equipo.nombre": "PC-0042"}, "comentario": "orden del turno"})
    assert r.status_code == 200 and r.json()[0]["estado"] == "simulada"
    prohibida = await api.post("/v1/acme/acciones/k8s.escalar_cero", headers=bearer(ACME["aprobador"]),
                               json={"objetivo": {"k8s.namespace": "prod", "k8s.workload": "deployment/web"}})
    assert prohibida.status_code == 409 and "prohibe" in prohibida.json()["error"]
    sin_objetivo = await api.post("/v1/lab/acciones/endpoint.aislar", headers=APR, json={"objetivo": {}})
    assert sin_objetivo.status_code == 409


# ====================================================================
# Perfiles que cambian en caliente
# ====================================================================

async def test_un_perfil_borrado_deja_sin_valor_sus_tokens(api, motor, carpeta_clientes):
    assert (await api.get("/v1/lab/aprobaciones", headers=APR)).status_code == 200
    (carpeta_clientes / "lab.yml").unlink()
    motor.clientes.recargar()
    assert (await api.post("/v1/lab/alertas/wazuh", headers=ING, json=alerta_local())).status_code == 401
    assert (await api.get("/v1/lab/edl/ip", headers=EDL)).status_code == 401
    assert (await api.get("/v1/lab/aprobaciones", headers=APR)).status_code == 401
    assert (await api.post("/v1/lab/acuses", headers=AGE, json={})).status_code == 401
    assert (await api.get("/salud")).json()["clientes"] == 2


async def test_un_perfil_con_errores_se_ve_en_salud_y_sigue_el_anterior(api, motor, carpeta_clientes):
    ruta = carpeta_clientes / "lab.yml"
    datos = yaml.safe_load(ruta.read_text(encoding="utf-8"))
    datos["conectores"]["thehive"]["api_key"] = "clave-en-claro"
    escribir_perfil(ruta, datos)
    motor.clientes.recargar()
    salud = (await api.get("/salud")).json()
    assert salud["perfiles_con_error"] == ["lab.yml"] and salud["clientes"] == 3
    r = await enviar(api, motor, "lab", "wazuh", alerta_local())
    assert r.status_code == 202, "los tokens del perfil anterior siguen valiendo"


async def test_estado_de_los_conectores_del_cliente(api):
    r = await api.get("/v1/lab/conectores", headers=APR)
    assert r.status_code == 200
    estado = r.json()
    assert estado["modo"] == "simulacion"
    assert estado["conectores"]["wazuh"]["estado"] == "error"
    assert estado["conectores"]["wazuh"]["detalle"] == "falta configuracion: usuario_env, clave_env"
    assert estado["conectores"]["edl"]["estado"] == "ok"
    assert "endpoint.aislar" in estado["conectores"]["wazuh"]["acciones"]


async def test_conectores_de_un_cliente_desconocido_no_da_500(api):
    r = await api.get("/v1/no-existe/conectores", headers=ADM)
    assert 400 <= r.status_code < 500


# ====================================================================
# Ciclo de vida
# ====================================================================

def test_el_ciclo_de_vida_crea_y_arranca_su_propio_motor(config, entorno_tokens):
    """Sin motor inyectado, la app lo crea al arrancar, lo pone a trabajar y lo para al salir."""
    from fastapi.testclient import TestClient

    app = crear_app(config)
    carga = alerta_local()
    with TestClient(app) as c:
        motor = app.state.motor
        assert isinstance(motor, Motor)
        assert c.get("/salud").status_code == 200
        assert c.post("/v1/lab/alertas/wazuh", headers=ING, json=carga).status_code == 202
        fin = time.monotonic() + 10
        while c.get("/salud").json()["cola"] and time.monotonic() < fin:
            time.sleep(0.05)
        assert motor.almacen.existe_alerta("lab", carga["id"]), "los trabajadores del propio motor la procesan"
    motor.almacen.cerrar()
