"""
Pruebas de los conectores (responselab.conectores).

Ninguna sale a la red: en produccion cada conector recibe un
httpx.MockTransport que registra la peticion exacta (metodo, ruta, cabeceras y
cuerpo) y contesta como lo haria la herramienta; en simulacion se comprueba
que el transporte no se usa nunca.
"""
from __future__ import annotations

import base64
import json
import sqlite3
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest

from responselab import conectores
from responselab.almacen import Almacen
from responselab.conectores import base
from responselab.conectores.base import ClienteHttp, ErrorConector, TokenCache
from responselab.conectores.declarativo import Declarativo, Script, renderizar
from responselab.conectores.wazuh import Wazuh

RAIZ = Path(__file__).resolve().parent.parent
CARPETA = RAIZ / "conectores"

ALERTA = {
    "id": "al-1", "siem": "wazuh", "cliente": "prueba", "titulo": "Prueba de conectores",
    "momento": "2026-10-01T10:00:00Z",
    "equipo": {"nombre": "PC-0042", "ip": "10.0.20.42"},
    "usuario": {"nombre": "ana", "upn": "ana@acme.test"},
    "correo": {"remitente": "malo@proveedor-falso.example"},
    "red": {"ip_origen": "8.8.8.8"},
    "observables": [{"tipo": "ip", "valor": "8.8.8.8"}, {"tipo": "hash", "valor": "ab" * 32}],
}


# ====================================================================
# Utilidades
# ====================================================================

@pytest.fixture(autouse=True)
def _cache_de_tokens_limpia(monkeypatch):
    monkeypatch.setattr(TokenCache, "_tokens", {})


@pytest.fixture(autouse=True)
def _credenciales(monkeypatch):
    """Variables de entorno de prueba (los perfiles solo guardan su nombre)."""
    for k, v in {"RLT_USUARIO": "usuario-prueba", "RLT_CLAVE": "clave-prueba", "RLT_TOKEN": "token-prueba",
                 "RLT_CLIENT_ID": "id-cliente", "RLT_CLIENT_SECRET": "secreto-cliente"}.items():
        monkeypatch.setenv(k, v)


class Red:
    """Transporte falso: guarda cada peticion y contesta con `responder` (599 si no deberia salir)."""

    def __init__(self, responder=None):
        self.peticiones: list[httpx.Request] = []
        self.responder = responder

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.peticiones.append(request)
        if self.responder is None:
            return httpx.Response(599, json={"error": "no se esperaba ninguna peticion"})
        return self.responder(request)

    def transporte(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)

    def rutas(self) -> list[tuple[str, str]]:
        return [(p.method, p.url.path) for p in self.peticiones]


def json_de(p: httpx.Request):
    return json.loads(p.content)


def formulario(p: httpx.Request) -> dict:
    return {k: v[0] for k, v in parse_qs(p.content.decode()).items()}


def construir(nombre: str, cfg: dict | None = None, simulacion: bool = False, red: Red | None = None,
              carpeta: Path = CARPETA, motor=None, **cliente):
    perfil = {"id": "prueba", "nombre": "Cliente de prueba", "conectores": {nombre: cfg or {}},
              "politica": {"bloqueo_perimetro_horas": 48}}
    perfil.update(cliente)
    return conectores.construir(nombre, perfil, simulacion, carpeta, red.transporte() if red else None, motor)


async def ejecutar(con, accion: str, objetivo: dict, alerta: dict | None = None, parametros: dict | None = None,
                   **contexto):
    ctx = {"alerta": ALERTA if alerta is None else alerta, "plan": {"resumen": "Resumen del plan"}, "paso": {},
           "incidente_id": "inc-prueba", "ejecucion_id": "ej-0123456789abcdef", "caso_externo": "",
           "datos_deshacer": {}}
    ctx.update(contexto)
    return await con.ejecutar(accion, objetivo, parametros or {}, ctx)


def token_oauth(request: httpx.Request):
    """Respuesta de un servidor OAuth2 (Entra, Falcon) o None si la peticion no es de token."""
    if request.url.host == "login.microsoftonline.com" or request.url.path == "/oauth2/token":
        return httpx.Response(200, json={"access_token": "tok-oauth", "expires_in": 3600})
    return None


# ====================================================================
# Registro, configuracion y simulacion
# ====================================================================

def test_construir_resuelve_integrados_declarativos_y_script():
    assert isinstance(construir("wazuh"), Wazuh)
    sn = construir("servicenow")
    assert isinstance(sn, Declarativo) and sn.nombre == "servicenow"
    assert sn.sabe("itsm.ticket") and not sn.sabe("endpoint.aislar")
    sc = construir("script", {"acciones": {"correo.bloquear_remitente": "ejemplo.py"}})
    assert isinstance(sc, Script) and sc.sabe("correo.bloquear_remitente") and not sc.sabe("endpoint.aislar")
    assert construir("no-existe") is None
    assert {"wazuh", "defender", "entra", "exchange", "crowdstrike", "sentinelone", "paloalto", "fortinet",
            "cloudflare", "kubernetes", "splunk", "thehive", "misp", "edl", "interno"} <= set(conectores.CLASES)


SIMULABLES = [
    ("wazuh", {"url": "https://wazuh.test:55000", "managers": ["10.0.30.10"]}, "endpoint.aislar", {"equipo.nombre": "PC-0042"}),
    ("defender", {"tenant_id": "t-1"}, "endpoint.aislar", {"equipo.nombre": "PC-0042"}),
    ("crowdstrike", {}, "endpoint.aislar", {"equipo.nombre": "PC-0042"}),
    ("sentinelone", {"url": "https://s1.test"}, "endpoint.aislar", {"equipo.nombre": "PC-0042"}),
    ("entra", {"tenant_id": "t-1"}, "identidad.revocar_sesiones", {"usuario.upn": "ana@acme.test"}),
    ("exchange", {"tenant_id": "t-1"}, "correo.deshabilitar_regla",
     {"correo.buzon": "ana@acme.test", "correo.regla_buzon": "Sincronizar"}),
    ("paloalto", {"url": "https://fw.test"}, "perimetro.bloquear_destino", {"red.ip_destino": "8.8.8.8"}),
    ("fortinet", {"url": "https://fg.test"}, "perimetro.bloquear_destino", {"red.ip_destino": "8.8.8.8"}),
    ("cloudflare", {"zona": "z-1"}, "waf.bloquear_origen", {"red.ip_origen": "8.8.8.8"}),
    ("kubernetes", {"url": "https://k8s.test:6443"}, "k8s.aislar_pod", {"k8s.namespace": "prod", "k8s.pod": "web-1"}),
    ("splunk", {"url": "https://splunk.test:8089"}, "evidencia.retener", {}),
    ("thehive", {"url": "https://thehive.test"}, "caso.nota", {}),
    ("servicenow", {"base_url": "https://snow.test"}, "itsm.ticket", {}),
    ("cisco-ise", {"base_url": "https://ise.test"}, "red.aislar_equipo", {"equipo.ip": "10.0.20.42"}),
    ("opnsense", {"base_url": "https://opn.test"}, "perimetro.bloquear_destino", {"red.ip_destino": "8.8.8.8"}),
    ("webhook-generico", {"base_url": "https://hook.test"}, "correo.bloquear_remitente", {}),
]


@pytest.mark.parametrize("nombre, cfg, accion, objetivo", SIMULABLES, ids=[s[0] for s in SIMULABLES])
async def test_la_simulacion_nunca_sale_a_la_red(nombre, cfg, accion, objetivo):
    red = Red()
    con = construir(nombre, cfg, simulacion=True, red=red)
    r = await ejecutar(con, accion, objetivo, caso_externo="~42")
    assert r.estado == "simulada", r.detalle
    assert r.peticiones and all(p["simulada"] for p in r.peticiones)
    assert red.peticiones == []


@pytest.mark.parametrize("nombre, cfg, faltan", [
    ("wazuh", {"url": "https://w.test", "usuario_env": "RLT_NO_U", "clave_env": "RLT_NO_C"}, "usuario_env, clave_env"),
    ("wazuh", {}, "url, usuario_env, clave_env"),
    ("crowdstrike", {"client_id_env": "RLT_NO_U", "client_secret_env": "RLT_CLIENT_SECRET"}, "client_id_env"),
    ("defender", {"client_id_env": "RLT_CLIENT_ID", "client_secret_env": "RLT_CLIENT_SECRET"}, "tenant_id"),
    ("entra", {"tenant_id": "t"}, "client_id_env, client_secret_env"),
    ("sentinelone", {"api_token_env": "RLT_TOKEN"}, "url"),
    ("paloalto", {"url": "https://fw.test", "api_key_env": "RLT_NO_K"}, "api_key_env"),
    ("fortinet", {"url": "https://fg.test"}, "api_token_env"),
    ("kubernetes", {"url": "https://k.test", "token_env": "RLT_NO_K"}, "token_env"),
    ("thehive", {"api_key_env": "RLT_TOKEN"}, "url"),
    ("splunk", {"url": "https://s.test", "token_env": "RLT_NO_K"}, "token_env"),
])
def test_configurado_dice_que_falta(nombre, cfg, faltan):
    assert construir(nombre, cfg).configurado() == (False, f"falta configuracion: {faltan}")


@pytest.mark.parametrize("nombre, cfg", [
    ("wazuh", {"url": "https://w.test", "usuario_env": "RLT_USUARIO", "clave_env": "RLT_CLAVE"}),
    ("defender", {"tenant_id": "t", "client_id_env": "RLT_CLIENT_ID", "client_secret_env": "RLT_CLIENT_SECRET"}),
    ("cloudflare", {"zona": "z-1", "api_token_env": "RLT_TOKEN"}),
    ("kubernetes", {"url": "https://k.test", "token_env": "RLT_TOKEN"}),
    ("edl", {}),
    ("interno", {}),
])
def test_configurado_con_todo_definido(nombre, cfg):
    assert construir(nombre, cfg).configurado() == (True, "")


def test_cloudflare_necesita_zona_o_cuenta():
    con = construir("cloudflare", {"api_token_env": "RLT_TOKEN"})
    assert con.configurado() == (False, "falta zona o cuenta de Cloudflare")
    assert construir("cloudflare", {"api_token_env": "RLT_TOKEN", "cuenta": "c-1"}).configurado() == (True, "")


def test_los_secretos_solo_salen_del_entorno():
    con = construir("paloalto", {"url": "https://fw.test", "api_key": "en-claro", "api_key_env": "RLT_TOKEN"})
    assert con.secreto("api_key") == "token-prueba"
    solo_en_claro = construir("paloalto", {"url": "https://fw.test", "api_key": "en-claro"})
    assert solo_en_claro.secreto("api_key") == ""
    assert solo_en_claro.configurado() == (False, "falta configuracion: api_key_env")


def test_declarativo_configurado(monkeypatch):
    for var in ("SNOW_URL", "SNOW_USUARIO", "SNOW_CLAVE"):
        monkeypatch.delenv(var, raising=False)
    assert construir("servicenow").configurado() == (False, "servicenow: falta base_url")
    con = construir("servicenow", {"base_url": "https://snow.test"})
    assert con.configurado() == (False, "servicenow: falta la variable SNOW_USUARIO")
    monkeypatch.setenv("SNOW_USUARIO", "u")
    monkeypatch.setenv("SNOW_CLAVE", "c")
    assert con.configurado() == (True, "")
    # El perfil puede usar sus propias variables
    propio = construir("servicenow", {"base_url": "https://snow.test", "usuario_env": "RLT_NO_U", "clave_env": "RLT_CLAVE"})
    assert propio.configurado() == (False, "servicenow: falta la variable RLT_NO_U")


# ====================================================================
# EDR: CrowdStrike, SentinelOne y Defender se niegan ante un objetivo ambiguo
# ====================================================================

CFG_FALCON = {"url": "https://falcon.test", "client_id_env": "RLT_CLIENT_ID", "client_secret_env": "RLT_CLIENT_SECRET"}


def falcon(recursos: list[str]):
    def responder(request):
        if (t := token_oauth(request)) is not None:
            return t
        if request.url.path == "/devices/queries/devices/v1":
            return httpx.Response(200, json={"resources": recursos})
        if request.url.path == "/devices/entities/devices-actions/v2":
            return httpx.Response(202, json={"resources": [{"id": recursos[0]}]})
        return httpx.Response(404)
    return responder


@pytest.mark.parametrize("recursos", [["aid-1", "aid-2"], []], ids=["dos-dispositivos", "ninguno"])
async def test_crowdstrike_no_actua_si_el_nombre_no_es_unico(recursos):
    red = Red(falcon(recursos))
    r = await ejecutar(construir("crowdstrike", CFG_FALCON, red=red), "endpoint.aislar", {"equipo.nombre": "PC-0042"})
    assert r.estado == "error"
    assert f"casa con {len(recursos)} dispositivos en Falcon: no se actua" in r.detalle
    assert ("POST", "/devices/entities/devices-actions/v2") not in red.rutas()


async def test_crowdstrike_contiene_un_unico_dispositivo():
    red = Red(falcon(["aid-1"]))
    r = await ejecutar(construir("crowdstrike", CFG_FALCON, red=red), "endpoint.aislar", {"equipo.nombre": "PC-0042"})
    assert (r.estado, r.datos) == ("ok", {"aid": "aid-1"})
    token, consulta, accion = red.peticiones
    assert formulario(token) == {"client_id": "id-cliente", "client_secret": "secreto-cliente"}
    assert consulta.url.params["filter"] == "hostname:'PC-0042'"
    assert accion.url.params["action_name"] == "contain"
    assert json_de(accion) == {"ids": ["aid-1"]}
    assert accion.headers["authorization"] == "Bearer tok-oauth"
    assert "secreto-cliente" not in json.dumps(r.peticiones), "el registro no guarda secretos"


async def test_crowdstrike_no_deja_inyectar_en_el_filtro():
    red = Red(falcon(["aid-1"]))
    await ejecutar(construir("crowdstrike", CFG_FALCON, red=red), "endpoint.aislar",
                   {"equipo.nombre": "PC-0042' OR hostname:'*"})
    filtro = red.peticiones[1].url.params["filter"]
    assert filtro == "hostname:'PC-0042 OR hostname:*'"


async def test_sentinelone_no_actua_con_dos_agentes():
    def responder(request):
        if request.url.path == "/web/api/v2.1/agents":
            return httpx.Response(200, json={"data": [{"id": "1"}, {"id": "2"}]})
        return httpx.Response(200, json={})

    red = Red(responder)
    r = await ejecutar(construir("sentinelone", {"url": "https://s1.test", "api_token_env": "RLT_TOKEN"}, red=red),
                       "endpoint.aislar", {"equipo.nombre": "PC-0042"})
    assert r.estado == "error" and "casa con 2 agentes en SentinelOne: no se actua" in r.detalle
    assert red.rutas() == [("GET", "/web/api/v2.1/agents")]
    assert red.peticiones[0].headers["authorization"] == "ApiToken token-prueba"


CFG_MS = {"tenant_id": "t-1", "client_id_env": "RLT_CLIENT_ID", "client_secret_env": "RLT_CLIENT_SECRET"}


def defender(maquinas: list[dict]):
    def responder(request):
        if (t := token_oauth(request)) is not None:
            return t
        if request.url.path == "/api/machines":
            return httpx.Response(200, json={"value": maquinas})
        if request.url.path.endswith("/isolate"):
            return httpx.Response(201, json={"id": "accion-mde-1", "status": "Pending"})
        return httpx.Response(404)
    return responder


async def test_defender_no_actua_con_dos_maquinas_del_mismo_nombre():
    red = Red(defender([{"id": "m-1", "computerDnsName": "pc-0042.acme.test"},
                        {"id": "m-2", "computerDnsName": "PC-0042.otro.test"}]))
    r = await ejecutar(construir("defender", CFG_MS, red=red), "endpoint.aislar", {"equipo.nombre": "PC-0042"})
    assert r.estado == "error" and "casa con 2 maquinas en Defender" in r.detalle
    assert not [p for p in red.peticiones if p.url.path.endswith("/isolate")]


async def test_defender_elige_la_coincidencia_exacta_entre_prefijos():
    red = Red(defender([{"id": "m-1", "computerDnsName": "pc-00421.acme.test"},
                        {"id": "m-2", "computerDnsName": "pc-0042.acme.test"}]))
    r = await ejecutar(construir("defender", CFG_MS, red=red), "endpoint.aislar", {"equipo.nombre": "PC-0042"})
    assert r.estado == "ok"
    assert r.datos == {"maquina": "m-2", "accion_mde": "accion-mde-1"}
    token, consulta, aislar = red.peticiones
    assert token.url.path == "/t-1/oauth2/v2.0/token"
    assert formulario(token)["scope"] == "https://api.securitycenter.microsoft.com/.default"
    assert consulta.url.params["$filter"] == "startswith(computerDnsName,'pc-0042')"
    assert (aislar.method, aislar.url.host, aislar.url.path) == ("POST", "api.security.microsoft.com",
                                                                 "/api/machines/m-2/isolate")
    cuerpo = json_de(aislar)
    assert cuerpo["IsolationType"] == "Full" and "inc-prueba" in cuerpo["Comment"]


async def test_defender_bloquear_destino_no_usa_ips_privadas():
    red = Red(lambda r: token_oauth(r) or httpx.Response(200, json={"id": "ind-1"}))
    r = await ejecutar(construir("defender", CFG_MS, red=red), "perimetro.bloquear_destino",
                       {"red.ip_destino": "10.0.0.5", "red.dominio": "malo.example"})
    assert r.estado == "ok"
    indicador = json_de(red.peticiones[-1])
    assert (indicador["indicatorType"], indicador["indicatorValue"]) == ("DomainName", "malo.example")


# ====================================================================
# Entra ID y Exchange Online
# ====================================================================

async def test_entra_revoca_las_sesiones():
    red = Red(lambda r: token_oauth(r) or httpx.Response(200, json={"value": True}))
    r = await ejecutar(construir("entra", CFG_MS, red=red), "identidad.revocar_sesiones",
                       {"usuario.upn": "ana@acme.test"})
    assert (r.estado, r.datos) == ("ok", {"usuario": "ana@acme.test"})
    token, revocar = red.peticiones
    assert formulario(token)["scope"] == "https://graph.microsoft.com/.default"
    assert (revocar.method, revocar.url.host, revocar.url.path) == (
        "POST", "graph.microsoft.com", "/v1.0/users/ana@acme.test/revokeSignInSessions")
    assert revocar.headers["authorization"] == "Bearer tok-oauth"


async def test_entra_sin_identidad_no_actua():
    red = Red(lambda r: token_oauth(r) or httpx.Response(200, json={}))
    r = await ejecutar(construir("entra", CFG_MS, red=red), "identidad.revocar_sesiones", {}, alerta={})
    assert r.estado == "omitida" and "sin UPN" in r.detalle
    assert [p.url.host for p in red.peticiones if p.url.host == "graph.microsoft.com"] == []


REGLAS = [{"id": "AAMkAD-1=", "displayName": "Sincronizar", "isEnabled": True,
           "actions": {"forwardTo": [{"emailAddress": {"address": "pablo@correo-personal.example"}}]}},
          {"id": "AAMkAD-2=", "displayName": "Facturas", "isEnabled": True}]
BUZON = "pruiz@acme.test"
RUTA_REGLAS = f"/v1.0/users/{BUZON}/mailFolders/inbox/messageRules"


def graph_reglas(reglas: list[dict]):
    def responder(request):
        if (t := token_oauth(request)) is not None:
            return t
        if request.method == "GET" and request.url.path == RUTA_REGLAS:
            return httpx.Response(200, json={"value": reglas})
        if request.method == "PATCH" and request.url.path.startswith(RUTA_REGLAS + "/"):
            return httpx.Response(200, json={})
        return httpx.Response(404)
    return responder


def parches(red: Red) -> list[tuple[str, dict]]:
    return [(p.url.path.rsplit("/", 1)[1], json_de(p)) for p in red.peticiones if p.method == "PATCH"]


@pytest.mark.parametrize("regla, ident", [("Sincronizar", "AAMkAD-1="), ("AAMkAD-2=", "AAMkAD-2=")],
                         ids=["por-nombre", "por-id-de-graph"])
async def test_exchange_deshabilita_la_regla_por_nombre_o_por_id(regla, ident):
    red = Red(graph_reglas(REGLAS))
    r = await ejecutar(construir("exchange", CFG_MS, red=red), "correo.deshabilitar_regla",
                       {"correo.buzon": BUZON, "correo.regla_buzon": regla})
    assert r.estado == "ok", r.detalle
    assert parches(red) == [(ident, {"isEnabled": False})]
    definicion = next(x for x in REGLAS if x["id"] == ident)
    assert r.datos == {"buzon": BUZON, "regla": ident, "definicion": definicion}


@pytest.mark.parametrize("reglas, nombre, n", [
    (REGLAS + [{"id": "AAMkAD-3=", "displayName": "Sincronizar"}], "Sincronizar", 2),
    (REGLAS, "No existe", 0),
], ids=["dos-con-el-mismo-nombre", "ninguna"])
async def test_exchange_no_actua_si_la_regla_no_es_unica(reglas, nombre, n):
    red = Red(graph_reglas(reglas))
    r = await ejecutar(construir("exchange", CFG_MS, red=red), "correo.deshabilitar_regla",
                       {"correo.buzon": BUZON, "correo.regla_buzon": nombre})
    assert r.estado == "error"
    assert f"casa con {n} reglas del buzon {BUZON}: no se actua" in r.detalle
    assert parches(red) == []


async def test_exchange_deshacer_vuelve_a_habilitar_la_misma_regla():
    red = Red(graph_reglas(REGLAS))
    con = construir("exchange", CFG_MS, red=red)
    hecho = await ejecutar(con, "correo.deshabilitar_regla", {"correo.buzon": BUZON, "correo.regla_buzon": "Sincronizar"})
    # Lo que vuelve de la base de datos: JSON, no los objetos originales
    datos = json.loads(json.dumps(hecho.datos))
    deshecho = await ejecutar(con, "correo.habilitar_regla", {"correo.buzon": "otro@acme.test",
                                                              "correo.regla_buzon": "Sincronizar"},
                              datos_deshacer=datos)
    assert deshecho.estado == "ok"
    assert parches(red) == [("AAMkAD-1=", {"isEnabled": False}), ("AAMkAD-1=", {"isEnabled": True})]
    assert red.peticiones[-1].url.path == f"{RUTA_REGLAS}/AAMkAD-1="


# ====================================================================
# Perimetro y WAF: nunca IPs internas
# ====================================================================

PERIMETRALES = [
    ("paloalto", {"url": "https://fw.test", "api_key_env": "RLT_TOKEN"}, "perimetro.bloquear_destino", "red.ip_destino"),
    ("paloalto", {"url": "https://fw.test", "api_key_env": "RLT_TOKEN"}, "waf.bloquear_origen", "red.ip_origen"),
    ("fortinet", {"url": "https://fg.test", "api_token_env": "RLT_TOKEN"}, "perimetro.bloquear_destino", "red.ip_destino"),
    ("fortinet", {"url": "https://fg.test", "api_token_env": "RLT_TOKEN"}, "waf.bloquear_origen", "red.ip_origen"),
    ("cloudflare", {"zona": "z-1", "api_token_env": "RLT_TOKEN"}, "waf.bloquear_origen", "red.ip_origen"),
]
INTERNAS = ["10.0.0.5", "172.16.4.4", "192.168.1.10", "127.0.0.1", "169.254.10.10", "::1", "fd00::1"]


@pytest.mark.parametrize("ip", INTERNAS)
@pytest.mark.parametrize("nombre, cfg, accion, campo", PERIMETRALES, ids=[f"{p[0]}-{p[2]}" for p in PERIMETRALES])
async def test_el_perimetro_no_bloquea_ips_internas(nombre, cfg, accion, campo, ip):
    red = Red(lambda r: httpx.Response(200, text='<response status="success"/>'))
    r = await ejecutar(construir(nombre, cfg, red=red), accion, {campo: ip}, alerta={})
    assert r.estado == "omitida"
    assert "interna" in r.detalle
    assert red.peticiones == []


async def test_paloalto_etiqueta_la_ip_publica_con_caducidad_y_sin_guardar_la_clave():
    red = Red(lambda r: httpx.Response(200, text='<response status="success"><msg>ok</msg></response>'))
    con = construir("paloalto", {"url": "https://fw.test", "api_key_env": "RLT_TOKEN"}, red=red)
    r = await ejecutar(con, "perimetro.bloquear_destino", {"red.ip_destino": "8.8.8.8"})
    assert (r.estado, r.datos) == ("ok", {"ip": "8.8.8.8", "etiqueta": "responselab-bloqueo"})
    assert "48 h" in r.detalle
    [p] = red.peticiones
    assert (p.method, p.url.path) == ("POST", "/api/")
    f = formulario(p)
    assert f["type"] == "user-id" and f["key"] == "token-prueba"
    assert "<register>" in f["cmd"]
    assert '<entry ip="8.8.8.8"><tag><member timeout="172800">responselab-bloqueo</member></tag></entry>' in f["cmd"]
    assert r.peticiones[0]["cuerpo"]["key"] == "***"
    deshecho = await ejecutar(con, "perimetro.desbloquear_destino", {"red.ip_destino": "8.8.8.8"},
                              datos_deshacer=r.datos)
    assert deshecho.estado == "ok"
    assert "<unregister>" in formulario(red.peticiones[-1])["cmd"]


async def test_paloalto_rechazo_del_cortafuegos_es_un_error():
    red = Red(lambda r: httpx.Response(200, text='<response status="error"><msg>sin permiso</msg></response>'))
    r = await ejecutar(construir("paloalto", {"url": "https://fw.test", "api_key_env": "RLT_TOKEN"}, red=red),
                       "perimetro.bloquear_destino", {"red.ip_destino": "8.8.8.8"})
    assert r.estado == "error" and "PAN-OS rechazo el registro" in r.detalle


async def test_fortinet_reutiliza_el_objeto_que_ya_existe():
    def responder(request):
        if request.url.path == "/api/v2/cmdb/firewall/address":
            return httpx.Response(500, json={"status": "error", "http_status": 500, "error": -5})
        return httpx.Response(200, json={"status": "success"})

    red = Red(responder)
    con = construir("fortinet", {"url": "https://fg.test", "api_token_env": "RLT_TOKEN", "reintentos": 0}, red=red)
    r = await ejecutar(con, "perimetro.bloquear_destino", {"red.ip_destino": "8.8.8.8"})
    assert r.estado == "ok", r.detalle
    objeto, miembro = red.peticiones
    assert objeto.url.params["vdom"] == "root"
    assert json_de(objeto) == {"name": "RL-8.8.8.8", "subnet": "8.8.8.8 255.255.255.255", "comment": "ResponseLab"}
    assert miembro.url.path == "/api/v2/cmdb/firewall/addrgrp/ResponseLab-Bloqueo/member"
    assert json_de(miembro) == {"name": "RL-8.8.8.8"}
    assert miembro.headers["authorization"] == "Bearer token-prueba"


async def test_cloudflare_bloquea_el_origen_y_lo_deshace_con_el_id_guardado():
    def responder(request):
        if request.method == "POST":
            return httpx.Response(200, json={"success": True, "result": {"id": "regla-1"}})
        return httpx.Response(200, json={"success": True})

    red = Red(responder)
    con = construir("cloudflare", {"zona": "z-1", "api_token_env": "RLT_TOKEN"}, red=red)
    r = await ejecutar(con, "waf.bloquear_origen", {"red.ip_origen": "8.8.8.8"})
    assert (r.estado, r.datos) == ("ok", {"regla": "regla-1", "ip": "8.8.8.8"})
    alta = red.peticiones[0]
    assert alta.url.path == "/client/v4/zones/z-1/firewall/access_rules/rules"
    assert json_de(alta)["mode"] == "block" and json_de(alta)["configuration"] == {"target": "ip", "value": "8.8.8.8"}
    await ejecutar(con, "waf.desbloquear_origen", {"red.ip_origen": "8.8.8.8"}, datos_deshacer=r.datos)
    assert red.rutas()[-1] == ("DELETE", "/client/v4/zones/z-1/firewall/access_rules/rules/regla-1")
    sin_datos = await ejecutar(con, "waf.desbloquear_origen", {"red.ip_origen": "8.8.8.8"})
    assert sin_datos.estado == "omitida"


async def test_cloudflare_no_bloquea_trafico_de_salida():
    red = Red()
    r = await ejecutar(construir("cloudflare", {"zona": "z-1"}, red=red), "perimetro.bloquear_destino",
                       {"red.ip_destino": "8.8.8.8"})
    assert r.estado == "omitida" and "trafico entrante" in r.detalle
    assert red.peticiones == []


# ====================================================================
# Conectores internos: EDL y tareas
# ====================================================================

@pytest.fixture
def motor_falso(tmp_path):
    """Lo unico que los conectores internos usan del motor: su almacen."""
    almacen = Almacen(tmp_path / "datos" / "responselab.db")
    try:
        yield types.SimpleNamespace(almacen=almacen)
    finally:
        almacen.cerrar()


async def test_edl_en_produccion_anade_con_caducidad_y_deshacer_quita(motor_falso):
    con = construir("edl", motor=motor_falso)
    objetivo = {"red.ip_destino": "8.8.8.8", "red.dominio": "Malo.Example", "red.url": "https://malo.example/x"}
    r = await ejecutar(con, "perimetro.bloquear_destino", objetivo)
    assert r.estado == "ok"
    al = motor_falso.almacen
    assert (al.edl("prueba", "ip"), al.edl("prueba", "dominio"), al.edl("prueba", "url")) == (
        ["8.8.8.8"], ["malo.example"], ["https://malo.example/x"])
    [(caduca,)] = sqlite3.connect(str(al.ruta)).execute("SELECT caduca FROM edl WHERE tipo='ip'").fetchall()
    restante = datetime.strptime(caduca, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)
    assert timedelta(hours=47) < restante <= timedelta(hours=48), "caduca segun politica.bloqueo_perimetro_horas"
    deshecho = await ejecutar(con, "perimetro.desbloquear_destino", {}, datos_deshacer=json.loads(json.dumps(r.datos)))
    assert deshecho.estado == "ok"
    assert al.edl("prueba", "ip") == [] and al.edl("prueba", "dominio") == [] and al.edl("prueba", "url") == []


async def test_edl_en_simulacion_no_toca_la_lista(motor_falso):
    r = await ejecutar(construir("edl", simulacion=True, motor=motor_falso), "perimetro.bloquear_destino",
                       {"red.ip_destino": "8.8.8.8"})
    assert r.estado == "simulada"
    assert motor_falso.almacen.edl("prueba", "ip") == []


@pytest.mark.parametrize("objetivo, motivo", [
    ({"red.ip_destino": "10.0.0.5", "red.dominio": "malo.example"}, "direccion interna"),
    ({"red.ip_destino": "127.0.0.1"}, "direccion interna"),
    ({"red.ip_destino": "no-es-una-ip"}, "sin IP, dominio ni URL"),
    ({}, "sin IP, dominio ni URL"),
])
async def test_edl_rechaza_lo_que_no_debe_bloquear(motor_falso, objetivo, motivo):
    r = await ejecutar(construir("edl", motor=motor_falso), "perimetro.bloquear_destino", objetivo, alerta={})
    assert r.estado == "omitida" and motivo in r.detalle
    assert motor_falso.almacen.edl("prueba", "ip") == [] and motor_falso.almacen.edl("prueba", "dominio") == []


async def test_interno_nota_y_marca_de_inventario(motor_falso):
    con = construir("interno", motor=motor_falso)
    r = await ejecutar(con, "caso.nota", {}, paso={"nombre": "Revisar el correo", "origen": "playbook de correo"})
    assert r.estado == "ok"
    [t] = motor_falso.almacen.tareas("inc-prueba")
    assert (t["grupo"], t["titulo"], t["descripcion"]) == ("Contencion", "Revisar el correo", "playbook de correo")
    await ejecutar(con, "inventario.marcar_no_fiable", {"equipo.nombre": "PC-0042"})
    assert [m["marca"] for m in motor_falso.almacen.marcas("prueba", "PC-0042")] == ["telemetria_no_fiable"]
    simulado = construir("interno", simulacion=True, motor=motor_falso)
    await ejecutar(simulado, "inventario.marcar_no_fiable", {"equipo.nombre": "PC-0099"})
    assert motor_falso.almacen.marcas("prueba", "PC-0099") == []


async def test_interno_tareas_de_obligacion_por_marco(motor_falso):
    plan = {"familia": "exfiltracion", "severidad": 4, "escalado": {}}
    con = construir("interno", motor=motor_falso, marcos=["rgpd", "nis2"])
    r = await ejecutar(con, "caso.tarea_obligacion", {}, plan=plan)
    assert r.estado == "ok" and len(r.datos["tareas"]) == 4
    titulos = sorted(t["titulo"] for t in motor_falso.almacen.tareas("inc-prueba"))
    assert sum(x.startswith("NIS2:") for x in titulos) == 3 and sum(x.startswith("RGPD:") for x in titulos) == 1
    assert all(t["plazo"] for t in motor_falso.almacen.tareas("inc-prueba"))
    sin_marcos = construir("interno", motor=motor_falso)
    r = await ejecutar(sin_marcos, "caso.tarea_obligacion", {}, plan=plan, incidente_id="inc-otro")
    assert [t["titulo"] for t in motor_falso.almacen.tareas("inc-otro")] == ["Evaluar si el hecho es notificable"]


# ====================================================================
# Wazuh: active response
# ====================================================================

CFG_WAZUH = {"url": "https://wazuh.test:55000", "usuario_env": "RLT_USUARIO", "clave_env": "RLT_CLAVE",
             "managers": ["10.0.30.10"], "permitidos": ["10.0.30.20"]}


def wazuh(agentes: list[dict], entregadas: int = 1):
    def responder(request):
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": "jwt-1"}, "error": 0})
        if request.url.path == "/agents":
            return httpx.Response(200, json={"data": {"affected_items": agentes, "total_affected_items": len(agentes)}})
        if request.url.path == "/active-response":
            return httpx.Response(200, json={"data": {"total_affected_items": entregadas, "failed_items": []}})
        return httpx.Response(404)
    return responder


ALERTA_SIN_AGENTE = {"id": "al-2", "titulo": "Prueba", "equipo": {"nombre": "PC-0042"}}


@pytest.mark.parametrize("plataforma, comando", [("windows", "!responselab-aislar.cmd"), ("ubuntu", "!responselab-aislar")])
async def test_wazuh_aisla_por_active_response(plataforma, comando):
    red = Red(wazuh([{"id": "001", "name": "PC-0042", "os": {"platform": plataforma}}]))
    r = await ejecutar(construir("wazuh", CFG_WAZUH, red=red), "endpoint.aislar", {"equipo.nombre": "PC-0042"},
                       alerta=ALERTA_SIN_AGENTE)
    assert r.estado == "ok" and "pendiente de acuse" in r.detalle
    autent, agentes, orden = red.peticiones
    assert autent.headers["authorization"] == "Basic " + base64.b64encode(b"usuario-prueba:clave-prueba").decode()
    assert agentes.url.params["name"] == "PC-0042" and agentes.url.params["limit"] == "2"
    assert (orden.method, orden.url.params["agents_list"]) == ("PUT", "001")
    assert orden.headers["authorization"] == "Bearer jwt-1"
    cuerpo = json_de(orden)
    assert cuerpo["command"] == comando and cuerpo["arguments"] == []
    assert cuerpo["alert"]["data"]["responselab"] == {"permitidos": ["10.0.30.10", "10.0.30.20"],
                                                      "ejecucion_id": "ej-0123456789abcdef", "caso": "inc-prueba"}


async def test_wazuh_con_agente_y_sistema_en_la_alerta_no_consulta_agentes():
    red = Red(wazuh([]))
    alerta = {"id": "al-3", "equipo": {"nombre": "PC-0042", "id_agente": "7", "so": "windows"}}
    r = await ejecutar(construir("wazuh", CFG_WAZUH, red=red), "endpoint.aislar", {"equipo.nombre": "PC-0042"},
                       alerta=alerta)
    assert r.estado == "ok"
    assert [p.url.path for p in red.peticiones] == ["/security/user/authenticate", "/active-response"]
    assert red.peticiones[-1].url.params["agents_list"] == "007"


@pytest.mark.parametrize("agentes, entregadas, detalle", [
    ([{"id": "001", "name": "PC-0042"}, {"id": "002", "name": "PC-0042"}], 1, "casa con varios agentes"),
    ([], 1, "no hay agente de Wazuh"),
    ([{"id": "001", "name": "PC-0042", "os": {"platform": "windows"}}], 0, "no entrego la orden"),
], ids=["nombre-ambiguo", "sin-agente", "orden-no-entregada"])
async def test_wazuh_errores_del_manager(agentes, entregadas, detalle):
    red = Red(wazuh(agentes, entregadas))
    r = await ejecutar(construir("wazuh", CFG_WAZUH, red=red), "endpoint.aislar", {"equipo.nombre": "PC-0042"},
                       alerta=ALERTA_SIN_AGENTE)
    assert r.estado == "error" and detalle in r.detalle
    if entregadas:
        assert "/active-response" not in [p.url.path for p in red.peticiones]


@pytest.mark.parametrize("cfg, accion, objetivo, motivo", [
    (dict(CFG_WAZUH, managers=[]), "endpoint.aislar", {"equipo.nombre": "PC-0042"}, "managers vacio"),
    (CFG_WAZUH, "proceso.matar", {"equipo.nombre": "PC-0042", "proceso.pid": 4242}, "sin PID y hora de arranque"),
    (CFG_WAZUH, "red.bloquear_destino_equipo", {"equipo.nombre": "PC-0042", "red.dominio": "malo.example; rm -rf /"},
     "destino no valido"),
    (CFG_WAZUH, "fichero.cuarentena", {"equipo.nombre": "PC-0042", "fichero.sha256": "ab" * 32}, "necesita la ruta"),
], ids=["sin-managers", "matar-sin-inicio", "destino-con-inyeccion", "cuarentena-sin-ruta"])
async def test_wazuh_se_niega_sin_datos_seguros(cfg, accion, objetivo, motivo):
    red = Red(wazuh([{"id": "001", "name": "PC-0042", "os": {"platform": "windows"}}]))
    r = await ejecutar(construir("wazuh", cfg, red=red), accion, objetivo, alerta=ALERTA_SIN_AGENTE)
    assert r.estado == "omitida" and motivo in r.detalle
    assert "/active-response" not in [p.url.path for p in red.peticiones]


# ====================================================================
# TheHive y MISP
# ====================================================================

CFG_HIVE = {"url": "https://thehive.test", "api_key_env": "RLT_TOKEN", "organizacion": "SOC"}
PLAN_CASO = {
    "familia": "endpoint", "clase": "auto_contener", "severidad": 4, "titulo": "Ransomware", "playbook": "Endpoint",
    "plantilla_caso": "ResponseLab - endpoint", "crear_caso": True, "cierres_propuestos": [], "resumen": "r",
    "secuencias": [{"nombre": "Ransomware"}],
    "regla": {"clave": "dl:ransomware", "titulo": "Cifrado masivo", "tecnicas": ["T1486"], "via": "id de regla"},
    "acciones": [{"modo": "aprobacion", "nombre": "Aislar el equipo", "motivo": "activo protegido",
                  "objetivo": {"equipo.nombre": "PC-0042"}, "origen": "a"},
                 {"modo": "automatica", "nombre": "Triage forense", "motivo": "evidencia", "origen": "b"},
                 {"modo": "manual", "nombre": "Llamar al usuario", "motivo": "sin conector", "origen": "c"}],
    "triaje": [{"pregunta": "Es una cuenta de administracion?", "resultado": "pendiente", "fuente": "inventario",
                "efecto": "subir_severidad"},
               {"pregunta": "Hay copia de seguridad?", "resultado": "si", "fuente": "cmdb", "efecto": ""}],
    "escalado": {"a": "guardia", "plazo_min": 10, "comprobar": [{"a": "L3", "si": "hay datos personales"}],
                 "nota_plazo": ""},
}


def thehive(request):
    if request.url.path == "/api/v1/alert":
        return httpx.Response(201, json={"_id": "~alerta-1"})
    if request.url.path == "/api/v1/alert/~alerta-1/case":
        return httpx.Response(201, json={"_id": "~caso-1", "number": 12})
    return httpx.Response(201, json={"_id": "~x"})


async def test_thehive_abre_alerta_caso_y_tareas_en_la_organizacion_del_cliente():
    red = Red(thehive)
    r = await construir("thehive", CFG_HIVE, red=red).abrir_caso(PLAN_CASO, ALERTA, {"id": "inc-1"})
    assert (r.estado, r.datos) == ("ok", {"alerta": "~alerta-1", "caso": "~caso-1"})
    alerta = red.peticiones[0]
    assert alerta.headers["x-organisation"] == "SOC" and alerta.headers["authorization"] == "Bearer token-prueba"
    cuerpo = json_de(alerta)
    assert cuerpo["sourceRef"] == "prueba-al-1" and cuerpo["severity"] == 4
    assert cuerpo["caseTemplate"] == "ResponseLab - endpoint"
    assert "rl:incidente=inc-1" in cuerpo["tags"]
    assert {"dataType": "hash", "data": "ab" * 32, "message": "ResponseLab", "ioc": True,
            "tags": ["responselab"]} in cuerpo["observables"]
    assert "procedures" not in cuerpo, "los TTP solo si el perfil lo activa"
    tareas = [json_de(p) for p in red.peticiones if p.url.path == "/api/v1/case/~caso-1/task"]
    assert sorted(t["group"] for t in tareas) == ["Aprobar", "Contencion", "Escalado", "Triaje"]


async def test_thehive_en_simulacion_y_comentarios():
    red = Red(thehive)
    simulado = await construir("thehive", CFG_HIVE, simulacion=True, red=red).abrir_caso(PLAN_CASO, ALERTA, {"id": "i"})
    assert simulado.estado == "simulada" and red.peticiones == []
    r = await construir("thehive", CFG_HIVE, red=red).comentar("~caso-1", "Segunda alerta del incidente")
    assert r.estado == "ok"
    assert red.rutas() == [("POST", "/api/v1/case/~caso-1/comment")]
    assert json_de(red.peticiones[0]) == {"message": "Segunda alerta del incidente"}


async def test_misp_solo_consulta_en_produccion():
    def responder(request):
        return httpx.Response(200, json={"response": {"Attribute": [
            {"value": "8.8.8.8", "type": "ip-dst", "event_id": "77", "category": "Network activity"}]}})

    red = Red(responder)
    assert await construir("misp", {"url": "https://misp.test", "api_key_env": "RLT_TOKEN"}, simulacion=True,
                           red=red).buscar(["8.8.8.8"]) == []
    assert red.peticiones == []
    hallados = await construir("misp", {"url": "https://misp.test", "api_key_env": "RLT_TOKEN"}, red=red).buscar(["8.8.8.8"])
    assert hallados == [{"valor": "8.8.8.8", "tipo": "ip-dst", "evento": "77", "categoria": "Network activity"}]
    assert red.peticiones[0].url.path == "/attributes/restSearch"
    assert json_de(red.peticiones[0])["value"] == ["8.8.8.8"]


# ====================================================================
# Kubernetes y Splunk: entradas que llegan de la alerta
# ====================================================================

CFG_K8S = {"url": "https://k8s.test:6443", "token_env": "RLT_TOKEN"}


@pytest.mark.parametrize("objetivo", [
    {"k8s.namespace": "../kube-system", "k8s.pod": "web-1"},
    {"k8s.namespace": "prod", "k8s.pod": "Web_1"},
    {"k8s.namespace": "prod", "k8s.pod": "web-1/../../nodes"},
    {"k8s.namespace": "prod"},
], ids=["namespace-con-ruta", "mayusculas", "pod-con-ruta", "sin-pod"])
async def test_kubernetes_rechaza_nombres_no_validos(objetivo):
    red = Red()
    r = await ejecutar(construir("kubernetes", CFG_K8S, red=red), "k8s.aislar_pod", objetivo, alerta={})
    assert r.estado == "omitida" and "no valido para Kubernetes" in r.detalle
    assert red.peticiones == []


async def test_kubernetes_aisla_solo_el_pod_afectado():
    red = Red(lambda r: httpx.Response(200, json={}))
    con = construir("kubernetes", CFG_K8S, red=red)
    r = await ejecutar(con, "k8s.aislar_pod", {"k8s.namespace": "prod", "k8s.pod": "web-1"})
    assert r.estado == "ok"
    # La marca sale de la ejecucion (sus 12 ultimos caracteres): solo este pod la lleva
    assert r.datos == {"ns": "prod", "pod": "web-1", "marca": "rl-456789abcdef"}
    parche, politica = red.peticiones
    assert (parche.method, parche.url.path) == ("PATCH", "/api/v1/namespaces/prod/pods/web-1")
    assert parche.headers["content-type"] == "application/merge-patch+json"
    assert json_de(parche) == {"metadata": {"labels": {"responselab-aislado": r.datos["marca"]}}}
    assert politica.url.path == "/apis/networking.k8s.io/v1/namespaces/prod/networkpolicies"
    spec = json_de(politica)["spec"]
    assert spec["podSelector"] == {"matchLabels": {"responselab-aislado": r.datos["marca"]}}
    assert spec["egress"] == [] and spec["ingress"] == []
    await ejecutar(con, "k8s.liberar_pod", {}, datos_deshacer=r.datos)
    assert red.rutas()[-2:] == [
        ("DELETE", f"/apis/networking.k8s.io/v1/namespaces/prod/networkpolicies/responselab-aislar-{r.datos['marca']}"),
        ("PATCH", "/api/v1/namespaces/prod/pods/web-1")]


@pytest.mark.parametrize("equipo, cfg, motivo", [
    ('PC-0042" | delete', {}, "nombre de equipo no valido"),
    ("PC-0042", {"indice_evidencias": "rl | delete"}, "indice de evidencias no valido"),
], ids=["equipo-con-spl", "indice-con-spl"])
async def test_splunk_no_deja_inyectar_spl(equipo, cfg, motivo):
    red = Red()
    alerta = dict(ALERTA, equipo={"nombre": equipo})
    r = await ejecutar(construir("splunk", {"url": "https://splunk.test:8089", "token_env": "RLT_TOKEN", **cfg}, red=red),
                       "evidencia.retener", {}, alerta=alerta)
    assert r.estado == "omitida" and motivo in r.detalle
    assert red.peticiones == []


async def test_splunk_copia_la_ventana_del_hecho():
    red = Red(lambda r: httpx.Response(201, json={"sid": "sid-1"}))
    r = await ejecutar(construir("splunk", {"url": "https://splunk.test:8089", "token_env": "RLT_TOKEN"}, red=red),
                       "evidencia.retener", {})
    assert (r.estado, r.datos) == ("ok", {"sid": "sid-1"})
    [p] = red.peticiones
    assert p.url.path == "/services/search/jobs" and p.headers["authorization"] == "Bearer token-prueba"
    busqueda = formulario(p)["search"]
    assert 'host="PC-0042"' in busqueda and "collect index=rl_evidencias" in busqueda
    assert 'rl_incidente="inc-prueba"' in busqueda
    momento = int(datetime(2026, 10, 1, 10, tzinfo=timezone.utc).timestamp())
    assert f"earliest={momento - 24 * 3600}" in busqueda and f"latest={momento + 3600}" in busqueda


# ====================================================================
# Declarativos: plantillas sin ejecucion de codigo
# ====================================================================

CTX = {"alerta": {"titulo": "Ataque <b>&", "equipo": {"nombre": "PC-0042"},
                  "observables": [{"tipo": "ip", "valor": "8.8.8.8"}]},
       "cliente": {"id": "prueba", "nombre": "Cliente"}, "parametros": {}, "guardado": {}}


@pytest.mark.parametrize("plantilla, esperado", [
    ("{{ alerta.__class__ }}", ""),
    ("{{ alerta.__dict__ }}", ""),
    ("{{ alerta.titulo.__class__.__mro__ }}", ""),
    ("{{ alerta.__init__.__globals__ }}", ""),
    ("{{ alerta.titulo.upper }}", ""),
    ("x{{ cliente.__class__.__subclasses__ }}y", "xy"),
    ("{{ ''.join }}", "{{ ''.join }}"),
    ("{{ alerta['titulo'] }}", "{{ alerta['titulo'] }}"),
    ("{{ __import__('os').system('id') }}", "{{ __import__('os').system('id') }}"),
    ("{{ 7*7 }}", "{{ 7*7 }}"),
    ("{% for x in alerta %}{{ x }}{% endfor %}", "{% for x in alerta %}{% endfor %}"),
])
def test_las_plantillas_no_evaluan_codigo(plantilla, esperado):
    salida = renderizar(plantilla, CTX)
    assert salida == esperado
    assert "<class" not in salida and "built-in" not in salida and "function" not in salida


def test_las_plantillas_no_reevaluan_lo_que_sustituyen():
    ctx = dict(CTX, alerta={"titulo": "{{ cliente.nombre }}", "nombre": "{{ alerta.titulo }}"})
    assert renderizar("Titulo: {{ alerta.titulo }}", ctx) == "Titulo: {{ cliente.nombre }}"
    assert renderizar("{{ alerta.nombre }}", ctx) == "{{ alerta.titulo }}"


def test_filtros_de_las_plantillas():
    assert renderizar("{{ alerta.observables|json }}", CTX) == [{"tipo": "ip", "valor": "8.8.8.8"}]
    assert renderizar("obs={{ alerta.observables|json }}", CTX) == 'obs=[{"tipo": "ip", "valor": "8.8.8.8"}]'
    assert renderizar("{{ alerta.titulo|urlencode }}", CTX) == "Ataque%20%3Cb%3E%26"
    assert renderizar("{{ alerta.equipo.nombre|minusculas }}", CTX) == "pc-0042"
    assert renderizar("{{alerta.equipo.nombre|default:otro}}", CTX) == "PC-0042"
    assert renderizar("{{ alerta.no_existe }}", CTX) == ""
    assert renderizar({"a": ["{{ cliente.id }}", 3, None], "b": {"c": "{{ alerta.equipo.nombre }}"}}, CTX) == {
        "a": ["prueba", 3, None], "b": {"c": "PC-0042"}}


async def test_el_filtro_default_no_arrastra_el_espacio_final():
    assert renderizar("{{ parametros.urgencia|default:2 }}", CTX) == "2"
    # El conector que se distribuye con ResponseLab: el nombre de la politica tiene que llegar exacto a ISE
    con = construir("cisco-ise", {"base_url": "https://ise.test:9060"}, simulacion=True)
    r = await ejecutar(con, "red.aislar_equipo", {"equipo.ip": "10.0.20.42"})
    datos = r.peticiones[0]["cuerpo"]["OperationAdditionalData"]["additionalData"]
    assert datos == [{"name": "ipAddress", "value": "10.0.20.42"}, {"name": "policyName", "value": "ResponseLab_Cuarentena"}]


DEFINICION_PELIGROSA = """
nombre: prueba-plantillas
base_url: https://plantillas.test
acciones:
  itsm.ticket:
    metodo: POST
    ruta: /tickets
    cuerpo:
      clase: "{{ alerta.__class__ }}"
      perfil: "{{ cliente.conectores }}"
      autenticacion: "{{ cliente.autenticacion }}"
      cliente: "{{ cliente.id }}"
      literal: "{{ ''.join }}"
      titulo: "{{ alerta.titulo }}"
"""


async def test_un_conector_declarativo_no_ve_la_configuracion_ni_los_secretos_del_cliente(tmp_path):
    (tmp_path / "prueba-plantillas.yml").write_text(DEFINICION_PELIGROSA, encoding="utf-8")
    red = Red()
    con = construir("prueba-plantillas", {}, simulacion=True, red=red, carpeta=tmp_path,
                    autenticacion={"token_env": "RLT_TOKEN"})
    alerta = dict(ALERTA, titulo="{{ cliente.autenticacion }}")
    r = await ejecutar(con, "itsm.ticket", {}, alerta=alerta)
    assert r.estado == "simulada"
    assert r.peticiones[0]["cuerpo"] == {"clase": "", "perfil": "", "autenticacion": "", "cliente": "prueba",
                                         "literal": "{{ ''.join }}", "titulo": "{{ cliente.autenticacion }}"}
    assert "token-prueba" not in json.dumps(r.peticiones) and "RLT_TOKEN" not in json.dumps(r.peticiones)


async def test_servicenow_en_produccion(monkeypatch):
    monkeypatch.setenv("SNOW_USUARIO", "snow-usuario")
    monkeypatch.setenv("SNOW_CLAVE", "snow-clave")
    red = Red(lambda r: httpx.Response(201, json={"result": {"sys_id": "abc123", "number": "INC0010001"}}))
    r = await ejecutar(construir("servicenow", {"base_url": "https://snow.test/"}, red=red), "itsm.ticket", {},
                       parametros={"urgencia": 1})
    assert (r.estado, r.detalle) == ("ok", "ticket ServiceNow abierto")
    assert r.datos == {"sys_id": "abc123", "numero": "INC0010001"}
    [p] = red.peticiones
    assert (p.method, str(p.url)) == ("POST", "https://snow.test/api/now/table/incident")
    assert p.headers["authorization"] == "Basic " + base64.b64encode(b"snow-usuario:snow-clave").decode()
    assert p.headers["accept"] == "application/json"
    assert json_de(p) == {"short_description": "[ResponseLab] Prueba de conectores", "description": "Resumen del plan",
                          "category": "security", "urgency": "1", "correlation_id": "inc-prueba"}
    assert "snow-clave" not in json.dumps(r.peticiones)


DEFINICION_PASOS = """
nombre: prueba-pasos
base_url_env: RLT_PASOS_URL
autenticacion: {tipo: bearer, token_env: RLT_TOKEN}
acciones:
  itsm.ticket:
    - metodo: POST
      ruta: /objetos
      cuerpo: {titulo: "{{ alerta.titulo }}"}
      guardar: {id: data.id}
      simulada: {data: {id: obj-simulado}}
    - metodo: POST
      ruta: "/objetos/{{ guardado.id|urlencode }}/notas"
      cuerpo: {texto: "incidente {{ incidente.id }}"}
      detalle: "objeto {{ guardado.id }} anotado"
"""


async def test_declarativo_de_varios_pasos_usa_lo_guardado(tmp_path, monkeypatch):
    monkeypatch.setenv("RLT_PASOS_URL", "https://pasos.test")
    (tmp_path / "prueba-pasos.yml").write_text(DEFINICION_PASOS, encoding="utf-8")

    def responder(request):
        if request.url.raw_path == b"/objetos":
            return httpx.Response(201, json={"data": {"id": "obj 1/x"}})
        return httpx.Response(201, json={})

    red = Red(responder)
    r = await ejecutar(construir("prueba-pasos", {}, red=red, carpeta=tmp_path), "itsm.ticket", {})
    assert (r.estado, r.detalle, r.datos) == ("ok", "objeto obj 1/x anotado", {"id": "obj 1/x"})
    primero, segundo = red.peticiones
    assert primero.headers["authorization"] == "Bearer token-prueba"
    assert segundo.url.raw_path == b"/objetos/obj%201%2Fx/notas"
    assert json_de(segundo) == {"texto": "incidente inc-prueba"}


# ====================================================================
# Script: solo ficheros de su carpeta y sin shell
# ====================================================================

@pytest.mark.parametrize("nombre", ["../../../../etc/passwd", "/bin/sh", "../declarativo.py", "../scripts/../../pyproject.toml"])
async def test_script_no_sale_de_su_carpeta(nombre):
    con = construir("script", {"acciones": {"correo.bloquear_remitente": nombre}})
    r = await ejecutar(con, "correo.bloquear_remitente", {"correo.remitente": "malo@x.example"})
    assert r.estado == "omitida" and "fuera de" in r.detalle
    assert r.peticiones == []


async def test_script_no_sigue_enlaces_que_salen_de_la_carpeta(tmp_path):
    fuera = tmp_path / "fuera.py"
    fuera.write_text("print('{\"ok\": true}')\n", encoding="utf-8")
    scripts = tmp_path / "conectores" / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "enlace.py").symlink_to(fuera)
    con = construir("script", {"acciones": {"correo.bloquear_remitente": "enlace.py"}}, carpeta=tmp_path / "conectores")
    r = await ejecutar(con, "correo.bloquear_remitente", {"correo.remitente": "malo@x.example"})
    assert r.estado == "omitida" and "fuera de" in r.detalle


async def test_script_en_simulacion_no_se_ejecuta():
    con = construir("script", {"acciones": {"correo.bloquear_remitente": "ejemplo.py"}}, simulacion=True)
    r = await ejecutar(con, "correo.bloquear_remitente", {"correo.remitente": "malo@x.example"})
    assert (r.estado, r.detalle) == ("simulada", "se lanzaria ejemplo.py")
    assert r.peticiones[0]["entrada"]["simulacion"] is True


async def test_script_en_produccion_recibe_la_orden_por_la_entrada_estandar():
    con = construir("script", {"acciones": {"correo.bloquear_remitente": "ejemplo.py"}, "timeout": 30})
    r = await ejecutar(con, "correo.bloquear_remitente", {"correo.remitente": "malo@x.example"})
    assert (r.estado, r.detalle) == ("ok", "remitente malo@x.example bloqueado (ejemplo)")
    assert r.datos == {"remitente": "malo@x.example"}
    entrada = r.peticiones[0]["entrada"]
    assert entrada["accion"] == "correo.bloquear_remitente" and entrada["cliente"] == "prueba"
    assert entrada["incidente"] == "inc-prueba" and entrada["simulacion"] is False


@pytest.mark.parametrize("codigo, estado, detalle", [
    ("import sys; sys.exit(3)", "error", "salio con 3"),
    ("print('{\"ok\": false, \"detalle\": \"la herramienta dijo que no\"}')", "error", "la herramienta dijo que no"),
    ("print('esto no es json')", "ok", "esto no es json"),
])
async def test_script_respuestas_de_la_herramienta(tmp_path, codigo, estado, detalle):
    scripts = tmp_path / "conectores" / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "herramienta.py").write_text(codigo + "\n", encoding="utf-8")
    con = construir("script", {"acciones": {"correo.bloquear_remitente": "herramienta.py"}}, carpeta=tmp_path / "conectores")
    r = await ejecutar(con, "correo.bloquear_remitente", {"correo.remitente": "malo@x.example"})
    assert r.estado == estado and detalle in r.detalle


# ====================================================================
# Cliente HTTP comun y cache de tokens
# ====================================================================

@pytest.fixture
def esperas(monkeypatch):
    """Los reintentos esperan 1, 2, 4... s: en las pruebas no se espera, se anota."""
    anotadas: list[float] = []

    async def no_esperar(segundos):
        anotadas.append(segundos)

    monkeypatch.setattr(base.asyncio, "sleep", no_esperar)
    return anotadas


async def test_reintenta_los_errores_transitorios(esperas):
    respuestas = iter([httpx.Response(503, text="ocupado"), httpx.Response(429), httpx.Response(200, json={"ok": True})])
    red = Red(lambda r: next(respuestas))
    http = ClienteHttp(False, reintentos=2, transporte=red.transporte())
    r = await http.peticion("GET", "https://api.test/recurso")
    assert r.json() == {"ok": True}
    assert len(red.peticiones) == 3 and esperas == [1, 2]
    assert [(e["metodo"], e["estado"]) for e in http.registro] == [("GET", 200)]


async def test_no_reintenta_los_errores_definitivos(esperas):
    red = Red(lambda r: httpx.Response(403, text="sin permiso"))
    http = ClienteHttp(False, reintentos=2, transporte=red.transporte())
    with pytest.raises(ErrorConector) as e:
        await http.peticion("POST", "https://api.test/recurso", json_={})
    assert e.value.estado == 403 and e.value.transitorio is False
    assert len(red.peticiones) == 1 and esperas == []
    assert "HTTP 403" in http.registro[-1]["error"]


async def test_un_error_de_red_es_transitorio(esperas):
    def sin_ruta(request):
        raise httpx.ConnectError("sin ruta al host", request=request)

    red = Red(sin_ruta)
    http = ClienteHttp(False, reintentos=1, transporte=red.transporte())
    with pytest.raises(ErrorConector) as e:
        await http.peticion("GET", "https://api.test/recurso")
    assert e.value.transitorio is True
    assert len(red.peticiones) == 2 and esperas == [1]


async def test_el_registro_de_peticiones_no_guarda_secretos():
    http = ClienteHttp(True)
    await http.peticion("POST", "https://api.test/x?token=abc&api_key=def&pagina=2",
                        cabeceras={"Authorization": "Bearer muy-secreto"},
                        json_={"password": "p", "anidado": {"api_key": "k", "valor": "v"}, "lista": [{"token": "t"}],
                               "texto": "x" * 5000})
    [e] = http.registro
    assert e["url"] == "https://api.test/x?token=***&api_key=***&pagina=2"
    assert e["cuerpo"]["password"] == "***" and e["cuerpo"]["anidado"] == {"api_key": "***", "valor": "v"}
    assert e["cuerpo"]["lista"] == [{"token": "***"}]
    assert e["cuerpo"]["texto"].endswith("...(recortado)") and len(e["cuerpo"]["texto"]) < 4100
    assert "muy-secreto" not in json.dumps(http.registro)


async def test_la_cache_de_tokens_reutiliza_el_token_hasta_que_caduca():
    red = Red(lambda r: httpx.Response(200, json={"access_token": "tok-1", "expires_in": 3600}))
    http = ClienteHttp(False, transporte=red.transporte())
    clave = ("https://login.test/token", "id-cliente", "ambito")
    assert await TokenCache.obtener(http, "https://login.test/token", {"grant_type": "client_credentials"}, clave) == "tok-1"
    assert await TokenCache.obtener(http, "https://login.test/token", {"grant_type": "client_credentials"}, clave) == "tok-1"
    assert len(red.peticiones) == 1
    otra = ("https://login.test/token", "otro-cliente", "ambito")
    await TokenCache.obtener(http, "https://login.test/token", {}, otra)
    assert len(red.peticiones) == 2
    simulado = ClienteHttp(True, transporte=red.transporte())
    assert await TokenCache.obtener(simulado, "https://login.test/token", {}, ("x",)) == "token-simulado"
    assert len(red.peticiones) == 2


async def test_la_cache_de_tokens_exige_access_token():
    red = Red(lambda r: httpx.Response(200, json={"error": "invalid_client"}))
    with pytest.raises(ErrorConector, match="sin access_token"):
        await TokenCache.obtener(ClienteHttp(False, transporte=red.transporte()), "https://login.test/token", {}, ("k",))
