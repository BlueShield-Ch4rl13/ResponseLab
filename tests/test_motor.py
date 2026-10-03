"""
Pruebas del motor (responselab.ejecutor.Motor) de extremo a extremo.

Las alertas salen de escenarios/*.yml, en el formato nativo de cada SIEM, y se
pasan por el motor de verdad con una base de datos temporal. En simulacion no
se toca la red; en produccion los conectores reciben un httpx.MockTransport
que registra cada peticion para comprobar la ruta y el cuerpo exactos.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import yaml

from responselab import nucleo, simulador
from responselab.conectores.base import TokenCache
from responselab.conectores.wazuh import Wazuh
from responselab.ejecutor import AlertaRechazada, Motor

ESCENARIOS = {e["id"]: e for e in simulador.cargar()}


# ====================================================================
# Utilidades
# ====================================================================

@pytest.fixture(autouse=True)
def _cache_de_tokens_limpia(monkeypatch):
    """La cache de tokens OAuth es de clase: cada prueba empieza sin tokens."""
    monkeypatch.setattr(TokenCache, "_tokens", {})


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

    def a(self, host: str, ruta: str = "", metodo: str | None = None) -> list[httpx.Request]:
        return [p for p in self.peticiones if p.url.host == host and p.url.path.endswith(ruta)
                and (metodo is None or p.method == metodo)]


def escribir_perfil(ruta, datos: dict):
    """Reescribe un perfil y le cambia la fecha: Clientes.recargar() solo relee si cambia."""
    ruta.write_text(yaml.safe_dump(datos, allow_unicode=True, sort_keys=False), encoding="utf-8")
    st = ruta.stat()
    os.utime(ruta, (st.st_atime, st.st_mtime + 5))


def leer_perfil(ruta) -> dict:
    return yaml.safe_load(ruta.read_text(encoding="utf-8"))


def consulta(config, sql: str, args=()) -> list[tuple]:
    con = sqlite3.connect(str(config.base_datos))
    try:
        return con.execute(sql, args).fetchall()
    finally:
        con.close()


def manipular(config, sql: str, args=()):
    """Escribe en la base de datos por fuera del almacen."""
    con = sqlite3.connect(str(config.base_datos))
    try:
        con.execute(sql, args)
        con.commit()
    finally:
        con.close()


def carga_de(escenario: str, n: int, base: datetime | None = None) -> tuple[str, dict]:
    """(siem, carga nativa) de la alerta n (desde 1) de un escenario, con id unico y hora reciente."""
    a = ESCENARIOS[escenario]["alertas"][n - 1]
    base = base or datetime.now(timezone.utc) - timedelta(minutes=40)
    ident = f"{escenario}-{n}-{uuid.uuid4().hex[:8]}"
    return a["siem"], simulador.preparar(a["siem"], a["carga"], base + timedelta(minutes=a.get("minuto", 0)), ident)


async def pasar_escenario(motor: Motor, escenario: str, hasta: int | None = None) -> list[dict]:
    """Pasa las alertas 1..hasta del escenario por el motor, una a una, como el simulador."""
    esc = ESCENARIOS[escenario]
    base = datetime.now(timezone.utc) - timedelta(minutes=40)
    salida = []
    for n in range(1, (hasta or len(esc["alertas"])) + 1):
        siem, carga = carga_de(escenario, n, base=base)
        salida.append(motor.recibir(esc.get("cliente", "lab"), siem, carga))
        await motor.drenar()
    return salida


def ejecuciones_de(motor: Motor, cliente: str, alerta_id: str | None = None, accion: str | None = None) -> list[dict]:
    return [e for e in motor.almacen.ejecuciones(cliente, limite=1000)
            if (alerta_id is None or e["alerta_id"] == alerta_id) and (accion is None or e["accion"] == accion)]


def eventos(motor: Motor, cliente: str | None = None) -> list[str]:
    return [f["evento"] for f in motor.almacen.auditoria(cliente, limite=1000)]


def alerta_local(regla: str, equipo: str, nivel: int = 8, ident: str | None = None) -> dict:
    """Alerta de Wazuh de una regla local (fuera del catalogo): abre incidente sin contener nada."""
    return {
        "id": ident or f"loc-{regla}-{equipo}-{uuid.uuid4().hex[:8]}",
        "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "rule": {"id": regla, "level": nivel, "description": f"Local: regla {regla}", "groups": ["local", "windows"]},
        "agent": {"id": "042", "name": equipo, "ip": "10.0.20.42"},
        "data": {"win": {"system": {"eventID": "1", "computer": f"{equipo}.lab.test"},
                         "eventdata": {"image": "C:\\Users\\Public\\svc.exe", "processId": "3300"}}},
    }


async def incidente_local(motor: Motor, cliente: str, equipo: str, regla: str = "100950") -> dict:
    motor.recibir(cliente, "wazuh", alerta_local(regla, equipo))
    await motor.drenar()
    inc = motor.almacen.incidente_abierto(cliente, "equipo", equipo, datetime.now(timezone.utc) - timedelta(hours=1))
    assert inc, f"la alerta local deberia haber abierto un incidente en {equipo}"
    return inc


async def parar_con_garantia(m: Motor):
    """Para el motor sin colgar la prueba.

    Motor.parar() puede no volver nunca en Python < 3.12 (ver
    test_parar_no_se_cuelga_si_llega_una_alerta_justo_antes): si pasa, se
    cancelan de nuevo las tareas hasta que acaben.
    """
    tareas = list(m._tareas)
    try:
        await asyncio.wait_for(m.parar(), timeout=5)
    except asyncio.TimeoutError:
        pendientes = [t for t in tareas if not t.done()]
        while pendientes:
            for t in pendientes:
                t.cancel()
            _, pendientes = await asyncio.wait(pendientes, timeout=0.5)


@pytest.fixture
async def nuevo_motor():
    """Fabrica de motores propios (otra config, otro transporte); los para al acabar."""
    creados: list[Motor] = []

    async def crear(config, transporte=None, arrancar=True) -> Motor:
        m = Motor(config, transporte=transporte)
        creados.append(m)
        if arrancar:
            await m.arrancar(vigilante=False)
        return m

    yield crear
    for m in creados:
        await parar_con_garantia(m)
        m.almacen.cerrar()


@pytest.fixture
def lab_en_produccion(config, carpeta_clientes, entorno_tokens, monkeypatch):
    """El perfil lab en modo produccion y sin el interruptor global de simulacion. Sin credenciales."""
    ruta = carpeta_clientes / "lab.yml"
    datos = leer_perfil(ruta)
    datos["modo"] = "produccion"
    escribir_perfil(ruta, datos)
    config.simulacion_global = False
    for var in ("RL_LAB_WAZUH_USUARIO", "RL_LAB_WAZUH_CLAVE", "RL_LAB_THEHIVE_KEY", "RL_LAB_DISCORD_WEBHOOK"):
        monkeypatch.delenv(var, raising=False)
    return config


# ====================================================================
# Entrada: clientes, deduplicacion y limitador
# ====================================================================

async def test_cliente_desconocido_se_rechaza(motor, nueva_alerta_wazuh):
    with pytest.raises(AlertaRechazada, match="desconocido o inactivo"):
        motor.recibir("no-existe", "wazuh", nueva_alerta_wazuh("100950"))
    with pytest.raises(AlertaRechazada):
        motor.decidir("no-existe", "wazuh", nueva_alerta_wazuh("100950"))
    assert motor.almacen.pendientes() == 0


async def test_cliente_inactivo_se_rechaza(motor, carpeta_clientes, nueva_alerta_wazuh):
    ruta = carpeta_clientes / "norte.yml"
    datos = leer_perfil(ruta)
    datos["activo"] = False
    escribir_perfil(ruta, datos)
    assert motor.clientes.recargar() is True
    with pytest.raises(AlertaRechazada, match="inactivo"):
        motor.recibir("norte", "wazuh", nueva_alerta_wazuh("100950"))
    assert "norte" not in {p["id"] for p in motor.clientes.todos()}


async def test_perfil_borrado_deja_de_existir(motor, carpeta_clientes, nueva_alerta_wazuh):
    (carpeta_clientes / "acme.yml").unlink()
    assert motor.clientes.recargar() is True
    assert motor.clientes.get("acme") is None
    with pytest.raises(AlertaRechazada):
        motor.recibir("acme", "wazuh", nueva_alerta_wazuh("100950"))


async def test_perfil_con_secreto_en_claro_no_sustituye_al_bueno(motor, carpeta_clientes):
    ruta = carpeta_clientes / "lab.yml"
    datos = leer_perfil(ruta)
    datos["conectores"]["wazuh"]["clave"] = "secreto-en-claro"
    escribir_perfil(ruta, datos)
    motor.clientes.recargar()
    assert any("secreto en claro" in e for e in motor.clientes.errores["lab.yml"])
    vigente = motor.clientes.get("lab")
    assert vigente is not None
    assert "clave" not in vigente["conectores"]["wazuh"], "sigue el perfil anterior, el bueno"


async def test_siem_no_soportado(motor):
    with pytest.raises(ValueError, match="SIEM no soportado"):
        motor.recibir("lab", "qradar", {"id": "x"})


async def test_alerta_duplicada_en_cola_y_ya_procesada(motor, nueva_alerta_wazuh):
    carga = nueva_alerta_wazuh("100950")
    assert motor.recibir("lab", "wazuh", carga)["estado"] == "encolada"
    assert motor.recibir("lab", "wazuh", carga)["estado"] == "duplicada"     # aun en la cola
    await motor.drenar()
    assert motor.recibir("lab", "wazuh", carga)["estado"] == "duplicada"     # ya en la base de datos
    assert len(motor.almacen.alertas("lab")) == 1
    assert motor.contadores["duplicadas"] == 2


async def test_alerta_duplicada_tras_reiniciar_el_motor(motor, config, nuevo_motor, nueva_alerta_wazuh):
    carga = nueva_alerta_wazuh("100950")
    motor.recibir("lab", "wazuh", carga)
    await motor.drenar()
    otro = await nuevo_motor(config, arrancar=False)     # sin memoria de lo recibido: solo la base de datos
    assert otro.recibir("lab", "wazuh", carga)["estado"] == "duplicada"


async def test_alerta_sin_id_se_deduplica_por_su_contenido(motor):
    carga = {"titulo": "Prueba sin identificador", "regla_id": "generica-1", "equipo": {"nombre": "PC-0042"}}
    primera = motor.recibir("lab", "generico", carga)
    assert primera["estado"] == "encolada" and primera["alerta_id"].startswith("rl-")
    assert motor.recibir("lab", "generico", dict(carga))["estado"] == "duplicada"
    otra = motor.recibir("lab", "generico", dict(carga, titulo="Otro contenido"))
    assert otra["estado"] == "encolada" and otra["alerta_id"] != primera["alerta_id"]
    await motor.drenar()


async def test_limitador_por_regla_y_equipo(motor, nueva_alerta_wazuh):
    motor.config.limite_por_clave = 2

    def alerta(regla, equipo, i):
        return dict(nueva_alerta_wazuh(regla, equipo=equipo), id=f"lim-{regla}-{equipo}-{i}")

    estados = [motor.recibir("lab", "wazuh", alerta("100960", "PC-0050", i))["estado"] for i in range(3)]
    assert estados == ["encolada", "encolada", "limitada"]
    assert motor.recibir("lab", "wazuh", alerta("100960", "PC-0051", 9))["estado"] == "encolada", "otro equipo"
    assert motor.recibir("lab", "wazuh", alerta("100961", "PC-0050", 9))["estado"] == "encolada", "otra regla"
    await motor.drenar()
    assert motor.contadores["limitadas"] == 1
    limitadas = [f for f in motor.almacen.auditoria("lab") if f["evento"] == "alerta.limitada"]
    assert [f["detalle"] for f in limitadas] == [{"alerta": "lim-100960-PC-0050-2", "regla": "100960"}]
    assert not motor.almacen.existe_alerta("lab", "lim-100960-PC-0050-2")


async def test_limitador_libera_al_pasar_la_ventana(motor, nueva_alerta_wazuh):
    motor.config.limite_por_clave = 1
    motor.config.limite_ventana_seg = 0.2

    def alerta(i):
        return dict(nueva_alerta_wazuh("100960", equipo="PC-0050"), id=f"ventana-{i}")

    assert motor.recibir("lab", "wazuh", alerta(1))["estado"] == "encolada"
    assert motor.recibir("lab", "wazuh", alerta(2))["estado"] == "limitada"
    await asyncio.sleep(0.3)
    assert motor.recibir("lab", "wazuh", alerta(3))["estado"] == "encolada"
    await motor.drenar()


async def test_deduplicacion_en_memoria_no_cruza_clientes(motor):
    # Dos managers de Wazuh distintos (dos clientes) pueden generar el mismo id de alerta.
    de_lab = motor.recibir("lab", "wazuh", alerta_local("100950", "PC-0042", ident="1727776800.4242"))
    de_acme = motor.recibir("acme", "wazuh", alerta_local("100951", "SRV-ACME-01", ident="1727776800.4242"))
    await motor.drenar()
    assert de_lab["estado"] == "encolada"
    assert de_acme["estado"] == "encolada"
    assert motor.almacen.existe_alerta("acme", "1727776800.4242")


async def test_reenvios_de_una_alerta_no_gastan_el_limitador(motor):
    motor.config.limite_por_clave = 3
    original = alerta_local("100960", "PC-0050", ident="reenviada-1")
    estados = [motor.recibir("lab", "wazuh", original)["estado"] for _ in range(4)]   # el SIEM reintenta
    nueva = motor.recibir("lab", "wazuh", alerta_local("100960", "PC-0050", ident="distinta-2"))
    await motor.drenar()
    assert estados == ["encolada", "duplicada", "duplicada", "duplicada"]
    assert nueva["estado"] == "encolada"
    assert motor.almacen.existe_alerta("lab", "distinta-2")


async def test_parar_no_se_cuelga_si_llega_una_alerta_justo_antes(config, entorno_tokens):
    m = Motor(config)
    await m.arrancar(vigilante=False)
    tareas = list(m._tareas)
    try:
        await asyncio.sleep(0.05)                              # el trabajador espera trabajo
        m.recibir("lab", "wazuh", alerta_local("100950", "PC-0042"))  # lo despierta...
        await asyncio.wait_for(m.parar(), timeout=1.5)         # ...y el servicio se apaga en ese momento
    finally:
        pendientes = [t for t in tareas if not t.done()]
        while pendientes:
            for t in pendientes:
                t.cancel()
            _, pendientes = await asyncio.wait(pendientes, timeout=0.5)
        m.almacen.cerrar()


# ====================================================================
# Correlacion en incidentes
# ====================================================================

async def test_mismo_equipo_un_incidente_y_otro_equipo_otro(motor):
    a1 = motor.recibir("lab", "wazuh", alerta_local("100950", "PC-0042", nivel=12))
    await motor.drenar()
    a2 = motor.recibir("lab", "wazuh", alerta_local("100952", "pc-0042", nivel=12))
    await motor.drenar()
    a3 = motor.recibir("lab", "wazuh", alerta_local("100950", "PC-0099", nivel=12))
    await motor.drenar()
    por_id = {a["id"]: a for a in motor.almacen.alertas("lab")}
    assert {por_id[x["alerta_id"]]["plan"]["estado"] for x in (a1, a2, a3)} == {"en_curso"}
    assert por_id[a1["alerta_id"]]["incidente_id"] == por_id[a2["alerta_id"]]["incidente_id"]
    assert por_id[a3["alerta_id"]]["incidente_id"] != por_id[a1["alerta_id"]]["incidente_id"]
    incidentes = {i["entidad"]: i for i in motor.almacen.incidentes("lab")}
    assert sorted(incidentes) == ["PC-0042", "PC-0099"]
    assert incidentes["PC-0042"]["n_alertas"] == 2 and incidentes["PC-0099"]["n_alertas"] == 1
    assert eventos(motor, "lab").count("incidente.abierto") == 2


async def test_correlacion_no_cruza_clientes(motor):
    inc_lab = await incidente_local(motor, "lab", "PC-0042")
    inc_acme = await incidente_local(motor, "acme", "PC-0042")
    assert inc_lab["id"] != inc_acme["id"]
    assert inc_lab["cliente"] == "lab" and inc_acme["cliente"] == "acme"
    assert inc_acme["n_alertas"] == 1


async def test_correlacion_por_usuario_entre_dos_siem(motor):
    """exfiltracion-tras-acceso: Sentinel y Splunk, mismo usuario, un solo incidente."""
    await pasar_escenario(motor, "exfiltracion-tras-acceso")
    incidentes = motor.almacen.incidentes("acme")
    assert len(incidentes) == 1
    inc = incidentes[0]
    assert (inc["entidad_tipo"], inc["entidad"], inc["n_alertas"]) == ("usuario", "pruiz", 2)
    assert {"cloud", "exfiltracion"} <= set(inc["familias"])
    assert {a["siem"] for a in motor.almacen.alertas("acme", inc["id"])} == {"sentinel", "splunk"}


# ====================================================================
# Ejecucion automatica, idempotencia y simulacion
# ====================================================================

async def test_contencion_automatica_en_simulacion_queda_simulada(motor):
    recibidas = await pasar_escenario(motor, "ransomware-puesto", hasta=2)
    aislar = ejecuciones_de(motor, "lab", recibidas[1]["alerta_id"], "endpoint.aislar")
    assert len(aislar) == 1
    ej = aislar[0]
    assert (ej["estado"], ej["conector"], ej["origen"]) == ("simulada", "wazuh", "automatica")
    assert ej["objetivo"] == {"equipo.nombre": "CORP-FIN-07"}
    assert ej["peticiones"] and all(p.get("simulada") for p in ej["peticiones"])
    orden = next(p for p in ej["peticiones"] if p["metodo"] == "PUT")
    assert orden["url"].endswith("/active-response")
    assert orden["cuerpo"]["command"] == "!responselab-aislar.cmd"
    assert "accion.simulada" in eventos(motor, "lab")


async def test_segunda_contencion_identica_del_incidente_queda_omitida(motor):
    recibidas = await pasar_escenario(motor, "ransomware-puesto")
    inc = motor.almacen.incidentes("lab")
    assert len(inc) == 1
    aislar = ejecuciones_de(motor, "lab", accion="endpoint.aislar")
    por_alerta = {e["alerta_id"]: e for e in aislar}
    primera, tercera = por_alerta[recibidas[1]["alerta_id"]], por_alerta[recibidas[2]["alerta_id"]]
    assert primera["estado"] == "simulada"
    assert tercera["estado"] == "omitida" and tercera["conector"] == ""
    assert primera["id"] in tercera["resultado"]["detalle"]
    assert [e["estado"] for e in aislar].count("simulada") == 1, "el equipo se aisla una sola vez"


async def test_el_mismo_paso_de_la_misma_alerta_no_se_ejecuta_dos_veces(motor):
    recibidas = await pasar_escenario(motor, "ransomware-puesto", hasta=2)
    fila = next(a for a in motor.almacen.alertas("lab") if a["id"] == recibidas[1]["alerta_id"])
    # La alerta normalizada tal como se guardo, y el mismo paso del mismo plan
    alerta = json.loads(consulta(motor.config, "SELECT alerta FROM alertas WHERE id=?", (fila["id"],))[0][0])
    paso = next(p for p in fila["plan"]["acciones"] if p["accion"] == "endpoint.aislar")
    antes = len(ejecuciones_de(motor, "lab"))
    otra = await motor.ejecutar_paso(motor.clientes.get("lab"), motor.almacen.incidente(fila["incidente_id"]),
                                     alerta, fila["plan"], paso, origen="automatica")
    assert otra == []
    assert len(ejecuciones_de(motor, "lab")) == antes


async def test_simulacion_nunca_usa_el_transporte(config, entorno_tokens, nuevo_motor):
    red = Red()
    m = await nuevo_motor(config, transporte=red.transporte())
    for escenario in ("ransomware-puesto", "phishing-a-cuenta", "exfiltracion-tras-acceso", "credenciales-movimiento-ot"):
        await pasar_escenario(m, escenario)
    assert red.peticiones == []
    hechas = [e for c in ("lab", "acme", "norte") for e in ejecuciones_de(m, c)]
    assert {e["conector"] for e in hechas} >= {"wazuh", "entra", "exchange", "crowdstrike"}
    assert {e["estado"] for e in hechas} <= {"simulada", "omitida"}
    for e in hechas:
        assert all(p.get("simulada") for p in e["peticiones"]), e


async def test_conector_que_lanza_excepcion_no_tumba_el_motor(motor, monkeypatch):
    async def roto(self, http, objetivo, parametros, contexto):
        raise RuntimeError("fallo inesperado del conector")

    monkeypatch.setattr(Wazuh, "aislar", roto)
    recibidas = await pasar_escenario(motor, "ransomware-puesto", hasta=2)
    por_accion = {e["accion"]: e for e in ejecuciones_de(motor, "lab", recibidas[1]["alerta_id"])}
    assert por_accion["endpoint.aislar"]["estado"] == "error"
    assert "RuntimeError: fallo inesperado" in por_accion["endpoint.aislar"]["resultado"]["detalle"]
    assert por_accion["evidencia.triage_forense"]["estado"] == "simulada", "el resto del plan sigue"
    assert "accion.error" in eventos(motor, "lab")
    assert motor.almacen.pendientes() == 0


async def test_trabajo_de_un_cliente_borrado_queda_en_error(config, entorno_tokens, carpeta_clientes, nuevo_motor):
    m = await nuevo_motor(config, arrancar=False)
    m.recibir("lab", "wazuh", alerta_local("100950", "PC-0042"))
    (carpeta_clientes / "lab.yml").unlink()
    m.clientes.recargar()
    await m.arrancar(vigilante=False)
    await m.drenar()
    [(estado, error)] = consulta(config, "SELECT estado, error FROM trabajos")
    assert estado == "error" and "AlertaRechazada" in error
    assert "trabajo.error" in eventos(m, "lab")


async def test_trabajos_interrumpidos_vuelven_a_la_cola_al_arrancar(config, entorno_tokens, nuevo_motor):
    caido = await nuevo_motor(config, arrancar=False)
    r = caido.recibir("lab", "wazuh", alerta_local("100950", "PC-0042"))
    assert caido.almacen.tomar_trabajo() is not None         # se queda "en_curso": el proceso muere aqui
    nuevo = await nuevo_motor(config)
    await nuevo.drenar()
    assert nuevo.almacen.existe_alerta("lab", r["alerta_id"])
    assert consulta(config, "SELECT estado FROM trabajos") == [("hecho",)]


async def test_decidir_no_ejecuta_ni_guarda_nada(motor):
    siem, carga = carga_de("ransomware-puesto", 2)
    plan = motor.decidir("lab", siem, carga)
    assert plan["familia"] == "endpoint"
    assert any(p["accion"] == "endpoint.aislar" for p in plan["acciones"])
    c = motor.almacen.contar()
    assert c["alertas"] == 0 and c["incidentes_abiertos"] == 0 and c["ejecuciones_por_estado"] == {}
    assert motor.almacen.pendientes() == 0
    assert motor.almacen.verificar_auditoria()["registros"] == 0


# ====================================================================
# Produccion con un transporte falso
# ====================================================================

def responder_lab(request: httpx.Request) -> httpx.Response:
    """Wazuh manager, TheHive y Discord del laboratorio, contestando como lo harian."""
    url = request.url
    if url.host == "wazuh-manager" and url.path == "/security/user/authenticate":
        return httpx.Response(200, json={"data": {"token": "jwt-prueba"}, "error": 0})
    if url.host == "wazuh-manager" and url.path == "/active-response":
        return httpx.Response(200, json={"data": {"total_affected_items": 1, "failed_items": []}, "error": 0})
    if url.host == "thehive" and url.path == "/api/v1/alert":
        return httpx.Response(201, json={"_id": "~4100"})
    if url.host == "thehive" and url.path == "/api/v1/alert/~4100/case":
        return httpx.Response(201, json={"_id": "~4200", "number": 7})
    if url.host == "thehive":
        return httpx.Response(201, json={"_id": "~tarea"})
    if url.host == "discord.test":
        return httpx.Response(204)
    return httpx.Response(404, json={"error": f"ruta no prevista: {request.method} {url}"})


async def test_produccion_hace_las_llamadas_reales(lab_en_produccion, monkeypatch, nuevo_motor):
    monkeypatch.setenv("RL_LAB_WAZUH_USUARIO", "wazuh-wui")
    monkeypatch.setenv("RL_LAB_WAZUH_CLAVE", "clave-wazuh")
    monkeypatch.setenv("RL_LAB_THEHIVE_KEY", "clave-thehive")
    monkeypatch.setenv("RL_LAB_DISCORD_WEBHOOK", "https://discord.test/api/webhooks/1/abc")
    red = Red(responder_lab)
    m = await nuevo_motor(lab_en_produccion, transporte=red.transporte())
    recibidas = await pasar_escenario(m, "ransomware-puesto", hasta=2)

    ejs = {e["accion"]: e for e in ejecuciones_de(m, "lab", recibidas[1]["alerta_id"])}
    assert ejs["endpoint.aislar"]["estado"] == "ok"
    assert not any(p.get("simulada") for p in ejs["endpoint.aislar"]["peticiones"])
    inc = m.almacen.incidentes("lab")[0]

    # Autenticacion en la API del manager con las credenciales del entorno
    autent = red.a("wazuh-manager", "/security/user/authenticate", "POST")
    assert autent
    assert autent[0].headers["authorization"] == "Basic " + base64.b64encode(b"wazuh-wui:clave-wazuh").decode()
    # La orden de aislamiento: agente, script, IPs permitidas y la ejecucion para el acuse
    ordenes = {json.loads(p.content)["command"]: p for p in red.a("wazuh-manager", "/active-response", "PUT")}
    assert set(ordenes) == {"!responselab-aislar.cmd", "!responselab-matar.cmd", "!responselab-triage.cmd"}
    aislar = ordenes["!responselab-aislar.cmd"]
    assert aislar.headers["authorization"] == "Bearer jwt-prueba"
    assert aislar.url.params["agents_list"] == "007"
    datos = json.loads(aislar.content)["alert"]["data"]["responselab"]
    assert datos["permitidos"] == ["10.0.30.10", "10.0.30.20"]
    assert datos["ejecucion_id"] == ejs["endpoint.aislar"]["id"]
    assert datos["caso"] == inc["id"]
    matar = json.loads(ordenes["!responselab-matar.cmd"].content)["alert"]["data"]["responselab"]
    assert matar["pid"] == 6388 and matar["imagen"].endswith("vssadmin.exe")
    # TheHive: alerta y caso en la organizacion del cliente
    alerta_th = red.a("thehive", "/api/v1/alert", "POST")[0]
    assert alerta_th.headers["x-organisation"] == "SOC"
    assert alerta_th.headers["authorization"] == "Bearer clave-thehive"
    cuerpo = json.loads(alerta_th.content)
    assert cuerpo["sourceRef"].startswith("lab-ransomware-puesto-1")
    assert {"dataType": "hostname", "data": "CORP-FIN-07", "message": "Equipo afectado"} in cuerpo["observables"]
    assert m.almacen.incidente(inc["id"])["caso_externo"] == "~4200"
    assert red.a("thehive", "/api/v1/case/~4200/comment", "POST"), "la segunda alerta comenta el caso abierto"
    assert red.a("discord.test", metodo="POST")


async def test_produccion_sin_credenciales_no_sale_a_la_red(lab_en_produccion, nuevo_motor):
    red = Red()
    m = await nuevo_motor(lab_en_produccion, transporte=red.transporte())
    recibidas = await pasar_escenario(m, "ransomware-puesto", hasta=2)
    aislar = ejecuciones_de(m, "lab", recibidas[1]["alerta_id"], "endpoint.aislar")[0]
    assert aislar["estado"] == "error"
    assert aislar["resultado"]["detalle"] == "falta configuracion: usuario_env, clave_env"
    assert red.peticiones == []
    assert "caso.error" in eventos(m, "lab")


# ====================================================================
# Aprobaciones
# ====================================================================

async def aprobacion_de(motor: Motor, accion: str) -> dict:
    """La aprobacion pendiente de `accion` tras la primera alerta del ransomware (clase auto_analisis)."""
    await pasar_escenario(motor, "ransomware-puesto", hasta=1)
    return next(a for a in motor.almacen.aprobaciones("lab", "pendiente") if a["paso"]["accion"] == accion)


async def test_la_alerta_sin_secuencia_pide_aprobacion_y_no_ejecuta(motor):
    await pasar_escenario(motor, "ransomware-puesto", hasta=1)
    pendientes = {a["paso"]["accion"] for a in motor.almacen.aprobaciones("lab", "pendiente")}
    assert {"endpoint.aislar", "proceso.matar"} <= pendientes
    assert ejecuciones_de(motor, "lab", accion="endpoint.aislar") == []
    assert eventos(motor, "lab").count("aprobacion.pedida") == len(motor.almacen.aprobaciones("lab"))


async def test_aprobar_ejecuta_el_paso_una_sola_vez(motor):
    ap = await aprobacion_de(motor, "endpoint.aislar")
    r = await motor.aprobar("lab", ap["id"], "analista@lab.test", "confirmado con el usuario")
    assert r["estado"] == "ejecutada"
    [ej] = r["ejecuciones"]
    assert (ej["accion"], ej["estado"], ej["origen"], ej["actor"]) == ("endpoint.aislar", "simulada", "aprobada",
                                                                      "analista@lab.test")
    guardada = motor.almacen.aprobacion(ap["id"])
    assert guardada["estado"] == "ejecutada" and guardada["ejecuciones"] == [ej["id"]]
    assert guardada["decidida_por"] == "analista@lab.test"
    with pytest.raises(AlertaRechazada, match="ya no esta pendiente"):
        await motor.aprobar("lab", ap["id"], "otra@lab.test")
    assert len(ejecuciones_de(motor, "lab", accion="endpoint.aislar")) == 1
    assert "aprobacion.aprobada" in eventos(motor, "lab")


async def test_rechazar_no_ejecuta_y_cierra_la_aprobacion(motor):
    ap = await aprobacion_de(motor, "endpoint.aislar")
    assert motor.rechazar("lab", ap["id"], "analista@lab.test", "falso positivo")["estado"] == "rechazada"
    with pytest.raises(AlertaRechazada):
        await motor.aprobar("lab", ap["id"], "analista@lab.test")
    with pytest.raises(AlertaRechazada):
        motor.rechazar("lab", ap["id"], "analista@lab.test")
    assert ejecuciones_de(motor, "lab", accion="endpoint.aislar") == []
    assert motor.almacen.aprobacion(ap["id"])["comentario"] == "falso positivo"


async def test_la_aprobacion_de_otro_cliente_no_existe_para_mi(motor):
    ap = await aprobacion_de(motor, "endpoint.aislar")
    with pytest.raises(AlertaRechazada, match="no encontrada"):
        await motor.aprobar("acme", ap["id"], "soc-guardia@acme.test")
    with pytest.raises(AlertaRechazada, match="no encontrada"):
        motor.rechazar("acme", ap["id"], "soc-guardia@acme.test")
    assert motor.almacen.aprobacion(ap["id"])["estado"] == "pendiente"


async def test_la_vigilancia_caduca_aprobaciones_vencidas(motor):
    ap = await aprobacion_de(motor, "endpoint.aislar")
    manipular(motor.config, "UPDATE aprobaciones SET caduca=? WHERE id=?", ("2020-01-01T00:00:00.000000Z", ap["id"]))
    await motor.vigilar_una_vez()
    assert motor.almacen.aprobacion(ap["id"])["estado"] == "caducada"
    assert "aprobacion.caducada" in eventos(motor, "lab")
    with pytest.raises(AlertaRechazada, match="caducada"):
        await motor.aprobar("lab", ap["id"], "analista@lab.test")


async def test_una_aprobacion_vencida_no_se_ejecuta_aunque_no_haya_pasado_la_vigilancia(motor):
    ap = await aprobacion_de(motor, "endpoint.aislar")
    manipular(motor.config, "UPDATE aprobaciones SET caduca=? WHERE id=?", ("2020-01-01T00:00:00.000000Z", ap["id"]))
    with pytest.raises(AlertaRechazada):
        await motor.aprobar("lab", ap["id"], "analista@lab.test")
    assert ejecuciones_de(motor, "lab", accion="endpoint.aislar") == []


# ====================================================================
# Deshacer
# ====================================================================

async def aislamiento(motor: Motor) -> dict:
    recibidas = await pasar_escenario(motor, "ransomware-puesto", hasta=2)
    return ejecuciones_de(motor, "lab", recibidas[1]["alerta_id"], "endpoint.aislar")[0]


async def test_deshacer_crea_la_ejecucion_inversa_y_la_accion_deja_de_estar_vigente(motor):
    ej = await aislamiento(motor)
    assert motor.almacen.accion_vigente("lab", ej["incidente_id"], "endpoint.aislar", ej["objetivo"])["id"] == ej["id"]
    [inversa] = await motor.deshacer("lab", ej["id"], "analista@lab.test")
    assert (inversa["accion"], inversa["deshace"], inversa["conector"]) == ("endpoint.liberar", ej["id"], "wazuh")
    assert (inversa["estado"], inversa["origen"], inversa["actor"]) == ("simulada", "deshacer", "analista@lab.test")
    assert inversa["incidente_id"] == ej["incidente_id"]
    assert motor.almacen.accion_vigente("lab", ej["incidente_id"], "endpoint.aislar", ej["objetivo"]) is None


async def test_tras_deshacer_una_nueva_alerta_vuelve_a_contener(motor):
    ej = await aislamiento(motor)
    await motor.deshacer("lab", ej["id"], "analista@lab.test")
    siem, carga = carga_de("ransomware-puesto", 3)
    r = motor.recibir("lab", siem, carga)
    await motor.drenar()
    [nueva] = ejecuciones_de(motor, "lab", r["alerta_id"], "endpoint.aislar")
    assert nueva["estado"] == "simulada"


async def test_deshacer_rechaza_lo_no_ejecutado_lo_irreversible_y_lo_ajeno(motor):
    recibidas = await pasar_escenario(motor, "ransomware-puesto")
    omitida = ejecuciones_de(motor, "lab", recibidas[2]["alerta_id"], "endpoint.aislar")[0]
    with pytest.raises(AlertaRechazada, match="solo se deshace lo ejecutado"):
        await motor.deshacer("lab", omitida["id"], "analista@lab.test")
    matar = ejecuciones_de(motor, "lab", recibidas[1]["alerta_id"], "proceso.matar")[0]
    with pytest.raises(AlertaRechazada, match="no tiene accion inversa"):
        await motor.deshacer("lab", matar["id"], "analista@lab.test")
    aislar = ejecuciones_de(motor, "lab", recibidas[1]["alerta_id"], "endpoint.aislar")[0]
    with pytest.raises(AlertaRechazada, match="no encontrada"):
        await motor.deshacer("acme", aislar["id"], "soc-guardia@acme.test")
    with pytest.raises(AlertaRechazada, match="no encontrada"):
        await motor.deshacer("lab", "ej-no-existe", "analista@lab.test")


async def test_deshacer_dos_veces_no_repite_la_accion_inversa(motor):
    ej = await aislamiento(motor)
    await motor.deshacer("lab", ej["id"], "analista@lab.test")
    with pytest.raises(AlertaRechazada):
        await motor.deshacer("lab", ej["id"], "analista@lab.test")
    assert len(ejecuciones_de(motor, "lab", accion="endpoint.liberar")) == 1


# ====================================================================
# Acuses de los agentes
# ====================================================================

async def test_acuses_actualizan_el_estado_de_la_ejecucion(motor):
    recibidas = await pasar_escenario(motor, "ransomware-puesto", hasta=2)
    ejs = {e["accion"]: e for e in ejecuciones_de(motor, "lab", recibidas[1]["alerta_id"])}
    aislar, matar, triage = ejs["endpoint.aislar"], ejs["proceso.matar"], ejs["evidencia.triage_forense"]

    assert motor.acuse("lab", aislar["id"], "ok", {"reglas": 3}) == {"ejecucion": aislar["id"], "estado": "confirmada"}
    confirmada = motor.almacen.ejecucion(aislar["id"])
    assert confirmada["estado"] == "confirmada" and confirmada["confirmada"]
    assert confirmada["resultado"]["confirmacion"] == {"reglas": 3}

    assert motor.acuse("lab", matar["id"], "ERROR", {"motivo": "el PID ya no existe"})["estado"] == "fallida"
    assert motor.almacen.ejecucion(matar["id"])["estado"] == "fallida"

    progreso = motor.acuse("lab", triage["id"], "en_curso", {"fase": "memoria"})
    assert progreso == {"ejecucion": triage["id"], "estado": "simulada", "progreso": "en_curso"}
    assert motor.almacen.ejecucion(triage["id"])["estado"] == "simulada", "el progreso solo se audita"
    assert {"accion.confirmada", "accion.fallida", "accion.progreso"} <= set(eventos(motor, "lab"))

    with pytest.raises(AlertaRechazada):
        motor.acuse("acme", aislar["id"], "ok", {})
    with pytest.raises(AlertaRechazada):
        motor.acuse("lab", "ej-no-existe", "ok", {})


async def test_acuse_con_informe_ftriage_del_equipo_se_incorpora(motor):
    ej = await aislamiento(motor)
    informe = {"host": {"hostname": "CORP-FIN-07"},
               "assessment": {"verdict": "Compromiso", "verdict_key": "alto", "risk_score": 70,
                              "attack_techniques": [{"attack": "T1486"}]}}
    salida = motor.acuse("lab", ej["id"], "ok", {"informe_ftriage": informe})
    assert salida["estado"] == "confirmada"
    assert salida["evidencia"]["incidente"] == ej["incidente_id"]
    assert salida["evidencia"]["tecnicas"] == ["T1486"]


async def test_acuse_con_informe_ftriage_se_asocia_al_incidente_de_la_ejecucion(motor):
    ej = await aislamiento(motor)
    # El resumen que manda el agente cuando no puede subir el informe entero: sin nombre de equipo
    informe = {"assessment": {"verdict": "Compromiso confirmado", "verdict_key": "critico", "risk_score": 88}}
    salida = motor.acuse("lab", ej["id"], "ok", {"informe_ftriage": informe})
    assert salida["evidencia"]["incidente"] == ej["incidente_id"]
    assert any(t["grupo"] == "Evidencia" for t in motor.almacen.tareas(ej["incidente_id"]))


# ====================================================================
# Evidencias de FtriageDFIR y Malpipe, acciones a demanda
# ====================================================================

INFORME_FTRIAGE = {
    "tool": "FtriageDFIR",
    "host": {"hostname": "PC-0042", "os": "Windows 11"},
    "assessment": {"verdict": "Compromiso confirmado", "verdict_key": "critico", "risk_score": 91, "confidence": "alta",
                   "attack_techniques": [{"attack": "T1486"}, {"attack": "T1490"}, {"attack": "T1486"}, {"nombre": "sin id"}]},
    "iocs": [{"type": "ip", "value": "185.220.101.4", "defanged": "185.220.101[.]4"},
             {"type": "ip", "value": "10.0.20.9", "private": True},
             {"type": "domain", "value": "malo.example", "defanged": "malo[.]example"}],
    "findings": [{"level": "crit", "text": "Cifrado masivo en Documents"}, {"level": "info", "text": "Prefetch normal"}],
}


async def test_ftriage_anade_iocs_y_tecnicas_al_incidente_del_equipo(motor):
    inc = await incidente_local(motor, "lab", "PC-0042")
    assert inc["severidad"] < 4
    resumen = motor.ingerir_ftriage("lab", json.loads(json.dumps(INFORME_FTRIAGE)))
    assert resumen == {"equipo": "PC-0042", "veredicto": "Compromiso confirmado", "riesgo": 91, "confianza": "alta",
                       "iocs": 2, "tecnicas": ["T1486", "T1490"], "hallazgos_criticos": ["Cifrado masivo en Documents"],
                       "incidente": inc["id"]}
    [tarea] = [t for t in motor.almacen.tareas(inc["id"]) if t["grupo"] == "Evidencia"]
    assert tarea["titulo"] == "Triage forense de PC-0042: Compromiso confirmado"
    assert "T1486, T1490" in tarea["descripcion"]
    assert "185.220.101[.]4" in tarea["descripcion"] and "malo[.]example" in tarea["descripcion"]
    assert "10.0.20.9" not in tarea["descripcion"], "los IOC privados no se anaden"
    assert motor.almacen.incidente(inc["id"])["severidad"] == 4, "veredicto critico sube la severidad"
    assert "evidencia.ftriage" in eventos(motor, "lab")


async def test_ftriage_por_nombre_de_caso_del_mismo_cliente(motor):
    inc = await incidente_local(motor, "lab", "PC-0042")
    informe = dict(INFORME_FTRIAGE, host={"hostname": "nombre-distinto"}, case={"name": inc["id"]},
                   assessment={"verdict": "Sospechoso", "verdict_key": "medio", "risk_score": 40})
    assert motor.ingerir_ftriage("lab", informe)["incidente"] == inc["id"]
    assert motor.almacen.incidente(inc["id"])["severidad"] == inc["severidad"]


async def test_ftriage_sin_incidente_solo_se_audita(motor):
    resumen = motor.ingerir_ftriage("lab", dict(INFORME_FTRIAGE, host={"hostname": "PC-SIN-INCIDENTE"}))
    assert resumen["incidente"] == ""
    assert "evidencia.ftriage" in eventos(motor, "lab")


async def test_ftriage_no_toca_incidentes_de_otro_cliente(motor):
    ajeno = await incidente_local(motor, "acme", "SRV-ACME-01")
    informe = {"case": {"name": ajeno["id"]}, "host": {"hostname": "PC-0042"},
               "assessment": {"verdict": "inyectado", "verdict_key": "critico", "risk_score": 99}}
    resumen = motor.ingerir_ftriage("lab", informe)
    assert resumen["incidente"] != ajeno["id"]
    assert motor.almacen.incidente(ajeno["id"])["severidad"] == ajeno["severidad"]
    assert [t for t in motor.almacen.tareas(ajeno["id"]) if t["cliente"] == "lab"] == []


INFORME_MALPIPE = {"verdict": "malicioso", "score": 97,
                   "static": {"filename": "upd.exe", "hashes": {"sha256": "ab" * 32},
                              "indicators": {"ips": ["185.220.101.4"], "domains": [], "urls": []}},
                   "dynamic": {"family": "LockBit"}, "attack": [{"id": "T1486"}]}


async def test_malpipe_malicioso_pide_aprobacion_para_bloquear_el_hash(motor):
    inc = await incidente_local(motor, "lab", "PC-0042")
    resumen = motor.ingerir_malpipe("lab", INFORME_MALPIPE, inc["id"])
    assert resumen["veredicto"] == "malicioso" and resumen["familia"] == "LockBit" and resumen["tecnicas"] == ["T1486"]
    [ap] = [a for a in motor.almacen.aprobaciones("lab", "pendiente") if a["paso"]["accion"] == "flota.bloquear_hash"]
    assert ap["incidente_id"] == inc["id"]
    assert ap["paso"]["objetivo"] == {"fichero.sha256": "ab" * 32}
    assert ap["paso"]["modo"] == "aprobacion", "radio organizacion: nunca automatico"
    # Benigno o sin incidente: solo se audita
    motor.ingerir_malpipe("lab", dict(INFORME_MALPIPE, verdict="benigno"), inc["id"])
    motor.ingerir_malpipe("lab", INFORME_MALPIPE, "")
    assert len([a for a in motor.almacen.aprobaciones("lab") if a["paso"]["accion"] == "flota.bloquear_hash"]) == 1
    assert eventos(motor, "lab").count("evidencia.malpipe") == 3


async def test_malpipe_no_referencia_incidentes_de_otro_cliente(motor):
    ajeno = await incidente_local(motor, "acme", "SRV-ACME-01")
    motor.ingerir_malpipe("lab", INFORME_MALPIPE, ajeno["id"])
    assert [a for a in motor.almacen.aprobaciones("lab") if a["incidente_id"] == ajeno["id"]] == []


async def test_accion_a_demanda_se_ejecuta_y_se_audita(motor):
    [ej] = await motor.accion_a_demanda("lab", "endpoint.aislar", {"equipo.nombre": "PC-0042"}, "analista@lab.test",
                                        comentario="orden del jefe de turno")
    assert (ej["estado"], ej["origen"], ej["actor"], ej["conector"]) == ("simulada", "demanda", "analista@lab.test", "wazuh")
    audit = next(f for f in motor.almacen.auditoria("lab") if f["evento"] == "accion.demanda")
    assert audit["detalle"]["objetivo"] == {"equipo.nombre": "PC-0042"}
    assert audit["actor"] == "analista@lab.test"


@pytest.mark.parametrize("cliente, accion, objetivo, mensaje", [
    ("acme", "k8s.escalar_cero", {"k8s.namespace": "prod", "k8s.workload": "deployment/web"}, "prohibe"),
    ("lab", "accion.inventada", {}, "desconocidos"),
    ("no-existe", "endpoint.aislar", {"equipo.nombre": "PC-0042"}, "desconocidos"),
    ("lab", "endpoint.aislar", {}, "faltan campos del objetivo"),
])
async def test_accion_a_demanda_rechazada(motor, cliente, accion, objetivo, mensaje):
    with pytest.raises(AlertaRechazada, match=mensaje):
        await motor.accion_a_demanda(cliente, accion, objetivo, "persona@test")
    assert ejecuciones_de(motor, cliente) == []


async def test_accion_a_demanda_no_escribe_en_incidentes_de_otro_cliente(motor):
    ajeno = await incidente_local(motor, "acme", "SRV-ACME-01")
    try:
        await motor.accion_a_demanda("lab", "caso.tarea_obligacion", {}, "analista@lab.test", incidente_id=ajeno["id"])
    except AlertaRechazada:
        pass                                   # rechazarla tambien es correcto
    assert [t for t in motor.almacen.tareas(ajeno["id"]) if t["cliente"] == "lab"] == []
    assert [e for e in ejecuciones_de(motor, "lab") if e["incidente_id"] == ajeno["id"]] == []


# ====================================================================
# Plazos regulatorios
# ====================================================================

def _fecha(texto: str) -> datetime:
    return nucleo.a_fecha(texto)


async def test_plazos_rgpd_y_nis2_en_el_ransomware_del_laboratorio(motor):
    await pasar_escenario(motor, "ransomware-puesto", hasta=1)
    [inc] = motor.almacen.incidentes("lab")
    assert inc["plazos_regulatorios"] == [], "una alerta suelta de severidad 3 no es un incidente significativo"
    await pasar_escenario(motor, "ransomware-puesto")
    [inc] = motor.almacen.incidentes("lab")
    plazos = inc["plazos_regulatorios"]
    assert sorted({p["marco"] for p in plazos}) == ["NIS2", "RGPD"]
    assert len(plazos) == 4, "RGPD (1 hito) + NIS2 (3 hitos), sin duplicar con la tercera alerta"
    abierto = _fecha(inc["abierto"])
    rgpd = next(p for p in plazos if p["marco"] == "RGPD")
    assert abs((_fecha(rgpd["vence"]) - abierto) - timedelta(hours=72)) < timedelta(seconds=2)
    alerta_temprana = min((p for p in plazos if p["marco"] == "NIS2"), key=lambda p: p["vence"])
    assert abs((_fecha(alerta_temprana["vence"]) - abierto) - timedelta(hours=24)) < timedelta(seconds=2)
    iniciados = [f for f in motor.almacen.auditoria("lab") if f["evento"] == "plazos.iniciados"]
    assert [f["detalle"]["marcos"] for f in iniciados] == [["NIS2", "RGPD"]]


async def test_plazos_dora_nis2_rgpd_en_la_exfiltracion_de_acme(motor):
    await pasar_escenario(motor, "exfiltracion-tras-acceso")
    [inc] = motor.almacen.incidentes("acme")
    assert {p["marco"] for p in inc["plazos_regulatorios"]} == {"DORA", "NIS2", "RGPD"}


async def test_sin_marcos_declarados_no_hay_plazos(motor, carpeta_clientes):
    ruta = carpeta_clientes / "lab.yml"
    datos = leer_perfil(ruta)
    datos["marcos"] = []
    escribir_perfil(ruta, datos)
    motor.clientes.recargar()
    await pasar_escenario(motor, "ransomware-puesto")
    [inc] = motor.almacen.incidentes("lab")
    assert inc["plazos_regulatorios"] == []
    assert "plazos.iniciados" not in eventos(motor, "lab")


# ====================================================================
# Auditoria
# ====================================================================

async def test_auditoria_integra_tras_un_escenario_y_detecta_la_manipulacion(motor):
    await pasar_escenario(motor, "ransomware-puesto")
    v = motor.almacen.verificar_auditoria()
    assert v["integra"] is True and v["registros"] > 10
    esperados = {"incidente.abierto", "alerta.decidida", "aprobacion.pedida", "accion.simulada", "plazos.iniciados",
                 "aviso.enviado"}
    assert esperados <= set(eventos(motor))
    # Alguien borra de la auditoria que el equipo se aislo
    [(n,)] = consulta(motor.config, "SELECT n FROM auditoria WHERE evento='accion.simulada' "
                                    "AND detalle LIKE '%endpoint.aislar%' ORDER BY n LIMIT 1")
    manipular(motor.config, "UPDATE auditoria SET detalle=? WHERE n=?", ('{"accion": "caso.nota"}', n))
    v = motor.almacen.verificar_auditoria()
    assert v["integra"] is False and v["rota_en"] == n
