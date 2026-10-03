"""
Escenarios de ataque (escenarios/*.yml) y el simulador que los comprueba
(responselab/simulador.py).

Cada escenario se ejecuta contra un motor real en simulacion, con la base de
datos en tmp_path; ademas se prueban por separado las piezas del simulador:
cada clave de expectativa de comprobar_alerta, momento_inicial y preparar.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest
import yaml

from responselab import nucleo, simulador

ESCENARIOS = sorted(p for p in simulador.ESCENARIOS.glob("*.yml") if not p.name.startswith("_"))
CLAVES_ESPERADO = {"familia", "clase", "estado", "regla_conocida", "severidad_minima", "severidad_maxima", "triaje",
                   "cierre_propuesto", "escalado", "secuencias", "sin_secuencias", "modos", "sin_contencion_automatica",
                   "nunca_automatica", "ejecuciones", "conectores", "sin_ejecucion", "aprobaciones", "avisar_ademas",
                   "notificar"}
CLAVES_FINAL = {"incidentes", "aprobaciones_pendientes", "plazos", "ejecuciones_ok", "auditoria_integra"}
CLAVES_ESCENARIO = {"id", "nombre", "cliente", "mitre", "inicio", "cti", "kev", "alertas", "final"}
CLAVES_ALERTA = {"minuto", "siem", "descripcion", "carga", "esperado"}


# === Los escenarios, de extremo a extremo ====================================

def test_hay_escenarios_y_se_cargan_todos():
    assert len(ESCENARIOS) >= 10
    cargados = simulador.cargar()
    assert sorted(e["_fichero"] for e in cargados) == [p.name for p in ESCENARIOS]
    assert len({e["id"] for e in cargados}) == len(cargados), "ids de escenario repetidos"


@pytest.mark.parametrize("fichero", ESCENARIOS, ids=[p.stem for p in ESCENARIOS])
def test_escenario_bien_formado(fichero, raiz):
    """Una clave mal escrita en 'esperado' no se comprueba nunca: el escenario pasaria sin probar nada."""
    esc = yaml.safe_load(fichero.read_text(encoding="utf-8"))
    assert set(esc) <= CLAVES_ESCENARIO, set(esc) - CLAVES_ESCENARIO
    assert esc.get("id", fichero.stem) == fichero.stem
    assert (raiz / "clientes" / f"{esc.get('cliente', 'lab')}.yml").is_file()
    assert esc["alertas"], "un escenario sin alertas no comprueba nada"
    for a in esc["alertas"]:
        assert set(a) <= CLAVES_ALERTA, set(a) - CLAVES_ALERTA
        assert a["siem"] in nucleo.NORMALIZADORES
        assert isinstance(a["carga"], dict) and a["carga"]
        assert set(a.get("esperado") or {}) <= CLAVES_ESPERADO, set(a.get("esperado") or {}) - CLAVES_ESPERADO
    assert set(esc.get("final") or {}) <= CLAVES_FINAL, set(esc.get("final") or {}) - CLAVES_FINAL
    minutos = [a.get("minuto", 0) for a in esc["alertas"]]
    assert minutos == sorted(minutos), "las alertas van en orden de llegada"


@pytest.mark.parametrize("fichero", ESCENARIOS, ids=[p.stem for p in ESCENARIOS])
async def test_escenario(fichero, tmp_path):
    [esc] = simulador.cargar(nombres=[fichero.stem])
    r = await simulador.ejecutar_escenario(esc, carpeta_datos=tmp_path / "datos")
    assert r["fallos"] == [], "\n".join(r["fallos"])
    assert r["ok"] is True
    assert r["comprobaciones"] > len(esc["alertas"])
    assert len(r["alertas"]) == len(esc["alertas"])
    for a in r["alertas"]:
        assert a["familia"], f"la alerta {a['n']} no llego a decidirse"


# === comprobar_alerta, clave a clave =========================================

PLAN = {
    "familia": "endpoint", "clase": "auto_contener", "estado": "en_curso", "severidad": 3,
    "regla": {"conocida": True, "via": "id de regla de Wazuh"},
    "triaje": [{"pregunta": "El escaner esta autorizado por el cliente?", "resultado": "si"},
               {"pregunta": "Hay mas equipos afectados?", "resultado": "pendiente"}],
    "cierres_propuestos": [{"condicion": "Es un escaner de vulnerabilidades conocido y en su ventana", "motivo": "x"}],
    "escalado": {"a": "guardia", "avisar_ademas": ["dpd"]},
    "secuencias": [{"id": "ransomware", "nombre": "Ransomware"}],
    "acciones": [
        {"id": "c1", "accion": "endpoint.aislar", "origen": "Aislar el equipo", "modo": "automatica"},
        {"id": "c2", "accion": "fichero.cuarentena", "origen": "Cuarentena", "modo": "aprobacion"},
        {"id": "c3", "accion": "fichero.cuarentena", "origen": "Cuarentena del padre", "modo": "manual"},
        {"id": "c4", "accion": "", "origen": "Avisar al usuario", "modo": "manual"},
        {"id": "e1", "accion": "evidencia.triage_forense", "origen": "Triage", "modo": "automatica", "es_evidencia": True},
        {"id": "e2", "accion": "caso.anotar", "origen": "Anotar", "modo": "automatica", "registro": True},
    ],
    "notificar": True,
}
EJECUCIONES = [{"accion": "endpoint.aislar", "conector": "wazuh", "estado": "simulada"},
               {"accion": "evidencia.triage_forense", "conector": "wazuh", "estado": "omitida"},
               {"accion": "red.bloquear", "conector": "opnsense", "estado": "ok"}]
APROBACIONES = [{"paso": {"accion": "fichero.cuarentena"}}]

CASOS = [
    # clave, valor que se cumple, valor que no
    ("familia", "endpoint", "red"),
    ("clase", "auto_contener", "auto_analisis"),
    ("estado", "en_curso", "cerrada_auto"),
    ("regla_conocida", True, False),
    ("severidad_minima", 3, 4),
    ("severidad_maxima", 3, 2),
    ("triaje", {"escaner esta AUTORIZADO": "si"}, {"escaner esta autorizado": "no"}),
    ("triaje", {"mas equipos": "pendiente"}, {"pregunta que no existe": "si"}),
    ("cierre_propuesto", ["escaner de vulnerabilidades"], ["cuenta de servicio"]),
    ("escalado", "guardia", "L3"),
    ("secuencias", ["ransomware"], ["intrusion_ssh"]),
    ("modos", {"endpoint.aislar": "automatica"}, {"endpoint.aislar": "aprobacion"}),
    ("modos", {"fichero.cuarentena": "manual"}, {"proceso.matar": "automatica"}),
    ("nunca_automatica", ["fichero.cuarentena", "flota.bloquear_hash"], ["endpoint.aislar"]),
    ("ejecuciones", {"endpoint.aislar": "simulada"}, {"endpoint.aislar": "ok"}),
    ("conectores", {"endpoint.aislar": "wazuh"}, {"endpoint.aislar": "crowdstrike"}),
    ("sin_ejecucion", ["proceso.matar"], ["red.bloquear"]),
    ("aprobaciones", ["fichero.cuarentena"], ["endpoint.aislar"]),
    ("avisar_ademas", ["dpd"], ["juridico"]),
    ("notificar", True, False),
]


@pytest.mark.parametrize("clave,bien,mal", CASOS, ids=[f"{c[0]}-{i}" for i, c in enumerate(CASOS)])
def test_comprobar_alerta_por_clave(clave, bien, mal):
    r = simulador.comprobar_alerta({clave: bien}, PLAN, EJECUCIONES, APROBACIONES)
    assert r and all(ok for ok, _ in r), r
    r = simulador.comprobar_alerta({clave: mal}, PLAN, EJECUCIONES, APROBACIONES)
    assert r and not all(ok for ok, _ in r), r
    assert all(isinstance(texto, str) and texto for _, texto in r)


def test_comprobar_alerta_sin_secuencias():
    sin = dict(PLAN, secuencias=[])
    assert simulador.comprobar_alerta({"sin_secuencias": True}, sin, [], []) == [(True, "sin secuencias (hay [])")]
    [(ok, _)] = simulador.comprobar_alerta({"sin_secuencias": True}, PLAN, [], [])
    assert ok is False


def test_comprobar_alerta_sin_contencion_automatica():
    """Las acciones de registro y de evidencia automaticas no cuentan como contencion."""
    [(ok, texto)] = simulador.comprobar_alerta({"sin_contencion_automatica": True}, PLAN, [], [])
    assert ok is False and "endpoint.aislar" in texto
    solo_registro = dict(PLAN, acciones=[a for a in PLAN["acciones"] if a["accion"] != "endpoint.aislar"])
    [(ok, _)] = simulador.comprobar_alerta({"sin_contencion_automatica": True}, solo_registro, [], [])
    assert ok is True


def test_comprobar_alerta_sin_expectativas_no_comprueba_nada():
    assert simulador.comprobar_alerta({}, PLAN, EJECUCIONES, APROBACIONES) == []


def test_comprobar_alerta_varias_claves_a_la_vez():
    esperado = {"familia": "endpoint", "clase": "auto_contener", "escalado": "guardia", "notificar": True,
                "modos": {"endpoint.aislar": "automatica", "fichero.cuarentena": "aprobacion"}}
    r = simulador.comprobar_alerta(esperado, PLAN, EJECUCIONES, APROBACIONES)
    assert len(r) == 6 and all(ok for ok, _ in r)


def test_sin_ejecucion_cuenta_las_ejecuciones_simuladas():
    r = simulador.comprobar_alerta({"sin_ejecucion": ["endpoint.aislar"]}, PLAN, EJECUCIONES, APROBACIONES)
    assert r == [(False, r[0][1])], r


async def test_escenario_con_sin_ejecucion_falla_si_la_accion_se_ejecuta(tmp_path):
    [esc] = simulador.cargar(nombres=["ransomware-puesto"])
    # En la segunda alerta el motor aisla el equipo (ejecuciones: {endpoint.aislar: simulada}):
    # exigir ademas que NO se ejecute tiene que poner el escenario en rojo.
    esc["alertas"][1]["esperado"]["sin_ejecucion"] = ["endpoint.aislar"]
    r = await simulador.ejecutar_escenario(esc, carpeta_datos=tmp_path / "datos")
    assert r["ok"] is False
    assert any("endpoint.aislar no se ejecuta" in f for f in r["fallos"])


# === momento_inicial y preparar ==============================================

UTC = timezone.utc


@pytest.mark.parametrize("inicio", [
    "2026-10-01T20:30:00Z",
    "2026-10-01T22:30:00+02:00",
    "2026-10-01T20:30:00",
    datetime(2026, 10, 1, 20, 30, tzinfo=UTC),
    datetime(2026, 10, 1, 20, 30),
])
def test_momento_inicial_con_inicio(inicio):
    m = simulador.momento_inicial({"inicio": inicio, "alertas": [{"minuto": 0}, {"minuto": 30}]})
    assert m.tzinfo is not None
    assert m == datetime(2026, 10, 1, 20, 30, tzinfo=UTC)


def test_momento_inicial_con_inicio_leido_de_yaml():
    esc = yaml.safe_load("inicio: 2026-10-01T20:30:00Z\nalertas: [{minuto: 0}]\n")
    assert simulador.momento_inicial(esc) == datetime(2026, 10, 1, 20, 30, tzinfo=UTC)


def test_momento_inicial_sin_inicio():
    """Sin inicio: ahora menos lo que dura el escenario y un minuto; la ultima alerta acaba de pasar."""
    antes = datetime.now(UTC)
    m = simulador.momento_inicial({"alertas": [{"minuto": 0}, {"minuto": 4}, {"minuto": 6}]})
    despues = datetime.now(UTC)
    assert antes - timedelta(minutes=7) <= m <= despues - timedelta(minutes=7)
    m = simulador.momento_inicial({"alertas": [{"siem": "wazuh"}]})
    assert datetime.now(UTC) - timedelta(minutes=1, seconds=5) <= m <= datetime.now(UTC) - timedelta(minutes=1)


def test_inicio_de_un_escenario_real():
    [esc] = simulador.cargar(nombres=["escaner-autorizado"])
    assert simulador.momento_inicial(esc) == datetime(2026, 10, 1, 20, 30, tzinfo=UTC)


MOMENTO = datetime(2026, 10, 1, 10, 0, 0, 123456, tzinfo=UTC)
ISO = "2026-10-01T10:00:00.123456Z"


@pytest.mark.parametrize("siem,carga,comprobar", [
    ("wazuh", {"rule": {"id": "1"}}, lambda c: (c["id"], c["timestamp"]) == ("x-1", ISO)),
    ("splunk", {"search_name": "s"}, lambda c: c["sid"] == "x-1" and c["result"]["_time"] == ISO),
    ("splunk", {"search_name": "s", "result": {"host": "h"}}, lambda c: c["result"] == {"host": "h", "_time": ISO}),
    ("sentinel", {"object": {"properties": {"title": "t"}}},
     lambda c: c["object"]["name"] == "x-1" and c["object"]["properties"]["firstActivityTimeUtc"] == ISO
     and c["object"]["properties"]["createdTimeUtc"] == ISO and c["object"]["properties"]["title"] == "t"),
    ("elastic", {"alerts": [{"a": 1}, {"a": 2}]},
     lambda c: [(x["_id"], x["@timestamp"]) for x in c["alerts"]] == [("x-1-0", ISO), ("x-1-1", ISO)]),
    ("elastic", {"rule": {"name": "r"}}, lambda c: (c["_id"], c["@timestamp"]) == ("x-1", ISO)),
    ("generico", {"titulo": "t"}, lambda c: (c["id"], c["momento"]) == ("x-1", ISO)),
])
def test_preparar_pone_id_y_hora_en_el_campo_de_cada_siem(siem, carga, comprobar):
    original = copy.deepcopy(carga)
    c = simulador.preparar(siem, carga, MOMENTO, "x-1")
    assert comprobar(c), c
    assert carga == original, "preparar no debe modificar el escenario"


def test_las_alertas_preparadas_se_normalizan_con_su_id_y_su_hora():
    for fichero in ESCENARIOS:
        [esc] = simulador.cargar(nombres=[fichero.stem])
        for n, a in enumerate(esc["alertas"], 1):
            c = simulador.preparar(a["siem"], a["carga"], MOMENTO, f"{esc['id']}-{n}")
            alerta = nucleo.normalizar(a["siem"], c, esc.get("cliente", "lab"))
            assert alerta["id"].startswith(f"{esc['id']}-{n}"), (fichero.name, n, alerta["id"])
            assert nucleo.a_fecha(alerta["momento"]) == MOMENTO, (fichero.name, n, alerta["momento"])
