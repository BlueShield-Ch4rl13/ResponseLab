"""
Pruebas del almacen SQLite: auditoria encadenada, incidentes, ejecuciones,
aprobaciones, cola persistente, EDL y utilidades.

Cada prueba usa una base de datos nueva en tmp_path. La manipulacion de la
auditoria se hace como la haria un atacante: con otra conexion a SQLite,
editando la fila directamente.
"""
from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from responselab.almacen import Almacen, _j, iso, normalizar_momento

AHORA = datetime.now(timezone.utc)
FUTURO = AHORA + timedelta(hours=2)
PASADO = AHORA - timedelta(hours=2)


@pytest.fixture
def almacen(tmp_path):
    a = Almacen(tmp_path / "datos" / "responselab.db")
    try:
        yield a
    finally:
        a.cerrar()


def manipular(almacen: Almacen, sql: str, args=()):
    """Escribe en la base de datos por fuera del almacen, como lo haria un atacante."""
    con = sqlite3.connect(str(almacen.ruta))
    try:
        con.execute(sql, args)
        con.commit()
    finally:
        con.close()


def plan_minimo(familia="endpoint", severidad=2, escalado="L2", plazo_min=30, secuencias=(), titulo="Regla de prueba"):
    return {"severidad": severidad, "titulo": "Titulo de la alerta", "familia": familia, "clase": "auto_analisis",
            "estado": "en_curso", "momento": "2026-10-01T10:00:00Z",
            "regla": {"titulo": titulo, "clave": "dl:regla_prueba", "tecnicas": ["T1059.001"]},
            "escalado": {"a": escalado, "plazo_min": plazo_min},
            "secuencias": [{"id": s, "nombre": s} for s in secuencias]}


def ejecucion(almacen: Almacen, **campos) -> dict:
    base = {"cliente": "lab", "incidente_id": "inc-1", "alerta_id": "al-1", "paso_id": "c1",
            "accion": "endpoint.aislar", "conector": "wazuh", "origen": "automatica", "estado": "simulada",
            "objetivo": {"equipo.nombre": "PC-0042"}, "parametros": {}, "actor": "sistema"}
    base.update(campos)
    return almacen.crear_ejecucion(**base)


# ====================================================================
# Auditoria encadenada
# ====================================================================

def test_auditoria_encadena_cada_registro_con_el_anterior(almacen):
    huellas = [almacen.auditar("lab", "sistema", f"evento.{i}", {"n": i, "texto": "accion sobre PC-0042"})
               for i in range(3)]
    v = almacen.verificar_auditoria()
    assert v == {"integra": True, "registros": 3, "ultima_huella": huellas[-1]}
    filas = list(reversed(almacen.auditoria(limite=10)))
    assert filas[0]["previo"] == "0" * 64
    assert [f["previo"] for f in filas[1:]] == huellas[:-1]
    assert [f["huella"] for f in filas] == huellas


def test_auditoria_vacia_es_integra(almacen):
    assert almacen.verificar_auditoria() == {"integra": True, "registros": 0, "ultima_huella": "0" * 64}


def test_auditoria_detecta_un_detalle_editado(almacen):
    for i in range(4):
        almacen.auditar("lab", "sistema", "accion.simulada", {"n": i})
    manipular(almacen, "UPDATE auditoria SET detalle=? WHERE n=2", ('{"n": 99}',))
    v = almacen.verificar_auditoria()
    assert v["integra"] is False
    assert v["rota_en"] == 2
    assert v["registros"] == 1


@pytest.mark.parametrize("columna, valor", [
    ("actor", "otro-analista"),
    ("evento", "accion.ok"),
    ("cliente", "acme"),
    ("momento", "2020-01-01T00:00:00.000000Z"),
])
def test_auditoria_detecta_cualquier_campo_editado(almacen, columna, valor):
    for i in range(3):
        almacen.auditar("lab", "sistema", "accion.simulada", {"n": i})
    manipular(almacen, f"UPDATE auditoria SET {columna}=? WHERE n=3", (valor,))
    v = almacen.verificar_auditoria()
    assert v["integra"] is False and v["rota_en"] == 3


def test_auditoria_detecta_una_fila_borrada(almacen):
    for i in range(4):
        almacen.auditar("lab", "sistema", "accion.simulada", {"n": i})
    manipular(almacen, "DELETE FROM auditoria WHERE n=2")
    v = almacen.verificar_auditoria()
    assert v["integra"] is False
    assert v["rota_en"] == 3


def test_auditoria_recalcular_la_huella_de_la_fila_no_basta(almacen):
    """Editar una fila y recalcular su huella rompe el enlace con la siguiente."""
    for i in range(3):
        almacen.auditar("lab", "sistema", "accion.simulada", {"n": i})
    fila = sqlite3.connect(str(almacen.ruta)).execute(
        "SELECT momento, cliente, actor, evento, previo FROM auditoria WHERE n=2").fetchone()
    momento, cliente, actor, evento, previo = fila
    detalle = {"n": 1, "falsificado": True}
    cuerpo = _j({"momento": momento, "cliente": cliente, "actor": actor, "evento": evento,
                 "detalle": detalle, "previo": previo})
    huella = hashlib.sha256(cuerpo.encode("utf-8")).hexdigest()
    manipular(almacen, "UPDATE auditoria SET detalle=?, huella=? WHERE n=2", (_j(detalle), huella))
    v = almacen.verificar_auditoria()
    assert v["integra"] is False
    assert v["rota_en"] == 3


def test_auditoria_por_cliente_mas_reciente_primero(almacen):
    almacen.auditar("lab", "sistema", "uno", {"a": 1})
    almacen.auditar("acme", "sistema", "otro", {"a": 2})
    almacen.auditar("lab", "analista@lab.test", "dos", {"a": 3})
    filas = almacen.auditoria("lab")
    assert [f["evento"] for f in filas] == ["dos", "uno"]
    assert filas[0]["detalle"] == {"a": 3}
    assert all(f["cliente"] == "lab" for f in filas)


# ====================================================================
# Alertas e incidentes
# ====================================================================

def test_guardar_alerta_y_leer_recientes(almacen):
    alerta = {"cliente": "lab", "id": "al-1", "siem": "wazuh", "equipo": {"nombre": "PC-0042"},
              "usuario": {"nombre": "jgarcia"}, "observables": [{"tipo": "ip", "valor": "8.8.8.8"}],
              "bruto": {"enorme": "x" * 1000}}
    almacen.guardar_alerta(alerta, plan_minimo(), "inc-1", [{"valor": "8.8.8.8"}])
    assert almacen.existe_alerta("lab", "al-1")
    assert not almacen.existe_alerta("acme", "al-1")
    recientes = almacen.recientes("lab", datetime(2026, 9, 30, tzinfo=timezone.utc))
    assert recientes[0]["observables"] == ["8.8.8.8"]
    assert recientes[0]["cti"] == ["8.8.8.8"]
    assert recientes[0]["tecnicas"] == ["T1059.001"]
    guardada = sqlite3.connect(str(almacen.ruta)).execute("SELECT alerta FROM alertas WHERE id='al-1'").fetchone()[0]
    assert "enorme" not in guardada, "el bruto no se guarda dos veces"


def test_incidente_abierto_decodifica_los_campos_json(almacen):
    inc = almacen.crear_incidente("lab", "equipo", "PC-0042", plan_minimo(secuencias=["ransomware"]))
    almacen.modificar_incidente(inc["id"], plazos_regulatorios=[{"marco": "RGPD", "vence": "2026-10-04T10:00:00Z"}])
    abierto = almacen.incidente_abierto("lab", "equipo", "pc-0042", PASADO)
    assert abierto["id"] == inc["id"]
    assert abierto["familias"] == ["endpoint"]
    assert abierto["secuencias"] == ["ransomware"]
    assert abierto["plazos_regulatorios"] == [{"marco": "RGPD", "vence": "2026-10-04T10:00:00Z"}]


def test_incidente_abierto_ignora_cerrados_otros_clientes_y_fuera_de_ventana(almacen):
    inc = almacen.crear_incidente("lab", "equipo", "PC-0042", plan_minimo())
    assert almacen.incidente_abierto("acme", "equipo", "PC-0042", PASADO) is None
    assert almacen.incidente_abierto("lab", "usuario", "PC-0042", PASADO) is None
    assert almacen.incidente_abierto("lab", "equipo", "PC-0042", FUTURO) is None
    almacen.modificar_incidente(inc["id"], estado="asumido")
    assert almacen.incidente_abierto("lab", "equipo", "PC-0042", PASADO)["id"] == inc["id"]
    almacen.modificar_incidente(inc["id"], estado="cerrado")
    assert almacen.incidente_abierto("lab", "equipo", "PC-0042", PASADO) is None


def test_actualizar_incidente_acumula_sin_rebajar(almacen):
    inc = almacen.crear_incidente("lab", "equipo", "PC-0042", plan_minimo(severidad=2, escalado="L2", plazo_min=60))
    plazo_inicial = inc["plazo"]
    act = almacen.actualizar_incidente(inc["id"], plan_minimo(familia="credenciales", severidad=4, escalado="L3",
                                                              plazo_min=10, secuencias=["robo"]))
    assert act["n_alertas"] == 2
    assert act["severidad"] == 4
    assert act["familias"] == ["credenciales", "endpoint"]
    assert act["escalado_a"] == "L3"
    assert act["secuencias"] == ["robo"]
    assert act["plazo"] < plazo_inicial, "el plazo mas corto manda mientras nadie lo asume"
    otra = almacen.actualizar_incidente(inc["id"], plan_minimo(severidad=1, escalado="L1", plazo_min=600))
    assert otra["n_alertas"] == 3
    assert otra["severidad"] == 4 and otra["escalado_a"] == "L3"
    assert otra["plazo"] == act["plazo"]


def test_actualizar_incidente_inexistente_devuelve_none(almacen):
    assert almacen.actualizar_incidente("inc-no-existe", plan_minimo()) is None


def test_incidentes_vencidos_solo_abiertos_y_sin_aviso(almacen):
    vencido = almacen.crear_incidente("lab", "equipo", "PC-1", plan_minimo())
    asumido = almacen.crear_incidente("lab", "equipo", "PC-2", plan_minimo())
    avisado = almacen.crear_incidente("lab", "equipo", "PC-3", plan_minimo())
    almacen.crear_incidente("lab", "equipo", "PC-4", plan_minimo())
    for inc in (vencido, asumido, avisado):
        almacen.modificar_incidente(inc["id"], plazo=iso(PASADO))
    almacen.modificar_incidente(asumido["id"], estado="asumido")
    almacen.modificar_incidente(avisado["id"], vencimiento_avisado=1)
    assert [i["id"] for i in almacen.incidentes_vencidos()] == [vencido["id"]]


# ====================================================================
# Ejecuciones
# ====================================================================

def test_ejecucion_decodifica_json_y_se_confirma(almacen):
    ej = ejecucion(almacen, estado="en_curso")
    assert ej["objetivo"] == {"equipo.nombre": "PC-0042"}
    assert ej["peticiones"] == []
    almacen.terminar_ejecucion(ej["id"], "ok", {"detalle": "orden entregada"}, [{"metodo": "PUT"}], {"agente": "007"})
    ej = almacen.ejecucion(ej["id"])
    assert ej["estado"] == "ok" and ej["terminada"]
    assert ej["datos_deshacer"] == {"agente": "007"}
    assert ej["peticiones"] == [{"metodo": "PUT"}]
    confirmada = almacen.confirmar_ejecucion(ej["id"], "confirmada", {"script": "aislar"})
    assert confirmada["estado"] == "confirmada" and confirmada["confirmada"]
    assert confirmada["resultado"] == {"detalle": "orden entregada", "confirmacion": {"script": "aislar"}}
    assert almacen.confirmar_ejecucion("ej-no-existe", "confirmada", {}) is None


def test_accion_vigente_hasta_que_se_deshace_con_exito(almacen):
    ej = ejecucion(almacen)
    objetivo = {"equipo.nombre": "PC-0042"}
    assert almacen.accion_vigente("lab", "inc-1", "endpoint.aislar", objetivo)["id"] == ej["id"]
    # Un deshacer que fallo no levanta la contencion
    ejecucion(almacen, accion="endpoint.liberar", origen="deshacer", deshace=ej["id"], estado="error")
    assert almacen.accion_vigente("lab", "inc-1", "endpoint.aislar", objetivo)["id"] == ej["id"]
    ejecucion(almacen, accion="endpoint.liberar", origen="deshacer", deshace=ej["id"], estado="simulada")
    assert almacen.accion_vigente("lab", "inc-1", "endpoint.aislar", objetivo) is None


@pytest.mark.parametrize("cambio", [
    {"cliente": "acme"},
    {"incidente_id": "inc-2"},
    {"accion": "endpoint.liberar"},
    {"objetivo": {"equipo.nombre": "PC-0099"}},
])
def test_accion_vigente_distingue_cliente_incidente_accion_y_objetivo(almacen, cambio):
    ejecucion(almacen)
    consulta = {"cliente": "lab", "incidente_id": "inc-1", "accion": "endpoint.aislar",
                "objetivo": {"equipo.nombre": "PC-0042"}}
    consulta.update(cambio)
    assert almacen.accion_vigente(**consulta) is None


@pytest.mark.parametrize("estado, vigente", [
    ("ok", True), ("simulada", True), ("en_curso", True), ("confirmada", True),
    ("omitida", False), ("error", False), ("fallida", False),
])
def test_accion_vigente_segun_estado(almacen, estado, vigente):
    ejecucion(almacen, estado=estado)
    encontrada = almacen.accion_vigente("lab", "inc-1", "endpoint.aislar", {"equipo.nombre": "PC-0042"})
    assert (encontrada is not None) is vigente


def test_accion_vigente_sin_incidente_nunca_bloquea(almacen):
    ejecucion(almacen, incidente_id="")
    assert almacen.accion_vigente("lab", "", "endpoint.aislar", {"equipo.nombre": "PC-0042"}) is None


def test_ejecucion_previa_ignora_errores_y_deshaceres(almacen):
    assert almacen.ejecucion_previa("lab", "al-1", "c1") is None
    ejecucion(almacen, estado="error")
    assert almacen.ejecucion_previa("lab", "al-1", "c1") is None
    ejecucion(almacen, estado="simulada", deshace="ej-anterior")
    assert almacen.ejecucion_previa("lab", "al-1", "c1") is None
    ej = ejecucion(almacen, estado="omitida")
    assert almacen.ejecucion_previa("lab", "al-1", "c1")["id"] == ej["id"]
    assert almacen.ejecucion_previa("acme", "al-1", "c1") is None


# ====================================================================
# Aprobaciones
# ====================================================================

def test_aprobacion_se_decide_una_sola_vez(almacen):
    ap = almacen.crear_aprobacion("lab", "inc-1", "al-1", {"accion": "endpoint.aislar"}, "motivo", FUTURO)
    assert ap["estado"] == "pendiente" and ap["paso"] == {"accion": "endpoint.aislar"} and ap["ejecuciones"] == []
    assert almacen.decidir_aprobacion(ap["id"], "aprobada", "ana@lab.test", "adelante") is True
    assert almacen.decidir_aprobacion(ap["id"], "rechazada", "otro@lab.test", "no") is False
    final = almacen.aprobacion(ap["id"])
    assert final["estado"] == "aprobada" and final["decidida_por"] == "ana@lab.test"
    almacen.anotar_ejecuciones_aprobacion(ap["id"], ["ej-1"], "ejecutada")
    assert almacen.aprobacion(ap["id"])["ejecuciones"] == ["ej-1"]


def test_caducar_aprobaciones_solo_las_pendientes_vencidas(almacen):
    vencida = almacen.crear_aprobacion("lab", "inc-1", "al-1", {"accion": "a"}, "m", PASADO)
    vigente = almacen.crear_aprobacion("lab", "inc-1", "al-2", {"accion": "b"}, "m", FUTURO)
    decidida = almacen.crear_aprobacion("lab", "inc-1", "al-3", {"accion": "c"}, "m", PASADO)
    almacen.decidir_aprobacion(decidida["id"], "rechazada", "ana@lab.test", "")
    caducadas = almacen.caducar_aprobaciones()
    assert [c["id"] for c in caducadas] == [vencida["id"]]
    assert almacen.aprobacion(vencida["id"])["estado"] == "caducada"
    assert almacen.aprobacion(vigente["id"])["estado"] == "pendiente"
    assert almacen.aprobacion(decidida["id"])["estado"] == "rechazada"
    assert almacen.caducar_aprobaciones() == []
    assert almacen.decidir_aprobacion(vencida["id"], "aprobada", "ana@lab.test", "") is False


def test_aprobaciones_filtra_por_cliente_y_estado(almacen):
    almacen.crear_aprobacion("lab", "inc-1", "al-1", {"accion": "a"}, "m", FUTURO)
    ap = almacen.crear_aprobacion("acme", "inc-2", "al-2", {"accion": "b"}, "m", FUTURO)
    almacen.decidir_aprobacion(ap["id"], "rechazada", "x", "")
    assert [a["cliente"] for a in almacen.aprobaciones("lab")] == ["lab"]
    assert almacen.aprobaciones("acme", "pendiente") == []
    assert [a["id"] for a in almacen.aprobaciones("acme", "rechazada")] == [ap["id"]]


# ====================================================================
# Cola persistente
# ====================================================================

def test_cola_toma_en_orden_y_termina(almacen):
    n1 = almacen.encolar("alerta", {"alerta": {"id": "a1"}})
    n2 = almacen.encolar("alerta", {"alerta": {"id": "a2"}})
    assert almacen.pendientes() == 2
    t = almacen.tomar_trabajo()
    assert t["n"] == n1 and t["carga"] == {"alerta": {"id": "a1"}}
    assert almacen.pendientes() == 2, "en_curso sigue contando como pendiente"
    almacen.terminar_trabajo(n1)
    t2 = almacen.tomar_trabajo()
    assert t2["n"] == n2
    almacen.terminar_trabajo(n2, "ValueError: roto")
    assert almacen.pendientes() == 0
    assert almacen.tomar_trabajo() is None
    estados = dict(sqlite3.connect(str(almacen.ruta)).execute("SELECT n, estado FROM trabajos").fetchall())
    assert estados == {n1: "hecho", n2: "error"}


def test_reencolar_huerfanos_respeta_los_intentos(almacen):
    n = almacen.encolar("alerta", {"alerta": {"id": "a1"}})
    almacen.tomar_trabajo()                       # intento 1, el proceso "se cae"
    assert almacen.reencolar_huerfanos() == 1
    assert almacen.tomar_trabajo()["n"] == n      # intento 2
    assert almacen.reencolar_huerfanos() == 1
    assert almacen.tomar_trabajo()["n"] == n      # intento 3
    intentos = sqlite3.connect(str(almacen.ruta)).execute("SELECT intentos FROM trabajos WHERE n=?", (n,)).fetchone()[0]
    assert intentos == 3
    # Tres intentos interrumpidos: no vuelve a la cola (una alerta venenosa no tumba el motor en bucle)
    assert almacen.reencolar_huerfanos() == 0
    assert almacen.tomar_trabajo() is None


# ====================================================================
# EDL
# ====================================================================

def test_edl_minusculas_caducidad_y_purga(almacen):
    almacen.edl_anadir("lab", "dominio", "Malo.EXAMPLE", "motivo", FUTURO, "ej-1")
    almacen.edl_anadir("lab", "ip", "8.8.8.8", "motivo", FUTURO, "ej-2")
    almacen.edl_anadir("lab", "ip", "9.9.9.9", "caducada", PASADO, "ej-3")
    almacen.edl_anadir("acme", "ip", "1.1.1.1", "otro cliente", FUTURO, "ej-4")
    assert almacen.edl("lab", "dominio") == ["malo.example"]
    assert almacen.edl("lab", "ip") == ["8.8.8.8"]
    assert almacen.edl("acme", "ip") == ["1.1.1.1"]
    assert almacen.edl_purgar() == 1
    assert almacen.edl_quitar("lab", "dominio", "MALO.example") is True
    assert almacen.edl_quitar("lab", "dominio", "malo.example") is False
    assert almacen.edl("lab", "dominio") == []


def test_edl_reanadir_renueva_la_caducidad(almacen):
    almacen.edl_anadir("lab", "ip", "8.8.8.8", "primero", PASADO, "ej-1")
    assert almacen.edl("lab", "ip") == []
    almacen.edl_anadir("lab", "ip", "8.8.8.8", "segundo", FUTURO, "ej-2")
    assert almacen.edl("lab", "ip") == ["8.8.8.8"]


# ====================================================================
# Utilidades
# ====================================================================

def test_visto_registra_la_primera_vez_sin_distinguir_mayusculas(almacen):
    assert almacen.visto("lab", "proceso.sha256", "ABC") is False
    assert almacen.visto("lab", "proceso.sha256", "abc") is True
    assert almacen.visto("acme", "proceso.sha256", "abc") is False
    assert almacen.visto("lab", "proceso.sha256", "") is False


def test_tareas_por_incidente_en_orden(almacen):
    t1 = almacen.crear_tarea("lab", "inc-1", "Evidencia", "Primera", "d")
    almacen.crear_tarea("lab", "inc-2", "Evidencia", "De otro incidente", "d")
    t3 = almacen.crear_tarea("lab", "inc-1", "Contencion", "Segunda", "d", "2026-10-02T00:00:00Z")
    assert [t["id"] for t in almacen.tareas("inc-1")] == [t1["id"], t3["id"]]
    assert almacen.tareas("inc-1")[1]["plazo"] == "2026-10-02T00:00:00Z"


def test_kv_y_marcas(almacen):
    assert almacen.kv("no-existe", {"defecto": 1}) == {"defecto": 1}
    almacen.kv_poner("estado", {"version": "abc"})
    assert almacen.kv("estado") == {"version": "abc"}
    almacen.marcar("lab", "PC-0042", "telemetria_no_fiable", "sensor parado")
    assert [m["marca"] for m in almacen.marcas("lab", "pc-0042")] == ["telemetria_no_fiable"]
    almacen.desmarcar("lab", "PC-0042", "telemetria_no_fiable")
    assert almacen.marcas("lab", "PC-0042") == []


def test_cti_historial_conserva_la_primera_vez(almacen):
    almacen.cti_registrar([("Malo.Example", "dominio")])
    primera = almacen.cti_historial(["malo.example"])[0]
    almacen.cti_registrar([("malo.example", "dominio")])
    segunda = almacen.cti_historial(["MALO.EXAMPLE"])[0]
    assert segunda["primera_vez"] == primera["primera_vez"]
    assert segunda["ultima_vez"] >= primera["ultima_vez"]
    assert almacen.cti_historial([]) == []


def test_contar_resume_el_estado(almacen):
    almacen.encolar("alerta", {})
    almacen.crear_incidente("lab", "equipo", "PC-1", plan_minimo())
    almacen.crear_aprobacion("lab", "inc-1", "al-1", {"accion": "a"}, "m", FUTURO)
    ejecucion(almacen, estado="simulada")
    ejecucion(almacen, estado="omitida")
    c = almacen.contar()
    assert c["trabajos_pendientes"] == 1
    assert c["incidentes_abiertos"] == 1
    assert c["aprobaciones_pendientes"] == 1
    assert c["ejecuciones_por_estado"] == {"simulada": 1, "omitida": 1}


@pytest.mark.parametrize("valor", [
    "2026-10-01T10:00:00Z", "2026-10-01T12:00:00+02:00", "2026-10-01 10:00:00", 1790848800, "1790848800000",
])
def test_normalizar_momento_mismo_formato(valor):
    assert normalizar_momento(valor) == "2026-10-01T10:00:00.000000Z"


def test_normalizar_momento_invalido_usa_la_hora_actual():
    texto = normalizar_momento("esto no es una fecha")
    momento = datetime.strptime(texto, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    assert abs((momento - datetime.now(timezone.utc)).total_seconds()) < 60
