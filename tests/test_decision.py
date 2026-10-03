"""
Decision: clase por nivel, regla desconocida, invariantes, politicas del
cliente, modo de cada accion y catalogos maliciosos o mal configurados.

Toda alerta lleva su hora: ninguna prueba depende del reloj.
"""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from responselab import nucleo, simulador, validacion

RAIZ = Path(__file__).resolve().parent.parent
LSASS = "dl:soc_edr_001_volcado_lsass"
SHA256 = "ab" * 32
SHA1 = "cd" * 20

# Proceso fuera de las rutas del sistema, identificado sin ambiguedad y con
# hashes: todas las acciones de la familia endpoint tienen objetivo.
EVENTO_COMPLETO = {
    "image": "C:\\Users\\Public\\dump.exe",
    "commandLine": "dump.exe -p 712 C:\\Users\\Public\\l.dmp",
    "processId": "3300",
    "processGuid": "{3f1c0a2b-1111-2222-3333-444455556666}",
    "utcTime": "2026-10-01 09:59:58.000",
    "hashes": f"SHA256={SHA256},SHA1={SHA1}",
    "user": "LAB\\jgarcia",
}

# El cliente que usa validacion.validar: lo permite todo. Lo que siga sin ser
# automatico con el, lo impide el propio nucleo.
PERMISIVO = {
    "id": "permisivo",
    "politica": {"contencion_automatica": True, "excepcion_sin_datos": "ignorar", "escalado_por_correlacion": True},
    "inventario": {"completo": True, "activos": []},
    "listas": {"aplicaciones_negocio": []},
}
MODOS = ("automatica", "aprobacion", "manual", "no_aplicable", "prohibida")


def escenario(nombre: str) -> dict:
    return yaml.safe_load((RAIZ / "escenarios" / f"{nombre}.yml").read_text(encoding="utf-8"))


def alerta_de_escenario(nombre: str, n: int, momento: str = "2026-10-01T10:00:00Z", cliente: str = "lab") -> dict:
    """Alerta n (desde 1) de un escenario con hora e id puestos como hace el simulador."""
    a = escenario(nombre)["alertas"][n - 1]
    carga = simulador.preparar(a["siem"], a["carga"], nucleo.a_fecha(momento), f"{nombre}-{n}")
    return nucleo.normalizar(a["siem"], carga, cliente)


@pytest.fixture
def alerta(nueva_alerta_wazuh):
    """Alerta de Wazuh normalizada. Lo que no se diga sale de EVENTO_COMPLETO; None lo quita."""
    def construir(regla="101206", equipo="PC-0042", cliente="lab", **eventdata):
        ev = {k: v for k, v in dict(EVENTO_COMPLETO, **eventdata).items() if v is not None}
        return nucleo.normalizar("wazuh", nueva_alerta_wazuh(regla, equipo=equipo, **ev), cliente)
    return construir


def alerta_de_regla(regla: dict, equipo: str = "PC-0042") -> dict:
    """Alerta que el catalogo resuelve a esa regla, en el formato del SIEM que la emite."""
    if regla.get("wazuh_ids"):
        c = {"id": "t-" + regla["clave"], "timestamp": "2026-10-01T10:00:00Z",
             "rule": {"id": regla["wazuh_ids"][0], "level": 10, "description": regla["titulo"]},
             "agent": {"id": "042", "name": equipo, "ip": "10.0.20.42"}}
        return nucleo.normalizar("wazuh", c, "lab")
    c = {"search_name": regla["splunk"], "sid": "t-" + regla["clave"],
         "result": {"_time": "2026-10-01T10:00:00Z", "host": equipo}}
    return nucleo.normalizar("splunk", c, "lab")


def pasos(plan: dict, accion: str) -> list:
    return [p for p in plan["acciones"] if p["accion"] == accion]


def paso(plan: dict, accion: str) -> dict:
    encontrados = pasos(plan, accion)
    assert encontrados, f"{accion} no esta en el plan: {[p['accion'] for p in plan['acciones']]}"
    return encontrados[0]


def contencion_automatica(plan: dict) -> list:
    """Acciones automaticas que contienen (las de registro y de evidencia aparte)."""
    return [p["accion"] for p in plan["acciones"]
            if p["modo"] == "automatica" and not p.get("registro") and not p.get("es_evidencia")]


def con_politica(perfil: dict, **politica) -> dict:
    p = copy.deepcopy(perfil)
    p.setdefault("politica", {}).update(politica)
    return p


def entrada(datos: dict, familia: str, accion: str) -> dict:
    """Primera entrada de contencion de una familia con esa accion (para manipular el catalogo)."""
    return next(c for c in datos["familias"][familia]["contencion"] if c["accion"] == accion)


# ============================================================================
# Clase y severidad
# ============================================================================

def test_regla_critica_es_auto_contener(alerta, catalogo, perfil_lab):
    plan = nucleo.decidir(alerta("101206"), catalogo, perfil_lab, {})
    assert (plan["regla"]["clave"], plan["regla"]["via"]) == (LSASS, "id de regla de Wazuh")
    assert plan["regla"]["conocida"] is True
    assert (plan["familia"], plan["clase_origen"], plan["clase"]) == ("endpoint", "auto_contener", "auto_contener")
    assert (plan["severidad_inicial"], plan["severidad"]) == (4, 4)
    assert plan["estado"] == "en_curso"
    assert plan["crear_caso"] and plan["notificar"] and plan["usar_llm"]
    assert plan["momento"] == "2026-10-01T10:00:00Z"


def test_regla_alta_es_auto_analisis_y_no_contiene_sola(alerta, catalogo, perfil_lab):
    plan = nucleo.decidir(alerta("101216"), catalogo, perfil_lab, {})
    assert (plan["clase"], plan["severidad"]) == ("auto_analisis", 3)
    assert contencion_automatica(plan) == []
    assert paso(plan, "endpoint.aislar")["motivo"] == \
        "la clase auto_analisis no autoriza contencion automatica: se prepara"
    # la evidencia de la familia endpoint solo se recoge sola en auto_contener
    triage = paso(plan, "evidencia.triage_forense")
    assert (triage["modo"], triage["motivo"]) == ("aprobacion", "recogida de evidencia disponible a demanda en esta clase")


@pytest.mark.parametrize("nivel,clase,severidad", [
    ("critical", "auto_contener", 4), ("high", "auto_analisis", 3), ("medium", "auto_analisis", 2),
    ("low", "auto_enriq", 1), ("informational", "auto_cierre", 1),
])
def test_clase_y_severidad_salen_del_nivel_si_la_regla_no_trae_clase(catalogo_datos, nivel, clase, severidad):
    datos = copy.deepcopy(catalogo_datos)
    regla = next(r for r in datos["reglas"] if r["nivel"] == nivel and (r.get("wazuh_ids") or r.get("splunk")))
    del regla["clase"]
    plan = nucleo.decidir(alerta_de_regla(regla), nucleo.Catalogo(datos), PERMISIVO, {})
    assert plan["regla"]["clave"] == regla["clave"]
    assert (plan["clase"], plan["severidad_inicial"]) == (clase, severidad)


def test_regla_informativa_se_descarta_sin_acciones(catalogo, catalogo_datos, perfil_lab):
    regla = next(r for r in catalogo_datos["reglas"] if r["nivel"] == "informational" and r.get("wazuh_ids"))
    plan = nucleo.decidir(alerta_de_regla(regla), catalogo, perfil_lab, {})
    assert (plan["clase"], plan["estado"]) == ("auto_cierre", "descartada")
    assert plan["acciones"] == [] and plan["triaje"] == []
    assert not plan["crear_caso"] and not plan["notificar"]


def test_regla_baja_solo_enriquece(catalogo, catalogo_datos, perfil_lab):
    regla = next(r for r in catalogo_datos["reglas"] if r["nivel"] == "low" and (r.get("wazuh_ids") or r.get("splunk")))
    plan = nucleo.decidir(alerta_de_regla(regla), catalogo, perfil_lab, {})
    assert plan["clase"] == "auto_enriq"
    assert plan["acciones"] == []
    assert not plan["crear_caso"] and not plan["usar_llm"]


def test_estructura_del_plan(alerta, catalogo, perfil_lab):
    plan = nucleo.decidir(alerta("101206"), catalogo, perfil_lab, {})
    assert {"familia", "clase", "severidad", "estado", "triaje", "cierre", "cierres_propuestos", "secuencias",
            "acciones", "escalado", "notificar", "crear_caso"} <= set(plan)
    assert {"a", "avisar_ademas", "plazo_min", "motivos", "comprobar"} <= set(plan["escalado"])
    assert [p["id"] for p in plan["acciones"]] == ["c1", "c2", "c3", "c4", "c5", "e1"]
    for p in plan["acciones"]:
        assert {"id", "accion", "modo", "motivo", "radio", "reversible", "objetivo", "registro",
                "es_evidencia"} <= set(p), p["id"]
        assert not {"objetivo_ok", "falta", "excepciones", "clases"} & set(p), "claves internas en el plan"
        assert p["modo"] in MODOS
        assert plan["modos"][p["id"]] == p["modo"]


def test_decidir_es_determinista_y_acepta_el_catalogo_como_dict(alerta, catalogo, catalogo_datos, perfil_lab):
    a = alerta("101206")
    assert nucleo.decidir(a, catalogo, perfil_lab, {}) == nucleo.decidir(copy.deepcopy(a), catalogo_datos, perfil_lab, {})


def test_sin_hora_en_la_alerta_se_usa_el_ahora_del_contexto(catalogo, perfil_lab):
    a = nucleo.normalizar("generico", {"titulo": "Volcado de memoria de LSASS", "equipo": {"nombre": "PC-0042"}}, "lab")
    plan = nucleo.decidir(a, catalogo, perfil_lab, {"ahora": "2027-04-01T08:30:00Z"})
    assert plan["momento"] == "2027-04-01T08:30:00Z"


# ============================================================================
# Regla desconocida
# ============================================================================

def test_regla_desconocida_va_al_generico_en_analisis(catalogo, perfil_lab):
    plan = nucleo.decidir(alerta_de_escenario("regla-desconocida", 1), catalogo, perfil_lab, {})
    assert plan["regla"]["conocida"] is False and plan["regla"]["via"] == ""
    assert (plan["familia"], plan["clase"]) == ("_generico", "auto_analisis")
    assert plan["acciones"] == []
    assert plan["escalado"]["a"] == "L2"
    assert "regla no encontrada en el catalogo (100950)" in plan["avisos"]


def test_regla_desconocida_que_dice_ser_auto_contener_se_queda_en_analisis(catalogo, perfil_lab):
    a = alerta_de_escenario("regla-desconocida", 2)
    assert (a["clase_pista"], a["familia_pista"]) == ("auto_contener", "endpoint")
    plan = nucleo.decidir(a, catalogo, perfil_lab, {})
    assert (plan["familia"], plan["clase"]) == ("endpoint", "auto_analisis")
    assert "regla desconocida: la clase se limita a auto_analisis" in plan["avisos"]
    assert contencion_automatica(plan) == []
    assert all(p["modo"] != "automatica" for p in pasos(plan, "endpoint.aislar"))


@pytest.mark.parametrize("severidad,clase", [(4, "auto_analisis"), (3, "auto_analisis"), (2, "auto_analisis"),
                                             (1, "auto_enriq")])
def test_regla_desconocida_toma_la_clase_de_su_severidad_sin_pasar_de_analisis(catalogo, severidad, clase):
    a = nucleo.normalizar("generico", {"titulo": "Regla local sin catalogo", "severidad_pista": severidad,
                                       "momento": "2026-10-01T10:00:00Z"})
    plan = nucleo.decidir(a, catalogo, PERMISIVO, {})
    assert (plan["clase"], plan["severidad"]) == (clase, severidad)


def test_familia_pista_que_no_existe_va_al_generico(catalogo):
    a = nucleo.normalizar("generico", {"titulo": "Regla local", "familia_pista": "astrologia",
                                       "clase_pista": "auto_contener", "severidad_pista": 4,
                                       "momento": "2026-10-01T10:00:00Z"})
    plan = nucleo.decidir(a, catalogo, PERMISIVO, {})
    assert (plan["familia"], plan["clase"]) == ("_generico", "auto_analisis")


SECUENCIA_POR_TECNICAS = {
    "id": "descarga_y_ejecucion", "nombre": "Descarga seguida de ejecucion", "objetivo": "equipo",
    "ventana_min": 60, "pasos": [["tecnica:T1105"], ["tecnica:T1059"]], "minimo": 2,
    "efecto": {"severidad": 4, "clase": "auto_contener"},
}


def test_regla_desconocida_no_contiene_ni_por_una_secuencia(catalogo_datos, perfil_lab):
    datos = copy.deepcopy(catalogo_datos)
    datos["secuencias"].append(SECUENCIA_POR_TECNICAS)
    carga = escenario("regla-desconocida")["alertas"][1]["carga"]
    carga = simulador.preparar("wazuh", carga, nucleo.a_fecha("2026-10-01T10:00:00Z"), "desconocida-1")
    carga["rule"]["mitre"] = {"id": ["T1059.001"]}
    a = nucleo.normalizar("wazuh", carga, "lab")
    previa = {"id": "previa-1", "momento": "2026-10-01T09:50:00Z", "regla_clave": "dl:otra_regla",
              "familia": "endpoint", "equipo": "PC-0042", "usuario": "jgarcia", "tecnicas": ["T1105"],
              "observables": [], "cti": []}
    plan = nucleo.decidir(a, nucleo.Catalogo(datos), perfil_lab, {"correlacion": {"recientes": [previa], "visto": {}}})
    # preparacion: la regla es desconocida y la secuencia se activa
    assert plan["regla"]["conocida"] is False
    assert [s["id"] for s in plan["secuencias"]] == ["descarga_y_ejecucion"]
    # lo que tiene que cumplirse
    assert plan["clase"] == "auto_analisis"
    assert contencion_automatica(plan) == []


# ============================================================================
# Invariantes
# ============================================================================

def paso_sintetico(**cambios) -> dict:
    p = {"accion": "prueba.accion", "radio": "objeto", "reversible": "si", "objetivo_ok": True,
         "objetivo": {"equipo.nombre": "PC-0042"}, "falta": [], "capacidad": "edr", "registro": False,
         "es_evidencia": False, "clases": [], "excepciones": [], "solo_reglas": [], "requiere_aprobacion_origen": "no"}
    p.update(cambios)
    return p


def contexto_de(a: dict, cliente: dict = PERMISIVO) -> dict:
    return {"alerta": a, "regla": {}, "cliente": cliente, "contexto": {},
            "momento": nucleo.a_fecha("2026-10-01T10:00:00Z"), "familia": "endpoint"}


@pytest.mark.parametrize("cambios,motivo", [
    ({"radio": "cuenta"}, "radio cuenta: afecta a quien no es el atacante"),
    ({"radio": "organizacion"}, "radio organizacion: afecta a quien no es el atacante"),
    ({"radio": "equipo", "reversible": "no"}, "irreversible con radio equipo"),
    ({"radio": "sesion", "reversible": "no"}, "irreversible con radio sesion"),
    ({"radio": "objeto", "reversible": "no"}, "irreversible con radio objeto"),
])
def test_invariantes_de_radio_y_reversibilidad(cambios, motivo):
    a = nucleo.normalizar("generico", {"titulo": "x", "equipo": {"nombre": "PC-0042"}})
    for escalada in (False, True):
        assert nucleo.decidir_modo(paso_sintetico(**cambios), "auto_contener", escalada, PERMISIVO, None,
                                   contexto_de(a)) == ("aprobacion", motivo)


@pytest.mark.parametrize("cambios,motivo", [
    ({"radio": "proceso", "reversible": "no"}, "radio proceso, proceso identificado"),
    ({"radio": "equipo", "reversible": "si"}, "radio equipo, reversible"),
])
def test_lo_que_las_invariantes_permiten(cambios, motivo):
    a = nucleo.normalizar("generico", {"titulo": "x", "equipo": {"nombre": "PC-0042"}})
    assert nucleo.decidir_modo(paso_sintetico(**cambios), "auto_contener", False, PERMISIVO, None,
                               contexto_de(a)) == ("automatica", motivo)


def test_radio_organizacion_nunca_automatico(alerta, catalogo, perfil_lab):
    for cliente in (perfil_lab, PERMISIVO):
        plan = nucleo.decidir(alerta("101206"), catalogo, cliente, {})
        flota = paso(plan, "flota.bloquear_hash")
        assert flota["objetivo"] == {"fichero.sha256": SHA256}
        assert (flota["modo"], flota["motivo"]) == ("aprobacion", "radio organizacion: afecta a quien no es el atacante")


def test_ninguna_regla_del_catalogo_automatiza_radio_amplio_ni_irreversible(catalogo_datos):
    """Cada regla del catalogo en analisis y en contencion, con todos los campos y un cliente que lo permite todo."""
    fallos = []
    for regla in catalogo_datos["reglas"]:
        a = validacion.alerta_completa(regla)
        for clase in ("auto_analisis", "auto_contener"):
            datos = dict(catalogo_datos, reglas=[dict(regla, clase=clase)])
            plan = nucleo.decidir(a, nucleo.Catalogo(datos), PERMISIVO, {})
            for p in plan["acciones"]:
                if p["modo"] == "automatica" and (p["radio"] in nucleo.RADIOS_AMPLIOS
                                                  or (p["reversible"] != "si" and p["radio"] != "proceso")):
                    fallos.append(f"{regla['clave']} ({clase}): {p['accion']} radio={p['radio']} rev={p['reversible']}")
    assert fallos == []


def test_irreversible_solo_automatico_con_radio_proceso(alerta, catalogo, perfil_lab):
    plan = nucleo.decidir(alerta("101206"), catalogo, perfil_lab, {})
    matar = paso(plan, "proceso.matar")
    assert (matar["radio"], matar["reversible"]) == ("proceso", "no")
    assert (matar["modo"], matar["motivo"]) == ("automatica", "radio proceso, proceso identificado")
    assert matar["objetivo"] == {"equipo.nombre": "PC-0042", "proceso.pid": 3300,
                                 "proceso.inicio": "2026-10-01 09:59:58.000"}


def test_cuarentena_nunca_automatica_sobre_ruta_del_sistema(alerta, catalogo, perfil_lab):
    a = alerta("101206", targetFilename="C:\\Windows\\System32\\drivers\\etc\\hosts")
    assert a["fichero"]["ruta"] == "C:\\Windows\\System32\\drivers\\etc\\hosts"
    plan = nucleo.decidir(a, catalogo, perfil_lab, {})
    cuarentena = paso(plan, "fichero.cuarentena")
    assert (cuarentena["modo"], cuarentena["motivo"]) == ("aprobacion", "el fichero esta en una ruta del sistema operativo")


def test_vssadmin_del_sistema_no_es_objetivo_de_cuarentena_ni_de_bloqueo(catalogo, perfil_lab):
    plan = nucleo.decidir(alerta_de_escenario("ransomware-puesto", 2), catalogo, perfil_lab, {})
    assert plan["clase"] == "auto_contener"
    assert paso(plan, "fichero.cuarentena")["modo"] == "no_aplicable"
    assert paso(plan, "flota.bloquear_hash")["modo"] == "no_aplicable"
    assert paso(plan, "endpoint.aislar")["modo"] == "automatica"


@pytest.mark.parametrize("ruta", ["/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/hosts"])
def test_cuarentena_nunca_automatica_sobre_configuracion_critica(catalogo, ruta):
    carga = escenario("explotacion-web-produccion")["alertas"][1]["carga"]
    carga = simulador.preparar("wazuh", carga, nucleo.a_fecha("2026-10-01T10:03:00Z"), "web-critica")
    carga["data"]["process_exec"]["args"] = [{"file_arg": {"path": ruta}}]
    a = nucleo.normalizar("wazuh", carga, "permisivo")
    assert a["fichero"]["ruta"] == ruta
    plan = nucleo.decidir(a, catalogo, PERMISIVO, {})
    assert plan["clase"] == "auto_contener"
    cuarentena = paso(plan, "fichero.cuarentena")
    assert (cuarentena["modo"], cuarentena["motivo"]) == ("aprobacion", "el fichero es configuracion critica del sistema")


# ============================================================================
# Catalogos maliciosos o mal configurados
# ============================================================================

def test_catalogo_que_declara_radio_organizacion_sin_aprobacion(alerta, catalogo_datos):
    datos = copy.deepcopy(catalogo_datos)
    datos["acciones"]["endpoint.aislar"]["radio"] = "organizacion"
    entrada(datos, "endpoint", "endpoint.aislar").update(radio="organizacion", requiere_aprobacion="no", excepciones=[])
    a = alerta("101206")
    plan = nucleo.decidir(a, nucleo.Catalogo(datos), PERMISIVO, {})
    aislar = paso(plan, "endpoint.aislar")
    assert (aislar["radio"], aislar["modo"]) == ("organizacion", "aprobacion")
    assert nucleo.verificar_invariantes(plan, a) == []


def test_accion_nueva_que_declara_menos_radio_del_que_tiene(alerta, catalogo_datos):
    datos = copy.deepcopy(catalogo_datos)
    datos["acciones"]["red.cortar_segmento"] = {
        "nombre": "Cortar el segmento de red entero", "radio": "organizacion", "reversible": "si",
        "capacidad": "nac", "requiere": ["equipo.ip"], "conectores": ["declarativo"]}
    datos["familias"]["endpoint"]["contencion"].append({
        "texto": "Cortar el segmento de red del equipo", "accion": "red.cortar_segmento", "radio": "proceso",
        "reversible": "si", "requiere_aprobacion": "no", "excepciones": [], "solo_reglas": [], "parametros": {}})
    plan = nucleo.decidir(alerta("101206"), nucleo.Catalogo(datos), PERMISIVO, {})
    cortar = paso(plan, "red.cortar_segmento")
    assert (cortar["radio"], cortar["modo"]) == ("organizacion", "aprobacion")


def test_entrada_del_playbook_no_rebaja_el_radio_de_la_accion(alerta, catalogo_datos):
    datos = copy.deepcopy(catalogo_datos)
    entrada(datos, "endpoint", "flota.bloquear_hash").update(radio="proceso", requiere_aprobacion="no")
    plan = nucleo.decidir(alerta("101206"), nucleo.Catalogo(datos), PERMISIVO, {})
    flota = paso(plan, "flota.bloquear_hash")
    assert (flota["radio"], flota["modo"]) == ("organizacion", "aprobacion")


@pytest.mark.parametrize("reversible", ["no", False, "No", "quizas"])
def test_catalogo_con_accion_irreversible_de_radio_equipo(alerta, catalogo_datos, reversible):
    datos = copy.deepcopy(catalogo_datos)
    datos["acciones"]["endpoint.aislar"]["reversible"] = reversible
    plan = nucleo.decidir(alerta("101206"), nucleo.Catalogo(datos), PERMISIVO, {})
    aislar = paso(plan, "endpoint.aislar")
    assert aislar["reversible"] == "no"
    assert (aislar["modo"], aislar["motivo"]) == ("aprobacion", "irreversible con radio equipo")


def test_entrada_del_playbook_irreversible_manda_sobre_la_accion(alerta, catalogo_datos):
    datos = copy.deepcopy(catalogo_datos)
    entrada(datos, "endpoint", "endpoint.aislar")["reversible"] = "no"
    plan = nucleo.decidir(alerta("101206"), nucleo.Catalogo(datos), PERMISIVO, {})
    assert paso(plan, "endpoint.aislar")["modo"] == "aprobacion"


def test_catalogo_con_radio_desconocido_cuenta_como_organizacion(alerta, catalogo_datos):
    datos = copy.deepcopy(catalogo_datos)
    datos["acciones"]["endpoint.aislar"]["radio"] = "planeta"
    plan = nucleo.decidir(alerta("101206"), nucleo.Catalogo(datos), PERMISIVO, {})
    aislar = paso(plan, "endpoint.aislar")
    assert (aislar["radio"], aislar["modo"]) == ("organizacion", "aprobacion")


def test_accion_sin_radio_declarado_cuenta_como_organizacion(alerta, catalogo_datos):
    assert nucleo.radio_efectivo(None, "") == "organizacion"
    datos = copy.deepcopy(catalogo_datos)
    del datos["acciones"]["endpoint.aislar"]["radio"]
    datos["acciones"]["endpoint.aislar"]["reversible"] = "no"
    entrada(datos, "endpoint", "endpoint.aislar").update(radio=None, reversible="no")
    plan = nucleo.decidir(alerta("101206"), nucleo.Catalogo(datos), PERMISIVO, {})
    assert paso(plan, "endpoint.aislar")["modo"] == "aprobacion"


def _flota_como_registro(datos: dict) -> None:
    datos["acciones"]["flota.bloquear_hash"]["registro"] = True


def _flota_como_evidencia(datos: dict) -> None:
    datos["familias"]["endpoint"]["evidencia_automatica"] = [{"accion": "flota.bloquear_hash", "clases": ["auto_contener"]}]


@pytest.mark.parametrize("manipular", [_flota_como_registro, _flota_como_evidencia], ids=["registro", "evidencia"])
def test_catalogo_no_salta_las_invariantes_marcando_registro_o_evidencia(alerta, catalogo_datos, perfil_lab, manipular):
    datos = copy.deepcopy(catalogo_datos)
    manipular(datos)
    plan = nucleo.decidir(alerta("101206"), nucleo.Catalogo(datos), perfil_lab, {})
    flota = pasos(plan, "flota.bloquear_hash")
    assert flota and all(p["radio"] == "organizacion" for p in flota)
    assert [p["modo"] for p in flota if p["modo"] == "automatica"] == []


def test_accion_sin_mapear_es_tarea_manual(alerta, catalogo_datos):
    datos = copy.deepcopy(catalogo_datos)
    datos["familias"]["endpoint"]["contencion"].append({
        "texto": "Llamar por telefono al usuario afectado", "accion": None, "radio": "cuenta", "reversible": "si",
        "requiere_aprobacion": "no", "excepciones": [], "solo_reglas": [], "parametros": {}})
    plan = nucleo.decidir(alerta("101206"), nucleo.Catalogo(datos), PERMISIVO, {})
    tarea = plan["acciones"][-2]                # la ultima antes de la evidencia automatica
    assert tarea["origen"] == "Llamar por telefono al usuario afectado"
    assert (tarea["modo"], tarea["motivo"]) == ("manual", "accion sin mapear a nada ejecutable: tarea del analista")
    assert (tarea["radio"], tarea["reversible"], tarea["objetivo"]) == ("cuenta", "no", {})


# ============================================================================
# verificar_invariantes: defensa en profundidad sobre un plan ya hecho
# ============================================================================

def forjar(plan: dict, accion: str, **cambios) -> dict:
    """Copia del plan con una accion puesta en automatica a mano."""
    falso = copy.deepcopy(plan)
    p = next(x for x in falso["acciones"] if x["accion"] == accion)
    p["modo"] = "automatica"
    p.update(cambios)
    return falso


def test_verificar_invariantes_acepta_un_plan_correcto(alerta, catalogo, perfil_lab):
    a = alerta("101206")
    assert nucleo.verificar_invariantes(nucleo.decidir(a, catalogo, perfil_lab, {}), a) == []


@pytest.mark.parametrize("accion,cambios,fallo", [
    ("flota.bloquear_hash", {}, "flota.bloquear_hash automatica con radio organizacion"),
    ("endpoint.aislar", {"radio": "cuenta"}, "endpoint.aislar automatica con radio cuenta"),
    ("endpoint.aislar", {"reversible": "no"}, "endpoint.aislar irreversible con radio equipo"),
    ("endpoint.aislar", {"objetivo": {}}, "endpoint.aislar automatica sin objetivo"),
])
def test_verificar_invariantes_caza_un_plan_forjado(alerta, catalogo, perfil_lab, accion, cambios, fallo):
    a = alerta("101206")
    plan = forjar(nucleo.decidir(a, catalogo, perfil_lab, {}), accion, **cambios)
    assert fallo in nucleo.verificar_invariantes(plan, a)


@pytest.mark.parametrize("ruta", ["C:\\Windows\\System32\\drivers\\etc\\hosts", "/usr/sbin/sshd", "/etc/shadow"])
def test_verificar_invariantes_caza_accion_de_fichero_forjada_sobre_el_sistema(ruta):
    a = nucleo.normalizar("generico", {"titulo": "x", "equipo": {"nombre": "PC-0042"}, "fichero": {"ruta": ruta}})
    plan = {"acciones": [{"id": "c1", "accion": "fichero.cuarentena", "modo": "automatica", "radio": "objeto",
                          "reversible": "si", "objetivo": {"fichero.ruta": ruta}}]}
    assert nucleo.verificar_invariantes(plan, a) == ["fichero.cuarentena automatica sobre una ruta del sistema"]


def test_verificar_invariantes_ignora_lo_que_no_es_automatico():
    plan = {"acciones": [{"id": "c1", "accion": "flota.bloquear_hash", "modo": "aprobacion", "radio": "organizacion",
                          "reversible": "no", "objetivo": {}}]}
    assert nucleo.verificar_invariantes(plan) == []


@pytest.mark.parametrize("marca", ["registro", "es_evidencia"])
def test_verificar_invariantes_no_se_fia_de_las_marcas_de_registro_o_evidencia(marca):
    plan = {"acciones": [{"id": "c5", "accion": "flota.bloquear_hash", "modo": "automatica", "radio": "organizacion",
                          "reversible": "si", "objetivo": {"fichero.sha256": SHA256}, marca: True}]}
    assert nucleo.verificar_invariantes(plan) == ["flota.bloquear_hash automatica con radio organizacion"]


# ============================================================================
# Politicas del cliente
# ============================================================================

def test_accion_prohibida_por_el_cliente(catalogo, catalogo_datos, perfil_acme):
    regla = next(r for r in catalogo_datos["reglas"] if r["clave"] == "dl:cont_escape_a_namespaces_host")
    plan = nucleo.decidir(validacion.alerta_completa(regla), catalogo, perfil_acme, {})
    assert plan["clase"] == "auto_contener"
    escalar = paso(plan, "k8s.escalar_cero")
    assert (escalar["modo"], escalar["motivo"]) == ("prohibida", "el perfil del cliente no permite esta accion")


def test_prohibida_va_antes_que_todo_lo_demas(alerta, catalogo, perfil_lab):
    cliente = con_politica(perfil_lab, acciones_prohibidas=["endpoint.aislar"])
    plan = nucleo.decidir(alerta("101206"), catalogo, cliente, {}, capacidades=set())
    assert paso(plan, "endpoint.aislar")["modo"] == "prohibida"


def test_accion_que_el_cliente_siempre_aprueba(alerta, catalogo, perfil_acme):
    plan = nucleo.decidir(alerta("101206", equipo="PC-1001", cliente="acme"), catalogo, perfil_acme, {})
    matar = paso(plan, "proceso.matar")
    assert (matar["modo"], matar["motivo"]) == ("aprobacion", "el cliente exige aprobacion para esta accion")
    # la politica es por accion: aislar un puesto sigue siendo automatico en ACME
    assert paso(plan, "endpoint.aislar")["modo"] == "automatica"


def test_cliente_sin_contencion_automatica(alerta, catalogo, perfil_lab):
    cliente = con_politica(perfil_lab, contencion_automatica=False)
    plan = nucleo.decidir(alerta("101206"), catalogo, cliente, {})
    for accion in ("endpoint.aislar", "proceso.matar", "fichero.cuarentena"):
        assert (paso(plan, accion)["modo"], paso(plan, accion)["motivo"]) == \
            ("aprobacion", "el cliente no admite contencion automatica"), accion
    # recoger evidencia no es contener
    assert paso(plan, "evidencia.triage_forense")["modo"] == "automatica"


def test_controlador_de_dominio_protegido_ni_aislamiento_ni_recogida(catalogo, perfil_lab):
    a = alerta_de_escenario("controlador-dominio", 1)
    plan = nucleo.decidir(a, catalogo, perfil_lab, {})
    assert (plan["familia"], plan["clase"]) == ("ad", "auto_contener")
    aislar = pasos(plan, "endpoint.aislar")
    assert aislar and all(p["modo"] == "aprobacion" for p in aislar)
    assert "activo protegido en el inventario del cliente" in [p["motivo"] for p in aislar]
    triage = paso(plan, "evidencia.triage_forense")
    assert (triage["modo"], triage["motivo"]) == \
        ("aprobacion", "activo protegido en el inventario del cliente: la recogida la decide una persona")
    assert contencion_automatica(plan) == []


def test_hmi_de_planta_protegido_y_puesto_de_ingenieria_no(alerta, catalogo, perfil_norte):
    hmi = nucleo.decidir(alerta("101206", equipo="HMI-02", cliente="norte"), catalogo, perfil_norte, {})
    assert contencion_automatica(hmi) == []
    assert paso(hmi, "endpoint.aislar")["motivo"] == "activo protegido en el inventario del cliente"
    assert paso(hmi, "evidencia.triage_forense")["modo"] == "aprobacion"
    puesto = nucleo.decidir(alerta("101206", equipo="ING-07", cliente="norte"), catalogo, perfil_norte, {})
    assert paso(puesto, "endpoint.aislar")["modo"] == "automatica"


def test_activo_protegido_por_etiqueta_del_inventario(alerta, catalogo, perfil_lab):
    cliente = copy.deepcopy(perfil_lab)
    cliente["inventario"]["activos"].insert(0, {"nombre": "PC-0042", "etiquetas": ["puesto", "protegido"]})
    plan = nucleo.decidir(alerta("101206"), catalogo, cliente, {})
    assert contencion_automatica(plan) == []
    assert paso(plan, "endpoint.aislar")["motivo"] == "activo protegido en el inventario del cliente"


def test_excepcion_que_se_cumple_pide_aprobacion(alerta, catalogo, perfil_lab):
    plan = nucleo.decidir(alerta("101206", equipo="SRV-WEB-01"), catalogo, perfil_lab, {})
    aislar = paso(plan, "endpoint.aislar")
    assert aislar["modo"] == "aprobacion"
    assert aislar["motivo"].startswith("se cumple una excepcion: inventario.etiqueta(")


def test_excepcion_sin_datos_pide_aprobacion(alerta, catalogo, perfil_acme):
    # ACME no tiene el inventario completo: de un equipo que no aparece no se sabe si es de produccion
    plan = nucleo.decidir(alerta("101206", equipo="WS-NUEVO-01", cliente="acme"), catalogo, perfil_acme, {})
    aislar = paso(plan, "endpoint.aislar")
    assert aislar["modo"] == "aprobacion"
    assert aislar["motivo"].startswith("no hay datos para descartar la excepcion: inventario.etiqueta(")


def test_excepcion_sin_datos_ignorada_si_el_cliente_lo_pide(alerta, catalogo, perfil_acme):
    cliente = con_politica(perfil_acme, excepcion_sin_datos="ignorar")
    plan = nucleo.decidir(alerta("101206", equipo="WS-NUEVO-01", cliente="acme"), catalogo, cliente, {})
    assert paso(plan, "endpoint.aislar")["modo"] == "automatica"


def test_detectionlab_marca_con_aprobacion(alerta, catalogo, perfil_lab):
    plan = nucleo.decidir(alerta("101128"), catalogo, perfil_lab, {})
    motivos = {p["origen"]: (p["modo"], p["motivo"]) for p in pasos(plan, "endpoint.aislar")}
    assert motivos["Aislar el controlador de dominio"] == ("aprobacion", "DetectionLab la marca con aprobacion")
    assert ("automatica", "radio equipo, reversible") in motivos.values()


# ============================================================================
# no_aplicable y manual
# ============================================================================

@pytest.mark.parametrize("requiere,ok,objetivo,falta", [
    (["equipo.nombre|equipo.id_agente"], True, {"equipo.nombre": "PC-0042"}, []),
    (["equipo.id_edr|equipo.nombre"], True, {"equipo.nombre": "PC-0042"}, []),
    (["proceso.pid+proceso.inicio|proceso.guid+proceso.pid"], True, {"proceso.guid": "g-1", "proceso.pid": 7}, []),
    (["equipo.nombre", "fichero.ruta|fichero.sha256"], False, {"equipo.nombre": "PC-0042"}, ["fichero.ruta|fichero.sha256"]),
    ([], True, {}, []),
])
def test_requisito_de_campos(requiere, ok, objetivo, falta):
    a = nucleo.normalizar("generico", {"titulo": "x", "equipo": {"nombre": "PC-0042"},
                                       "proceso": {"guid": "g-1", "pid": "7"}})
    assert nucleo.requisito(a, requiere) == (ok, objetivo, falta)


def test_sin_proceso_identificado_matar_no_aplica(nueva_alerta_wazuh, catalogo, perfil_lab):
    carga = nueva_alerta_wazuh("101206", image="C:\\Users\\Public\\dump.exe", processId="3300",
                               utcTime="2026-10-01 09:59:58.000", destinationIp="185.220.101.4")
    carga["data"]["win"]["system"]["eventID"] = "3"      # conexion de red: sin hora de arranque ni GUID
    plan = nucleo.decidir(nucleo.normalizar("wazuh", carga, "lab"), catalogo, perfil_lab, {})
    matar = paso(plan, "proceso.matar")
    assert matar["modo"] == "no_aplicable"
    assert matar["motivo"] == ("la alerta no trae proceso.pid+proceso.inicio|proceso.guid+proceso.pid; "
                               "no hay objetivo inequivoco")


def test_sin_persistencia_en_la_alerta_deshabilitarla_no_aplica(alerta, catalogo, perfil_lab):
    plan = nucleo.decidir(alerta("101206"), catalogo, perfil_lab, {})
    assert paso(plan, "persistencia.deshabilitar")["modo"] == "no_aplicable"


def test_accion_solo_para_otras_reglas_no_aplica(catalogo, catalogo_datos):
    unicamente = "Aislar el endpoint en la red, unicamente para el borrado del registro de auditoria"
    otra = next(r for r in catalogo_datos["reglas"] if r["clave"] == "dl:zta_net_001_protocolo_en_claro")
    plan = nucleo.decidir(validacion.alerta_completa(otra), catalogo, PERMISIVO, {})
    p = next(x for x in plan["acciones"] if x["origen"] == unicamente)
    assert (p["modo"], p["motivo"]) == ("no_aplicable", "solo aplica a las reglas zta_vis_001_borrado_registro_auditoria")
    propia = next(r for r in catalogo_datos["reglas"] if r["clave"] == "dl:zta_vis_001_borrado_registro_auditoria")
    plan = nucleo.decidir(validacion.alerta_completa(propia), catalogo, PERMISIVO, {})
    assert next(x for x in plan["acciones"] if x["origen"] == unicamente)["modo"] == "automatica"


def test_sin_capacidad_en_el_cliente_es_manual(alerta, catalogo, perfil_lab):
    plan = nucleo.decidir(alerta("101206"), catalogo, perfil_lab, {}, capacidades={"agente", "casos"})
    aislar = paso(plan, "endpoint.aislar")
    assert (aislar["modo"], aislar["motivo"]) == ("manual", "el cliente no tiene conector de edr")
    # la recogida de evidencia va por el agente, que si tiene
    assert paso(plan, "evidencia.triage_forense")["modo"] == "automatica"


def test_sin_conector_que_sepa_hacerla_es_manual(alerta, catalogo, perfil_lab):
    plan = nucleo.decidir(alerta("101206"), catalogo, perfil_lab, {},
                          acciones_disponibles={"endpoint.aislar", "evidencia.triage_forense"})
    matar = paso(plan, "proceso.matar")
    assert (matar["modo"], matar["motivo"]) == ("manual", "ningun conector del cliente sabe hacer proceso.matar")
    assert paso(plan, "endpoint.aislar")["modo"] == "automatica"


def test_accion_de_registro_con_capacidad_interna_no_necesita_conector(catalogo, catalogo_datos):
    regla = next(r for r in catalogo_datos["reglas"] if r["clave"] == "dl:xdr_001_desinstalacion_sensor_edr")
    plan = nucleo.decidir(validacion.alerta_completa(regla), catalogo, PERMISIVO, {}, capacidades=set())
    marcar = paso(plan, "inventario.marcar_no_fiable")
    assert (marcar["modo"], marcar["motivo"]) == ("automatica", "accion de registro")


# ============================================================================
# Triaje, cierre y escalado
# ============================================================================

def test_triaje_sube_severidad_con_alertas_de_otras_familias(alerta, catalogo, perfil_lab):
    previa = {"id": "previa-red", "momento": "2026-10-01T08:00:00Z", "regla_clave": "dl:soc_net_001_beaconing",
              "familia": "red", "equipo": "PC-0042", "usuario": "jgarcia", "tecnicas": [], "observables": [], "cti": []}
    plan = nucleo.decidir(alerta("101216"), catalogo, perfil_lab, {"correlacion": {"recientes": [previa], "visto": {}}})
    pregunta = next(t for t in plan["triaje"] if "otras familias" in t["pregunta"])
    assert pregunta["resultado"] == "si"
    assert (plan["severidad_inicial"], plan["severidad"]) == (3, 4)


def test_triaje_no_sube_por_encima_de_cuatro(alerta, catalogo, perfil_lab):
    plan = nucleo.decidir(alerta("101211"), catalogo, perfil_lab, {})
    assert next(t for t in plan["triaje"] if "copias sombra" in t["pregunta"])["resultado"] == "si"
    assert plan["severidad"] == 4


def test_triaje_sin_datos_queda_pendiente(alerta, catalogo, perfil_lab):
    plan = nucleo.decidir(alerta("101216"), catalogo, perfil_lab, {})
    resultados = {t["pregunta"]: t["resultado"] for t in plan["triaje"]}
    assert resultados["El equipo acumula alertas de otras familias en las ultimas 24 h"] == "pendiente"
    assert all(t["resultado"] == "pendiente" for t in plan["triaje"] if not t["automatica"])


def test_bajar_severidad_reduce_un_escalon_como_mucho(alerta, catalogo_datos, perfil_lab):
    datos = copy.deepcopy(catalogo_datos)
    siempre = {"evento.campo_existe": "equipo.nombre"}
    datos["familias"]["endpoint"]["triaje"] = [
        {"pregunta": "Primera rebaja", "efecto": "bajar_severidad", "evaluador": siempre},
        {"pregunta": "Segunda rebaja", "efecto": "bajar_severidad", "evaluador": siempre},
    ]
    plan = nucleo.decidir(alerta("101206"), nucleo.Catalogo(datos), perfil_lab, {})
    assert [t["resultado"] for t in plan["triaje"]] == ["si", "si"]
    assert plan["severidad"] == 3


def test_escaner_autorizado_en_su_ventana_baja_severidad_pero_no_cierra(catalogo, perfil_lab):
    # jueves 22:30 en Madrid: dentro de la ventana de escaneo del laboratorio
    a = alerta_de_escenario("escaner-autorizado", 1, "2026-10-01T20:30:00Z")
    plan = nucleo.decidir(a, catalogo, perfil_lab, {})
    assert next(t for t in plan["triaje"] if "escaner autorizado" in t["pregunta"].lower())["resultado"] == "si"
    assert plan["severidad"] == 1
    assert (plan["estado"], plan["cierre"]) == ("en_curso", None)
    assert any("escaner de vulnerabilidades autorizado" in c["condicion"].lower() for c in plan["cierres_propuestos"])
    assert contencion_automatica(plan) == []


def test_el_mismo_escaneo_desde_internet_no_recibe_rebaja(catalogo, perfil_lab):
    a = alerta_de_escenario("escaner-autorizado", 2, "2026-10-01T20:31:00Z")
    plan = nucleo.decidir(a, catalogo, perfil_lab, {})
    assert next(t for t in plan["triaje"] if "escaner autorizado" in t["pregunta"].lower())["resultado"] == "no"
    assert plan["severidad"] >= 2


def protocolo_en_claro(momento: str) -> dict:
    return {"id": f"zta-{momento}", "timestamp": momento,
            "rule": {"id": "101252", "level": 8, "description": "Protocolo en claro hacia un recurso que exige cifrado"},
            "agent": {"id": "042", "name": "PC-0042", "ip": "10.0.20.42"},
            "data": {"srcip": "10.0.20.55", "dstip": "10.0.20.30", "dstport": "21"}}


def test_cierre_automatico_por_excepcion_vigente(catalogo, perfil_lab):
    plan = nucleo.decidir(nucleo.normalizar("wazuh", protocolo_en_claro("2026-10-01T10:00:00Z"), "lab"),
                          catalogo, perfil_lab, {})
    assert plan["regla"]["clave"] == "dl:zta_net_001_protocolo_en_claro"
    assert plan["estado"] == "cerrada_auto"
    assert plan["cierre"]["condicion"]
    assert plan["acciones"] == []
    assert not plan["crear_caso"] and not plan["notificar"]


def test_sin_cierre_cuando_la_excepcion_ha_vencido(catalogo, perfil_lab):
    plan = nucleo.decidir(nucleo.normalizar("wazuh", protocolo_en_claro("2027-04-01T10:00:00Z"), "lab"),
                          catalogo, perfil_lab, {})
    assert (plan["estado"], plan["cierre"]) == ("en_curso", None)
    assert plan["crear_caso"]


def test_cifrado_masivo_escala_a_guardia_con_plazo_corto(alerta, catalogo, perfil_lab):
    plan = nucleo.decidir(alerta("101226"), catalogo, perfil_lab, {})
    assert plan["escalado"]["a"] == "guardia"
    assert plan["escalado"]["plazo_min"] == 10
    assert len(plan["escalado"]["motivos"]) == 2


def test_borrado_de_copias_escala_a_l3(alerta, catalogo, perfil_lab):
    plan = nucleo.decidir(alerta("101211"), catalogo, perfil_lab, {})
    assert (plan["escalado"]["a"], plan["escalado"]["plazo_min"]) == ("L3", 20)
    assert plan["escalado"]["comprobar"] == []


def test_escalado_que_depende_de_datos_que_faltan_queda_para_comprobar(alerta, catalogo, perfil_acme):
    plan = nucleo.decidir(alerta("101211", equipo="WS-NUEVO-01", cliente="acme"), catalogo, perfil_acme, {})
    assert plan["escalado"]["a"] == "L3"
    assert [c["a"] for c in plan["escalado"]["comprobar"]] == ["guardia"]


def test_exfiltracion_avisa_al_dpd_y_a_la_asesoria_juridica(catalogo, perfil_acme):
    a = alerta_de_escenario("exfiltracion-tras-acceso", 2, "2026-10-01T10:35:00Z", cliente="acme")
    plan = nucleo.decidir(a, catalogo, perfil_acme, {})
    assert (plan["familia"], plan["clase"]) == ("exfiltracion", "auto_contener")
    assert plan["escalado"]["avisar_ademas"] == ["asesoria_juridica", "dpd"]
    regla = paso(plan, "correo.deshabilitar_regla")
    assert regla["modo"] == "automatica"
    assert regla["objetivo"] == {"correo.buzon": "pruiz@acme.test", "correo.regla_buzon": "Sincronizar"}
    assert paso(plan, "perimetro.bloquear_destino")["modo"] != "automatica"
