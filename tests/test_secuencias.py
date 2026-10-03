"""
Secuencias: varias alertas del mismo ataque sobre el mismo equipo o usuario.

El historico llega como lo devuelve almacen.recientes(): filas con id,
momento, regla_clave, familia, equipo, usuario, tecnicas, observables y cti.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from responselab import nucleo, simulador
from responselab.clientes import Clientes

RAIZ = Path(__file__).resolve().parent.parent
ESCENARIOS = RAIZ / "escenarios"
T0 = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)

DEFENSAS = "dl:soc_edr_004_defensas_deshabilitadas"
COPIAS = "dl:soc_edr_003_borrado_copias_sombra"
LSASS = "dl:soc_edr_001_volcado_lsass"

# Proceso del atacante en el perfil del usuario, con hash: todas las acciones tienen objetivo
PROCESO = {"image": "C:\\Users\\jgarcia\\AppData\\Local\\Temp\\upd.exe", "commandLine": "upd.exe /s",
           "processId": "5544", "processGuid": "{3f1c0a2b-1111-2222-3333-000011112222}",
           "utcTime": "2026-10-01 08:59:00.000", "hashes": "SHA256=" + "ab" * 32, "user": "LAB\\jgarcia"}


def en(minutos: int) -> datetime:
    return T0 + timedelta(minutes=minutos)


def reciente(regla_clave: str, minutos: int, equipo: str = "CORP-FIN-07", usuario: str = "jgarcia",
             familia: str = "endpoint", tecnicas=(), ident: str | None = None) -> dict:
    return {"id": ident or f"previa-{regla_clave}-{equipo}-{minutos}", "momento": nucleo.iso(en(minutos)),
            "regla_clave": regla_clave, "familia": familia, "equipo": equipo, "usuario": usuario,
            "tecnicas": list(tecnicas), "observables": [], "cti": []}


def historico(*recientes) -> dict:
    return {"correlacion": {"recientes": list(recientes), "visto": {}}}


def escenario(nombre: str) -> dict:
    return yaml.safe_load((ESCENARIOS / f"{nombre}.yml").read_text(encoding="utf-8"))


def de_escenario(nombre: str, n: int, minutos: int, cliente: str) -> dict:
    a = escenario(nombre)["alertas"][n - 1]
    carga = simulador.preparar(a["siem"], a["carga"], en(minutos), f"{nombre}-{n}")
    return nucleo.normalizar(a["siem"], carga, cliente)


def generica(minutos: int, equipo: str = "PC-0042", tecnicas=()) -> dict:
    return nucleo.normalizar("generico", {"id": f"g-{minutos}", "titulo": "Alerta de prueba", "momento": nucleo.iso(en(minutos)),
                                          "equipo": {"nombre": equipo}, "tecnicas": list(tecnicas)})


def activadas(alerta: dict, catalogo, *recientes) -> dict:
    regla, _via = catalogo.buscar_regla(alerta)
    familia = (regla or {}).get("familia") or alerta.get("familia_pista") or "_generico"
    return {s["id"]: s for s in nucleo.evaluar_secuencias(alerta, regla, familia, catalogo.secuencias, list(recientes))}


def paso(plan: dict, accion: str) -> dict:
    return next(p for p in plan["acciones"] if p["accion"] == accion)


@pytest.fixture
def wazuh(nueva_alerta_wazuh):
    """Alerta de Wazuh en el puesto de finanzas, a T0 + minutos."""
    def construir(regla: str, minutos: int, equipo: str = "CORP-FIN-07", **eventdata):
        c = nueva_alerta_wazuh(regla, equipo=equipo, **dict(PROCESO, **eventdata))
        c["timestamp"] = nucleo.iso(en(minutos))
        return nucleo.normalizar("wazuh", c, "lab")
    return construir


# ============================================================================
# Activacion
# ============================================================================

def test_sin_historico_no_hay_secuencias(wazuh, catalogo, perfil_lab):
    a = wazuh("101211", 4)
    regla, _via = catalogo.buscar_regla(a)
    assert nucleo.evaluar_secuencias(a, regla, "endpoint", catalogo.secuencias, None) == []
    assert nucleo.decidir(a, catalogo, perfil_lab, {})["secuencias"] == []


def test_una_alerta_sola_no_completa_una_secuencia(wazuh, catalogo):
    assert activadas(wazuh("101216", 0), catalogo) == {}


def test_ransomware_con_dos_de_tres_pasos(wazuh, catalogo):
    s = activadas(wazuh("101211", 4), catalogo, reciente(DEFENSAS, 0))
    assert list(s) == ["ransomware"]
    assert (s["ransomware"]["pasos_casados"], s["ransomware"]["pasos"]) == (2, 3)
    assert s["ransomware"]["efecto"] == {"severidad": 4, "escalar_a": "guardia", "clase": "auto_contener"}


@pytest.mark.parametrize("previas,activa", [
    pytest.param([("infra:110060", 0)], False, id="dos-pasos"),
    pytest.param([("infra:110060", 0), ("infra:110010", 6)], True, id="tres-pasos"),
])
def test_intrusion_ssh_necesita_su_minimo_de_tres_pasos(catalogo, previas, activa):
    a = de_escenario("intrusion-ssh-dmz", 3, 9, "lab")
    recientes = [reciente(clave, m, equipo="victima-dmz", usuario="root", familia="linux") for clave, m in previas]
    assert ("intrusion_ssh" in activadas(a, catalogo, *recientes)) is activa


@pytest.mark.parametrize("minutos_previa,activa", [(-360, True), (-361, False), (360, True), (361, False)])
def test_fuera_de_la_ventana_no_cuenta(wazuh, catalogo, minutos_previa, activa):
    assert ("ransomware" in activadas(wazuh("101216", 0), catalogo, reciente(COPIAS, minutos_previa))) is activa


def test_la_alerta_actual_tiene_que_ser_un_paso_de_la_secuencia(wazuh, catalogo):
    previas = (reciente(DEFENSAS, 0), reciente(COPIAS, 4))
    # una persistencia en el mismo equipo no es paso del ransomware: esa secuencia la completaron otras
    assert activadas(wazuh("101230", 10), catalogo, *previas) == {}
    # el cifrado si lo es
    assert activadas(wazuh("101226", 10), catalogo, *previas)["ransomware"]["pasos_casados"] == 3


def test_otro_equipo_no_cuenta_y_el_nombre_no_distingue_mayusculas(wazuh, catalogo):
    a = wazuh("101216", 10)
    assert activadas(a, catalogo, reciente(COPIAS, 4, equipo="CORP-FIN-99")) == {}
    assert "ransomware" in activadas(a, catalogo, reciente(COPIAS, 4, equipo="corp-fin-07"))


def test_regla_desconocida_no_completa_secuencias_de_reglas_con_nombre(catalogo, perfil_lab):
    a = escenario("regla-desconocida")["alertas"][0]
    carga = simulador.preparar("wazuh", a["carga"], en(10), "desconocida-ransomware")
    carga["agent"]["name"] = "CORP-FIN-07"
    plan = nucleo.decidir(nucleo.normalizar("wazuh", carga, "lab"), catalogo, perfil_lab,
                          historico(reciente(DEFENSAS, 0), reciente(COPIAS, 4)))
    assert plan["regla"]["conocida"] is False
    assert (plan["secuencias"], plan["clase"]) == ([], "auto_analisis")


# ============================================================================
# Efecto en el plan
# ============================================================================

def test_la_secuencia_eleva_la_alerta_que_la_completa(wazuh, catalogo, perfil_lab):
    plan = nucleo.decidir(wazuh("101216", 10), catalogo, perfil_lab, historico(reciente(COPIAS, 4)))
    assert [s["id"] for s in plan["secuencias"]] == ["ransomware"]
    assert (plan["clase_origen"], plan["clase"]) == ("auto_analisis", "auto_contener")
    assert "clase elevada a auto_contener por la secuencia ransomware" in plan["avisos"]
    assert (plan["severidad"], plan["escalado"]["a"], plan["escalado"]["plazo_min"]) == (4, "guardia", 10)
    assert "secuencia Preparacion y ejecucion de ransomware" in plan["escalado"]["motivos"]
    assert plan["notificar"] and plan["crear_caso"]
    assert paso(plan, "endpoint.aislar")["modo"] == "automatica"
    assert paso(plan, "evidencia.triage_forense")["modo"] == "automatica"
    # las invariantes siguen mandando: ninguna secuencia autoriza radio organizacion
    assert paso(plan, "flota.bloquear_hash")["modo"] == "aprobacion"


def test_el_cliente_puede_desactivar_la_elevacion_por_correlacion(wazuh, catalogo, perfil_lab):
    cliente = copy.deepcopy(perfil_lab)
    cliente["politica"]["escalado_por_correlacion"] = False
    plan = nucleo.decidir(wazuh("101216", 10), catalogo, cliente, historico(reciente(COPIAS, 4)))
    assert [s["id"] for s in plan["secuencias"]] == ["ransomware"]
    assert plan["clase"] == "auto_analisis"
    assert not any("clase elevada" in aviso for aviso in plan["avisos"])
    # la secuencia sigue subiendo la severidad y el escalado
    assert (plan["severidad"], plan["escalado"]["a"]) == (4, "guardia")
    aislar = paso(plan, "endpoint.aislar")
    assert (aislar["modo"], aislar["motivo"]) == ("aprobacion", "la clase auto_analisis no autoriza contencion automatica: se prepara")


def test_secuencia_sin_efecto_de_clase_sube_severidad_pero_no_eleva(catalogo, perfil_norte):
    psexec = de_escenario("credenciales-movimiento-ot", 1, 30, "norte")
    plan = nucleo.decidir(psexec, catalogo, perfil_norte,
                          historico(reciente(LSASS, 18, equipo="ING-07", usuario="adm-jlopez")))
    assert [s["id"] for s in plan["secuencias"]] == ["credenciales_a_movimiento"]
    assert (plan["clase"], plan["severidad"], plan["escalado"]["a"]) == ("auto_analisis", 4, "L3")
    assert plan["notificar"]


def test_secuencia_por_usuario_del_correo_a_la_cuenta(catalogo, perfil_acme):
    mfa = de_escenario("phishing-a-cuenta", 2, 12, "acme")
    clic = reciente("dl:soc_mail_005_url_pulsada", 0, equipo="", usuario="lmartin", familia="correo")
    assert "phishing_a_cuenta" in activadas(mfa, catalogo, clic)
    assert activadas(mfa, catalogo, dict(clic, usuario="pruiz")) == {}
    assert activadas(mfa, catalogo, dict(clic, momento=nucleo.iso(en(-49)))) == {}   # 61 minutos antes
    plan = nucleo.decidir(mfa, catalogo, perfil_acme, historico(clic))
    assert (plan["clase_origen"], plan["clase"], plan["escalado"]["a"]) == ("auto_analisis", "auto_contener", "L3")
    assert paso(plan, "identidad.revocar_sesiones")["modo"] == "automatica"
    assert paso(plan, "identidad.retirar_consentimiento")["modo"] != "automatica"


def test_alerta_sin_usuario_no_entra_en_secuencias_por_usuario(catalogo):
    mfa = de_escenario("phishing-a-cuenta", 2, 12, "acme")
    mfa["usuario"] = {}
    clic = reciente("dl:soc_mail_005_url_pulsada", 0, equipo="", usuario="", familia="correo")
    assert activadas(mfa, catalogo, clic) == {}


def test_secuencia_por_usuario_con_alertas_de_dos_siem(catalogo, perfil_acme):
    acceso = de_escenario("exfiltracion-tras-acceso", 1, 0, "acme")      # Sentinel
    reenvio = de_escenario("exfiltracion-tras-acceso", 2, 35, "acme")    # Splunk
    assert acceso["usuario"]["nombre"] == reenvio["usuario"]["nombre"] == "pruiz"
    previa = reciente("dl:soc_cld_008_origen_anonimizado", 0, equipo="", usuario="pruiz", familia="cloud",
                      ident=acceso["id"])
    plan = nucleo.decidir(reenvio, catalogo, perfil_acme, historico(previa))
    assert [s["id"] for s in plan["secuencias"]] == ["acceso_y_exfiltracion"]
    assert plan["escalado"]["a"] == "L3"
    assert {"dpd", "asesoria_juridica"} <= set(plan["escalado"]["avisar_ademas"])


# ============================================================================
# Pasos por tecnica y por familia
# ============================================================================

@pytest.mark.parametrize("item,fila,casa", [
    ("tecnica:T1059*", {"tecnicas": ["t1059.001"]}, True),
    ("tecnica:T1059", {"tecnicas": ["T1059.003"]}, True),
    ("tecnica:T1059.001", {"tecnicas": ["T1059"]}, False),
    ("familia:red", {"familia": "red"}, True),
    ("familia:red", {"familia": "redes"}, False),
    ("soc_edr_003_borrado_copias_sombra", {"regla_clave": COPIAS}, True),
    ("DL:SOC_EDR_003_BORRADO_COPIAS_SOMBRA", {"regla_clave": COPIAS}, True),
    ("110060", {"regla_clave": "infra:110060"}, True),
    ("110060", {"regla_clave": "infra:1100600"}, False),
])
def test_casa_paso(item, fila, casa):
    assert nucleo._casa_paso(item, fila) is casa


TECNICA_Y_FAMILIA = {"id": "tecnica_y_familia", "objetivo": "equipo", "ventana_min": 60,
                     "pasos": [["tecnica:T1059*"], ["familia:red"]], "minimo": 2, "efecto": {}}
SIN_MINIMO = {"id": "sin_minimo", "objetivo": "equipo", "ventana_min": 60,
              "pasos": [["tecnica:T1059"], ["tecnica:T1105"]], "efecto": {}}


def test_secuencia_por_tecnica_y_familia():
    a = generica(10, tecnicas=["T1059.001"])
    red = reciente("dl:otra", 0, equipo="PC-0042", familia="red")
    activa = nucleo.evaluar_secuencias(a, {"clave": "dl:prueba"}, "endpoint", [TECNICA_Y_FAMILIA], [red])
    assert [(s["id"], s["nombre"]) for s in activa] == [("tecnica_y_familia", "tecnica_y_familia")]
    assert nucleo.evaluar_secuencias(a, {"clave": "dl:prueba"}, "endpoint", [TECNICA_Y_FAMILIA],
                                     [dict(red, familia="ad")]) == []


def test_sin_minimo_hacen_falta_todos_los_pasos():
    a = generica(10, tecnicas=["T1059.003"])
    descarga = reciente("dl:otra", 0, equipo="PC-0042", tecnicas=["T1105"])
    assert nucleo.evaluar_secuencias(a, {}, "endpoint", [SIN_MINIMO], []) == []
    assert [s["id"] for s in nucleo.evaluar_secuencias(a, {}, "endpoint", [SIN_MINIMO], [descarga])] == ["sin_minimo"]


# ============================================================================
# Escenarios completos, solo con el nucleo
# ============================================================================

# Lo que comprueban los escenarios sobre el plan; lo demas (ejecuciones,
# conectores, aprobaciones) es del motor y lo prueban sus propias pruebas.
CLAVES_DEL_PLAN = {"familia", "clase", "estado", "regla_conocida", "severidad_minima", "severidad_maxima", "triaje",
                   "cierre_propuesto", "escalado", "secuencias", "sin_secuencias", "modos", "sin_contencion_automatica",
                   "nunca_automatica", "avisar_ademas", "notificar"}
INICIO_FIJO = datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)


def reproducir(esc: dict, catalogo):
    """Cada alerta del escenario, decidida con el historico de las anteriores (como almacen.recientes)."""
    cliente = yaml.safe_load((RAIZ / "clientes" / f"{esc['cliente']}.yml").read_text(encoding="utf-8"))
    base = nucleo.a_fecha(esc["inicio"]) if esc.get("inicio") else INICIO_FIJO
    capacidades = set(Clientes.capacidades(cliente))
    recientes = []
    for n, a in enumerate(esc["alertas"], 1):
        carga = simulador.preparar(a["siem"], a["carga"], base + timedelta(minutes=a.get("minuto", 0)), f"{esc['id']}-{n}")
        alerta = nucleo.normalizar(a["siem"], carga, cliente["id"])
        plan = nucleo.decidir(alerta, catalogo, cliente, historico(*recientes), capacidades=capacidades)
        yield n, a, alerta, plan
        recientes.insert(0, {"id": alerta["id"], "momento": plan["momento"], "regla_clave": plan["regla"]["clave"],
                             "familia": plan["familia"], "equipo": alerta["equipo"].get("nombre", ""),
                             "usuario": alerta["usuario"].get("nombre", ""), "tecnicas": plan["regla"]["tecnicas"],
                             "observables": [o["valor"] for o in alerta["observables"]], "cti": []})


@pytest.mark.parametrize("nombre", sorted(p.stem for p in ESCENARIOS.glob("*.yml")))
def test_escenario_reproducido_solo_con_el_nucleo(catalogo, nombre):
    esc = escenario(nombre)
    esc.setdefault("id", nombre)
    fallos, comprobadas = [], 0
    for n, a, alerta, plan in reproducir(esc, catalogo):
        esperado = {k: v for k, v in (a.get("esperado") or {}).items() if k in CLAVES_DEL_PLAN}
        for ok, texto in simulador.comprobar_alerta(esperado, plan, [], []):
            comprobadas += 1
            if not ok:
                fallos.append(f"alerta {n}: {texto}")
        fallos += [f"alerta {n}: invariante rota: {f}" for f in nucleo.verificar_invariantes(plan, alerta)]
    assert comprobadas > 0
    assert fallos == []
