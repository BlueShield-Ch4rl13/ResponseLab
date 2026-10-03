"""
Evaluadores: cada uno contesta True, False o None, y None ("no lo se") es una
respuesta legitima que nunca se convierte en un no.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest
import yaml

from responselab import nucleo

MOMENTO = datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)  # jueves, 12:00 en Madrid
IP_PUBLICA = "185.220.101.4"


def ctx(alerta=None, cliente=None, contexto=None, momento=MOMENTO, regla=None, familia="endpoint") -> dict:
    """Contexto de evaluacion como el que arma decidir, con la alerta en el esquema comun."""
    datos = dict(alerta or {})
    datos.setdefault("titulo", "alerta de prueba")
    if isinstance(momento, str):
        momento = nucleo.a_fecha(momento)
    return {"alerta": nucleo.normalizar("generico", datos, (cliente or {}).get("id", "")), "regla": regla or {},
            "cliente": cliente or {}, "contexto": contexto or {}, "momento": momento, "familia": familia}


def ev(spec, **kwargs):
    return nucleo.evaluar(spec, ctx(**kwargs))


# ============================================================================
# Logica de tres valores
# ============================================================================

SI = {"evento.campo_existe": "equipo.nombre"}
NO = {"evento.campo_existe": "k8s.pod"}
NOSE = {"lista.valor_en": {"lista": "no_declarada", "campo": "equipo.nombre"}}
CON_EQUIPO = {"equipo": {"nombre": "PC-0042"}}


def test_piezas_basicas():
    assert ev(SI, alerta=CON_EQUIPO) is True
    assert ev(NO, alerta=CON_EQUIPO) is False
    assert ev(NOSE, alerta=CON_EQUIPO) is None


@pytest.mark.parametrize("spec,esperado", [
    pytest.param({"todos": [SI, SI]}, True, id="todos-si"),
    pytest.param({"todos": [SI, NO]}, False, id="todos-un-no"),
    pytest.param({"todos": [SI, NOSE]}, None, id="todos-un-nose"),
    pytest.param({"todos": [NOSE, NO]}, False, id="todos-no-gana-a-nose"),
    pytest.param({"todos": []}, True, id="todos-vacio"),
    pytest.param({"alguno": [NO, NO]}, False, id="alguno-no"),
    pytest.param({"alguno": [NO, SI]}, True, id="alguno-un-si"),
    pytest.param({"alguno": [NO, NOSE]}, None, id="alguno-un-nose"),
    pytest.param({"alguno": [NOSE, SI]}, True, id="alguno-si-gana-a-nose"),
    pytest.param({"alguno": []}, False, id="alguno-vacio"),
    pytest.param({"negar": SI}, False, id="negar-si"),
    pytest.param({"negar": NO}, True, id="negar-no"),
    pytest.param({"negar": NOSE}, None, id="negar-nose"),
    pytest.param({"negar": {"todos": [SI, NOSE]}}, None, id="negar-anidado"),
    pytest.param({"alguno": [{"negar": NO}, NOSE]}, True, id="alguno-con-negar"),
    pytest.param([SI, NO], False, id="lista-es-todos"),
    pytest.param([SI, NOSE], None, id="lista-con-nose"),
])
def test_logica_de_tres_valores(spec, esperado):
    assert ev(spec, alerta=CON_EQUIPO) is esperado


def test_sin_especificacion_es_no_se():
    assert nucleo.evaluar(None, ctx()) is None


@pytest.mark.parametrize("spec", [{"evento.campo_existe": "a", "evento.campo_valor": {}}, "evento.campo_existe", 42, {}])
def test_evaluador_mal_formado(spec):
    with pytest.raises(ValueError, match="mal formado"):
        nucleo.evaluar(spec, ctx())


def test_evaluador_desconocido():
    with pytest.raises(ValueError, match="evaluador desconocido: inventario.adivinar"):
        nucleo.evaluar({"inventario.adivinar": {}}, ctx())


def test_clave_no_sin_comillas_falla_en_vez_de_negar():
    """En YAML `no:` es el booleano False: por eso el operador se llama negar."""
    spec = yaml.safe_load("{no: {evento.campo_existe: equipo.nombre}}")
    assert list(spec) == [False]
    with pytest.raises(ValueError, match="evaluador desconocido"):
        nucleo.evaluar(spec, ctx(alerta=CON_EQUIPO))


def test_describir_evaluador():
    spec = {"todos": [{"lista.valor_en": {"lista": "x", "campo": "y"}}, {"negar": {"evento.campo_existe": "k8s.pod"}},
                      {"alguno": [{"evento.regla_en": ["a", "b"]}, {"cti.tipo_coincidencia": ["ip"]}]}]}
    assert nucleo.describir_evaluador(spec) == (
        "lista.valor_en(lista=x, campo=y) y no (evento.campo_existe(k8s.pod)) y "
        "evento.regla_en(a, b) o cti.tipo_coincidencia(ip)")


# ============================================================================
# Evento
# ============================================================================

COPIAS = {"clave": "dl:soc_edr_003_borrado_copias_sombra", "wazuh_ids": ["101211", "101212"]}


@pytest.mark.parametrize("reglas,esperado", [
    (["soc_edr_003_borrado_copias_sombra"], True),
    (["DL:SOC_EDR_003_BORRADO_COPIAS_SOMBRA"], True),
    (["101212"], True),
    (["soc_edr_007_cifrado_masivo"], False),
    ([], False),
])
def test_regla_en(reglas, esperado):
    assert ev({"evento.regla_en": reglas}, regla=COPIAS) is esperado


def test_regla_en_por_fichero_de_origen_de_la_alerta():
    assert ev({"evento.regla_en": ["lin_read_shadow"]}, alerta={"regla_fichero": "rules/linux/lin_read_shadow.yml"}) is True


def test_campo_contiene_valor_y_existe():
    alerta = {"proceso": {"linea": "vssadmin.exe delete shadows /all /quiet"}, "http": {"estado": "200"}}
    assert ev({"evento.campo_contiene": {"campo": "proceso.linea", "valores": ["DELETE SHADOWS"]}}, alerta=alerta) is True
    assert ev({"evento.campo_contiene": {"campo": "proceso.linea", "valores": ["wmic"]}}, alerta=alerta) is False
    assert ev({"evento.campo_contiene": {"campo": "proceso.padre_linea", "valores": ["x"]}}, alerta=alerta) is None
    assert ev({"evento.campo_valor": {"campo": "http.estado", "valores": [200, "201"]}}, alerta=alerta) is True
    assert ev({"evento.campo_valor": {"campo": "http.estado", "valores": ["500"]}}, alerta=alerta) is False
    assert ev({"evento.campo_valor": {"campo": "http.metodo", "valores": ["GET"]}}, alerta=alerta) is None
    assert ev({"evento.campo_existe": {"campo": "http.estado"}}, alerta=alerta) is True
    assert ev({"evento.campo_existe": "http.metodo"}, alerta=alerta) is False


def test_texto_contiene_busca_tambien_en_la_alerta_original():
    c = {"titulo": "Inyeccion SQL", "full_log": "GET /x 200 \"sqlmap/1.8.4#stable\""}
    assert ev({"evento.texto_contiene": {"valores": ["SQLMAP"]}}, alerta=c) is True
    assert ev({"evento.texto_contiene": {"valores": ["nikto"]}}, alerta=c) is False


# ============================================================================
# Listas del cliente: declarada vacia es "ninguno", no declarada es "no se"
# ============================================================================

def test_lista_valor_en(perfil_lab):
    padre = {"proceso": {"padre_imagen": "C:\\Windows\\CCM\\CcmExec.exe"}}
    spec = {"lista.valor_en": {"lista": "agentes_distribucion", "campo": "proceso.padre_nombre"}}
    assert ev(spec, alerta=padre, cliente=perfil_lab) is True
    assert ev(spec, alerta={"proceso": {"padre_imagen": "C:\\x\\otro.exe"}}, cliente=perfil_lab) is False
    assert ev(spec, alerta={}, cliente=perfil_lab) is None
    assert ev({"lista.valor_en": {"lista": "no_declarada", "campo": "proceso.padre_nombre"}},
              alerta=padre, cliente=perfil_lab) is None
    assert ev({"lista.valor_en": {"lista": "aplicaciones_negocio", "campo": "proceso.padre_nombre"}},
              alerta=padre, cliente=perfil_lab) is False


@pytest.mark.parametrize("ip,esperado", [("10.0.30.50", True), ("10.0.30.51", False), (IP_PUBLICA, False),
                                         ("SRV-WEB-01", None)])
def test_lista_ip_en_rango(perfil_lab, ip, esperado):
    spec = {"lista.ip_en_rango": {"lista": "escaneres_autorizados", "campo": "red.ip_origen"}}
    assert ev(spec, alerta={"red": {"ip_origen": ip}}, cliente=perfil_lab) is esperado


def test_lista_ip_en_rango_salta_entradas_invalidas_e_ipv6():
    cliente = {"listas": {"rangos": ["no-es-una-red", "10.0.0.0/33", "192.168.0.0/16", "2001:db8::/32"]}}
    spec = {"lista.ip_en_rango": {"lista": "rangos", "campo": "red.ip_origen"}}
    assert ev(spec, alerta={"red": {"ip_origen": "192.168.4.4"}}, cliente=cliente) is True
    assert ev(spec, alerta={"red": {"ip_origen": "2001:db8::7"}}, cliente=cliente) is True
    assert ev(spec, alerta={"red": {"ip_origen": "10.1.1.1"}}, cliente=cliente) is False
    assert ev(spec, alerta={}, cliente=cliente) is None
    assert ev({"lista.ip_en_rango": {"lista": "otra", "campo": "red.ip_origen"}},
              alerta={"red": {"ip_origen": "192.168.4.4"}}, cliente=cliente) is None


def test_lista_prefijo(perfil_acme):
    en = {"lista.prefijo_en": {"lista": "administradores", "campo": "usuario.nombre"}}
    no_en = {"lista.prefijo_no_en": {"lista": "administradores", "campo": "usuario.nombre"}}
    admin, normal = {"usuario": {"nombre": "ACME\\ADM-jlopez"}}, {"usuario": {"nombre": "jlopez"}}
    assert (ev(en, alerta=admin, cliente=perfil_acme), ev(no_en, alerta=admin, cliente=perfil_acme)) == (True, False)
    assert (ev(en, alerta=normal, cliente=perfil_acme), ev(no_en, alerta=normal, cliente=perfil_acme)) == (False, True)
    assert ev(no_en, alerta={}, cliente=perfil_acme) is None


def test_lista_par_en(perfil_lab):
    spec = {"lista.par_en": {"lista": "soportes_cifrados",
                             "campos": {"serie": "dispositivo.serie", "titular": "usuario.nombre"}}}
    assert ev(spec, alerta={"dispositivo": {"serie": "usb-0001"}, "usuario": {"nombre": "LAB\\JGarcia"}},
              cliente=perfil_lab) is True
    assert ev(spec, alerta={"dispositivo": {"serie": "USB-0002"}, "usuario": {"nombre": "jgarcia"}},
              cliente=perfil_lab) is False
    assert ev(spec, alerta={"usuario": {"nombre": "jgarcia"}}, cliente=perfil_lab) is None


@pytest.mark.parametrize("usuario,lista,esperado", [
    ("LAB\\Administrator", "administradores", True),
    ("admin-soc@lab.test", "administradores", True),
    ("breakglass@lab.test", "cuentas_emergencia", True),
    ("jgarcia", "administradores", False),
    ("jgarcia", "no_declarada", None),
    (None, "administradores", None),
])
def test_cuenta_en_lista(perfil_lab, usuario, lista, esperado):
    alerta = {"usuario": {"nombre": usuario}} if usuario else {}
    assert ev({"directorio.cuenta_en_lista": {"lista": lista}}, alerta=alerta, cliente=perfil_lab) is esperado


# ============================================================================
# Inventario: con inventario completo, no aparecer es un no; si no, no se sabe
# ============================================================================

@pytest.mark.parametrize("equipo,etiqueta,esperado", [
    ({"nombre": "DC01"}, "controlador_dominio", True),
    ({"nombre": "DC01.lab.test"}, "controlador_dominio", True),
    ({"nombre": "PC-0042"}, "puesto", True),
    ({"nombre": "PC-0042"}, "servidor_produccion", False),
    ({"nombre": "XYZ-01"}, "servidor_produccion", False),
    ({"nombre": "OTRO", "ip": "10.0.20.30"}, "heredado", True),
    ({}, "servidor_produccion", None),
])
def test_inventario_completo(perfil_lab, equipo, etiqueta, esperado):
    spec = {"inventario.etiqueta": {"etiquetas": [etiqueta]}}
    assert ev(spec, alerta={"equipo": equipo}, cliente=perfil_lab) is esperado


def test_inventario_incompleto_no_se_sabe(perfil_acme):
    spec = {"inventario.etiqueta": {"etiquetas": ["servidor_produccion"]}}
    assert ev(spec, alerta={"equipo": {"nombre": "XYZ-01"}}, cliente=perfil_acme) is None
    assert ev(spec, alerta={"equipo": {"nombre": "PC-DIR-01"}}, cliente=perfil_acme) is False
    assert ev({"inventario.etiqueta": {"etiquetas": ["direccion"]}},
              alerta={"equipo": {"nombre": "PC-DIR-01"}}, cliente=perfil_acme) is True


def test_inventario_del_destino(perfil_lab):
    spec = {"inventario.etiqueta": {"etiquetas": ["heredado"], "objetivo": "destino"}}
    assert ev(spec, alerta={"equipo": {"nombre": "PC-0042"}, "red": {"ip_destino": "10.0.20.30"}},
              cliente=perfil_lab) is True
    por_campo = {"inventario.etiqueta": {"etiquetas": ["heredado"], "objetivo": "red.ip_origen"}}
    assert ev(por_campo, alerta={"red": {"ip_origen": "10.0.20.30"}}, cliente=perfil_lab) is True


# ============================================================================
# Ventanas en la zona horaria del cliente
# ============================================================================

ESCANEO = {"inventario.ventana_abierta": {"tipo": "escaneo"}}


@pytest.mark.parametrize("instante,abierta", [
    pytest.param("2026-10-01T20:30:00Z", True, id="jueves-22.30-madrid"),
    pytest.param("2026-10-01T21:59:00Z", True, id="jueves-23.59-madrid"),
    pytest.param("2026-10-01T19:59:00Z", False, id="jueves-21.59-madrid"),
    pytest.param("2026-10-01T22:30:00Z", False, id="jueves-en-utc-pero-viernes-en-madrid"),
    pytest.param("2026-10-02T20:30:00Z", False, id="viernes-22.30-madrid"),
    pytest.param("2026-10-08T20:30:00Z", True, id="jueves-siguiente"),
    pytest.param("2026-12-03T21:30:00Z", True, id="invierno-jueves-22.30"),
    pytest.param("2026-12-03T22:59:00Z", True, id="invierno-jueves-23.59"),
    pytest.param("2026-12-03T23:00:00Z", False, id="invierno-viernes-00.00"),
])
def test_ventana_de_escaneo_en_hora_de_madrid(perfil_lab, instante, abierta):
    assert ev(ESCANEO, alerta={"equipo": {"nombre": "SRV-WEB-01"}}, cliente=perfil_lab, momento=instante) is abierta


def test_la_zona_horaria_del_cliente_cambia_el_dia(perfil_lab):
    sin_zona = copy.deepcopy(perfil_lab)
    del sin_zona["zona_horaria"]
    # 22:30 UTC del jueves: en UTC aun es jueves (abierta), en Madrid ya es viernes (cerrada)
    assert ev(ESCANEO, cliente=sin_zona, momento="2026-10-01T22:30:00Z") is True
    assert ev(ESCANEO, cliente=perfil_lab, momento="2026-10-01T22:30:00Z") is False


@pytest.mark.parametrize("instante,equipo,objetivo,abierta", [
    ("2026-10-06T01:00:00Z", "SRV-WEB-01", None, True),        # martes 03:00 en Madrid
    ("2026-10-06T00:30:00Z", "SRV-WEB-01", None, True),        # martes 02:30 en Madrid (en UTC, 00:30: fuera)
    ("2026-10-06T02:30:00Z", "SRV-WEB-01", None, False),       # martes 04:30
    ("2026-10-05T23:30:00Z", "SRV-WEB-01", None, False),       # martes 01:30
    ("2026-10-06T01:00:00Z", "PC-0042", None, False),          # la ventana es solo para ^SRV-
    ("2026-10-06T01:00:00Z", "PC-0042", "ninguno", True),      # salvo que se pregunte sin equipo
])
def test_ventana_de_mantenimiento_por_equipo(perfil_lab, instante, equipo, objetivo, abierta):
    spec = {"inventario.ventana_abierta": {"tipo": "mantenimiento", "objetivo": objetivo}}
    assert ev(spec, alerta={"equipo": {"nombre": equipo}}, cliente=perfil_lab, momento=instante) is abierta


@pytest.mark.parametrize("dias", [["martes"], ["Ma"], ["1"]])
def test_dias_por_nombre_abreviatura_o_numero(dias):
    cliente = {"zona_horaria": "Europe/Madrid", "ventanas": [
        {"tipo": "despliegue", "dias": dias, "desde": "02:00", "hasta": "04:00"}]}
    spec = {"inventario.ventana_abierta": {"tipo": "despliegue"}}
    assert ev(spec, cliente=cliente, momento="2026-10-06T01:00:00Z") is True
    assert ev(spec, cliente=cliente, momento="2026-10-07T01:00:00Z") is False


def test_ventana_con_inicio_y_fin():
    cliente = {"ventanas": [{"tipo": "cambio", "inicio": "2026-10-10T20:00:00Z", "fin": "2026-10-10T23:00:00Z"}]}
    spec = {"inventario.ventana_abierta": {"tipo": "cambio"}}
    assert ev(spec, cliente=cliente, momento="2026-10-10T21:00:00Z") is True
    assert ev(spec, cliente=cliente, momento="2026-10-10T23:00:01Z") is False


def test_sin_ventanas_es_un_no_y_no_un_no_se(perfil_lab):
    assert ev({"inventario.ventana_abierta": {}}, cliente={}) is False
    assert ev({"inventario.ventana_abierta": {"tipo": "despliegue"}}, cliente=perfil_lab,
              momento="2026-10-01T20:30:00Z") is False


VENTANA_NOCTURNA = {"zona_horaria": "Europe/Madrid", "ventanas": [
    {"tipo": "mantenimiento", "dias": ["vi"], "desde": "22:00", "hasta": "06:00"}]}
NOCTURNA = {"inventario.ventana_abierta": {"tipo": "mantenimiento"}}


def test_ventana_nocturna_abierta_antes_de_medianoche():
    assert ev(NOCTURNA, cliente=VENTANA_NOCTURNA, momento="2026-10-02T21:00:00Z") is True   # viernes 23:00


@pytest.mark.parametrize("instante,abierta", [
    pytest.param("2026-10-03T01:00:00Z", True, id="sabado-03.00-sigue-la-ventana-del-viernes"),
    pytest.param("2026-10-02T01:00:00Z", False, id="viernes-03.00-es-la-noche-del-jueves"),
])
def test_ventana_nocturna_pertenece_al_dia_en_que_empieza(instante, abierta):
    assert ev(NOCTURNA, cliente=VENTANA_NOCTURNA, momento=instante) is abierta


# ============================================================================
# Excepciones del cliente
# ============================================================================

EN_CLARO = {"clave": "dl:zta_net_001_protocolo_en_claro", "wazuh_ids": ["101252"]}
FTP = {"equipo": {"nombre": "PC-0042"}, "red": {"ip_origen": "10.0.20.55", "ip_destino": "10.0.20.30"}}
EXCEPCION = {"objetivo": "red.ip_destino", "segmento": "red.ip_origen"}


def test_excepcion_vigente_y_caducada(perfil_lab):
    vigente, caducada = {"inventario.excepcion_vigente": EXCEPCION}, {"inventario.excepcion_caducada": EXCEPCION}
    assert ev(vigente, alerta=FTP, cliente=perfil_lab, regla=EN_CLARO) is True
    assert ev(caducada, alerta=FTP, cliente=perfil_lab, regla=EN_CLARO) is False
    despues = "2027-04-01T00:00:00Z"
    assert ev(vigente, alerta=FTP, cliente=perfil_lab, regla=EN_CLARO, momento=despues) is False
    assert ev(caducada, alerta=FTP, cliente=perfil_lab, regla=EN_CLARO, momento=despues) is True


def test_excepcion_solo_para_su_regla_y_su_segmento(perfil_lab):
    vigente = {"inventario.excepcion_vigente": EXCEPCION}
    assert ev(vigente, alerta=FTP, cliente=perfil_lab, regla={"clave": "dl:otra_regla"}) is False
    fuera = {"equipo": {"nombre": "PC-0042"}, "red": {"ip_origen": "10.0.99.9", "ip_destino": "10.0.20.30"}}
    assert ev(vigente, alerta=fuera, cliente=perfil_lab, regla=EN_CLARO) is False
    assert ev({"inventario.excepcion_caducada": EXCEPCION}, alerta=fuera, cliente=perfil_lab, regla=EN_CLARO) is False


# ============================================================================
# Correlacion: sin historico, "no se"
# ============================================================================

def reciente(regla_clave="dl:otra", familia="red", equipo="PC-0042", usuario="jgarcia", minutos=-30,
             observables=(), cti=(), ident=None) -> dict:
    return {"id": ident or f"r-{regla_clave}-{equipo}-{minutos}", "momento": nucleo.iso(MOMENTO + timedelta(minutes=minutos)),
            "regla_clave": regla_clave, "familia": familia, "equipo": equipo, "usuario": usuario,
            "observables": list(observables), "cti": list(cti), "tecnicas": []}


def historico(*recientes, visto=None) -> dict:
    return {"correlacion": {"recientes": list(recientes), "visto": visto or {}}}


LSASS = {"clave": "dl:soc_edr_001_volcado_lsass"}
EQUIPO_USUARIO = {"equipo": {"nombre": "PC-0042"}, "usuario": {"nombre": "jgarcia"},
                  "proceso": {"sha256": "ab" * 32}, "red": {"ip_destino": IP_PUBLICA}}


@pytest.mark.parametrize("spec", [
    {"correlacion.otras_familias": {}},
    {"correlacion.misma_regla_en_equipos": {"minimo": 2}},
    {"correlacion.unico_equipo": {}},
    {"correlacion.regla_en_equipo": {"reglas": ["x"]}},
    {"correlacion.familia_en_usuario": {"familias": ["cloud"]}},
    {"correlacion.primera_vez": {"campo": "proceso.sha256"}},
    {"correlacion.mismo_observable_en_equipos": {"campos": ["red.ip_destino"]}},
    {"correlacion.observables_distintos_en_equipo": {}},
])
def test_correlacion_sin_historico_es_no_se(spec):
    assert ev(spec, alerta=EQUIPO_USUARIO, regla=LSASS) is None


def test_otras_familias():
    spec = {"correlacion.otras_familias": {"horas": 24}}
    assert ev(spec, alerta=EQUIPO_USUARIO, contexto=historico(reciente(familia="red"))) is True
    assert ev(spec, alerta=EQUIPO_USUARIO, contexto=historico(reciente(familia="endpoint"))) is False
    assert ev(spec, alerta=EQUIPO_USUARIO, contexto=historico(reciente(equipo="PC-0099"))) is False
    assert ev(spec, alerta=EQUIPO_USUARIO, contexto=historico(reciente(minutos=-25 * 60))) is False
    assert ev({"correlacion.otras_familias": {"objetivo": "usuario"}}, alerta=EQUIPO_USUARIO,
              contexto=historico(reciente(equipo="PC-0099", usuario="JGARCIA"))) is True
    assert ev(spec, alerta={}, contexto=historico(reciente())) is None


def test_la_propia_alerta_no_cuenta_en_su_historico():
    alerta = dict(EQUIPO_USUARIO, id="alerta-actual")
    propia = reciente(familia="red", ident="alerta-actual")
    assert ev({"correlacion.otras_familias": {}}, alerta=alerta, contexto=historico(propia)) is False


def test_misma_regla_en_varios_equipos():
    otros = [reciente(regla_clave=LSASS["clave"], equipo=e, minutos=-10) for e in ("PC-1", "PC-2")]
    lejos = reciente(regla_clave=LSASS["clave"], equipo="PC-3", minutos=-120)
    contexto = historico(*otros, lejos)
    assert ev({"correlacion.misma_regla_en_equipos": {"minutos": 60, "minimo": 3}},
              alerta=EQUIPO_USUARIO, regla=LSASS, contexto=contexto) is True
    assert ev({"correlacion.misma_regla_en_equipos": {"minutos": 60, "minimo": 4}},
              alerta=EQUIPO_USUARIO, regla=LSASS, contexto=contexto) is False
    assert ev({"correlacion.unico_equipo": {}}, alerta=EQUIPO_USUARIO, regla=LSASS, contexto=historico()) is True
    assert ev({"correlacion.unico_equipo": {}}, alerta=EQUIPO_USUARIO, regla=LSASS, contexto=contexto) is False
    assert ev({"correlacion.misma_regla_en_equipos": {}}, alerta=EQUIPO_USUARIO, regla={}, contexto=contexto) is None


def test_regla_en_equipo():
    shell = reciente(regla_clave="dl:web_012_shell_tras_explotacion", minutos=-20)
    spec = {"correlacion.regla_en_equipo": {"reglas": ["web_012_shell_tras_explotacion"], "minutos": 30}}
    assert ev(spec, alerta=EQUIPO_USUARIO, contexto=historico(shell)) is True
    assert ev(spec, alerta=EQUIPO_USUARIO, contexto=historico(dict(shell, momento=nucleo.iso(MOMENTO - timedelta(minutes=45))))) is False
    assert ev(spec, alerta=EQUIPO_USUARIO, contexto=historico(dict(shell, equipo="PC-0099"))) is False


def test_familia_en_usuario():
    spec = {"correlacion.familia_en_usuario": {"familias": ["cloud"], "minutos": 60}}
    assert ev(spec, alerta=EQUIPO_USUARIO, contexto=historico(reciente(familia="cloud", usuario="JGarcia"))) is True
    assert ev(spec, alerta=EQUIPO_USUARIO, contexto=historico(reciente(familia="cloud", usuario="pruiz"))) is False
    assert ev(spec, alerta={"equipo": {"nombre": "PC-0042"}}, contexto=historico()) is None


@pytest.mark.parametrize("visto,esperado", [({"proceso.sha256": False}, True), ({"proceso.sha256": True}, False), ({}, None)])
def test_primera_vez(visto, esperado):
    spec = {"correlacion.primera_vez": {"campo": "proceso.sha256"}}
    assert ev(spec, alerta=EQUIPO_USUARIO, contexto=historico(visto=visto)) is esperado


def test_mismo_observable_en_varios_equipos():
    spec = {"correlacion.mismo_observable_en_equipos": {"campos": ["red.ip_destino"], "minimo": 3}}
    vistos = [reciente(equipo=e, observables=[IP_PUBLICA]) for e in ("PC-1", "PC-2")]
    assert ev(spec, alerta=EQUIPO_USUARIO, contexto=historico(*vistos)) is True
    assert ev(spec, alerta=EQUIPO_USUARIO, contexto=historico(vistos[0])) is False
    solo = {"correlacion.mismo_observable_en_equipos": {"campos": ["red.ip_destino"], "minimo": 3, "sin_otras_alertas": True}}
    assert ev(solo, alerta=EQUIPO_USUARIO, contexto=historico(*vistos)) is True
    assert ev(solo, alerta=EQUIPO_USUARIO, contexto=historico(*vistos, reciente(equipo="PC-1", ident="otra"))) is False


def test_observables_distintos_en_el_equipo():
    spec = {"correlacion.observables_distintos_en_equipo": {"minimo": 3}}
    contexto = dict(historico(reciente(cti=["a.example", "b.example"])), cti={"coincidencias": [{"valor": "c.example"}]})
    assert ev(spec, alerta=EQUIPO_USUARIO, contexto=contexto) is True
    assert ev(spec, alerta=EQUIPO_USUARIO, contexto=historico(reciente(cti=["a.example"]))) is False


# ============================================================================
# Inteligencia, DNS y plazos
# ============================================================================

def cti(*coincidencias, **resto) -> dict:
    return {"cti": dict({"coincidencias": list(coincidencias)}, **resto)}


def test_cti_coincidencia():
    spec = {"cti.coincidencia": {}}
    assert ev(spec) is None
    assert ev(spec, contexto=cti()) is False
    assert ev(spec, contexto=cti({"nivel": "alta"})) is True
    assert ev(spec, contexto=cti({"nivel": "baja"})) is False
    assert ev({"cti.coincidencia": {"nivel_minimo": "baja"}}, contexto=cti({"nivel": "baja"})) is True


def test_cti_tipo_de_la_alerta_o_del_contexto():
    assert ev({"cti.tipo_coincidencia": ["ip"]}, alerta={"cti_tipo": "ip"}) is True
    assert ev({"cti.tipo_coincidencia": ["dominio"]}, alerta={"cti_tipo": "ip"}) is False
    assert ev({"cti.tipo_coincidencia": ["dominio"]}) is None
    assert ev({"cti.tipo_coincidencia": ["dominio"]}, contexto=cti()) is False
    assert ev({"cti.tipo_coincidencia": {"tipos": ["dominio"]}}, contexto=cti({"tipo": "dominio"})) is True


def test_cti_nivel_antiguedad_y_fuentes():
    contexto = cti({"nivel": "baja", "edad_dias": 40, "fuentes": ["threatfox"]},
                   {"nivel": "media", "edad_dias": 50, "fuentes": ["urlhaus"]})
    assert ev({"cti.nivel_en": ["media", "baja"]}, contexto=contexto) is True
    assert ev({"cti.nivel_en": ["alta"]}, contexto=contexto) is False
    assert ev({"cti.antiguedad_mayor": {"dias": 30}}, contexto=contexto) is True
    assert ev({"cti.antiguedad_mayor": {"dias": 45}}, contexto=contexto) is False
    assert ev({"cti.una_sola_fuente": {}}, contexto=contexto) is True
    assert ev({"cti.una_sola_fuente": {}}, contexto=cti({"fuentes": ["a", "b"]})) is False
    for spec in ({"cti.nivel_en": ["alta"]}, {"cti.antiguedad_mayor": {}}, {"cti.una_sola_fuente": {}}):
        assert ev(spec, contexto=cti()) is None


def test_cti_retirado_del_feed():
    alerta = {"red": {"dominio": "malo.example"}}
    spec = {"cti.retirado_del_feed": {"dias_minimos": 25}}
    assert ev(spec, alerta=alerta) is None
    assert ev(spec, alerta=alerta, contexto=cti(retirados=[{"valor": "MALO.example", "primera_vez_dias": 30}])) is True
    assert ev(spec, alerta=alerta, contexto=cti(retirados=[{"valor": "malo.example", "primera_vez_dias": 10}])) is False


def test_cti_kev():
    alerta = {"titulo": "Explotacion de CVE-2021-44228"}
    assert ev({"cti.kev": {}}, alerta=alerta, contexto=cti(kev=["cve-2021-44228"])) is True
    assert ev({"cti.kev": {}}, alerta=alerta, contexto=cti(kev=[])) is False
    assert ev({"cti.kev": {}}, alerta=alerta) is None
    assert ev({"cti.kev": {}}, contexto=cti(kev=["CVE-2021-44228"])) is None


def test_dns_proveedor_cdn():
    alerta = {"red": {"ip_destino": IP_PUBLICA}}
    spec = {"dns.proveedor_cdn": {}}
    assert ev(spec, alerta=alerta) is None
    assert ev(spec, alerta=alerta, contexto={"dns": {IP_PUBLICA: {"ptr": "server-1.mad50.r.cloudfront.net."}}}) is True
    assert ev(spec, alerta=alerta, contexto={"dns": {IP_PUBLICA: {"ptr": "vps-123.hosting.example"}}}) is False
    assert ev(spec, alerta=alerta, contexto={"dns": {IP_PUBLICA: {"cdn": False, "ptr": "x.cloudfront.net"}}}) is False
    assert ev(spec, alerta={"red": {"dominio": "cdn.ejemplo.example"}},
              contexto={"dns": {"cdn.ejemplo.example": {"cdn": True}}}) is True


def test_plazo_regulatorio():
    spec = {"regulatorio.plazo_menor_horas": {"horas": 24}}
    assert ev(spec) is None
    assert ev(spec, contexto={"plazos": []}) is False
    assert ev(spec, contexto={"plazos": [{"marco": "nis2", "horas_restantes": 5}]}) is True
    assert ev(spec, contexto={"plazos": [{"marco": "rgpd", "horas_restantes": 70}]}) is False
