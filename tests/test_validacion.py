"""
Validacion del catalogo compilado (validacion.validar) y de los perfiles de
cliente (clientes.validar_perfil y la recarga de la carpeta clientes/).
"""
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path

import pytest
import yaml

from responselab import clientes, nucleo, validacion

RAIZ = Path(__file__).resolve().parent.parent
PERFILES_REALES = sorted(p.name for p in (RAIZ / "clientes").glob("*.yml") if not p.name.startswith("_"))


# ============================================================================
# Catalogo real
# ============================================================================

def test_catalogo_real_sin_errores(catalogo_datos):
    errores, _avisos, metricas = validacion.validar(catalogo_datos, validacion.cargar_contratos())
    assert errores == []
    assert metricas["reglas"] == len(catalogo_datos["reglas"])
    assert sum(metricas["reglas_por_origen"].values()) == len(catalogo_datos["reglas"])
    assert metricas["acciones_catalogo"] == len(catalogo_datos["acciones"])
    assert set(metricas["familias"]) == set(catalogo_datos["familias"])
    assert metricas["modos_critico"], "la simulacion en auto_contener no produjo acciones"


def test_avisos_del_catalogo_real_no_son_errores(catalogo_datos):
    errores, avisos, _ = validacion.validar(catalogo_datos, None)
    assert errores == []
    assert any("k8s.acordonar_nodo" in a and "declara radio objeto en DetectionLab" in a for a in avisos)


def test_validar_no_toca_el_catalogo(catalogo_datos):
    antes = copy.deepcopy(catalogo_datos)
    validacion.validar(catalogo_datos, None)
    assert catalogo_datos == antes


def test_alerta_completa_da_objetivo_a_todas_las_acciones(catalogo_datos):
    a = validacion.alerta_completa(catalogo_datos["reglas"][0])
    for nombre, meta in sorted(catalogo_datos["acciones"].items()):
        ok, _objetivo, falta = nucleo.requisito(a, meta.get("requiere"))
        assert ok, f"{nombre}: la alerta sintetica no trae {falta}"


# ============================================================================
# Catalogos rotos
# ============================================================================

def _accion(nombre: str, **cambios):
    def romper(datos: dict) -> None:
        datos["acciones"][nombre].update(cambios)
    return romper


def _contencion(familia: str, cual: str, **cambios):
    """Cambia la primera entrada de contencion de la familia cuya accion es `cual`."""
    def romper(datos: dict) -> None:
        next(c for c in datos["familias"][familia]["contencion"] if c["accion"] == cual).update(cambios)
    return romper


def _secuencia(**cambios):
    def romper(datos: dict) -> None:
        datos["secuencias"][0].update(cambios)
    return romper


def _wazuh_repetido(datos: dict) -> None:
    copias = next(r for r in datos["reglas"] if r["clave"] == "dl:soc_edr_003_borrado_copias_sombra")
    copias["wazuh_ids"] = list(copias["wazuh_ids"]) + ["101206"]


ROTURAS = [
    pytest.param(_accion("endpoint.aislar", radio="planeta"),
                 "accion endpoint.aislar: radio 'planeta' no valido", id="radio-de-accion"),
    pytest.param(_accion("endpoint.aislar", reversible=False),
                 "accion endpoint.aislar: reversible=False; debe ir entrecomillado", id="reversible-booleano"),
    pytest.param(_accion("endpoint.aislar", capacidad="telepatia"),
                 "accion endpoint.aislar: capacidad 'telepatia' desconocida", id="capacidad"),
    pytest.param(_accion("endpoint.aislar", conectores=["wazuh", "skynet"]),
                 "accion endpoint.aislar: conector 'skynet' desconocido", id="conector"),
    pytest.param(_accion("endpoint.aislar", deshacer="endpoint.desaislar"),
                 "accion endpoint.aislar: su inversa 'endpoint.desaislar' no existe", id="inversa"),
    pytest.param(_accion("endpoint.aislar", requiere=["Equipo.Nombre"]),
                 "accion endpoint.aislar: campo requerido mal escrito 'Equipo.Nombre'", id="campo-requerido"),
    pytest.param(_accion("endpoint.aislar", requiere=[]),
                 "INVARIANTE ROTA en dl:soc_edr_001_volcado_lsass (auto_contener): endpoint.aislar automatica sin objetivo",
                 id="accion-sin-objetivo"),
    pytest.param(_contencion("endpoint", "endpoint.aislar", accion="endpoint.teletransportar"),
                 "endpoint: accion 'endpoint.teletransportar' no esta en el catalogo", id="accion-inexistente"),
    pytest.param(_contencion("endpoint", "endpoint.aislar", radio="galaxia"),
                 "endpoint: radio 'galaxia' no valido en", id="radio-de-contencion"),
    pytest.param(_contencion("endpoint", "endpoint.aislar", reversible=False),
                 "endpoint: reversible=False en", id="reversible-de-contencion"),
    pytest.param(_contencion("endpoint", "endpoint.aislar", requiere_aprobacion="quizas"),
                 "endpoint: requiere_aprobacion='quizas' en", id="aprobacion-de-contencion"),
    pytest.param(_wazuh_repetido, "id de Wazuh 101206 repetido en", id="id-de-wazuh-repetido"),
    pytest.param(_secuencia(pasos=[["familia:astrologia"], ["soc_edr_003_borrado_copias_sombra"]]),
                 "secuencia ransomware: familia inexistente 'familia:astrologia'", id="familia-de-secuencia"),
    pytest.param(_secuencia(efecto={"escalar_a": "director_general"}),
                 "secuencia ransomware: escalar_a no valido", id="escalado-de-secuencia"),
]


@pytest.mark.parametrize("romper,error", ROTURAS)
def test_catalogo_roto_da_error(catalogo_datos, romper, error):
    datos = copy.deepcopy(catalogo_datos)
    romper(datos)
    errores, _avisos, _metricas = validacion.validar(datos, None)
    assert any(error in e for e in errores), errores[:5]


@pytest.mark.parametrize("donde", ["triaje", "cierre", "excepcion"])
def test_evaluador_desconocido_es_un_error_y_no_una_excepcion(catalogo_datos, donde):
    datos = copy.deepcopy(catalogo_datos)
    familia = datos["familias"]["endpoint"]
    desconocido = {"inventario.adivinar": {}}
    if donde == "triaje":
        familia["triaje"][0]["evaluador"] = desconocido
    elif donde == "cierre":
        familia["cierre"][0]["evaluador"] = desconocido
    else:
        next(c for c in familia["contencion"] if c["accion"] == "endpoint.aislar")["excepciones"] = [desconocido]
    errores, _avisos, _metricas = validacion.validar(datos, None)
    assert "endpoint: evaluador desconocido 'inventario.adivinar'" in errores


def test_validar_detecta_accion_de_radio_amplio_marcada_como_registro(catalogo_datos):
    datos = copy.deepcopy(catalogo_datos)
    datos["acciones"]["flota.bloquear_hash"]["registro"] = True
    errores, _avisos, _metricas = validacion.validar(datos, None)
    assert any("INVARIANTE ROTA" in e and "flota.bloquear_hash" in e for e in errores)


# ============================================================================
# Contratos con los proyectos vecinos
# ============================================================================

def _sin_fuente(c: dict) -> None:
    del c["newscti"]


def _malpipe_sin_veredicto(c: dict) -> None:
    c["malpipe"]["modelos"]["Report"].remove("verdict")


def _ftriage_sin_opcion(c: dict) -> None:
    c["ftriagedfir"]["opciones_triage"].remove("--case")


def _ftriage_sin_iocs(c: dict) -> None:
    del c["ftriagedfir"]["informe"]["iocs"]


def _newscti_sin_iocs(c: dict) -> None:
    c["newscti"]["claves"].remove("iocs")


@pytest.mark.parametrize("romper,error", [
    pytest.param(_sin_fuente, "contrato newscti: no sincronizado", id="fuente-ausente"),
    pytest.param(_malpipe_sin_veredicto, "Malpipe cambio su formato: Report ya no tiene ['verdict']", id="malpipe"),
    pytest.param(_ftriage_sin_opcion, "FtriageDFIR cambio su CLI: faltan ['--case']", id="ftriage-cli"),
    pytest.param(_ftriage_sin_iocs, "FtriageDFIR cambio su informe: faltan ['iocs']", id="ftriage-informe"),
    pytest.param(_newscti_sin_iocs, "News CTI cambio su formato: claves sin ['iocs']", id="newscti"),
])
def test_contrato_roto_con_un_proyecto_vecino(catalogo_datos, romper, error):
    contratos = copy.deepcopy(validacion.cargar_contratos())
    romper(contratos)
    errores, _avisos, _metricas = validacion.validar(catalogo_datos, contratos)
    assert any(e.startswith(error) for e in errores), errores


# ============================================================================
# Perfiles de cliente
# ============================================================================

def cargar_perfil(fichero: str) -> dict:
    return yaml.safe_load((RAIZ / "clientes" / fichero).read_text(encoding="utf-8"))


def poner(perfil: dict, ruta: str, valor) -> None:
    actual = perfil
    *camino, ultima = ruta.split(".")
    for parte in camino:
        actual = actual.setdefault(parte, {})
    actual[ultima] = valor


def test_estan_los_perfiles_de_ejemplo():
    assert {"lab.yml", "acme.yml", "norte.yml"} <= set(PERFILES_REALES)


@pytest.mark.parametrize("fichero", PERFILES_REALES)
def test_perfiles_reales_sin_errores(fichero):
    assert clientes.validar_perfil(cargar_perfil(fichero)) == []


@pytest.mark.parametrize("clave", ["api_key", "clave", "secreto", "password", "token", "client_secret"])
def test_secreto_en_claro_en_un_conector(perfil_lab, clave):
    perfil_lab["conectores"]["wazuh"][clave] = "valor-en-claro"
    assert clientes.validar_perfil(perfil_lab) == [
        f"conectores.wazuh.{clave}: secreto en claro; usa {clave}_env con el nombre de una variable"]


def test_nombre_de_variable_no_es_un_secreto(perfil_lab):
    perfil_lab["conectores"]["thehive"]["api_key_env"] = "RL_LAB_OTRA_CLAVE"
    perfil_lab["conectores"]["wazuh"]["clave_env"] = "RL_LAB_OTRA_CLAVE_WAZUH"
    assert clientes.validar_perfil(perfil_lab) == []


@pytest.mark.parametrize("ruta,valor", [
    pytest.param("conectores.cloudflare.api_token", "0123456789abcdef-token-real", id="api_token"),
    pytest.param("conectores.teams.webhook", "https://acme.webhook.office.com/webhookb2/secreto", id="webhook"),
    pytest.param("autenticacion.token", "token-de-ingesta-en-claro", id="token-de-ingesta"),
])
def test_validar_perfil_rechaza_otros_secretos_en_claro(perfil_acme, ruta, valor):
    poner(perfil_acme, ruta, valor)
    errores = clientes.validar_perfil(perfil_acme)
    assert any(ruta.rsplit(".", 1)[-1] in e and "en claro" in e for e in errores), errores


def test_validar_perfil_rechaza_horas_de_ventana_sin_comillas():
    perfil = yaml.safe_load("id: planta\nventanas:\n  - {tipo: mantenimiento, dias: [do], desde: 06:00, hasta: 14:00}\n")
    assert perfil["ventanas"][0]["hasta"] == 840
    assert clientes.validar_perfil(perfil) != []


@pytest.mark.parametrize("cambio,error", [
    pytest.param({"id": ""}, "falta id", id="sin-id"),
    pytest.param({"modo": "pruebas"}, "modo 'pruebas' no valido (simulacion, produccion)", id="modo"),
    pytest.param({"politica": {"excepcion_sin_datos": "quizas"}},
                 "politica.excepcion_sin_datos debe ser 'aprobacion' o 'ignorar'", id="excepcion-sin-datos"),
    pytest.param({"aprobadores": [{"nombre": "Sin token", "email": "x@lab.test"}]},
                 "aprobador Sin token: sin token_sha256 ni token_env", id="aprobador-sin-token"),
])
def test_perfil_mal_formado(perfil_lab, cambio, error):
    perfil_lab.update(cambio)
    assert error in clientes.validar_perfil(perfil_lab)


# ============================================================================
# Recarga de la carpeta de perfiles
# ============================================================================

def escribir(ruta: Path, perfil: dict) -> None:
    """Reescribe el perfil y mueve su mtime, por si el sistema de ficheros tiene poca resolucion."""
    ruta.write_text(yaml.safe_dump(perfil, allow_unicode=True), encoding="utf-8")
    st = ruta.stat()
    os.utime(ruta, ns=(st.st_atime_ns, st.st_mtime_ns + 2_000_000_000))


def test_carga_los_perfiles_y_no_la_plantilla(carpeta_clientes):
    c = clientes.Clientes(carpeta_clientes)
    assert set(c.perfiles) == {"lab", "acme", "norte"}
    assert c.errores == {}
    assert {p["id"] for p in c.todos()} == {"lab", "acme", "norte"}


def test_perfil_borrado_desaparece_al_recargar(carpeta_clientes):
    c = clientes.Clientes(carpeta_clientes)
    (carpeta_clientes / "acme.yml").unlink()
    assert c.recargar() is True
    assert c.get("acme") is None and "acme" not in c.perfiles
    assert c.get("lab") is not None
    assert c.recargar() is False


def test_perfil_invalido_no_sustituye_al_bueno(carpeta_clientes):
    c = clientes.Clientes(carpeta_clientes)
    ruta = carpeta_clientes / "lab.yml"
    perfil = yaml.safe_load(ruta.read_text(encoding="utf-8"))
    perfil["conectores"]["wazuh"]["clave"] = "en-claro"
    escribir(ruta, perfil)
    c.recargar()
    assert c.errores["lab.yml"] == ["conectores.wazuh.clave: secreto en claro; usa clave_env con el nombre de una variable"]
    assert "clave" not in c.get("lab")["conectores"]["wazuh"]


def test_perfil_corregido_vuelve_a_cargarse(carpeta_clientes):
    c = clientes.Clientes(carpeta_clientes)
    ruta = carpeta_clientes / "lab.yml"
    perfil = yaml.safe_load(ruta.read_text(encoding="utf-8"))
    perfil["nombre"] = "Laboratorio renombrado"
    escribir(ruta, perfil)
    assert c.recargar() is True
    assert c.get("lab")["nombre"] == "Laboratorio renombrado"


def test_yaml_invalido_no_tumba_la_carga(carpeta_clientes):
    (carpeta_clientes / "roto.yml").write_text("id: [sin cerrar\n", encoding="utf-8")
    c = clientes.Clientes(carpeta_clientes)
    assert c.errores["roto.yml"][0].startswith("YAML invalido")
    assert set(c.perfiles) == {"lab", "acme", "norte"}


def test_perfil_inactivo_no_se_sirve(carpeta_clientes):
    ruta = carpeta_clientes / "norte.yml"
    perfil = yaml.safe_load(ruta.read_text(encoding="utf-8"))
    perfil["activo"] = False
    escribir(ruta, perfil)
    c = clientes.Clientes(carpeta_clientes)
    assert c.get("norte") is None
    assert "norte" not in {p["id"] for p in c.todos()}


def test_huella_es_el_sha256_del_token():
    assert clientes.huella("token-ingesta-lab") == hashlib.sha256(b"token-ingesta-lab").hexdigest()
    assert clientes.Clientes._casa_token("x", {"token_sha256": clientes.huella("x").upper()}) is True
    assert clientes.Clientes._casa_token("y", {"token_sha256": clientes.huella("x")}) is False


def test_tokens_por_variable_de_entorno(carpeta_clientes, entorno_tokens):
    c = clientes.Clientes(carpeta_clientes)
    assert c.token_ingesta_valido("lab", entorno_tokens["RL_LAB_TOKEN"]) is True
    assert c.token_ingesta_valido("lab", "otro-token") is False
    assert c.token_agente_valido("lab", entorno_tokens["RL_LAB_TOKEN_AGENTES"]) is True
    assert c.token_edl_valido("lab", entorno_tokens["RL_LAB_TOKEN_EDL"]) is True
    assert c.aprobador("lab", entorno_tokens["RL_LAB_TOKEN_APROBADOR"])["nombre"] == "Analista del laboratorio"
    assert c.aprobador("lab", entorno_tokens["RL_LAB_TOKEN"]) is None
    # ACME trae huellas de ejemplo: ningun token casa con ellas
    assert c.token_ingesta_valido("acme", "cualquier-cosa") is False


def test_capacidades_incluyen_siempre_la_interna(perfil_acme):
    caps = clientes.Clientes.capacidades(perfil_acme)
    assert caps["interno"] == ["interno"]
    assert (caps["edr"], caps["perimetro"]) == (["defender"], ["paloalto", "edl"])
