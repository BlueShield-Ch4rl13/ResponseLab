"""
Normalizacion: la alerta nativa de cada SIEM al esquema comun del nucleo, y
busqueda de su regla en el catalogo.

Las cargas de escenarios/*.yml son alertas reales en el formato de cada SIEM y
se reutilizan aqui como entradas. Los casos limite van escritos a mano.
"""
from __future__ import annotations

import copy
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from responselab import nucleo

RAIZ = Path(__file__).resolve().parent.parent
ESCENARIOS = RAIZ / "escenarios"
LSASS = "dl:soc_edr_001_volcado_lsass"
# Las direcciones de documentacion de los escenarios (203.0.113.0/24,
# 198.51.100.0/24) son "privadas" para ipaddress; esta es publica de verdad.
IP_PUBLICA = "185.220.101.4"
REF = datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)
# Zona POSIX (UTC-5 con horario de verano): no necesita ficheros de zoneinfo
ZONA_LEJANA = "EST5EDT,M3.2.0,M11.1.0"


def escenario(nombre: str) -> dict:
    return yaml.safe_load((ESCENARIOS / f"{nombre}.yml").read_text(encoding="utf-8"))


def carga(nombre: str, n: int) -> dict:
    """Carga nativa de la alerta n (desde 1) de un escenario, copiada para poder tocarla."""
    return copy.deepcopy(escenario(nombre)["alertas"][n - 1]["carga"])


def generica(**campos) -> dict:
    """Alerta escrita ya en el esquema comun (SIEM generico)."""
    campos.setdefault("titulo", "alerta de prueba")
    return nucleo.normalizar("generico", campos)


def _alertas_de_los_escenarios() -> list:
    salida = []
    for fichero in sorted(ESCENARIOS.glob("*.yml")):
        esc = yaml.safe_load(fichero.read_text(encoding="utf-8"))
        for i, alerta in enumerate(esc["alertas"], 1):
            salida.append(pytest.param(alerta["siem"], alerta["carga"], id=f"{fichero.stem}-{i}"))
    return salida


@pytest.fixture
def zona_del_host(monkeypatch):
    """Cambia la zona horaria del proceso (TZ) y la deja como estaba al acabar."""
    if not hasattr(time, "tzset"):
        pytest.skip("time.tzset no existe en esta plataforma")

    def cambiar(nombre: str) -> None:
        monkeypatch.setenv("TZ", nombre)
        time.tzset()

    yield cambiar
    monkeypatch.undo()
    time.tzset()


# ============================================================================
# Esquema comun
# ============================================================================

@pytest.mark.parametrize("siem,carga_nativa", _alertas_de_los_escenarios())
def test_toda_alerta_de_los_escenarios_cumple_el_esquema(siem, carga_nativa):
    original = copy.deepcopy(carga_nativa)
    a = nucleo.normalizar(siem, carga_nativa, "lab")
    assert a["siem"] == siem and a["cliente"] == "lab"
    assert a["id"] and a["titulo"]
    assert set(nucleo.alerta_vacia(siem)) <= set(a)
    assert all(set(o) == {"tipo", "valor"} and o["valor"] for o in a["observables"])
    assert carga_nativa == original, "normalizar no debe modificar la carga recibida"
    assert a["bruto"] == original


def test_siem_no_soportado_se_rechaza():
    with pytest.raises(ValueError, match="SIEM no soportado"):
        nucleo.normalizar("qradar", {"titulo": "x"})


def test_siem_vacio_es_el_generico():
    assert nucleo.normalizar("", {"titulo": "x"})["siem"] == "generico"


# ============================================================================
# Wazuh (Sysmon, accesslog, Falco, Tetragon, auditd, office365, Kubernetes)
# ============================================================================

def test_wazuh_sysmon_vssadmin_del_sistema_no_es_fichero_objetivo():
    a = nucleo.normalizar("wazuh", carga("ransomware-puesto", 2), "lab")
    p = a["proceso"]
    assert p["imagen"] == "C:\\Windows\\System32\\vssadmin.exe"
    assert (p["imagen_nombre"], p["padre_nombre"]) == ("vssadmin.exe", "upd.exe")
    assert p["guid"] == "3f1c0a2b-1111-2222-3333-777788889999"
    assert p["pid"] == 6388
    assert p["sha256"] == "7e1b4c6f0a2d9e8b3c5a7f1e9d2b4c6a8f0e1d3c5b7a9e2f4d6c8b0a1e3f5d7c"
    assert p["sha1"] == "4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b"
    # Ni la ruta ni los hashes del binario del sistema pasan a ser el fichero objetivo
    assert a["fichero"] == {}
    assert a["equipo"] == {"nombre": "CORP-FIN-07", "ip": "10.0.20.57", "id_agente": "007", "so": "windows"}
    assert a["usuario"] == {"nombre": "jgarcia", "dominio": "LAB"}
    assert (a["regla_id"], a["familia_pista"], a["severidad_pista"]) == ("101211", "endpoint", 4)
    assert a["tecnicas"] == ["T1490"]


def test_wazuh_fichero_explicito_manda_sobre_la_imagen():
    a = nucleo.normalizar("wazuh", carga("ransomware-puesto", 3), "lab")
    assert a["proceso"]["imagen"] == "C:\\Users\\jgarcia\\AppData\\Local\\Temp\\upd.exe"
    assert a["fichero"] == {"ruta": "C:\\Users\\jgarcia\\Documents\\nominas-2026.xlsx.locked",
                            "nombre": "nominas-2026.xlsx.locked"}


def test_wazuh_registro_de_acceso_web():
    a = nucleo.normalizar("wazuh", carga("explotacion-web-produccion", 1), "lab")
    assert a["http"] == {"uri": "/productos.php?id=1%27%20UNION%20SELECT%20usuario,clave%20FROM%20usuarios--",
                         "metodo": "GET", "estado": "200"}
    assert a["red"] == {"ip_origen": "198.51.100.23"}
    assert "sqlmap" in a["descripcion"]


@pytest.mark.parametrize("nivel,severidad", [(15, 4), (14, 4), (13, 3), (12, 3), (10, 2), (8, 2), (7, 1), (3, 1)])
def test_wazuh_severidad_pista_por_nivel(nivel, severidad):
    c = {"id": "w-1", "rule": {"id": "999001", "level": nivel, "description": "x"}}
    assert nucleo.normalizar("wazuh", c)["severidad_pista"] == severidad


def test_wazuh_info_y_grupos_dan_las_pistas():
    c = {"id": "w-2", "rule": {"id": "999002", "level": 15, "description": "x",
                              "groups": ["soc_endpoint", "auto_contener", "cti_ip"],
                              "info": "playbook=ad severidad_thehive=2 origen=ad_013_dcshadow.yml"}}
    a = nucleo.normalizar("wazuh", c)
    assert a["familia_pista"] == "ad"          # info manda sobre el grupo soc_endpoint
    assert a["severidad_pista"] == 2           # severidad_thehive manda sobre el nivel
    assert a["regla_fichero"] == "ad_013_dcshadow.yml"
    assert a["clase_pista"] == "auto_contener"
    assert a["cti_tipo"] == "ip"


@pytest.mark.parametrize("grupos,familia", [(["soc_ad"], "ad"), (["windows", "soc_xdr"], "xdr"),
                                            (["soc_inventada"], ""), ([], "")])
def test_wazuh_familia_por_grupo_soc(grupos, familia):
    c = {"id": "w-3", "rule": {"id": "999003", "level": 10, "description": "x", "groups": grupos}}
    assert nucleo.normalizar("wazuh", c)["familia_pista"] == familia


def test_wazuh_carga_reducida_de_detectionlab():
    c = {"origen": "detection-lab", "wazuh_id": "1727780400.55", "regla_id": "101206",
         "regla_sigma": "soc_edr_001_volcado_lsass.yml", "playbook": "endpoint",
         "clase_automatizacion": "auto_contener", "severidad": 4, "descripcion": "Volcado de memoria de LSASS",
         "mitre": ["t1003.001"], "marca_tiempo": "2026-10-01T10:00:00Z", "agente": "PC-0042",
         "agente_ip": "10.0.20.42",
         "observables": {"ip": IP_PUBLICA, "hash": "SHA256=" + "C" * 64, "usuario": "LAB\\jgarcia"}}
    a = nucleo.normalizar("wazuh", c, "lab")
    assert a["id"] == "1727780400.55"
    assert (a["regla_id"], a["regla_fichero"]) == ("101206", "soc_edr_001_volcado_lsass.yml")
    assert (a["familia_pista"], a["clase_pista"], a["severidad_pista"]) == ("endpoint", "auto_contener", 4)
    assert a["tecnicas"] == ["T1003.001"]
    assert a["momento"] == "2026-10-01T10:00:00Z"
    assert a["equipo"] == {"nombre": "PC-0042", "ip": "10.0.20.42"}
    assert a["usuario"] == {"nombre": "jgarcia", "dominio": "LAB"}
    assert a["proceso"]["sha256"] == "c" * 64
    assert {"tipo": "ip", "valor": IP_PUBLICA} in a["observables"]
    assert {"tipo": "hash", "valor": "c" * 64} in a["observables"]


def test_falco_campos_con_punto():
    a = nucleo.normalizar("wazuh", carga("intrusion-ssh-dmz", 2), "lab")
    p = a["proceso"]
    assert (p["imagen"], p["linea"], p["pid"]) == ("/usr/bin/bash", "bash -i", 2304)
    assert (p["padre_imagen"], p["padre_nombre"]) == ("/usr/sbin/sshd", "sshd")
    assert a["usuario"] == {"nombre": "root"}
    assert a["fichero"] == {}                  # bash es del sistema


def test_falco_en_kubernetes_con_fichero_sensible():
    c = {"id": "falco-k8s", "timestamp": "2026-10-01T10:00:00Z",
         "rule": {"id": "110012", "level": 12, "description": "Falco: lectura de fichero sensible"},
         "agent": {"id": "031", "name": "k8s-nodo-2"},
         "data": {"rule": "Read sensitive file untrusted", "output_fields": {
             "proc.exepath": "/usr/bin/cat", "proc.cmdline": "cat /etc/shadow", "proc.pid": 4242,
             "proc.pname": "sh", "user.name": "www-data", "fd.name": "/etc/shadow",
             "k8s.ns.name": "tienda", "k8s.pod.name": "web-7d9f",
             "container.image.repository": "registry.lab.test/tienda/web"}}}
    a = nucleo.normalizar("wazuh", c, "lab")
    assert a["fichero"] == {"ruta": "/etc/shadow", "nombre": "shadow"}
    assert a["k8s"] == {"namespace": "tienda", "pod": "web-7d9f", "imagen": "registry.lab.test/tienda/web"}
    assert (a["proceso"]["imagen"], a["proceso"]["padre_imagen"]) == ("/usr/bin/cat", "sh")
    assert a["usuario"] == {"nombre": "www-data"}


def test_falco_descriptor_que_no_es_ruta_no_es_fichero():
    c = {"id": "falco-red", "rule": {"id": "110013", "level": 10, "description": "Falco: conexion saliente"},
         "data": {"output_fields": {"proc.exepath": "/usr/bin/nc", "proc.pid": 77,
                                    "fd.name": "10.0.0.5:51514->185.220.101.4:4444"}}}
    assert nucleo.normalizar("wazuh", c)["fichero"] == {}


def test_tetragon_kprobe_con_fichero_en_los_argumentos():
    a = nucleo.normalizar("wazuh", carga("intrusion-ssh-dmz", 3), "lab")
    p = a["proceso"]
    assert (p["pid"], p["imagen"], p["padre_imagen"]) == (2391, "/usr/bin/cat", "/usr/bin/bash")
    assert p["linea"] == "/usr/bin/cat /etc/shadow"
    assert p["inicio"] == "2026-10-01T03:21:44.102Z"
    assert a["fichero"] == {"ruta": "/etc/shadow", "nombre": "shadow"}


def test_tetragon_process_exec():
    a = nucleo.normalizar("wazuh", carga("explotacion-web-produccion", 2), "lab")
    p = a["proceso"]
    assert (p["pid"], p["imagen"], p["padre_imagen"]) == (48211, "/bin/sh", "/usr/sbin/php-fpm8.2")
    assert p["linea"] == "/bin/sh -c id;uname -a;cat /etc/passwd"
    assert p["inicio"] == "2026-10-01T08:03:02.881Z"
    assert a["fichero"] == {}


def test_tetragon_exec_id_conserva_las_mayusculas():
    a = nucleo.normalizar("wazuh", carga("explotacion-web-produccion", 2), "lab")
    assert a["proceso"]["guid"] == "U1JWLVdFQi0wMTo0ODIxMQ=="


def test_guid_de_windows_sin_llaves_y_en_minusculas():
    a = generica(proceso={"guid": "{3F1C0A2B-1111-2222-3333-444455556666}"})
    assert a["proceso"]["guid"] == "3f1c0a2b-1111-2222-3333-444455556666"


def test_wazuh_auditd():
    c = {"id": "aud-1", "rule": {"id": "80792", "level": 10, "description": "Audit: ejecucion desde /tmp"},
         "agent": {"name": "victima-dmz"},
         "data": {"audit": {"pid": "3121", "exe": "/tmp/.x/kworkerd", "auid": "1001",
                            "execve": {"a0": "/tmp/.x/kworkerd", "a1": "-c", "a2": f"{IP_PUBLICA}:4444"}}}}
    a = nucleo.normalizar("wazuh", c)
    assert (a["proceso"]["pid"], a["proceso"]["imagen"]) == (3121, "/tmp/.x/kworkerd")
    assert a["proceso"]["linea"] == f"/tmp/.x/kworkerd -c {IP_PUBLICA}:4444"
    assert a["usuario"] == {"nombre": "1001"}
    assert a["fichero"] == {"ruta": "/tmp/.x/kworkerd", "nombre": "kworkerd"}


def test_wazuh_auditoria_de_kubernetes():
    c = {"id": "k8s-1", "rule": {"id": "87910", "level": 12, "description": "K8s: ClusterRoleBinding creado"},
         "data": {"objectRef": {"resource": "clusterrolebindings", "name": "admin-puerta-trasera"},
                  "user": {"username": "system:serviceaccount:dev:ci"}}}
    a = nucleo.normalizar("wazuh", c)
    assert a["k8s"] == {"sujeto": "system:serviceaccount:dev:ci",
                        "rolebinding": "clusterrolebindings/admin-puerta-trasera"}
    c["data"]["objectRef"] = {"resource": "pods", "namespace": "tienda", "name": "web-1"}
    assert nucleo.normalizar("wazuh", c)["k8s"] == {"namespace": "tienda", "pod": "web-1",
                                                     "sujeto": "system:serviceaccount:dev:ci"}


# ============================================================================
# Guarda de rutas del sistema: el binario que lanza el atacante no es su fichero
# ============================================================================

RUTAS_DEL_SISTEMA = [
    "C:\\Windows\\System32\\vssadmin.exe",
    "c:\\windows\\syswow64\\rundll32.exe",
    "\"C:\\Windows\\System32\\cmd.exe\"",
    "\\\\?\\C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
    "%SystemRoot%\\System32\\sc.exe",
    "/usr/bin/bash",
    "/usr/sbin/sshd",
    "/bin/sh",
    "/sbin/init",
    "/usr/lib/systemd/systemd",
    "/usr/libexec/openssh/sftp-server",
    "/lib64/ld-linux-x86-64.so.2",
    "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
]


@pytest.mark.parametrize("imagen", RUTAS_DEL_SISTEMA)
def test_imagen_del_sistema_nunca_es_fichero_objetivo(imagen):
    a = generica(proceso={"imagen": imagen, "sha256": "a" * 64, "sha1": "b" * 40})
    assert nucleo.ruta_sistema(imagen)
    assert a["fichero"] == {}
    # el hash sigue siendo observable del proceso, no objetivo de una accion de fichero
    assert {"tipo": "hash", "valor": "a" * 64} in a["observables"]


@pytest.mark.parametrize("imagen,nombre", [
    ("C:\\Users\\Public\\svc.exe", "svc.exe"),
    ("C:\\Users\\jgarcia\\AppData\\Local\\Temp\\upd.exe", "upd.exe"),
    ("C:\\ProgramData\\actualizador\\agente.exe", "agente.exe"),
    ("/tmp/.x/kworkerd", "kworkerd"),
    ("/home/dev/.cache/minero", "minero"),
])
def test_imagen_fuera_del_sistema_es_el_fichero_objetivo(imagen, nombre):
    a = generica(proceso={"imagen": imagen, "sha256": "a" * 64, "md5": "c" * 32})
    assert a["fichero"] == {"ruta": imagen, "nombre": nombre, "sha256": "a" * 64, "md5": "c" * 32}
    # el mismo hash no se repite en los observables
    assert [o["valor"] for o in a["observables"]].count("a" * 64) == 1


def test_guarda_de_rutas_del_sistema_cubre_usr_lib64():
    ruta = "/usr/lib64/libc.so.6"
    assert nucleo.ruta_sistema(ruta)
    assert generica(proceso={"imagen": ruta})["fichero"] == {}
    plan = {"acciones": [{"id": "c1", "accion": "fichero.cuarentena", "modo": "automatica", "radio": "objeto",
                          "reversible": "si", "objetivo": {"fichero.ruta": ruta}}]}
    assert nucleo.verificar_invariantes(plan, generica(fichero={"ruta": ruta}))


FALCO_SOLO_NOMBRE = {
    "id": "falco-1", "timestamp": "2026-10-01T10:00:00Z",
    "rule": {"id": "110010", "level": 10, "description": "SOC/Falco: shell interactiva detectada"},
    "agent": {"id": "012", "name": "victima-dmz"},
    "data": {"output_fields": {"proc.name": "bash", "proc.cmdline": "bash -i", "proc.pid": 2304}},
}
NOTABLE_SIN_RUTA = {
    "search_name": "Endpoint - DL - Destruccion de copias de seguridad y puntos de restauracion - Rule",
    "event_id": "notable-77", "dest": "PC-0042", "user": "LAB\\jgarcia", "urgency": "critical",
    "process": "vssadmin.exe delete shadows /all /quiet", "process_name": "vssadmin.exe",
}


@pytest.mark.parametrize("siem,carga_nativa", [
    pytest.param("wazuh", FALCO_SOLO_NOMBRE, id="falco-proc-name"),
    pytest.param("splunk", NOTABLE_SIN_RUTA, id="splunk-cim-process"),
])
def test_imagen_sin_ruta_absoluta_no_es_fichero_objetivo(siem, carga_nativa):
    a = nucleo.normalizar(siem, copy.deepcopy(carga_nativa))
    assert "ruta" not in a["fichero"], a["fichero"]


# ============================================================================
# Usuarios, IPs y observables
# ============================================================================

@pytest.mark.parametrize("valor,esperado", [
    ("LAB\\jgarcia", ("jgarcia", "LAB", None)),
    ("pruiz@acme.test", ("pruiz", "acme.test", "pruiz@acme.test")),
    ("  LAB\\svc_backup  ", ("svc_backup", "LAB", None)),
    ("root", ("root", None, None)),
    ("", (None, None, None)),
    (None, (None, None, None)),
])
def test_partir_usuario(valor, esperado):
    assert nucleo.partir_usuario(valor) == esperado


def test_usuario_dominio_con_barra_invertida():
    a = nucleo.normalizar("wazuh", carga("ransomware-puesto", 1), "lab")
    assert a["usuario"] == {"nombre": "jgarcia", "dominio": "LAB"}


def test_usuario_upn():
    a = nucleo.normalizar("splunk", carga("exfiltracion-tras-acceso", 2), "acme")
    assert a["usuario"] == {"nombre": "pruiz", "dominio": "acme.test", "upn": "pruiz@acme.test"}


def test_usuario_no_pisa_dominio_ni_upn_que_ya_vienen():
    a = generica(usuario={"nombre": "LAB\\jgarcia", "dominio": "lab.test"})
    assert a["usuario"] == {"nombre": "jgarcia", "dominio": "lab.test"}
    b = generica(usuario={"nombre": "jgarcia@lab.test", "upn": "j.garcia@lab.test"})
    assert b["usuario"] == {"nombre": "jgarcia", "dominio": "lab.test", "upn": "j.garcia@lab.test"}


def test_solo_las_ips_publicas_son_observables():
    a = generica(red={"ip_origen": "10.0.20.42", "ip_destino": IP_PUBLICA})
    assert [o for o in a["observables"] if o["tipo"] == "ip"] == [{"tipo": "ip", "valor": IP_PUBLICA}]


@pytest.mark.parametrize("ip", ["10.1.2.3", "172.16.5.4", "192.168.1.10", "127.0.0.1", "169.254.10.10",
                                "224.0.0.251", "fd00::1", "fe80::1", "::1"])
def test_ip_no_publica_no_es_observable(ip):
    assert generica(red={"ip_origen": ip, "ip_destino": ip})["observables"] == []


@pytest.mark.parametrize("ip", [IP_PUBLICA, "8.8.8.8", "2606:4700:4700::1111"])
def test_ip_publica_es_observable_una_sola_vez(ip):
    assert generica(red={"ip_origen": ip, "ip_destino": ip})["observables"] == [{"tipo": "ip", "valor": ip}]


def test_valor_que_no_es_ip_no_es_observable_ni_rompe():
    assert generica(red={"ip_destino": "no-es-una-ip"})["observables"] == []


def test_observables_de_url_dominio_y_remitente():
    a = nucleo.normalizar("sentinel", carga("phishing-a-cuenta", 1), "acme")
    assert a["red"]["dominio"] == "acme-portal-login.example"
    assert a["correo"]["dominio_remitente"] == "proveedor-falso.example"
    assert a["observables"] == [
        {"tipo": "dominio", "valor": "acme-portal-login.example"},
        {"tipo": "url", "valor": "https://acme-portal-login.example/o365/auth?u=lmartin"},
        {"tipo": "correo", "valor": "facturas@proveedor-falso.example"},
    ]


def test_url_con_ip_no_inventa_dominio():
    url = f"http://{IP_PUBLICA}:8080/x.sh"
    a = generica(red={"url": url})
    assert "dominio" not in a["red"]
    assert a["observables"] == [{"tipo": "url", "valor": url}]


def test_cve_del_titulo_y_tecnicas_normalizadas():
    a = generica(titulo="Explotacion de cve-2021-44228 en log4j", descripcion="y despues CVE-2023-4966",
                 tecnicas=["t1059.001", "T1059.001", "", None, "t1190"])
    assert a["cve"] == ["CVE-2021-44228", "CVE-2023-4966"]
    assert a["tecnicas"] == ["T1059.001", "T1190"]


# ============================================================================
# Sentinel
# ============================================================================

def incidente(titulo: str, nombres_alerta=(), entidades=(), **propiedades) -> dict:
    props = {"title": titulo, "severity": "High", "relatedEntities": list(entidades),
             "alerts": [{"properties": {"alertDisplayName": n}} for n in nombres_alerta]}
    props.update(propiedades)
    return {"object": {"name": "inc-0001", "properties": props}}


def test_sentinel_prefiere_el_nombre_de_la_alerta_al_titulo(catalogo):
    c = incidente("Incidente multietapa en PC-0042 con varias alertas", ["DL - Volcado de memoria de LSASS"])
    a = nucleo.normalizar("sentinel", c, "acme")
    assert a["id"] == "inc-0001"
    assert a["titulo"] == "Incidente multietapa en PC-0042 con varias alertas"
    assert a["regla_nombre"] == "DL - Volcado de memoria de LSASS"
    regla, _via = catalogo.buscar_regla(a)
    assert regla["clave"] == LSASS


def test_sentinel_salta_alertas_sin_nombre_y_si_no_hay_ninguna_usa_el_titulo():
    c = incidente("Incidente reescrito por Defender")
    c["object"]["properties"]["alerts"] = [{"properties": {}}, "no es un dict",
                                           {"properties": {"alertDisplayName": "DL - Cifrado masivo"}}]
    assert nucleo.normalizar("sentinel", c)["regla_nombre"] == "DL - Cifrado masivo"
    assert nucleo.normalizar("sentinel", incidente("DL - Volcado de memoria de LSASS"))["regla_nombre"] == \
        "DL - Volcado de memoria de LSASS"


def test_sentinel_entidades():
    entidades = [
        {"kind": "Host", "properties": {"hostName": "PC-0042", "osFamily": "Windows",
                                        "additionalData": {"MdatpDeviceId": "edr-0042"}}},
        {"kind": "Account", "properties": {"accountName": "lmartin", "upnSuffix": "acme.test", "ntDomain": "ACME",
                                           "aadUserId": "7f9e2c1a-0000-4000-8000-000000000001",
                                           "sid": "S-1-5-21-1-2-3-1104"}},
        {"kind": "Ip", "properties": {"address": IP_PUBLICA}},
        {"kind": "Ip", "properties": {"address": "10.0.20.42"}},
        {"kind": "FileHash", "properties": {"algorithm": "SHA256", "hashValue": "AB" * 32}},
        {"kind": "File", "properties": {"directory": "C:\\Users\\Public\\", "fileName": "svc.exe"}},
        {"kind": "Process", "properties": {"processId": "3300", "commandLine": "svc.exe -k",
                                           "creationTimeUtc": "2026-10-01T09:59:58Z"}},
        {"kind": "Url", "properties": {"url": "https://malo.example/carga"}},
        {"kind": "Mailbox", "properties": {"mailboxPrimaryAddress": "lmartin@acme.test"}},
        {"kind": "CloudApplication", "properties": {"appId": "4f3c", "appName": "Aplicacion OAuth"}},
    ]
    a = nucleo.normalizar("sentinel", incidente("DL - x", entidades=entidades, severity="Medium"))
    assert a["severidad_pista"] == 2
    assert a["equipo"] == {"nombre": "PC-0042", "id_edr": "edr-0042", "so": "Windows"}
    assert a["usuario"] == {"nombre": "lmartin", "dominio": "ACME", "upn": "lmartin@acme.test",
                            "id_nube": "7f9e2c1a-0000-4000-8000-000000000001", "sid": "S-1-5-21-1-2-3-1104"}
    assert (a["red"]["ip_origen"], a["red"]["ip_destino"]) == (IP_PUBLICA, "10.0.20.42")
    assert a["fichero"] == {"sha256": "ab" * 32, "nombre": "svc.exe", "ruta": "C:\\Users\\Public\\svc.exe"}
    assert (a["proceso"]["pid"], a["proceso"]["linea"]) == (3300, "svc.exe -k")
    assert (a["red"]["url"], a["red"]["dominio"]) == ("https://malo.example/carga", "malo.example")
    assert a["correo"] == {"buzon": "lmartin@acme.test"}
    assert a["nube"] == {"app_id": "4f3c", "app_nombre": "Aplicacion OAuth"}


# ============================================================================
# Splunk
# ============================================================================

def test_splunk_webhook_de_busqueda_guardada(catalogo):
    a = nucleo.normalizar("splunk", carga("escaner-autorizado", 1), "lab")
    assert a["regla_nombre"] == a["titulo"] == "DET-WEB-001 Escaneo de rutas"
    assert a["equipo"] == {"nombre": "SRV-WEB-01"}
    assert a["red"] == {"ip_origen": "10.0.30.50"}
    assert a["http"] == {"uri": "/admin/.env", "estado": "404"}
    regla, via = catalogo.buscar_regla(a)
    assert (regla["clave"], via) == ("splunklab:DET-WEB-001", "busqueda guardada de Splunk")


def test_splunk_id_del_webhook_con_sid_y_cd():
    c = {"search_name": "x", "sid": "scheduler__admin__search__RMD5", "result": {"_cd": "12:3456", "host": "PC-0042"}}
    assert nucleo.normalizar("splunk", c)["id"] == "scheduler__admin__search__RMD5:12:3456"


def test_splunk_sin_sid_recibe_un_id_determinista_y_propio():
    c1 = {"search_name": "DET-WEB-001 Escaneo de rutas", "result": {"clientip": "10.0.30.50", "host": "SRV-WEB-01"}}
    c2 = {"search_name": "DET-WEB-001 Escaneo de rutas", "result": {"clientip": IP_PUBLICA, "host": "SRV-WEB-01"}}
    a1, a2 = nucleo.normalizar("splunk", c1), nucleo.normalizar("splunk", c2)
    assert a1["id"] != a2["id"]
    assert a1["id"] == nucleo.normalizar("splunk", copy.deepcopy(c1))["id"]


def test_splunk_notable_plano_de_es(catalogo):
    c = {"search_name": "Threat - DL - Volcado de memoria de LSASS - Rule", "event_id": "4D8E@@notable@@0001",
         "rule_title": "Volcado de LSASS en PC-0042", "dest": "PC-0042", "user": "LAB\\jgarcia",
         "urgency": "critical", "_time": "2026-10-01T10:00:00.000+00:00",
         "Image": "C:\\Users\\Public\\dump.exe", "ProcessGuid": "{3F1C0A2B-1111-2222-3333-444455556666}",
         "ProcessId": "3300", "Hashes": "SHA256=" + "AB" * 32}
    a = nucleo.normalizar("splunk", c, "acme")
    assert a["id"] == "4D8E@@notable@@0001"
    assert a["regla_nombre"] == "Threat - DL - Volcado de memoria de LSASS - Rule"
    assert a["titulo"] == "Volcado de LSASS en PC-0042"
    assert (a["momento"], a["severidad_pista"]) == ("2026-10-01T10:00:00.000+00:00", 4)
    assert a["equipo"] == {"nombre": "PC-0042"}
    assert a["usuario"] == {"nombre": "jgarcia", "dominio": "LAB"}
    assert (a["proceso"]["guid"], a["proceso"]["pid"]) == ("3f1c0a2b-1111-2222-3333-444455556666", 3300)
    assert a["fichero"] == {"ruta": "C:\\Users\\Public\\dump.exe", "nombre": "dump.exe", "sha256": "ab" * 32}
    regla, via = catalogo.buscar_regla(a)
    assert (regla["clave"], via) == (LSASS, "titulo")


def test_splunk_ignora_valores_vacios_y_toma_el_primero_de_un_multivalor():
    c = {"search_name": "x", "sid": "s-1", "result": {
        "dest": "unknown", "host": "PC-0042", "user": ["-", "LAB\\otro"], "User": ["LAB\\jgarcia", "LAB\\otro"],
        "severity": "high", "tecnica": "T1020,T1114.003"}}
    a = nucleo.normalizar("splunk", c)
    assert a["equipo"] == {"nombre": "PC-0042"}
    assert a["usuario"] == {"nombre": "jgarcia", "dominio": "LAB"}
    assert a["severidad_pista"] == 3
    assert a["tecnicas"] == ["T1020", "T1114.003"]


# ============================================================================
# Elastic
# ============================================================================

def test_elastic_claves_con_puntos_del_conector_de_kibana(catalogo):
    a = nucleo.normalizar("elastic", carga("credenciales-movimiento-ot", 2), "norte")
    assert a["titulo"] == a["regla_nombre"] == "DL - Volcado de memoria de LSASS"
    assert a["severidad_pista"] == 4
    assert a["equipo"] == {"nombre": "ING-07", "ip": "10.20.5.17"}
    assert a["usuario"] == {"nombre": "adm-jlopez", "dominio": "NORTE"}
    p = a["proceso"]
    assert (p["guid"], p["pid"]) == ("6c3f8a1e-7720-4000-8000-0000000000a7", 7720)
    assert (p["imagen_nombre"], p["padre_imagen"]) == ("rundll32.exe", "C:\\Windows\\PSEXESVC.exe")
    assert p["sha256"] == "9f2d8c6a1b0e4f3a5c7d9e1f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b"
    assert a["fichero"] == {}                  # rundll32.exe es de System32
    assert catalogo.buscar_regla(a)[0]["clave"] == LSASS


def test_elastic_tecnicas_e_id_de_regla():
    a = nucleo.normalizar("elastic", carga("credenciales-movimiento-ot", 1), "norte")
    assert a["tecnicas"] == ["T1569", "T1569.002"]
    assert a["regla_id"] == "3c1e2a90-0000-4000-8000-000000000196"
    assert a["severidad_pista"] == 3
    assert a["red"] == {"ip_origen": "10.20.3.44"}
    assert a["observables"] == []


def test_elastic_regla_solo_en_la_cabecera_del_conector():
    c = carga("credenciales-movimiento-ot", 1)
    del c["alerts"][0]["kibana.alert.rule.name"]
    del c["alerts"][0]["kibana.alert.rule.rule_id"]
    a = nucleo.normalizar("elastic", c)
    assert a["titulo"] == "DL - Ejecucion remota tipo PsExec"
    assert a["regla_id"] == "3c1e2a90-0000-4000-8000-000000000196"


def test_elastic_documento_ecs_anidado():
    c = {"_id": "doc-1", "@timestamp": "2026-10-01T10:00:00.000Z",
         "kibana": {"alert": {"rule": {"name": "DL - Volcado de memoria de LSASS",
                                       "rule_id": "84045599-ca95-50f1-86c8-66d8351fc0e8"},
                              "severity": "critical"}},
         "host": {"name": "PC-0042", "ip": "10.0.20.42"}, "user": {"name": "jgarcia", "domain": "LAB"},
         "process": {"executable": "C:\\Users\\Public\\dump.exe", "pid": 3300, "hash": {"sha256": "ab" * 32}},
         "destination": {"ip": IP_PUBLICA, "port": 443}}
    a = nucleo.normalizar("elastic", c)
    assert (a["id"], a["momento"]) == ("doc-1", "2026-10-01T10:00:00.000Z")
    assert a["titulo"] == "DL - Volcado de memoria de LSASS"
    assert a["regla_id"] == "84045599-ca95-50f1-86c8-66d8351fc0e8"
    assert a["severidad_pista"] == 4
    assert a["equipo"] == {"nombre": "PC-0042", "ip": "10.0.20.42"}
    assert a["fichero"] == {"ruta": "C:\\Users\\Public\\dump.exe", "nombre": "dump.exe", "sha256": "ab" * 32}
    assert a["red"]["puerto_destino"] == 443
    assert {"tipo": "ip", "valor": IP_PUBLICA} in a["observables"]


# ============================================================================
# Exchange: regla de buzon en las tres formas de Parameters
# ============================================================================

FORMAS_DE_PARAMETERS = [
    pytest.param("wazuh", {
        "id": "o365-1", "timestamp": "2026-10-01T10:00:00Z",
        "rule": {"id": "91575", "level": 12, "description": "Office 365: regla de buzon nueva"},
        "data": {"office365": {
            "Operation": "New-InboxRule", "UserId": "pruiz@acme.test", "ClientIP": IP_PUBLICA,
            "ObjectId": "pruiz@acme.test\\Sincronizar",
            "Parameters": [{"Name": "Name", "Value": "Sincronizar"},
                           {"Name": "ForwardTo", "Value": "smtp:pablo@correo-personal.example"},
                           {"Name": "StopProcessingRules", "Value": "True"}]}}},
        id="wazuh-lista-name-value"),
    pytest.param("elastic", {
        "_id": "o365-2", "@timestamp": "2026-10-01T10:00:00Z",
        "kibana.alert.rule.name": "DL - Regla de buzon con reenvio externo creada",
        "event": {"action": "New-InboxRule"},
        "o365": {"audit": {"Operation": "New-InboxRule", "UserId": "pruiz@acme.test",
                           "Parameters": {"Name": "Sincronizar", "ForwardTo": "pablo@correo-personal.example"}}}},
        id="elastic-objeto"),
    pytest.param("splunk", {
        "search_name": "DL - Regla de buzon con reenvio externo creada", "sid": "o365-3",
        # el TA de O365 de Splunk trae UserId y su alias CIM user, como el escenario
        "result": {"Operation": "New-InboxRule", "UserId": "pruiz@acme.test", "user": "pruiz@acme.test",
                   "ObjectId": "pruiz@acme.test\\Sincronizar",
                   "Parameters{}.Name": ["Name", "ForwardTo", "StopProcessingRules"],
                   "Parameters{}.Value": ["Sincronizar", "pablo@correo-personal.example", "True"]}},
        id="splunk-multivalor"),
]


@pytest.mark.parametrize("siem,carga_nativa", FORMAS_DE_PARAMETERS)
def test_regla_de_buzon_en_las_tres_formas_de_parameters(siem, carga_nativa):
    a = nucleo.normalizar(siem, copy.deepcopy(carga_nativa), "acme")
    c = a["correo"]
    assert (c["regla_buzon"], c["reenvio_a"], c["buzon"]) == \
        ("Sincronizar", "pablo@correo-personal.example", "pruiz@acme.test")
    assert a["usuario"]["upn"] == "pruiz@acme.test"


def test_regla_de_buzon_del_escenario_de_splunk():
    a = nucleo.normalizar("splunk", carga("exfiltracion-tras-acceso", 2), "acme")
    assert a["correo"] == {"regla_buzon": "Sincronizar", "reenvio_a": "pablo.ruiz.casa@correo-personal.example",
                           "buzon": "pruiz@acme.test"}
    assert a["tecnicas"] == ["T1020", "T1114.003"]
    assert a["severidad_pista"] == 4


def test_parameters_de_un_solo_valor_y_regla_tomada_del_objectid():
    c = {"search_name": "x", "sid": "o365-4", "result": {
        "Operation": "Set-InboxRule", "ObjectId": "pruiz@acme.test\\Reenvio",
        "Parameters{}.Name": "RedirectTo", "Parameters{}.Value": "fuera@correo-personal.example"}}
    assert nucleo.normalizar("splunk", c)["correo"] == {
        "regla_buzon": "Reenvio", "reenvio_a": "fuera@correo-personal.example", "buzon": "pruiz@acme.test"}


def test_set_mailbox_con_reenvio_smtp_en_mayusculas():
    c = {"id": "o365-5", "rule": {"id": "91576", "level": 12, "description": "x"}, "data": {"office365": {
        "Operation": "Set-Mailbox", "UserId": "pruiz@acme.test",
        "Parameters": [{"Name": "Identity", "Value": "pruiz"},
                       {"Name": "ForwardingSmtpAddress", "Value": "SMTP:fuera@correo-personal.example"}]}}}
    a = nucleo.normalizar("wazuh", c)
    assert a["correo"]["reenvio_a"] == "fuera@correo-personal.example"
    assert "regla_buzon" not in a["correo"]


def test_operacion_que_no_es_de_buzon_no_rellena_correo():
    c = {"id": "o365-6", "rule": {"id": "91545", "level": 5, "description": "x"}, "data": {"office365": {
        "Operation": "UserLoggedIn", "UserId": "pruiz@acme.test", "ClientIP": IP_PUBLICA}}}
    a = nucleo.normalizar("wazuh", c)
    assert a["correo"] == {}
    assert a["usuario"]["upn"] == "pruiz@acme.test"
    assert a["red"] == {"ip_origen": IP_PUBLICA}


@pytest.mark.parametrize("valor,esperado", [
    ([{"Name": "ForwardTo", "Value": "a@b.example"}, {"Value": "sin nombre"}, "basura"], {"ForwardTo": "a@b.example"}),
    ({"ForwardTo": "a@b.example"}, {"ForwardTo": "a@b.example"}),
    ('[{"Name": "ForwardTo", "Value": "a@b.example"}]', {"ForwardTo": "a@b.example"}),
    ("no es json", {}),
    (None, {}),
])
def test_parametros_o365_en_cualquier_forma(valor, esperado):
    assert nucleo._parametros_o365(valor) == esperado


# ============================================================================
# Identificador
# ============================================================================

@pytest.mark.parametrize("siem,nombre,n", [("wazuh", "ransomware-puesto", 1), ("sentinel", "phishing-a-cuenta", 1),
                                           ("elastic", "credenciales-movimiento-ot", 1)])
def test_id_determinista_cuando_la_alerta_no_trae_id(siem, nombre, n):
    c = carga(nombre, n)
    a1 = nucleo.normalizar(siem, c)
    a2 = nucleo.normalizar(siem, copy.deepcopy(c))
    assert re.fullmatch(r"rl-[0-9a-f]{20}", a1["id"])
    assert a1["id"] == a2["id"]


def test_id_distinto_para_alertas_distintas():
    assert nucleo.normalizar("wazuh", carga("ransomware-puesto", 1))["id"] != \
        nucleo.normalizar("wazuh", carga("ransomware-puesto", 2))["id"]


def test_id_no_depende_del_orden_de_las_claves():
    c = carga("ransomware-puesto", 1)
    invertida = dict(reversed(list(c.items())))
    assert nucleo.normalizar("wazuh", c)["id"] == nucleo.normalizar("wazuh", invertida)["id"]


def test_id_nativo_se_conserva():
    c = carga("ransomware-puesto", 1)
    c["id"] = "1727780400.123456"
    assert nucleo.normalizar("wazuh", c)["id"] == "1727780400.123456"


# ============================================================================
# Utilidades: leer, fechas
# ============================================================================

@pytest.mark.parametrize("datos,ruta,esperado", [
    ({"proc.name": "bash"}, "proc.name", "bash"),
    ({"proc": {"name": "bash"}}, "proc.name", "bash"),
    ({"a": {"b.c": {"d": 1}}}, "a.b.c.d", 1),
    ({"a": {"b": "   "}}, "a.b", None),
    ({"a": {"b": []}}, "a.b", None),
    ({"a": {"b": {}}}, "a.b", None),
    ({"a": "texto"}, "a.b", None),
    ({"a": 0}, "a", 0),
    (None, "a", None),
])
def test_leer_rutas_con_y_sin_puntos(datos, ruta, esperado):
    assert nucleo.leer(datos, ruta) == esperado


@pytest.mark.parametrize("valor", [
    "2026-10-01T10:00:00Z", "2026-10-01T12:00:00+02:00", "2026-10-01T12:00:00+0200", "2026-10-01T05:00:00-05:00",
    "2026-10-01 10:00:00.000", "2026-10-01T10:00:00.000000000Z", "2026-10-01T10:00:00",
    int(REF.timestamp()), int(REF.timestamp()) * 1000, str(int(REF.timestamp())), float(REF.timestamp()),
    datetime(2026, 10, 1, 10, 0), REF,
])
def test_a_fecha_formatos(valor):
    assert nucleo.a_fecha(valor) == REF


@pytest.mark.parametrize("valor", [None, "", "ayer por la tarde", "2026-13-45T99:00:00Z"])
def test_a_fecha_invalida_es_none(valor):
    assert nucleo.a_fecha(valor) is None


@pytest.mark.parametrize("valor", ["2026-10-01T10:00:00Z", "2026-10-01T12:00:00+02:00", "2026-10-01T10:00:00",
                                   "2026-10-01 10:00:00.000"])
def test_a_fecha_con_segundos_no_depende_de_la_zona_del_host(zona_del_host, valor):
    zona_del_host(ZONA_LEJANA)
    assert nucleo.a_fecha(valor) == REF


@pytest.mark.parametrize("valor,esperado", [
    ("2026-10-01T10:00", REF),
    ("2026-10-01 10:00", REF),
    ("2026-10-01", datetime(2026, 10, 1, tzinfo=timezone.utc)),
])
def test_a_fecha_sin_segundos_ni_zona_tambien_es_utc(zona_del_host, valor, esperado):
    zona_del_host(ZONA_LEJANA)
    assert nucleo.a_fecha(valor) == esperado


def test_iso():
    assert nucleo.iso(REF) == "2026-10-01T10:00:00Z"
    assert nucleo.iso(None) == ""


# ============================================================================
# Busqueda de la regla: identificadores, prefijos y sufijos
# ============================================================================

@pytest.mark.parametrize("nombre,esperado", [
    ("DL - Volcado de memoria de LSASS", "Volcado de memoria de LSASS"),
    ("RL - Volcado de memoria de LSASS", "Volcado de memoria de LSASS"),
    ("ResponseLab - Volcado de memoria de LSASS", "Volcado de memoria de LSASS"),
    ("Threat - DL - Volcado de memoria de LSASS - Rule", "Volcado de memoria de LSASS"),
    ("Endpoint - Volcado de memoria de LSASS - Rule", "Volcado de memoria de LSASS"),
    ("access - Volcado de memoria de LSASS - rule", "Volcado de memoria de LSASS"),
    ("  Identity -Volcado de memoria de LSASS  ", "Volcado de memoria de LSASS"),
    ("Volcado de memoria de LSASS", "Volcado de memoria de LSASS"),
    (None, ""),
])
def test_limpiar_nombre_regla(nombre, esperado):
    assert nucleo.limpiar_nombre_regla(nombre) == esperado


BUSQUEDAS = [
    pytest.param("wazuh", {"id": "b1", "rule": {"id": "101206", "level": 15, "description": "otra cosa"}},
                 LSASS, "id de regla de Wazuh", id="wazuh-id"),
    pytest.param("wazuh", {"id": "b2", "rule": {"id": "101129", "level": 15, "description": "x"}},
                 "dl:ad_013_dcshadow", "id de regla de Wazuh", id="wazuh-segundo-id"),
    pytest.param("wazuh", {"id": "b3", "rule": {"id": "999999", "level": 15,
                                                "description": "Volcado de memoria de LSASS"}},
                 LSASS, "titulo", id="wazuh-id-desconocido-titulo-conocido"),
    pytest.param("splunk", {"search_name": "DL - Volcado de memoria de LSASS", "sid": "b4", "result": {}},
                 LSASS, "busqueda guardada de Splunk", id="splunk-busqueda"),
    pytest.param("splunk", {"search_name": "Endpoint - Volcado de memoria de LSASS - Rule", "event_id": "b5"},
                 LSASS, "titulo", id="splunk-es-sufijo"),
    pytest.param("sentinel", {"object": {"name": "b6", "properties": {"title": "DL - Volcado de memoria de LSASS"}}},
                 LSASS, "busqueda guardada de Splunk", id="sentinel-prefijo-dl"),
    pytest.param("elastic", {"_id": "b7", "kibana.alert.rule.name": "Nombre local de la regla",
                             "kibana.alert.rule.rule_id": "84045599-CA95-50F1-86C8-66D8351FC0E8"},
                 LSASS, "id Sigma", id="elastic-sigma"),
    pytest.param("generico", {"titulo": "x", "regla_fichero": "rules/windows/soc_edr_001_volcado_lsass.yml"},
                 LSASS, "fichero de origen", id="fichero-de-origen"),
    pytest.param("generico", {"titulo": "VOLCADO de memoria de LS\u00c1SS"}, LSASS, "titulo", id="titulo-con-tilde"),
    pytest.param("generico", {"titulo": "x", "regla_id": "101206"}, LSASS, "id de regla", id="id-wazuh-desde-otro-siem"),
]


@pytest.mark.parametrize("siem,carga_nativa,clave,via", BUSQUEDAS)
def test_buscar_regla(catalogo, siem, carga_nativa, clave, via):
    regla, via_real = catalogo.buscar_regla(nucleo.normalizar(siem, carga_nativa))
    assert (regla["clave"], via_real) == (clave, via)


def test_regla_que_no_esta_en_el_catalogo(catalogo):
    assert catalogo.buscar_regla(generica(titulo="Regla local que nadie ha revisado")) == (None, "")
