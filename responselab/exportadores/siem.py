"""
Configuracion de los SIEM que depende del catalogo (generada).

  siem/wazuh/ossec-responselab.conf       bloques <integration> con la lista
                                          exacta de reglas que el catalogo conoce
  siem/elastic/reglas-responselab.json    titulos de las reglas de Elastic a las
                                          que configurar.ps1 anade la accion
  siem/splunk/savedsearches-<origen>.conf accion webhook hacia el motor en cada
                                          busqueda guardada (DetectionLab y
                                          SplunkLab) que tiene playbook

Cuando DetectionLab o SplunkLab anaden una regla, la sincronizacion la trae al
catalogo y estos ficheros cambian solos: el SIEM manda al motor exactamente lo
que el motor sabe gestionar, ni mas (ruido) ni menos (alertas sin respuesta).
"""
from __future__ import annotations

import json

LOTE_WAZUH = 200          # el parser XML de Wazuh admite 20480 bytes por etiqueta; se va sobrado
NIVEL_SIN_PLAYBOOK = 12   # alertas graves que ninguna regla del catalogo cubre: playbook generico


def _wazuh(catalogo: dict) -> str:
    ids = sorted({str(w) for r in catalogo["reglas"] for w in (r.get("wazuh_ids") or [])}, key=int)
    l = ["<!--",
         f"  Generado por ResponseLab (tools/compilar.py) desde el catalogo {catalogo['version']}. No editar:",
         "  se regenera cuando DetectionLab o Infra-SocAnalyst cambian sus reglas.",
         "",
         "  Pegar dentro de <ossec_config> en el manager (/var/ossec/etc/ossec.conf) y",
         "  reiniciar: systemctl restart wazuh-manager. instalar-manager.sh lo hace.",
         "",
         f"  1. Las {len(ids)} reglas de Wazuh que el catalogo conoce, por id exacto.",
         f"  2. Cualquier alerta de nivel {NIVEL_SIN_PLAYBOOK} o mas: el motor le aplica el playbook generico.",
         "  3. Los acuses de los scripts de active response (reglas 109900-109903).",
         "  Si una alerta casa con varios bloques llega dos veces: el motor descarta",
         "  la repetida por su id.",
         "-->"]
    for i in range(0, len(ids), LOTE_WAZUH):
        l += ["<integration>",
              "  <name>custom-responselab</name>",
              f"  <rule_id>{','.join(ids[i:i + LOTE_WAZUH])}</rule_id>",
              "  <alert_format>json</alert_format>",
              "</integration>"]
    l += ["<integration>",
          "  <name>custom-responselab</name>",
          f"  <level>{NIVEL_SIN_PLAYBOOK}</level>",
          "  <alert_format>json</alert_format>",
          "</integration>",
          "<integration>",
          "  <name>custom-responselab</name>",
          "  <group>responselab_acuse</group>",
          "  <alert_format>json</alert_format>",
          "</integration>"]
    return "\n".join(l) + "\n"


APPS_SPLUNK = {
    # origen del catalogo -> (fichero de salida, app de Splunk donde viven sus busquedas)
    "detectionlab": ("siem/splunk/savedsearches-detectionlab.conf", "TA-detection-lab"),
    "splunklab": ("siem/splunk/savedsearches-splunklab.conf", "mi_indice"),
}


def _splunk(catalogo: dict, origen: str, app: str) -> str:
    busquedas = sorted({r["splunk"]: r for r in catalogo["reglas"] if r.get("splunk") and r.get("origen") == origen}.items())
    l = ["# Generado por ResponseLab (tools/compilar.py) desde el catalogo " + catalogo["version"] + ". No editar.",
         "#",
         f"# Anade la accion webhook hacia el motor a las {len(busquedas)} busquedas guardadas de {origen}",
         f"# que tienen playbook. Copiar a $SPLUNK_HOME/etc/apps/{app}/local/savedsearches.conf:",
         "# Splunk combina local/ con default/ clave a clave, asi que solo se anaden estas",
         "# dos claves y el resto de cada busqueda (cron, umbral, notable) no cambia.",
         "#",
         "# 1. Sustituye MOTOR, CLIENTE y TOKEN_DE_INGESTA (python -m responselab token).",
         "#    El webhook de Splunk no admite cabeceras: el token va en la URL, que queda",
         "#    en el registro del proxy. Ese token solo sirve para enviar alertas.",
         "# 2. Splunk 9 exige que la URL este en la lista de webhooks permitidos:",
         "#    siem/splunk/alert_actions.conf.",
         "# 3. Con alert.digest_mode = 1 el webhook lleva solo el primer resultado de",
         "#    cada ejecucion; con 0, uno por resultado.",
         ""]
    for nombre, r in busquedas:
        l += [f"# {r['familia']} | {r.get('clase', '')} | {r['titulo']}",
              f"[{nombre}]",
              "action.webhook = 1",
              "action.webhook.param.url = https://MOTOR:8443/v1/CLIENTE/alertas/splunk?token=TOKEN_DE_INGESTA",
              ""]
    return "\n".join(l)


def _elastic(catalogo: dict) -> str:
    """Titulos de las reglas que DetectionLab despliega en Elastic Security (Sigma
    convertidas a ES|QL o Lucene): configurar.ps1 anade la accion del motor a las
    reglas de Kibana que se llaman asi, con o sin el prefijo "DL - "."""
    titulos = sorted({r["titulo"] for r in catalogo["reglas"] if str(r.get("tipo", "")).startswith("sigma")})
    return json.dumps({"_generado": "Generado por ResponseLab (tools/compilar.py). No editar.",
                       "version_catalogo": catalogo["version"], "titulos": titulos},
                      ensure_ascii=False, indent=1) + "\n"


def exportar(catalogo: dict) -> dict[str, str]:
    salidas = {"siem/wazuh/ossec-responselab.conf": _wazuh(catalogo),
               "siem/elastic/reglas-responselab.json": _elastic(catalogo)}
    for origen, (ruta, app) in APPS_SPLUNK.items():
        salidas[ruta] = _splunk(catalogo, origen, app)
    return salidas
