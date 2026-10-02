"""
n8n: workflow importable (Workflows > Import from file).

    Webhook ─► Configuracion ─► Decidir (motor) ─┬─► ¿Contencion? ─► Ejecutar en el motor
                                                 ├─► ¿Caso? ─► TheHive alerta ─► TheHive caso
                                                 └─► ¿Aviso? ─► Aviso (Teams / Slack / Discord)

Solo usa nodos estables (Webhook, Code, HTTP Request). Las bifurcaciones son
nodos Code que devuelven cero elementos cuando no toca seguir: en n8n un nodo
sin elementos de salida no ejecuta lo que tiene detras. Es menos vistoso que
un IF y no depende de la version del nodo IF, que ha cambiado de formato.

La decision la toma el motor. Credenciales a crear en n8n (tipo Header Auth):
"ResponseLab motor" (Authorization: Bearer <token de ingesta>) y "TheHive"
(Authorization: Bearer <api key>).
"""
from __future__ import annotations

import json

from .comun import uid

CONFIG = r"""// Configuracion del workflow (edita estos valores)
const motor = "https://HOST_SOC:8443";        // URL del motor de ResponseLab
const cliente = "lab";                        // id del cliente en el motor
const siem = "wazuh";                         // wazuh | splunk | sentinel | elastic | generico
const thehive = "http://HOST_SOC:9000";       // vacio si no usas TheHive
const aviso = "";                             // webhook de Teams, Slack o Discord; vacio = sin aviso
const formatoAviso = "teams";                 // teams | slack | discord

const entrada = $input.first().json;
return [{ json: { motor, cliente, siem, thehive, aviso, formatoAviso, alerta: entrada.body ?? entrada } }];
"""

CONTENCION = r"""// Sigue solo si hay contencion automatica o que espere aprobacion
const plan = $input.first().json;
const cfg = $('Configuracion').first().json;
const hay = (plan.acciones || []).some(a => a.modo === 'automatica' || a.modo === 'aprobacion');
return hay ? [{ json: { ...cfg, familia: plan.familia, clase: plan.clase } }] : [];
"""

CASO = r"""// Sigue solo si el plan pide caso y hay TheHive configurado
const plan = $input.first().json;
const cfg = $('Configuracion').first().json;
if (!plan.crear_caso || !cfg.thehive) return [];
const lineas = (plan.acciones || []).map(a => `- [${a.modo}] ${a.nombre}: ${a.motivo}`);
const triaje = (plan.triaje || []).map(t => `- [${t.resultado}] ${t.pregunta}`);
const cuerpo = {
  type: 'responselab',
  source: `responselab-${cfg.siem}`,
  sourceRef: `${cfg.cliente}-${plan.alerta_id}`.slice(0, 128),
  title: `[${plan.familia}] ${(plan.regla && plan.regla.titulo) || plan.titulo}`.slice(0, 512),
  description: [`**${plan.playbook}** | clase \`${plan.clase}\` | severidad ${plan.severidad}`, '',
                '### Acciones', ...lineas, '', '### Triaje', ...triaje, '',
                `Escalar a **${plan.escalado.a}** en ${plan.escalado.plazo_min} min`].join('\n'),
  severity: plan.severidad,
  tlp: 2, pap: 2,
  tags: ['responselab', `rl:familia=${plan.familia}`, `rl:clase=${plan.clase}`],
  caseTemplate: plan.plantilla_caso,
};
return [{ json: { thehive: cfg.thehive, cuerpo } }];
"""

AVISO = r"""// Sigue solo si el plan pide aviso y hay webhook configurado
const plan = $input.first().json;
const cfg = $('Configuracion').first().json;
if (!plan.notificar || !cfg.aviso) return [];
const titulo = `${(plan.regla && plan.regla.titulo) || plan.titulo}`;
const auto = (plan.acciones || []).filter(a => a.modo === 'automatica').map(a => a.nombre).join('; ') || 'ninguna';
const espera = (plan.acciones || []).filter(a => a.modo === 'aprobacion').map(a => a.nombre).join('; ') || 'ninguna';
const texto = `${plan.familia} | ${plan.clase} | severidad ${plan.severidad} | escalar a ${plan.escalado.a} en ${plan.escalado.plazo_min} min`;
let cuerpo;
if (cfg.formatoAviso === 'slack') {
  cuerpo = { text: `*${titulo}*\n${texto}\nAutomatico: ${auto}\nEspera aprobacion: ${espera}` };
} else if (cfg.formatoAviso === 'discord') {
  cuerpo = { username: 'ResponseLab', embeds: [{ title: titulo.slice(0, 256), description: texto,
             fields: [{ name: 'Automatico', value: auto.slice(0, 1000) }, { name: 'Espera aprobacion', value: espera.slice(0, 1000) }] }] };
} else {
  cuerpo = { type: 'message', attachments: [{ contentType: 'application/vnd.microsoft.card.adaptive', content: {
    type: 'AdaptiveCard', $schema: 'http://adaptivecards.io/schemas/adaptive-card.json', version: '1.4',
    body: [{ type: 'TextBlock', text: titulo, weight: 'Bolder', wrap: true }, { type: 'TextBlock', text: texto, wrap: true },
           { type: 'FactSet', facts: [{ title: 'Automatico', value: auto }, { title: 'Espera aprobacion', value: espera }] }] } }] };
}
return [{ json: { aviso: cfg.aviso, cuerpo } }];
"""


def _nodo(nombre, tipo, version, parametros, x, y, **extra):
    n = {"parameters": parametros, "id": uid("n8n", nombre), "name": nombre, "type": tipo,
         "typeVersion": version, "position": [x, y]}
    n.update(extra)
    return n


def _http(nombre, url, cuerpo, x, y, credencial=None):
    p = {"method": "POST", "url": url, "sendBody": True, "specifyBody": "json", "jsonBody": cuerpo, "options": {}}
    extra = {}
    if credencial:
        p["authentication"] = "genericCredentialType"
        p["genericAuthType"] = "httpHeaderAuth"
        extra["credentials"] = {"httpHeaderAuth": {"id": "", "name": credencial}}
    return _nodo(nombre, "n8n-nodes-base.httpRequest", 4.2, p, x, y, **extra)


def _code(nombre, codigo, x, y):
    return _nodo(nombre, "n8n-nodes-base.code", 2, {"jsCode": codigo}, x, y)


def workflow() -> dict:
    nodos = [
        _nodo("Webhook", "n8n-nodes-base.webhook", 2,
              {"httpMethod": "POST", "path": "responselab", "responseMode": "onReceived", "options": {}},
              0, 300, webhookId=uid("n8n", "webhook")),
        _code("Configuracion", CONFIG, 220, 300),
        _http("Decidir", "={{ $json.motor }}/v1/{{ $json.cliente }}/decidir/{{ $json.siem }}",
              "={{ JSON.stringify($json.alerta) }}", 440, 300, "ResponseLab motor"),
        _code("Contencion", CONTENCION, 680, 120),
        _http("Ejecutar en el motor", "={{ $json.motor }}/v1/{{ $json.cliente }}/alertas/{{ $json.siem }}",
              "={{ JSON.stringify($('Configuracion').first().json.alerta) }}", 900, 120, "ResponseLab motor"),
        _code("Caso", CASO, 680, 300),
        _http("TheHive alerta", "={{ $json.thehive }}/api/v1/alert", "={{ JSON.stringify($json.cuerpo) }}",
              900, 300, "TheHive"),
        _http("TheHive caso", "={{ $('Caso').first().json.thehive }}/api/v1/alert/{{ $json._id }}/case",
              "={}", 1120, 300, "TheHive"),
        _code("Aviso", AVISO, 680, 480),
        _http("Enviar aviso", "={{ $json.aviso }}", "={{ JSON.stringify($json.cuerpo) }}", 900, 480),
    ]

    def a(*destinos):
        return {"main": [[{"node": d, "type": "main", "index": 0} for d in destinos]]}

    conexiones = {
        "Webhook": a("Configuracion"),
        "Configuracion": a("Decidir"),
        "Decidir": a("Contencion", "Caso", "Aviso"),
        "Contencion": a("Ejecutar en el motor"),
        "Caso": a("TheHive alerta"),
        "TheHive alerta": a("TheHive caso"),
        "Aviso": a("Enviar aviso"),
    }
    return {"name": "ResponseLab - respuesta a incidentes", "nodes": nodos, "connections": conexiones,
            "settings": {"executionOrder": "v1"}, "pinData": {}, "active": False, "tags": [],
            "meta": {"templateCredsSetupCompleted": False}}


def exportar(catalogo: dict) -> dict[str, str]:
    return {"soar/n8n/responselab.json": json.dumps(workflow(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"}
