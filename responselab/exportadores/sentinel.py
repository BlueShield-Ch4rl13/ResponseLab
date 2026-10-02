"""
Microsoft Sentinel: playbooks de Logic Apps y regla de automatizacion.

Dos caminos, elegidos al desplegar la regla de automatizacion (docs/SOAR.md):

  motor   incidente -> RL-Reenviar-al-motor -> ResponseLab decide y actua con
          sus conectores (Defender, Entra, cortafuegos...) y responde en el caso
  nativo  incidente -> RL-Respuesta, que decide sin salir de Azure con la tabla
          que este exportador calcula ejecutando el nucleo regla a regla

En modo nativo la decision se toma de antemano: para cada regla se ejecuta
nucleo.decidir con una alerta que trae todos los campos y el cliente prudente
(sin inventario: toda excepcion pide aprobacion). Lo que sale "automatica" ahi
es lo unico que RL-Respuesta puede hacer solo; en tiempo real comprueba que el
objetivo existe, que no es ambiguo, que no esta en la lista de protegidos y que
no hay ficheros en rutas del sistema. Lo demas lo deja como "con aprobacion":
el analista lo aprueba ejecutando desde el incidente el playbook de esa accion
(RL-Aislar-equipo, RL-Revocar-sesiones...).

La regla del incidente se reconoce por el NOMBRE DE LAS ALERTAS (el nombre de
la regla de analitica), no por el titulo del incidente: el portal de Defender
reescribe titulos al correlar y Microsoft desaconseja condicionar en ellos.

Salida (soar/sentinel/):
  playbooks.json          plantilla ARM: conexion de Sentinel y todos los playbooks
  automatizacion.json     plantilla ARM: la regla de automatizacion (nativo o motor)
  conceder-permisos.ps1   roles de Sentinel y permisos de API de cada identidad

Las llamadas a Defender, Graph y a la API de Sentinel van por HTTP con la
identidad administrada de cada playbook: sin secretos en las plantillas.
"""
from __future__ import annotations

import json

from .comun import catalogo_para_soar, modos_estaticos, uid

API_SENTINEL = "2025-09-01"
API_REGLAS = "2024-09-01"
AUD_MDE = "https://api.securitycenter.microsoft.com"
AUD_GRAPH = "https://graph.microsoft.com"
AUD_ARM = "https://management.azure.com/"
GRAPH = "https://graph.microsoft.com/v1.0"
TODOS = ["Succeeded", "Failed", "Skipped", "TimedOut"]
MAX_TAREAS = 30   # Sentinel admite 40 por incidente; se deja sitio a las del analista

# Tipos de accion nativa (acciones/catalogo.yml -> soar.sentinel.tipo)
TIPOS = {
    "mde_aislar": {"nombre": "Aislar el equipo en Defender", "playbook": "RL-Aislar-equipo"},
    "mde_cuarentena": {"nombre": "Parar y poner en cuarentena el fichero (SHA-1)", "playbook": "RL-Cuarentena-fichero"},
    "mde_paquete": {"nombre": "Recoger el paquete de investigacion de Defender", "playbook": "RL-Paquete-investigacion"},
    "graph_revocar": {"nombre": "Revocar las sesiones en Entra ID", "playbook": "RL-Revocar-sesiones"},
    "graph_riesgo": {"nombre": "Confirmar la cuenta como comprometida", "playbook": "RL-Confirmar-compromiso"},
}
PESO_CLASE = {"auto_contener": 4, "auto_analisis": 3, "auto_enriq": 2, "auto_cierre": 1}


def comprobada_en_sentinel(accion: str, excepcion: dict) -> bool:
    """Excepciones de playbooks/comun.yml que RL-Respuesta comprueba por su cuenta.

    - "servidor de produccion" (inventario.etiqueta) -> parametro ActivosProtegidos
    - hash de una aplicacion de negocio (lista.valor_en) -> parametro HashesDeNegocio
    Cualquier otra excepcion no se puede comprobar en Sentinel sin el motor: la
    accion que la tenga queda con aprobacion.
    """
    if not isinstance(excepcion, dict) or len(excepcion) != 1:
        return False
    nombre, arg = next(iter(excepcion.items()))
    if nombre == "inventario.etiqueta":
        return set(arg.get("etiquetas") or []) <= {"servidor_produccion"} and not arg.get("objetivo")
    if nombre == "lista.valor_en":
        return (accion == "fichero.cuarentena" and arg.get("lista") == "aplicaciones_negocio"
                and arg.get("campo") in ("fichero.sha256", "fichero.sha1"))
    return False

# Permisos de cada playbook (los aplica conceder-permisos.ps1)
PERMISOS = {
    "RL-Respuesta": {"mde": ["Machine.Read.All", "Machine.Isolate", "Machine.StopAndQuarantine", "Machine.CollectForensics"],
                     "graph": ["User.RevokeSessions.All", "IdentityRiskyUser.ReadWrite.All"]},
    "RL-Aislar-equipo": {"mde": ["Machine.Read.All", "Machine.Isolate"]},
    "RL-Liberar-equipo": {"mde": ["Machine.Read.All", "Machine.Isolate"]},
    "RL-Cuarentena-fichero": {"mde": ["Machine.Read.All", "Machine.StopAndQuarantine"]},
    "RL-Paquete-investigacion": {"mde": ["Machine.Read.All", "Machine.CollectForensics"]},
    "RL-Revocar-sesiones": {"graph": ["User.RevokeSessions.All"]},
    "RL-Confirmar-compromiso": {"graph": ["IdentityRiskyUser.ReadWrite.All"]},
    "RL-Descartar-riesgo": {"graph": ["IdentityRiskyUser.ReadWrite.All"]},
    "RL-Reenviar-al-motor": {},
}

# ═══ Expresiones WDL reutilizadas ════════════════════════════════════════════
PROPS = "triggerBody()?['object']?['properties']"
INCIDENTE = "triggerBody()?['object']?['id']"
ENTIDADES = f"coalesce({PROPS}?['relatedEntities'], json('[]'))"
ALERTAS = f"coalesce({PROPS}?['Alerts'], {PROPS}?['alerts'], json('[]'))"
COMENTARIO_MDE = (f"ResponseLab (Sentinel #@{{{PROPS}?['incidentNumber']}}): "
                  f"@{{take(coalesce({PROPS}?['title'], ''), 200)}}")


def _tipo(kind: str) -> str:
    return f"equals(toLower(coalesce(item()?['kind'], '')), '{kind}')"


def _dir() -> str:
    # Ruta normalizada: minusculas, barras '/', y '/' al final para casar carpetas
    return "toLower(concat(replace(coalesce(item()?['properties']?['directory'], ''), '\\', '/'), '/'))"


def _ruta_sistema() -> str:
    """El equivalente de nucleo.RE_RUTA_SISTEMA para entidades File."""
    d = _dir()
    pruebas = [f"contains({d}, ':/windows/')"]
    pruebas += [f"startsWith({d}, '{p}')" for p in
                ("%systemroot%", "%windir%", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/",
                 "/usr/libexec/", "/lib/", "/lib64/", "/system/", "/usr/local/bin/", "/usr/local/sbin/")]
    return "or(" + ", ".join(pruebas) + ")"


NOMBRE_EQUIPO = ("toLower(first(split(trim(coalesce(items('Por_cada_equipo')?['properties']?['hostName'], "
                 "items('Por_cada_equipo')?['properties']?['netBiosName'], '')), '.')))")


# ═══ Piezas de un workflow ═══════════════════════════════════════════════════

def _despues(*nombres, estados=None):
    return {n: list(estados or ["Succeeded"]) for n in nombres}


def _cadena(acciones: list, primero_despues=None) -> dict:
    """[(nombre, accion), ...] -> dict con runAfter encadenado.

    Cada accion corre despues de la anterior pase lo que pase (TODOS), salvo
    que ya traiga su propio runAfter: un fallo de Defender no debe impedir que
    se comente el incidente.
    """
    salida, anterior = {}, primero_despues
    for nombre, accion in acciones:
        if "runAfter" not in accion:
            accion["runAfter"] = _despues(anterior, estados=TODOS) if anterior else {}
        salida[nombre] = accion
        anterior = nombre
    return salida


def _http(metodo: str, uri: str, audiencia: str, cuerpo=None, consultas=None, cabeceras=None, run_after=None) -> dict:
    entradas = {"method": metodo, "uri": uri,
                "authentication": {"type": "ManagedServiceIdentity", "audience": audiencia}}
    if cuerpo is not None:
        entradas["body"] = cuerpo
    if consultas:
        entradas["queries"] = consultas
    if cabeceras:
        entradas["headers"] = cabeceras
    a = {"type": "Http", "inputs": entradas}
    if run_after is not None:
        a["runAfter"] = run_after
    return a


def _anotar(texto: str, variable="Resultados", run_after=None) -> dict:
    a = {"type": "AppendToArrayVariable", "inputs": {"name": variable, "value": texto}}
    if run_after is not None:
        a["runAfter"] = run_after
    return a


def _si(expresion, entonces: dict, si_no: dict | None = None, run_after=None) -> dict:
    a = {"type": "If", "expression": expresion, "actions": entonces}
    if si_no:
        a["else"] = {"actions": si_no}
    if run_after is not None:
        a["runAfter"] = run_after
    return a


def _bucle(origen: str, acciones: dict, run_after=None) -> dict:
    a = {"type": "Foreach", "foreach": origen, "actions": acciones,
         "runtimeConfiguration": {"concurrency": {"repetitions": 1}}}
    if run_after is not None:
        a["runAfter"] = run_after
    return a


def _filtro(origen: str, donde: str, run_after=None) -> dict:
    a = {"type": "Query", "inputs": {"from": origen, "where": "@" + donde}}
    if run_after is not None:
        a["runAfter"] = run_after
    return a


def _variable(nombre: str, tipo="array", valor=None) -> dict:
    return {"type": "InitializeVariable",
            "inputs": {"variables": [{"name": nombre, "type": tipo, "value": [] if valor is None else valor}]}}


def _con_resultado(nombre: str, accion: dict, ok: str, error: str) -> dict:
    """Accion HTTP + anotacion de exito o de error en Resultados."""
    accion = dict(accion, runAfter={})
    return {
        nombre: accion,
        nombre + "_ok": _anotar(ok, run_after=_despues(nombre)),
        nombre + "_error": _anotar(error + " (HTTP @{outputs('" + nombre + "')?['statusCode']})",
                                   run_after=_despues(nombre, estados=["Failed", "TimedOut"])),
    }


def _comentario(html: str, run_after=None) -> dict:
    return _http("PUT", f"https://management.azure.com@{{{INCIDENTE}}}/comments/@{{guid()}}?api-version={API_SENTINEL}",
                 AUD_ARM, cuerpo={"properties": {"message": html}}, run_after=run_after)


def _disparador() -> dict:
    return {"Microsoft_Sentinel_incident": {
        "type": "ApiConnectionWebhook",
        "inputs": {"body": {"callback_url": "@{listCallbackUrl()}"},
                   "host": {"connection": {"name": "@parameters('$connections')['azuresentinel']['connectionId']"}},
                   "path": "/incident-creation"}}}


def _definicion(acciones: dict, parametros: dict) -> dict:
    p = {"$connections": {"defaultValue": {}, "type": "Object"}}
    p.update(parametros)
    return {"$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
            "contentVersion": "1.0.0.0", "parameters": p, "triggers": _disparador(), "actions": acciones, "outputs": {}}


# ═══ Bloques comunes ═════════════════════════════════════════════════════════

def _entidades() -> list:
    return [
        ("Equipos", _filtro("@" + ENTIDADES, _tipo("host"))),
        ("Cuentas", _filtro("@" + ENTIDADES, _tipo("account"))),
        ("Hashes_sha1", _filtro("@" + ENTIDADES, f"and({_tipo('filehash')}, equals(toLower(coalesce(item()?['properties']?['algorithm'], '')), 'sha1'))")),
        ("Ficheros_de_sistema", _filtro("@" + ENTIDADES, f"and({_tipo('file')}, {_ruta_sistema()})")),
        ("Hashes_de_negocio", _filtro("@" + ENTIDADES, f"and({_tipo('filehash')}, contains(parameters('HashesDeNegocio'), "
                                                       "toLower(coalesce(item()?['properties']?['hashValue'], ''))))")),
        ("Identidades", {"type": "Select", "inputs": {"from": "@body('Cuentas')", "select": {
            "nombre": "@{toLower(coalesce(item()?['properties']?['accountName'], item()?['properties']?['friendlyName'], ''))}",
            "aad": "@{toLower(coalesce(item()?['properties']?['aadUserId'], ''))}",
            "upn": "@{if(empty(coalesce(item()?['properties']?['upnSuffix'], '')), '', toLower(concat(coalesce(item()?['properties']?['accountName'], ''), '@', coalesce(item()?['properties']?['upnSuffix'], ''))))}"}}}),
    ]


def _protegida(item="item()") -> str:
    return (f"or(contains(parameters('CuentasProtegidas'), {item}?['nombre']), "
            f"contains(parameters('CuentasProtegidas'), {item}?['upn']), "
            f"and(not(empty({item}?['aad'])), contains(parameters('CuentasProtegidas'), {item}?['aad'])))")


def _buscar_maquinas() -> dict:
    """Por cada entidad Host: id de Defender, o busqueda por nombre que tiene
    que devolver exactamente una maquina. Ambiguo = no se actua."""
    directo = "items('Por_cada_equipo')?['properties']?['additionalData']?['MdatpDeviceId']"
    buscar = _http("GET", "@{parameters('ApiDefender')}/api/machines", AUD_MDE,
                   consultas={"$filter": "startswith(computerDnsName,'@{replace(outputs('Nombre_equipo'), '''', '')}')",
                              "$top": "20"}, run_after={})
    coinciden = _filtro("@coalesce(body('Buscar_en_Defender')?['value'], json('[]'))",
                        "equals(first(split(toLower(coalesce(item()?['computerDnsName'], '')), '.')), outputs('Nombre_equipo'))",
                        run_after=_despues("Buscar_en_Defender"))
    unica = _si({"and": [{"equals": ["@length(body('Coinciden'))", 1]}]},
                {"Anotar_maquina": {"type": "AppendToArrayVariable", "runAfter": {}, "inputs": {"name": "Maquinas", "value": {
                    "id": "@{first(body('Coinciden'))?['id']}", "nombre": "@{outputs('Nombre_equipo')}",
                    "protegido": "@contains(parameters('ActivosProtegidos'), outputs('Nombre_equipo'))"}}}},
                {"Anotar_ambigua": _anotar("Equipo @{outputs('Nombre_equipo')}: casa con @{length(body('Coinciden'))} "
                                           "maquinas en Defender; objetivo ambiguo, no se actua", run_after={})},
                run_after=_despues("Coinciden"))
    por_nombre = {"Buscar_en_Defender": buscar, "Coinciden": coinciden, "Si_es_unica": unica,
                  "Buscar_error": _anotar("Equipo @{outputs('Nombre_equipo')}: no se pudo consultar Defender "
                                          "(HTTP @{outputs('Buscar_en_Defender')?['statusCode']})",
                                          run_after=_despues("Buscar_en_Defender", estados=["Failed", "TimedOut"]))}
    con_id = {"Anotar_por_id": {"type": "AppendToArrayVariable", "runAfter": {}, "inputs": {"name": "Maquinas", "value": {
        "id": "@{" + directo + "}", "nombre": "@{outputs('Nombre_equipo')}",
        "protegido": "@contains(parameters('ActivosProtegidos'), outputs('Nombre_equipo'))"}}}}
    cuerpo = {
        "Nombre_equipo": {"type": "Compose", "runAfter": {}, "inputs": "@" + NOMBRE_EQUIPO},
        "Si_trae_id_de_Defender": _si({"and": [{"not": {"equals": [f"@coalesce({directo}, '')", ""]}}]}, con_id,
                                      {"Si_hay_nombre": _si({"and": [{"not": {"equals": ["@outputs('Nombre_equipo')", ""]}}]},
                                                            por_nombre, run_after={})},
                                      run_after=_despues("Nombre_equipo")),
    }
    return _bucle("@body('Equipos')", cuerpo)


def _bloque_maquinas(nombre: str, tipo: str, origen: str, ruta: str, cuerpo: dict, hecho: str, verbo: str,
                     automatico: bool) -> tuple:
    """Una accion de Defender sobre cada maquina de 'origen'. Devuelve (nombre, accion):
    en modo automatico va dentro de un If con ese nombre; si no, es el bucle
    'Maquina_<tipo>', que es el nombre al que se refieren sus acciones."""
    llamada = _http("POST", "@{parameters('ApiDefender')}/api/machines/@{items('Maquina_" + tipo + "')?['id']}/" + ruta,
                    AUD_MDE, cuerpo=cuerpo)
    acciones = _con_resultado("Llamada_" + tipo, llamada, f"{hecho} @{{items('Maquina_{tipo}')?['nombre']}}",
                              f"Error al {verbo} @{{items('Maquina_{tipo}')?['nombre']}}")
    if automatico:
        acciones = {"Si_modo_activo_" + tipo: _si({"and": [{"equals": ["@parameters('ContencionAutomatica')", True]}]}, acciones,
                                                  {"Observacion_" + tipo: _anotar(
                                                      f"Observacion: se habria pedido {verbo} @{{items('Maquina_{tipo}')?['nombre']}}",
                                                      run_after={})}, run_after={})}
    if not automatico:
        return "Maquina_" + tipo, _bucle(origen, acciones)
    return nombre, _si({"and": [{"contains": ["@outputs('Regla')?['a']", tipo]}]},
                       {"Maquina_" + tipo: _bucle(origen, acciones, run_after={})})


# ═══ RL-Respuesta (modo nativo) ══════════════════════════════════════════════

def _respuesta(reglas: dict, familias: dict) -> dict:
    regla = "outputs('Regla')"
    cuerpo_cuarentena = {"Comment": COMENTARIO_MDE, "Sha1": "@{items('Hash_mde_cuarentena')?['properties']?['hashValue']}"}

    # Cuarentena: bucle doble maquina x hash
    llamada_q = _http("POST", "@{parameters('ApiDefender')}/api/machines/@{items('Maquina_mde_cuarentena')?['id']}/StopAndQuarantineFile",
                      AUD_MDE, cuerpo=cuerpo_cuarentena)
    q = _con_resultado("Llamada_mde_cuarentena", llamada_q,
                       "Cuarentena pedida en @{items('Maquina_mde_cuarentena')?['nombre']} para @{items('Hash_mde_cuarentena')?['properties']?['hashValue']}",
                       "Error al poner en cuarentena en @{items('Maquina_mde_cuarentena')?['nombre']}")
    q = {"Si_modo_activo_mde_cuarentena": _si({"and": [{"equals": ["@parameters('ContencionAutomatica')", True]}]}, q,
                                              {"Observacion_mde_cuarentena": _anotar(
                                                  "Observacion: se habria pedido la cuarentena de @{items('Hash_mde_cuarentena')?['properties']?['hashValue']} "
                                                  "en @{items('Maquina_mde_cuarentena')?['nombre']}", run_after={})}, run_after={})}
    cuarentena = _si({"and": [{"contains": [f"@{regla}?['a']", "mde_cuarentena"]},
                              {"equals": ["@length(body('Ficheros_de_sistema'))", 0]},
                              {"equals": ["@length(body('Hashes_de_negocio'))", 0]},
                              {"greater": ["@length(body('Hashes_sha1'))", 0]}]},
                     {"Maquina_mde_cuarentena": _bucle("@body('Maquinas_actuables')",
                                                       {"Hash_mde_cuarentena": _bucle("@body('Hashes_sha1')", q, run_after={})},
                                                       run_after={})})
    cuarentena_no = _si({"and": [{"contains": [f"@{regla}?['a']", "mde_cuarentena"]},
                                 {"or": [{"greater": ["@length(body('Ficheros_de_sistema'))", 0]},
                                         {"greater": ["@length(body('Hashes_de_negocio'))", 0]},
                                         {"equals": ["@length(body('Hashes_sha1'))", 0]}]}]},
                        {"Anotar_cuarentena_no": _anotar(
                            "Cuarentena no ejecutada: @{if(greater(length(body('Ficheros_de_sistema')), 0), "
                            "'el incidente incluye ficheros en rutas del sistema (requiere aprobacion)', "
                            "if(greater(length(body('Hashes_de_negocio')), 0), "
                            "'el hash es de una aplicacion de negocio (HashesDeNegocio): requiere aprobacion', "
                            "'el incidente no trae el SHA-1 del fichero, que Defender necesita'))}", run_after={})})

    # Identidades
    objetivo = "if(empty(items('Cuenta_graph_revocar')?['aad']), items('Cuenta_graph_revocar')?['upn'], items('Cuenta_graph_revocar')?['aad'])"
    rev = _con_resultado("Llamada_graph_revocar",
                         _http("POST", f"{GRAPH}/users/@{{encodeUriComponent({objetivo})}}/revokeSignInSessions", AUD_GRAPH, cuerpo={}),
                         "Sesiones revocadas de @{items('Cuenta_graph_revocar')?['nombre']}",
                         "Error al revocar sesiones de @{items('Cuenta_graph_revocar')?['nombre']}")
    rev = _si({"and": [{"or": [{"not": {"equals": ["@items('Cuenta_graph_revocar')?['aad']", ""]}},
                               {"not": {"equals": ["@items('Cuenta_graph_revocar')?['upn']", ""]}}]}]},
              {"Si_modo_activo_graph_revocar": _si({"and": [{"equals": ["@parameters('ContencionAutomatica')", True]}]}, rev,
                                                   {"Observacion_graph_revocar": _anotar(
                                                       "Observacion: se habrian revocado las sesiones de @{items('Cuenta_graph_revocar')?['nombre']}",
                                                       run_after={})}, run_after={})},
              {"Sin_id_graph_revocar": _anotar("Cuenta @{items('Cuenta_graph_revocar')?['nombre']}: sin identificador "
                                               "de Entra ID (ni id ni UPN); no se revoca", run_after={})}, run_after={})
    revocar = _si({"and": [{"contains": [f"@{regla}?['a']", "graph_revocar"]}]},
                  {"Cuenta_graph_revocar": _bucle("@body('Identidades_actuables')", {"Si_tiene_id_revocar": rev}, run_after={})})

    ries = _con_resultado("Llamada_graph_riesgo",
                          _http("POST", f"{GRAPH}/identityProtection/riskyUsers/confirmCompromised", AUD_GRAPH,
                                cuerpo={"userIds": ["@{items('Cuenta_graph_riesgo')?['aad']}"]}),
                          "Cuenta @{items('Cuenta_graph_riesgo')?['nombre']} confirmada como comprometida",
                          "Error al confirmar el compromiso de @{items('Cuenta_graph_riesgo')?['nombre']}")
    ries = _si({"and": [{"not": {"equals": ["@items('Cuenta_graph_riesgo')?['aad']", ""]}}]},
               {"Si_modo_activo_graph_riesgo": _si({"and": [{"equals": ["@parameters('ContencionAutomatica')", True]}]}, ries,
                                                   {"Observacion_graph_riesgo": _anotar(
                                                       "Observacion: se habria confirmado como comprometida @{items('Cuenta_graph_riesgo')?['nombre']}",
                                                       run_after={})}, run_after={})},
               {"Sin_id_graph_riesgo": _anotar("Cuenta @{items('Cuenta_graph_riesgo')?['nombre']}: sin id de Entra ID; "
                                               "no se puede marcar el riesgo", run_after={})}, run_after={})
    riesgo = _si({"and": [{"contains": [f"@{regla}?['a']", "graph_riesgo"]}]},
                 {"Cuenta_graph_riesgo": _bucle("@body('Identidades_actuables')", {"Si_tiene_id_riesgo": ries}, run_after={})})

    html = ("<p><b>ResponseLab</b> &middot; @{outputs('Familia')?['n']} &middot; regla <i>@{first(body('Elegidas'))}</i> "
            "&middot; clase <code>@{outputs('Regla')?['c']}</code></p>"
            "<p><b>Contencion automatica</b>@{if(parameters('ContencionAutomatica'), '', ' (modo observacion: no se ha ejecutado nada)')}:<br>"
            "@{if(empty(variables('Resultados')), 'ninguna', join(variables('Resultados'), '<br>'))}</p>"
            "<p><b>Con aprobacion</b> (se aprueba ejecutando desde el incidente el playbook indicado):<br>"
            "@{if(empty(body('Pendientes')), 'ninguna', join(body('Pendientes'), '<br>'))}</p>"
            "<p>Escalar a <b>@{outputs('Familia')?['e']}</b> en @{outputs('Familia')?['m']} min. "
            "El resto del playbook esta en las tareas del incidente.</p>")

    tarea = _http("PUT", f"https://management.azure.com@{{{INCIDENTE}}}/tasks/@{{guid()}}?api-version={API_SENTINEL}", AUD_ARM,
                  cuerpo={"properties": {"title": "@{items('Tareas')?['t']}", "description": "@{items('Tareas')?['d']}",
                                         "status": "New"}}, run_after={})

    pasos = [
        ("Resultados", _variable("Resultados")),
        ("Maquinas", _variable("Maquinas")),
        ("Nombres_de_alertas", {"type": "Select", "inputs": {
            "from": "@" + ALERTAS, "select": "@toLower(trim(coalesce(item()?['properties']?['alertDisplayName'], '')))"}}),
        ("Nombres_sin_prefijo", {"type": "Select", "inputs": {
            "from": "@body('Nombres_de_alertas')",
            "select": "@if(or(startsWith(item(), 'dl - '), startsWith(item(), 'rl - ')), substring(item(), 5), item())"}}),
        ("Candidatos", {"type": "Compose", "inputs":
            f"@union(body('Nombres_de_alertas'), body('Nombres_sin_prefijo'), createArray(toLower(trim(coalesce({PROPS}?['title'], '')))))"}),
        ("Reglas_que_casan", _filtro("@outputs('Candidatos')", "not(equals(parameters('Reglas')?[item()], null))")),
        ("Si_no_es_de_ResponseLab", _si({"and": [{"equals": ["@length(body('Reglas_que_casan'))", 0]}]},
                                        {"Terminar": {"type": "Terminate", "runAfter": {},
                                                      "inputs": {"runStatus": "Succeeded"}}})),
        ("Pesos", {"type": "Select", "inputs": {"from": "@body('Reglas_que_casan')",
                                                "select": "@parameters('Reglas')?[item()]?['w']"}}),
        ("Elegidas", _filtro("@body('Reglas_que_casan')", "equals(parameters('Reglas')?[item()]?['w'], max(body('Pesos')))")),
        ("Regla", {"type": "Compose", "inputs": "@parameters('Reglas')?[first(body('Elegidas'))]"}),
        ("Familia", {"type": "Compose", "inputs": "@parameters('Familias')?[outputs('Regla')?['f']]"}),
        *_entidades(),
        ("Identidades_actuables", _filtro("@body('Identidades')", "not(" + _protegida() + ")")),
        ("Identidades_protegidas", _filtro("@body('Identidades')", _protegida())),
        ("Si_hace_falta_Defender", _si({"or": [{"contains": [f"@{regla}?['a']", t]}
                                               for t in ("mde_aislar", "mde_cuarentena", "mde_paquete")]},
                                       {"Por_cada_equipo": dict(_buscar_maquinas(), runAfter={})})),
        ("Maquinas_actuables", _filtro("@variables('Maquinas')", "equals(item()?['protegido'], false)")),
        ("Maquinas_protegidas", _filtro("@variables('Maquinas')", "equals(item()?['protegido'], true)")),
        ("Si_hay_protegidos", _si({"and": [{"greater": [f"@length({regla}?['a'])", 0]},
                                           {"greater": ["@add(length(body('Maquinas_protegidas')), length(body('Identidades_protegidas')))", 0]}]},
                                  {"Anotar_protegidos": _anotar(
                                      "Activos protegidos en el incidente; su contencion y la recogida de evidencia quedan para aprobacion: "
                                      "@{length(body('Maquinas_protegidas'))} equipos y @{length(body('Identidades_protegidas'))} "
                                      "cuentas (parametros ActivosProtegidos y CuentasProtegidas)", run_after={})})),
        _bloque_maquinas("Aislar", "mde_aislar", "@body('Maquinas_actuables')", "isolate",
                         {"Comment": COMENTARIO_MDE, "IsolationType": "Full"}, "Aislamiento pedido en Defender para",
                         "aislar", True),
        ("Cuarentena", cuarentena),
        ("Cuarentena_no_ejecutada", cuarentena_no),
        _bloque_maquinas("Paquete", "mde_paquete", "@body('Maquinas_actuables')", "collectInvestigationPackage",
                         {"Comment": COMENTARIO_MDE}, "Paquete de investigacion pedido para",
                         "recoger el paquete de", True),
        ("Revocar", revocar),
        ("Riesgo", riesgo),
        ("Pendientes", {"type": "Select", "inputs": {"from": f"@coalesce({regla}?['p'], json('[]'))",
                                                     "select": "@parameters('Tipos')?[item()]"}}),
        ("Tareas", _bucle("@coalesce(outputs('Familia')?['t'], json('[]'))", {"Crear_tarea": tarea})),
        ("Comentar", _comentario(html)),
    ]
    pasos_dict = _cadena(pasos)
    parametros = {
        "Reglas": {"type": "Object", "defaultValue": reglas},
        "Familias": {"type": "Object", "defaultValue": familias},
        "Tipos": {"type": "Object", "defaultValue": {k: f"{v['nombre']}: ejecuta {v['playbook']}" for k, v in TIPOS.items()}},
        "ContencionAutomatica": {"type": "Bool", "defaultValue": False},
        "ActivosProtegidos": {"type": "Array", "defaultValue": []},
        "CuentasProtegidas": {"type": "Array", "defaultValue": []},
        "HashesDeNegocio": {"type": "Array", "defaultValue": []},
        "ApiDefender": {"type": "String", "defaultValue": "https://api.security.microsoft.com"},
    }
    return _definicion(pasos_dict, parametros)


# ═══ Playbooks de una accion (aprobacion y deshacer) ════════════════════════

def _playbook_maquinas(tipo: str, ruta: str, cuerpo: dict, hecho: str, verbo: str, con_hash=False) -> dict:
    if con_hash:
        llamada = _http("POST", "@{parameters('ApiDefender')}/api/machines/@{items('Maquina_" + tipo + "')?['id']}/" + ruta,
                        AUD_MDE, cuerpo=dict(cuerpo, Sha1="@{items('Hash_" + tipo + "')?['properties']?['hashValue']}"))
        interior = _con_resultado("Llamada_" + tipo, llamada,
                                  f"{hecho} @{{items('Maquina_{tipo}')?['nombre']}} (@{{items('Hash_{tipo}')?['properties']?['hashValue']}})",
                                  f"Error al {verbo} en @{{items('Maquina_{tipo}')?['nombre']}}")
        bloque = ("Cuarentena", _si({"and": [{"greater": ["@length(body('Hashes_sha1'))", 0]}]},
                                    {"Maquina_" + tipo: _bucle("@variables('Maquinas')",
                                                               {"Hash_" + tipo: _bucle("@body('Hashes_sha1')", interior, run_after={})},
                                                               run_after={})},
                                    {"Sin_sha1": _anotar("El incidente no trae el SHA-1 del fichero, que Defender necesita",
                                                         run_after={})}))
        entidades = ("Equipos", "Hashes_sha1", "Ficheros_de_sistema")
    else:
        bloque = _bloque_maquinas("", tipo, "@variables('Maquinas')", ruta, cuerpo, hecho, verbo, False)
        entidades = ("Equipos",)
    pasos = [
        ("Resultados", _variable("Resultados")),
        ("Maquinas", _variable("Maquinas")),
        *[x for x in _entidades() if x[0] in entidades],
        ("Por_cada_equipo", _buscar_maquinas()),
        ("Avisar_sistema", _si({"and": [{"greater": ["@length(body('Ficheros_de_sistema'))", 0]}]},
                               {"Anotar_sistema": _anotar("Aviso: el incidente incluye ficheros en rutas del sistema operativo; "
                                                          "Defender no pone en cuarentena binarios firmados por Microsoft",
                                                          run_after={})})) if con_hash else None,
        bloque,
        ("Comentar", _comentario(
            f"<p><b>ResponseLab</b> &middot; {TIPO_TITULO.get(tipo, tipo)} (ejecutado desde el incidente)</p>"
            "<p>@{if(empty(variables('Resultados')), 'Sin equipos de Defender en el incidente.', join(variables('Resultados'), '<br>'))}</p>")),
    ]
    return _definicion(_cadena([p for p in pasos if p]), {
        "ActivosProtegidos": {"type": "Array", "defaultValue": []},
        "ApiDefender": {"type": "String", "defaultValue": "https://api.security.microsoft.com"},
    })


def _playbook_identidad(tipo: str, uri: str, cuerpo, hecho: str, verbo: str, solo_aad: bool) -> dict:
    item = f"items('Cuenta_{tipo}')"
    objetivo = f"if(empty({item}?['aad']), {item}?['upn'], {item}?['aad'])"
    llamada = _http("POST", uri.replace("{objetivo}", "@{encodeUriComponent(" + objetivo + ")}"), AUD_GRAPH, cuerpo=cuerpo)
    interior = _con_resultado("Llamada_" + tipo, llamada, f"{hecho} @{{{item}?['nombre']}}", f"Error al {verbo} @{{{item}?['nombre']}}")
    if solo_aad:
        cond = {"and": [{"not": {"equals": [f"@{item}?['aad']", ""]}}]}
    else:
        cond = {"or": [{"not": {"equals": [f"@{item}?['aad']", ""]}}, {"not": {"equals": [f"@{item}?['upn']", ""]}}]}
    cuerpo_bucle = {"Si_tiene_id": _si(cond, interior, {"Sin_id": _anotar(
        f"Cuenta @{{{item}?['nombre']}}: sin identificador de Entra ID", run_after={})}, run_after={})}
    pasos = [
        ("Resultados", _variable("Resultados")),
        *[x for x in _entidades() if x[0] in ("Cuentas", "Identidades")],
        ("Cuenta_" + tipo, _bucle("@body('Identidades')", cuerpo_bucle)),
        ("Comentar", _comentario(
            f"<p><b>ResponseLab</b> &middot; {TIPO_TITULO.get(tipo, tipo)} (ejecutado desde el incidente)</p>"
            "<p>@{if(empty(variables('Resultados')), 'Sin cuentas en el incidente.', join(variables('Resultados'), '<br>'))}</p>")),
    ]
    return _definicion(_cadena(pasos), {})


TIPO_TITULO = {
    "mde_aislar": "Aislar equipos en Defender",
    "mde_liberar": "Levantar el aislamiento en Defender",
    "mde_cuarentena": "Parar y poner en cuarentena ficheros",
    "mde_paquete": "Recoger el paquete de investigacion",
    "graph_revocar": "Revocar sesiones en Entra ID",
    "graph_riesgo": "Confirmar cuentas como comprometidas",
    "graph_descartar": "Descartar el riesgo de las cuentas",
}


def _reenviar() -> dict:
    """RL-Reenviar-al-motor: el incidente entero al motor; el motor decide."""
    enviar = {"type": "Http", "runAfter": {},
              "inputs": {"method": "POST",
                         "uri": "@{parameters('MotorUrl')}/v1/@{parameters('Cliente')}/alertas/sentinel",
                         "headers": {"Authorization": "Bearer @{parameters('TokenMotor')}", "Content-Type": "application/json"},
                         "body": "@triggerBody()",
                         "retryPolicy": {"type": "exponential", "count": 4, "interval": "PT15S"}},
              "runtimeConfiguration": {"secureData": {"properties": ["inputs"]}}}
    ok = _comentario("<p><b>ResponseLab</b>: enviado al motor (@{parameters('Cliente')}) &middot; "
                     "@{body('Enviar_al_motor')?['estado']} &middot; alerta <code>@{body('Enviar_al_motor')?['alerta_id']}</code>. "
                     "Decision, aprobaciones y acciones en @{parameters('MotorUrl')}/panel</p>",
                     run_after=_despues("Enviar_al_motor"))
    error = _comentario("<p><b>ResponseLab</b>: no se pudo enviar al motor (HTTP @{outputs('Enviar_al_motor')?['statusCode']}). "
                        "El incidente sigue su curso manual.</p>",
                        run_after=_despues("Enviar_al_motor", estados=["Failed", "TimedOut"]))
    return _definicion({"Enviar_al_motor": enviar, "Comentar": ok, "Comentar_error": error}, {
        "MotorUrl": {"type": "String", "defaultValue": ""},
        "Cliente": {"type": "String", "defaultValue": ""},
        "TokenMotor": {"type": "SecureString", "defaultValue": ""},
    })


# ═══ Datos de decision ═══════════════════════════════════════════════════════

def _limpio(texto: str, n: int) -> str:
    return " ".join(str(texto or "").split())[:n]


def _tareas(f: dict, acciones: dict) -> list:
    t = []
    esc = f.get("escalado") or {}
    desc = f"Escalar a {esc.get('a', 'L2')} en {esc.get('plazo_min', 30)} minutos."
    for clave, nivel in (("a_L3_si", "L3"), ("a_guardia_si", "guardia")):
        if esc.get(clave):
            desc += f" A {nivel} si: {_limpio(esc[clave], 400)}."
    t.append({"t": f"Escalado: {esc.get('a', 'L2')} en {esc.get('plazo_min', 30)} min", "d": desc})
    for e in f.get("evidencia") or []:
        t.append({"t": "Evidencia: " + _limpio(e["descripcion"], 140),
                  "d": _limpio(f"Como: {e.get('comando', '')}. Donde: {e.get('donde', '')}", 1500)})
    for q in f.get("triaje") or []:
        t.append({"t": "Triaje: " + _limpio(q["pregunta"], 140),
                  "d": _limpio(f"Fuente: {q.get('fuente', '')}. {q.get('nota', '')}", 1500)})
    for c in f.get("contencion") or []:
        meta = acciones.get(c.get("accion") or "") or {}
        tipo = ((meta.get("soar") or {}).get("sentinel") or {}).get("tipo")
        como = (f"Si se aprueba: ejecutar el playbook {TIPOS[tipo]['playbook']} desde el incidente."
                if tipo in TIPOS else "Sin accion nativa en Sentinel: manual, o con el motor de ResponseLab.")
        t.append({"t": "Contencion: " + _limpio(c["texto"], 140),
                  "d": _limpio(f"Radio {c.get('radio')}, reversible {c.get('reversible')}. {como} "
                               f"{('Excepcion: ' + c['excepcion']) if c.get('excepcion') else ''}", 1500)})
    for c in f.get("cierre") or []:
        t.append({"t": "Cierre: " + _limpio(c["condicion"], 140), "d": _limpio(c.get("justificacion", ""), 1500)})
    for r in f.get("requiere_persona") or []:
        t.append({"t": "Requiere persona: " + _limpio(r["situacion"], 130), "d": _limpio(r.get("motivo", ""), 1500)})
    return t[:MAX_TAREAS]


def _datos(catalogo: dict) -> tuple[dict, dict]:
    acciones = catalogo["acciones"]
    por_tipo = {}
    for a, meta in acciones.items():
        tipo = ((meta.get("soar") or {}).get("sentinel") or {}).get("tipo")
        if tipo:
            if tipo not in TIPOS:
                raise ValueError(f"tipo de Sentinel desconocido en {a}: {tipo}")
            por_tipo[a] = tipo
    disponibles = set(por_tipo)
    cat = catalogo_para_soar(catalogo, comprobada_en_sentinel)
    reglas, usadas = {}, set()
    for r in catalogo["reglas"]:
        if not str(r.get("tipo", "")).startswith("sigma"):
            continue            # en Sentinel solo estan las reglas Sigma convertidas a KQL
        d = modos_estaticos(cat, r, disponibles)
        auto = sorted({por_tipo[a] for a, m in d["modos"].items() if m == "automatica" and a in por_tipo})
        aprob = sorted({por_tipo[a] for a, m in d["modos"].items() if m == "aprobacion" and a in por_tipo} - set(auto))
        clave = r["titulo"].strip().lower()
        if clave.startswith("[") and clave.endswith("]"):
            raise ValueError(f"titulo que ARM tomaria por expresion: {r['titulo']}")
        reglas[clave] = {"f": d["familia"], "c": d["clase"], "w": PESO_CLASE.get(d["clase"], 0), "a": auto, "p": aprob}
        usadas.add(d["familia"])
    familias = {}
    for nombre in sorted(usadas):
        f = catalogo["familias"][nombre]
        esc = f.get("escalado") or {}
        familias[nombre] = {"n": f["nombre"], "e": esc.get("a", "L2"), "m": int(esc.get("plazo_min", 30)),
                            "t": _tareas(f, acciones)}
    return reglas, familias


# ═══ Plantillas ARM ══════════════════════════════════════════════════════════

def _escapar_arm(valor):
    """ARM evalua como expresion toda cadena que empieza por '[' y acaba en ']'.
    Dentro de la definicion del workflow no hay expresiones ARM: esas se
    escapan con '[[' (ARM quita el corchete extra al desplegar). Una cadena que
    empieza por '[' pero no acaba en ']' no se toca: ARM la deja como esta."""
    if isinstance(valor, dict):
        return {k: _escapar_arm(v) for k, v in valor.items()}
    if isinstance(valor, list):
        return [_escapar_arm(v) for v in valor]
    if isinstance(valor, str) and valor.startswith("[") and valor.endswith("]"):
        return "[" + valor
    return valor


CONEXION = "[variables('conexion')]"
API_ID = "[variables('api')]"


def _workflow(nombre: str, definicion: dict, parametros: dict, descripcion: str, condicion=None) -> dict:
    valores = {"$connections": {"value": {"azuresentinel": {
        "connectionId": "[resourceId('Microsoft.Web/connections', variables('conexion'))]",
        "connectionName": CONEXION, "id": API_ID,
        "connectionProperties": {"authentication": {"type": "ManagedServiceIdentity"}}}}}}
    valores.update({k: {"value": v} for k, v in parametros.items()})
    r = {"type": "Microsoft.Logic/workflows", "apiVersion": "2017-07-01", "name": nombre,
         "location": "[resourceGroup().location]", "identity": {"type": "SystemAssigned"},
         "tags": {"responselab": "playbook", "descripcion": descripcion[:250]},
         "dependsOn": ["[resourceId('Microsoft.Web/connections', variables('conexion'))]"],
         "properties": {"state": "Enabled", "definition": _escapar_arm(definicion), "parameters": valores}}
    if condicion:
        r["condition"] = condicion
    return r


def plantilla_playbooks(catalogo: dict) -> dict:
    reglas, familias = _datos(catalogo)
    mde = {"ActivosProtegidos": "[parameters('ActivosProtegidos')]", "ApiDefender": "[parameters('ApiDefender')]"}
    recursos = [
        {"type": "Microsoft.Web/connections", "apiVersion": "2016-06-01", "name": CONEXION,
         "location": "[resourceGroup().location]", "kind": "V1",
         "properties": {"displayName": CONEXION, "customParameterValues": {}, "parameterValueType": "Alternative",
                        "api": {"id": API_ID}}},
        _workflow("RL-Respuesta", _respuesta(reglas, familias),
                  dict(mde, ContencionAutomatica="[parameters('ContencionAutomatica')]",
                       CuentasProtegidas="[parameters('CuentasProtegidas')]",
                       HashesDeNegocio="[parameters('HashesDeNegocio')]"),
                  "ResponseLab modo nativo: reconoce la regla, contiene lo que la politica permite, comenta y crea las tareas"),
        _workflow("RL-Aislar-equipo", _playbook_maquinas("mde_aislar", "isolate",
                                                         {"Comment": COMENTARIO_MDE, "IsolationType": "Full"},
                                                         "Aislamiento pedido en Defender para", "aislar"), mde,
                  "Aprobacion: aisla en Defender los equipos del incidente"),
        _workflow("RL-Liberar-equipo", _playbook_maquinas("mde_liberar", "unisolate", {"Comment": COMENTARIO_MDE},
                                                          "Fin del aislamiento pedido para", "liberar"), mde,
                  "Deshacer: levanta el aislamiento de Defender"),
        _workflow("RL-Cuarentena-fichero", _playbook_maquinas("mde_cuarentena", "StopAndQuarantineFile",
                                                              {"Comment": COMENTARIO_MDE},
                                                              "Cuarentena pedida en", "poner en cuarentena", con_hash=True), mde,
                  "Aprobacion: StopAndQuarantineFile por SHA-1 en los equipos del incidente"),
        _workflow("RL-Paquete-investigacion", _playbook_maquinas("mde_paquete", "collectInvestigationPackage",
                                                                 {"Comment": COMENTARIO_MDE},
                                                                 "Paquete de investigacion pedido para", "recoger el paquete de"), mde,
                  "Evidencia: paquete de investigacion de Defender"),
        _workflow("RL-Revocar-sesiones", _playbook_identidad("graph_revocar", GRAPH + "/users/{objetivo}/revokeSignInSessions",
                                                             {}, "Sesiones revocadas de", "revocar las sesiones de", False), {},
                  "Aprobacion: revoca sesiones y tokens de refresco en Entra ID"),
        _workflow("RL-Confirmar-compromiso", _playbook_identidad(
            "graph_riesgo", GRAPH + "/identityProtection/riskyUsers/confirmCompromised",
            {"userIds": ["@{items('Cuenta_graph_riesgo')?['aad']}"]}, "Confirmada como comprometida", "confirmar", True), {},
                  "Aprobacion: confirma las cuentas como comprometidas en ID Protection"),
        _workflow("RL-Descartar-riesgo", _playbook_identidad(
            "graph_descartar", GRAPH + "/identityProtection/riskyUsers/dismiss",
            {"userIds": ["@{items('Cuenta_graph_descartar')?['aad']}"]}, "Riesgo descartado para", "descartar el riesgo de", True), {},
                  "Deshacer: descarta el riesgo marcado sobre las cuentas"),
        _workflow("RL-Reenviar-al-motor", _reenviar(),
                  {"MotorUrl": "[parameters('MotorUrl')]", "Cliente": "[parameters('Cliente')]",
                   "TokenMotor": "[parameters('TokenMotor')]"},
                  "Modo motor: envia el incidente a ResponseLab", condicion="[parameters('DesplegarReenvio')]"),
    ]
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {"descripcion": "ResponseLab: playbooks de respuesta para Microsoft Sentinel. Generado por tools/compilar.py; "
                                    "no editar a mano.", "version_catalogo": catalogo["version"],
                     "reglas_reconocidas": len(reglas), "familias": sorted(familias)},
        "parameters": {
            "ContencionAutomatica": {"type": "bool", "defaultValue": False, "metadata": {"description":
                "false = modo observacion: RL-Respuesta comenta lo que haria sin hacerlo. Ponlo a true tras revisar esos comentarios."}},
            "ActivosProtegidos": {"type": "array", "defaultValue": [], "metadata": {"description":
                "Nombres cortos de equipo, en minusculas, que nunca se contienen solos (controladores de dominio, servidores criticos)."}},
            "CuentasProtegidas": {"type": "array", "defaultValue": [], "metadata": {"description":
                "Cuentas (nombre, UPN o id, en minusculas) que nunca se tocan solas: cuentas de emergencia, de servicio criticas."}},
            "HashesDeNegocio": {"type": "array", "defaultValue": [], "metadata": {"description":
                "SHA-1 o SHA-256, en minusculas, de aplicaciones de negocio: nunca se ponen en cuarentena solas."}},
            "ApiDefender": {"type": "string", "defaultValue": "https://api.security.microsoft.com", "metadata": {"description":
                "API de Defender for Endpoint. Para datos en la UE: https://eu.api.security.microsoft.com"}},
            "DesplegarReenvio": {"type": "bool", "defaultValue": False, "metadata": {"description":
                "true para desplegar RL-Reenviar-al-motor (modo motor)."}},
            "MotorUrl": {"type": "string", "defaultValue": "", "metadata": {"description": "https://motor.ejemplo:8443 (modo motor)"}},
            "Cliente": {"type": "string", "defaultValue": "", "metadata": {"description": "Id del cliente en el motor (modo motor)"}},
            "TokenMotor": {"type": "securestring", "defaultValue": "", "metadata": {"description":
                "Token de ingesta del cliente (modo motor). Mejor desde Key Vault con una referencia en el fichero de parametros."}},
        },
        "variables": {
            "conexion": "azuresentinel-responselab",
            "api": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Web/locations/', resourceGroup().location, '/managedApis/azuresentinel')]",
        },
        "resources": recursos,
        "outputs": {r["name"].replace("-", "_"): {"type": "string", "condition": r.get("condition", True),
                                "value": f"[reference(resourceId('Microsoft.Logic/workflows', '{r['name']}'), '2017-07-01', 'full').identity.principalId]"}
                    for r in recursos if r["type"] == "Microsoft.Logic/workflows"},
    }


def plantilla_automatizacion() -> dict:
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {"descripcion": "ResponseLab: regla de automatizacion que lanza el playbook en cada incidente nuevo. "
                                    "Despliega antes playbooks.json y ejecuta conceder-permisos.ps1."},
        "parameters": {
            "Workspace": {"type": "string", "metadata": {"description": "Nombre del workspace de Log Analytics con Sentinel"}},
            "Modo": {"type": "string", "allowedValues": ["nativo", "motor"], "defaultValue": "nativo", "metadata": {"description":
                "nativo = RL-Respuesta decide en Azure; motor = RL-Reenviar-al-motor envia el incidente a ResponseLab"}},
            "GrupoPlaybooks": {"type": "string", "defaultValue": "[resourceGroup().name]",
                               "metadata": {"description": "Grupo de recursos donde se desplego playbooks.json"}},
            "Orden": {"type": "int", "defaultValue": 100, "minValue": 1, "maxValue": 1000},
        },
        "variables": {"playbook": "[if(equals(parameters('Modo'), 'motor'), 'RL-Reenviar-al-motor', 'RL-Respuesta')]"},
        "resources": [{
            "type": "Microsoft.SecurityInsights/automationRules", "apiVersion": API_REGLAS,
            "scope": "[format('Microsoft.OperationalInsights/workspaces/{0}', parameters('Workspace'))]",
            "name": uid("sentinel", "regla-automatizacion"),
            "properties": {
                "displayName": "ResponseLab - respuesta a incidentes", "order": "[parameters('Orden')]",
                "triggeringLogic": {"isEnabled": True, "triggersOn": "Incidents", "triggersWhen": "Created", "conditions": []},
                "actions": [{"order": 1, "actionType": "RunPlaybook", "actionConfiguration": {
                    "logicAppResourceId": "[resourceId(parameters('GrupoPlaybooks'), 'Microsoft.Logic/workflows', variables('playbook'))]",
                    "tenantId": "[subscription().tenantId]"}}],
            },
        }],
    }


PERMISOS_PS1 = r'''<#
.SYNOPSIS
  Concede a los playbooks de ResponseLab los permisos que necesitan.

.DESCRIPTION
  Generado por ResponseLab (tools/compilar.py). No editar: se regenera.

  1. Rol "Microsoft Sentinel Responder" a la identidad de cada playbook sobre
     el grupo de recursos del workspace: comentar y crear tareas en incidentes.
  2. Permisos de aplicacion en Defender for Endpoint (WindowsDefenderATP) y en
     Microsoft Graph: a cada playbook solo los que usa.
  3. Rol "Microsoft Sentinel Automation Contributor" a "Azure Security
     Insights" sobre el grupo de los playbooks, para que la regla de
     automatizacion pueda ejecutarlos.

  Requiere: Az.Accounts, Az.Resources y Microsoft.Graph.Applications, y ser
  Owner (o User Access Administrator) de los dos grupos de recursos y poder
  conceder permisos de aplicacion (Privileged Role Administrator).
  Se puede ejecutar varias veces: lo que ya esta concedido se salta.

.EXAMPLE
  ./conceder-permisos.ps1 -GrupoPlaybooks rg-soar -GrupoWorkspace rg-sentinel
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $GrupoPlaybooks,
    [Parameter(Mandatory)] [string] $GrupoWorkspace,
    [string] $Suscripcion
)
$ErrorActionPreference = 'Stop'

$Permisos = @{
__PERMISOS__
}
$AppMde = 'fc780465-2017-40d4-a0c5-307022471b92'     # WindowsDefenderATP
$AppGraph = '00000003-0000-0000-c000-000000000000'   # Microsoft Graph

if ($Suscripcion) { Set-AzContext -Subscription $Suscripcion | Out-Null }
$ctx = Get-AzContext
if (-not $ctx) { throw 'Ejecuta Connect-AzAccount antes.' }
Connect-MgGraph -TenantId $ctx.Tenant.Id -Scopes 'AppRoleAssignment.ReadWrite.All', 'Application.Read.All' -NoWelcome

$spMde = Get-MgServicePrincipal -Filter "appId eq '$AppMde'" -ErrorAction SilentlyContinue
$spGraph = Get-MgServicePrincipal -Filter "appId eq '$AppGraph'"
if (-not $spMde) { Write-Warning 'Defender for Endpoint no esta en el tenant: se omiten sus permisos.' }
$rgWorkspace = (Get-AzResourceGroup -Name $GrupoWorkspace).ResourceId
$rgPlaybooks = (Get-AzResourceGroup -Name $GrupoPlaybooks).ResourceId

function Conceder-Rol($objeto, $rol, $ambito, $quien) {
    $ya = Get-AzRoleAssignment -ObjectId $objeto -RoleDefinitionName $rol -Scope $ambito -ErrorAction SilentlyContinue
    if ($ya) { Write-Host "  = $rol ya concedido a $quien"; return }
    New-AzRoleAssignment -ObjectId $objeto -RoleDefinitionName $rol -Scope $ambito | Out-Null
    Write-Host "  + $rol a $quien"
}

function Conceder-Api($objeto, $sp, $valores, $quien) {
    if (-not $sp) { return }
    $ya = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $objeto -All |
          Where-Object { $_.ResourceId -eq $sp.Id } | ForEach-Object { $_.AppRoleId }
    foreach ($v in $valores) {
        $rol = $sp.AppRoles | Where-Object { $_.Value -eq $v -and $_.AllowedMemberTypes -contains 'Application' }
        if (-not $rol) { Write-Warning "  ! $($sp.DisplayName) no tiene el permiso $v"; continue }
        if ($ya -contains $rol.Id) { Write-Host "  = $v ya concedido a $quien"; continue }
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $objeto -PrincipalId $objeto `
            -ResourceId $sp.Id -AppRoleId $rol.Id | Out-Null
        Write-Host "  + $v a $quien"
    }
}

foreach ($nombre in $Permisos.Keys | Sort-Object) {
    $wf = Get-AzResource -ResourceGroupName $GrupoPlaybooks -ResourceType 'Microsoft.Logic/workflows' -Name $nombre -ErrorAction SilentlyContinue
    if (-not $wf) { Write-Host "- $nombre no esta desplegado: se omite"; continue }
    $objeto = $wf.Identity.PrincipalId
    if (-not $objeto) { Write-Warning "$nombre no tiene identidad administrada"; continue }
    Write-Host $nombre
    Conceder-Rol $objeto 'Microsoft Sentinel Responder' $rgWorkspace $nombre
    Conceder-Api $objeto $spMde $Permisos[$nombre].mde $nombre
    Conceder-Api $objeto $spGraph $Permisos[$nombre].graph $nombre
}

$asi = Get-AzADServicePrincipal -DisplayName 'Azure Security Insights' | Select-Object -First 1
if ($asi) {
    Write-Host 'Azure Security Insights'
    Conceder-Rol $asi.Id 'Microsoft Sentinel Automation Contributor' $rgPlaybooks 'Azure Security Insights'
} else {
    Write-Warning 'No se encontro Azure Security Insights: concede el permiso desde Sentinel > Configuracion > Permisos de playbooks.'
}
Write-Host 'Listo. Los permisos de API pueden tardar unos minutos en aplicarse.'
'''


def _ps1() -> str:
    lineas = []
    for nombre in sorted(PERMISOS):
        p = PERMISOS[nombre]
        mde = ", ".join(f"'{x}'" for x in p.get("mde", []))
        graph = ", ".join(f"'{x}'" for x in p.get("graph", []))
        lineas.append(f"    '{nombre}' = @{{ mde = @({mde}); graph = @({graph}) }}")
    return PERMISOS_PS1.replace("__PERMISOS__", "\n".join(lineas)).replace("\n", "\r\n")


def _json(datos) -> str:
    return json.dumps(datos, ensure_ascii=False, indent=2, sort_keys=False) + "\n"


def exportar(catalogo: dict) -> dict[str, str]:
    return {
        "soar/sentinel/playbooks.json": _json(plantilla_playbooks(catalogo)),
        "soar/sentinel/automatizacion.json": _json(plantilla_automatizacion()),
        "soar/sentinel/conceder-permisos.ps1": _ps1(),
    }
