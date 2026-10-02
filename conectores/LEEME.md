# Conectores declarativos

Cualquier herramienta con API HTTP se integra con un fichero YAML en esta carpeta,
sin tocar el motor. El nombre del fichero no importa. Lo que importa es el campo
`nombre`, que es el que se cita en `capacidades` del perfil del cliente.

```yaml
nombre: mi-herramienta
descripcion: Qué hace
base_url_env: MI_HERRAMIENTA_URL     # o base_url: https://...
autenticacion:
  tipo: bearer                       # ninguna | bearer | cabecera | basica | oauth2_cc
  token_env: MI_HERRAMIENTA_TOKEN
acciones:
  perimetro.bloquear_destino:        # id de una acción de acciones/catalogo.yml
    metodo: POST
    ruta: /api/bloqueos
    cuerpo: {valor: "{{ objetivo.red.ip_destino }}", motivo: "{{ alerta.titulo }}"}
    exito: [200, 201]
    guardar: {id: data.id}           # se guarda para deshacer: {{ deshacer.id }}
    detalle: "bloqueada {{ objetivo.red.ip_destino }}"
  perimetro.desbloquear_destino:
    metodo: DELETE
    ruta: /api/bloqueos/{{ deshacer.id }}
```

## Plantillas

`{{ ruta.al.campo }}` se puede usar sobre `alerta`, `objetivo`, `plan`, `cliente`,
`parametros`, `deshacer`, `incidente` y `ejecucion`. Admite cuatro filtros:
`json`, `urlencode`, `minusculas` y `default:valor`.

No hay expresiones. Una plantilla que pudiera ejecutar código convertiría cada
fichero de esta carpeta en una vía de ejecución remota.

## Credenciales por cliente

Cada cliente puede usar sus propias credenciales. En su perfil,
`conectores.<nombre>` sustituye cualquier `*_env` de la definición. Los valores
siempre son nombres de variables de entorno, nunca el secreto.

## Herramientas sin API HTTP

Se usa `conectores/scripts/`. El conector `script` lanza un ejecutable de esa
carpeta, y solo de esa. Le pasa un JSON por la entrada estándar y lee otro por la
salida: `{"ok": true, "detalle": "...", "datos": {...}}`.

Los argumentos van en lista, nunca a través de una shell, y la ejecución tiene un
tiempo máximo.

## Ejemplos incluidos

| Fichero | Herramienta | Acciones |
|---|---|---|
| `cisco-ise.yml` | Cisco ISE (ANC) | Aplica y retira una política de cuarentena por IP (`red.aislar_equipo`, `red.liberar_equipo`) |
| `opnsense.yml` | OPNsense | Añade y quita IP del alias de bloqueo (`perimetro.bloquear_destino` y su inversa) |
| `servicenow.yml` | ServiceNow | Abre y anota incidentes con la Table API (`itsm.ticket`, `caso.tarea_desviacion`) |
| `webhook-generico.yml` | Un endpoint HTTP propio | Pasarela de correo y aplicaciones (`correo.bloquear_remitente`, `aplicacion.invalidar_sesion`...) |
| `scripts/ejemplo.py` | Plantilla de script | Bloqueo de un remitente: lee la orden por la entrada estándar y contesta por la salida |
