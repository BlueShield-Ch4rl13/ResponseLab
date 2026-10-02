# Capa ejecutable de los playbooks

Los playbooks de respuesta los escribe DetectionLab, en `respuesta/playbooks/`, y se
sincronizan a `ecosistema/detectionlab/playbooks/`. Están pensados para una
persona. Dicen qué preguntar en el triaje, cuándo cerrar, qué contener, con qué
radio, si es reversible y por qué. Esta carpeta añade lo que necesita una máquina
para hacer lo mismo sin adivinar.

| Fichero | Qué añade |
|---|---|
| `<familia>.yml` | Evaluadores para las preguntas de triaje, las condiciones de cierre y el escalado de esa familia |
| `comun.yml` | Qué acción del catálogo ejecuta cada frase de contención, las excepciones de cada acción y la evidencia que se recoge sola |
| `secuencias.yml` | Las secuencias de ataque que correlan varias alertas |
| `_generico.yml` | La familia de reserva para reglas sin playbook: nunca contiene nada |

La prosa sigue mandando. Si DetectionLab añade una pregunta o una acción que aquí no
tiene traducción, no se pierde ni se adivina: la pregunta queda como tarea del
analista, la acción como paso manual, y `tools/validar.py` la lista para que alguien
decida.

## Cómo se casa con la prosa

Antes de comparar, los textos se normalizan: sin tildes, mayúsculas ni puntuación.
Así, una coma cambiada aguas arriba no rompe nada.
- Las preguntas de triaje casan por su texto completo.
- Las condiciones de cierre casan por cómo empiezan (`empieza`).
- Las frases de contención de `comun.yml` casan por su texto.

Una entrada que deja de casar porque DetectionLab reescribió la frase queda
huérfana, y el validador la lista como aviso.

```yaml
familia: endpoint

triaje:
  - pregunta: El proceso padre es el agente de distribucion de software del parque y hay ventana de despliegue abierta
    evaluador:
      todos:
        - {lista.valor_en: {lista: agentes_distribucion, campo: proceso.padre_nombre}}
        - {inventario.ventana_abierta: {tipo: despliegue}}
    nota: lo que la maquina no puede ver y el analista deberia saber

cierre:
  - empieza: Ejecucion desde ruta de usuario o creacion de servicio
    evaluador: {...}           # TODAS las condiciones; si alguna es "no se", no cierra

escalado:
  a_L3_si: {evento.regla_en: [soc_edr_003_borrado_copias_sombra]}
  a_guardia_si: {inventario.etiqueta: {etiquetas: [servidor_ficheros]}}
```

## Evaluadores

Cada evaluador contesta `True`, `False` o `None`. `None` significa que no hay datos
para contestar. Se combinan así:
- `todos` es falso si alguno es falso, desconocido si alguno es desconocido y
  verdadero solo si todos lo son;
- `alguno` es verdadero si alguno lo es;
- `negar` invierte, y lo desconocido sigue siendo desconocido.

| Grupo | Evaluadores | Con qué datos |
|---|---|---|
| `evento.*` | `regla_en`, `campo_valor`, `campo_contiene`, `campo_existe`, `texto_contiene` | La propia alerta normalizada |
| `inventario.*` | `etiqueta`, `ventana_abierta`, `excepcion_vigente`, `excepcion_caducada` | El inventario, las ventanas (en la zona horaria del cliente) y las excepciones del perfil |
| `lista.*` | `valor_en`, `ip_en_rango`, `prefijo_en`, `prefijo_no_en`, `par_en` | Las listas del perfil (administradores, escáneres, aplicaciones de negocio...) |
| `directorio.*` | `cuenta_en_lista` | Listas de cuentas del perfil |
| `correlacion.*` | `otras_familias`, `misma_regla_en_equipos`, `unico_equipo`, `regla_en_equipo`, `familia_en_usuario`, `primera_vez`, `mismo_observable_en_equipos`, `observables_distintos_en_equipo` | Las alertas de los últimos siete días |
| `cti.*` | `coincidencia`, `tipo_coincidencia`, `nivel_en`, `antiguedad_mayor`, `una_sola_fuente`, `retirado_del_feed`, `kev` | News CTI y su historial |
| `dns.*` | `proveedor_cdn` | DNS inverso del destino |
| `regulatorio.*` | `plazo_menor_horas` | Los plazos de RGPD, NIS2 y DORA del incidente |

Un evaluador que el núcleo no conoce es un error de validación. Así, un catálogo
escrito para una versión más nueva del motor se rechaza con un mensaje, en vez de
romper la decisión de cada alerta.

## Secuencias

```yaml
- id: ransomware
  objetivo: equipo               # equipo | usuario: lo que comparten las alertas
  ventana_min: 360
  pasos:                         # cada paso se cumple con cualquiera de sus elementos
    - [soc_edr_004_defensas_deshabilitadas, xdr_001_desinstalacion_sensor_edr]
    - [soc_edr_003_borrado_copias_sombra]
    - [soc_edr_007_cifrado_masivo]
  minimo: 2
  efecto: {severidad: 4, escalar_a: guardia, clase: auto_contener, avisar: [dpd]}
```

Un elemento puede ser la clave de una regla (o su fichero sin extensión),
`familia:<f>` o `tecnica:<T>`. El efecto se aplica a la alerta que completa la
secuencia, y solo si esa alerta forma parte de ella. `clase: auto_contener` nunca
eleva una alerta de una regla que no está en el catálogo.

## Después de cambiar algo

```powershell
python tools/compilar.py      # catalogo y artefactos de cada SOAR
python tools/validar.py       # errores, avisos e invariantes
python tools/simular.py       # los ataques de escenarios/ siguen dando lo esperado
python -m pytest -q
```
