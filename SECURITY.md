# Seguridad

ResponseLab ejecuta acciones de contención en la infraestructura de los clientes:
aísla equipos, revoca sesiones y bloquea en el perímetro. Un fallo suyo es un
incidente en sí mismo. Las vulnerabilidades se tratan con prioridad.

## Cómo informar

No abras un issue público. Escribe a **contact@carlosvillalbalagos.com** con:

- qué componente afecta (motor, API, conectores, scripts de active response,
  artefactos de un SOAR...);
- cómo reproducirlo;
- qué impacto tiene: ejecutar una acción que no debía, actuar sobre otro cliente,
  leer secretos, saltarse una aprobación...

Recibirás respuesta en un plazo de 72 horas. Cuando haya corrección, se publicará
con el crédito que prefieras.

## Qué cuenta como vulnerabilidad

- Que una acción de radio cuenta u organización, o irreversible sobre algo más que
  un proceso, se ejecute sin aprobación.
- Que el token de un cliente, o de una función, sirva para otro cliente u otra
  función.
- Que un catálogo, un perfil o una alerta manipulados consigan ejecutar algo que la
  política no permite.
- Que un script de active response actúe sobre ficheros del sistema, procesos
  críticos o rutas fuera de su objetivo.
- Que se pueda alterar la auditoría sin que `verificar` lo detecte.
- La exposición de secretos en registros, respuestas o artefactos generados.

## Qué no lo es

- Que una acción espere aprobación cuando podría ejecutarse sola: es la política
  funcionando. Si crees que la política es demasiado prudente, abre un issue normal.
- Fallos de herramientas de terceros (Wazuh, Splunk, Defender…), salvo que
  ResponseLab los empeore.
