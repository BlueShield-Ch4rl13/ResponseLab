"""ResponseLab: respuesta a incidentes como codigo, multi-SIEM y multi-SOAR.

El paquete tiene dos mitades que conviene no mezclar:

* ``responselab.nucleo`` decide. Es Python puro, sin dependencias, y es el
  mismo codigo que se incrusta en los nodos de Shuffle, en los playbooks de
  Splunk SOAR y en el script de Cortex XSOAR. Una decision, seis ejecutores.
* El resto (``api``, ``ejecutor``, ``conectores``...) ejecuta: recibe alertas,
  guarda estado, pide aprobaciones y habla con las herramientas del cliente.
"""

__version__ = "1.0.0"
