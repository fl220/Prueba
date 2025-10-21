# Monitor de red doméstica

Este repositorio contiene una utilidad de línea de comandos escrita en Python para
obtener una visión rápida del estado de la red local. La herramienta muestra las
interfaces de red IPv4 detectadas, la tabla ARP del sistema y ofrece un escaneo
opcional mediante ping para intentar descubrir dispositivos que todavía no aparecen en
la tabla.

## Requisitos

* Python 3.8 o superior.
* Herramientas del sistema:
  * Linux/macOS: `ip` y `ping`.
  * Windows: `ipconfig`, `arp` y `ping`.

## Uso

Ejecute el script desde la raíz del proyecto:

```bash
python network_monitor.py
```

Para realizar un escaneo rápido (máximo 32 hosts por defecto):

```bash
python network_monitor.py --scan
```

Opciones disponibles:

* `--scan`: activa el escaneo mediante ping.
* `--interface`: especifica la interfaz sobre la que realizar el escaneo.
* `--max-hosts`: limita el número de direcciones que se consultan (32 por defecto).
* `--timeout`: tiempo de espera de cada ping en milisegundos.
* `--count`: número de solicitudes de ping por host.

## Próximos pasos

A partir de esta base podemos ampliar la utilidad incorporando inventariado histórico,
detección de dispositivos nuevos, notificaciones o integración con protocolos como
SNMP. ¡Vamos construyéndolo juntos!
