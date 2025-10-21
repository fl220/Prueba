# Monitor de red doméstica

Este repositorio contiene una utilidad en Python para
obtener una visión rápida del estado de la red local. Además del modo de línea de
comandos original, ahora incluye una interfaz gráfica con estética "liquid glass" que
permite explorar las interfaces detectadas, los dispositivos registrados en la tabla
ARP y lanzar escaneos básicos mediante ping.

## Requisitos

* Python 3.8 o superior.
* Herramientas opcionales del sistema:
  * Linux/macOS: se aprovechan `ip` o `ifconfig` si están disponibles, pero el script
    también puede leer directamente desde `/sys/class/net` y `/proc/net/arp`.
  * Windows: `ipconfig` y `arp`.
* `ping` (en cualquier plataforma) para realizar escaneos activos. Si no está
  disponible, la aplicación seguirá mostrando interfaces y dispositivos ya
  registrados, pero no podrá comprobar la disponibilidad de hosts.

## Uso

Ejecute el script desde la raíz del proyecto:

```bash
python network_monitor.py
```

La ventana muestra tres paneles principales:

* **Interfaces de red**: lista cada interfaz IPv4 y su red asociada.
* **Dispositivos conocidos (ARP)**: refleja la tabla ARP del sistema.
* **Escaneo de red**: al pulsar "Escanear" se lanza un ping contra los primeros hosts
  del segmento y se listan los resultados en estilo "vidrio líquido".

### Uso en CLI

Si prefieres el modo clásico de consola, actívalo con `--cli`:

```bash
python network_monitor.py --cli
```

Parámetros disponibles (CLI y GUI):

* `--scan`: en CLI ejecuta el escaneo inmediatamente; en GUI lanza un escaneo automático al abrir.
* `--interface`: especifica la interfaz sobre la que realizar el escaneo (solo CLI).
* `--max-hosts`: limita el número de direcciones que se consultan (32 por defecto).
* `--timeout`: tiempo de espera de cada ping en milisegundos.
* `--count`: número de solicitudes de ping por host.

## Próximos pasos

A partir de esta base podemos ampliar la utilidad incorporando inventariado histórico,
detección de dispositivos nuevos, notificaciones o integración con protocolos como
SNMP. ¡Vamos construyéndolo juntos!
