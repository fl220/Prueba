"""Herramienta de línea de comandos para inspeccionar dispositivos en la red local.

Este módulo detecta interfaces, pasarelas y dispositivos descubiertos a través de la
tabla ARP. También ofrece la posibilidad de realizar un escaneo básico mediante ping
para intentar descubrir dispositivos que aún no aparecen en la tabla ARP.
"""
from __future__ import annotations

import argparse
import dataclasses
import ipaddress
import platform
import subprocess
import sys
import textwrap
from itertools import islice
from typing import Dict, Iterable, List, Optional


@dataclasses.dataclass
class NetworkInterface:
    """Representa una interfaz de red con su configuración IPv4."""

    name: str
    address: str
    prefix_length: int
    broadcast: Optional[str] = None

    @property
    def network(self) -> Optional[ipaddress.IPv4Network]:
        """Devuelve la red asociada a la interfaz, si se puede determinar."""

        try:
            return ipaddress.IPv4Interface(f"{self.address}/{self.prefix_length}").network
        except ValueError:
            return None


@dataclasses.dataclass
class NetworkDevice:
    """Representa un dispositivo detectado en la red local."""

    ip_address: str
    mac_address: Optional[str] = None
    interface: Optional[str] = None
    state: Optional[str] = None


class NetworkScanner:
    """Extrae información básica sobre la red utilizando utilidades del sistema."""

    def __init__(self, run_command=subprocess.run):
        self._run = run_command
        self._system = platform.system()
        self._missing_commands: set[str] = set()

    # Utilidades de ejecución -------------------------------------------------
    def _execute(self, command: List[str]) -> str:
        """Ejecuta un comando en el sistema y devuelve su salida estándar."""

        try:
            completed = self._run(command, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            if command:
                self._missing_commands.add(command[0])
            return ""
        if completed.returncode != 0:
            return completed.stdout
        return completed.stdout

    @property
    def missing_commands(self) -> List[str]:
        """Devuelve un listado de comandos que no se pudieron ejecutar."""

        return sorted(self._missing_commands)

    # Interfaces ---------------------------------------------------------------
    def get_interfaces(self) -> List[NetworkInterface]:
        """Recupera la configuración de interfaces IPv4."""

        if self._system == "Windows":
            return self._get_interfaces_windows()
        return self._get_interfaces_unix()

    def _get_interfaces_unix(self) -> List[NetworkInterface]:
        output = self._execute(["ip", "-o", "-4", "addr", "show"])
        interfaces: List[NetworkInterface] = []
        for line in output.splitlines():
            parts = line.split()
            if "inet" not in parts:
                continue
            try:
                name = parts[1]
                inet_index = parts.index("inet")
                cidr = parts[inet_index + 1]
                address, prefix = cidr.split("/")
                broadcast: Optional[str] = None
                if "brd" in parts:
                    brd_index = parts.index("brd")
                    broadcast = parts[brd_index + 1]
                interfaces.append(
                    NetworkInterface(
                        name=name,
                        address=address,
                        prefix_length=int(prefix),
                        broadcast=broadcast,
                    )
                )
            except (ValueError, IndexError):
                continue
        return interfaces

    def _get_interfaces_windows(self) -> List[NetworkInterface]:
        output = self._execute(["ipconfig"])
        interfaces: List[NetworkInterface] = []
        current_name: Optional[str] = None
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if raw_line and not raw_line.startswith(" "):
                current_name = raw_line.rstrip(":")
                continue
            if "IPv4" in line and ":" in line:
                try:
                    _, address = line.split(":", 1)
                    address = address.strip()
                    interfaces.append(
                        NetworkInterface(
                            name=current_name or "desconocida",
                            address=address,
                            prefix_length=24,
                        )
                    )
                except ValueError:
                    continue
        return interfaces

    # Dispositivos ------------------------------------------------------------
    def get_devices(self) -> List[NetworkDevice]:
        if self._system == "Windows":
            return self._get_devices_windows()
        return self._get_devices_unix()

    def _get_devices_unix(self) -> List[NetworkDevice]:
        output = self._execute(["ip", "neigh", "show"])
        devices: List[NetworkDevice] = []
        for line in output.splitlines():
            parts = line.split()
            if not parts:
                continue
            ip_address = parts[0]
            device = NetworkDevice(ip_address=ip_address)
            if "dev" in parts:
                dev_index = parts.index("dev")
                if dev_index + 1 < len(parts):
                    device.interface = parts[dev_index + 1]
            if "lladdr" in parts:
                mac_index = parts.index("lladdr")
                if mac_index + 1 < len(parts):
                    device.mac_address = parts[mac_index + 1]
            if parts[-1].isupper():
                device.state = parts[-1]
            devices.append(device)
        return devices

    def _get_devices_windows(self) -> List[NetworkDevice]:
        output = self._execute(["arp", "-a"])
        devices: List[NetworkDevice] = []
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("Interface") or line.startswith("Internet"):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            ip_address, mac_address, state = parts[:3]
            devices.append(
                NetworkDevice(
                    ip_address=ip_address,
                    mac_address=mac_address,
                    state=state.upper(),
                )
            )
        return devices

    # Escaneo -----------------------------------------------------------------
    def scan_network(
        self,
        network: ipaddress.IPv4Network,
        max_hosts: int,
        count: int = 1,
        timeout_ms: int = 1000,
    ) -> Dict[str, bool]:
        """Realiza un ping básico a direcciones del rango indicado."""

        reachable: Dict[str, bool] = {}
        for ip in self._iter_hosts(network, max_hosts):
            reachable[str(ip)] = self._ping(str(ip), count=count, timeout_ms=timeout_ms)
        return reachable

    def _iter_hosts(self, network: ipaddress.IPv4Network, max_hosts: int) -> Iterable[ipaddress.IPv4Address]:
        return islice(network.hosts(), max_hosts)

    def _ping(self, ip: str, *, count: int, timeout_ms: int) -> bool:
        timeout_seconds = max(1, int(timeout_ms / 1000))
        if self._system == "Windows":
            command = ["ping", "-n", str(count), "-w", str(timeout_ms), ip]
        else:
            command = ["ping", "-c", str(count), "-W", str(timeout_seconds), ip]
        try:
            result = self._run(command, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            if command:
                self._missing_commands.add(command[0])
            return False
        return result.returncode == 0


def format_interfaces(interfaces: List[NetworkInterface]) -> str:
    if not interfaces:
        return "No se detectaron interfaces IPv4."
    lines = ["Interfaces detectadas:"]
    for interface in interfaces:
        network = interface.network
        network_text = str(network) if network else "desconocida"
        broadcast = interface.broadcast or "desconocida"
        lines.append(
            f"  - {interface.name}: {interface.address}/{interface.prefix_length}\n"
            f"      red: {network_text} | broadcast: {broadcast}"
        )
    return "\n".join(lines)


def format_devices(devices: List[NetworkDevice]) -> str:
    if not devices:
        return "No se detectaron dispositivos en la tabla ARP."
    lines = ["Dispositivos detectados (tabla ARP):"]
    for device in devices:
        mac = device.mac_address or "desconocida"
        iface = device.interface or "desconocida"
        state = device.state or "desconocido"
        lines.append(f"  - IP: {device.ip_address} | MAC: {mac} | interfaz: {iface} | estado: {state}")
    return "\n".join(lines)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inspecciona la red local y muestra información de interfaces y dispositivos",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Ejemplos de uso:
              python network_monitor.py           # Muestra un resumen general
              python network_monitor.py --scan    # Realiza un escaneo rápido (máx. 32 hosts)
              python network_monitor.py --scan --max-hosts 128
            """
        ),
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Ejecuta un ping contra las direcciones del segmento (máximo configurable)",
    )
    parser.add_argument(
        "--interface",
        help="Nombre de la interfaz sobre la que realizar el escaneo",
    )
    parser.add_argument(
        "--max-hosts",
        type=int,
        default=32,
        help="Número máximo de hosts a consultar al escanear (por defecto: 32)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=1000,
        help="Tiempo de espera de cada ping en milisegundos",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="Número de solicitudes de ping por host",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    scanner = NetworkScanner()

    interfaces = scanner.get_interfaces()
    devices = scanner.get_devices()

    print(format_interfaces(interfaces))
    print()
    print(format_devices(devices))

    if scanner.missing_commands:
        print()
        print(
            "Aviso: no se encontraron los siguientes comandos requeridos: "
            + ", ".join(scanner.missing_commands)
        )
        print(
            "Instálelos para obtener resultados completos (consulte la sección de "
            "requisitos del README)."
        )

    if args.scan:
        target_interface = None
        if args.interface:
            target_interface = next((iface for iface in interfaces if iface.name == args.interface), None)
            if target_interface is None:
                print(f"La interfaz '{args.interface}' no se encontró. Se aborta el escaneo.")
                return 1
        else:
            target_interface = interfaces[0] if interfaces else None

        if not target_interface or not target_interface.network:
            print("No se pudo determinar una red válida para el escaneo.")
            return 1

        print()
        print(
            f"Escaneando hasta {args.max_hosts} hosts en la red {target_interface.network} "
            f"(interfaz {target_interface.name})"
        )
        reachability = scanner.scan_network(
            target_interface.network,
            max_hosts=args.max_hosts,
            count=args.count,
            timeout_ms=args.timeout,
        )
        online = [ip for ip, ok in reachability.items() if ok]
        offline = [ip for ip, ok in reachability.items() if not ok]
        print(f"Hosts en línea ({len(online)}): {', '.join(online) if online else 'ninguno'}")
        print(f"Hosts sin respuesta ({len(offline)}): {', '.join(offline) if offline else 'ninguno'}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
