"""Herramienta para inspeccionar dispositivos en la red local con interfaz gráfica.

El módulo permite obtener interfaces, dispositivos conocidos por la tabla ARP y
realizar escaneos básicos mediante ping. Además de la interfaz de línea de
comandos original, ahora incluye una ventana con estética "liquid glass" inspirada
en iOS 16.
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
import shutil
import socket
import struct
import subprocess
import sys
import textwrap
import threading
from datetime import datetime
from itertools import islice
from pathlib import Path
from typing import Dict, Iterable, List, Optional

try:
    import fcntl  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - solo Windows
    fcntl = None  # type: ignore[assignment]

import tkinter as tk
from tkinter import messagebox, ttk


# ---------------------------------------------------------------------------
# Modelo de datos
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Lógica de inspección de red
# ---------------------------------------------------------------------------


class NetworkScanner:
    """Extrae información básica sobre la red utilizando utilidades del sistema."""

    def __init__(self, run_command=subprocess.run):
        self._run = run_command
        self._system = platform.system()
        self._missing_commands: set[str] = set()
        self._command_cache: Dict[str, bool] = {}

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

    def _has_command(self, name: str) -> bool:
        if name not in self._command_cache:
            self._command_cache[name] = shutil.which(name) is not None
        return self._command_cache[name]

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

    def _normalize_netmask(self, value: str) -> Optional[str]:
        if value.startswith("0x"):
            try:
                packed = struct.pack("!I", int(value, 16))
                return socket.inet_ntoa(packed)
            except (ValueError, OSError, struct.error):
                return None
        return value

    def _get_interfaces_unix(self) -> List[NetworkInterface]:
        if self._system == "Darwin" and self._has_command("ifconfig"):
            interfaces = self._get_interfaces_from_ifconfig()
            if interfaces:
                return interfaces

        if self._has_command("ip"):
            interfaces = self._get_interfaces_from_ip()
            if interfaces:
                return interfaces

        fallback = self._get_interfaces_from_sysfs()
        if fallback:
            return fallback

        if self._has_command("ifconfig"):
            return self._get_interfaces_from_ifconfig()

        return []

    def _get_interfaces_from_ip(self) -> List[NetworkInterface]:
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

    def _get_interfaces_from_ifconfig(self) -> List[NetworkInterface]:
        output = self._execute(["ifconfig"])
        interfaces: List[NetworkInterface] = []
        current_name: Optional[str] = None
        address: Optional[str] = None
        netmask: Optional[str] = None
        broadcast: Optional[str] = None

        def flush() -> None:
            nonlocal address, netmask, broadcast
            if current_name and address and netmask:
                normalized_mask = self._normalize_netmask(netmask)
                try:
                    prefix = ipaddress.IPv4Network(f"0.0.0.0/{normalized_mask or netmask}").prefixlen
                except (ipaddress.AddressValueError, ValueError):
                    prefix = 24
                interfaces.append(
                    NetworkInterface(
                        name=current_name,
                        address=address,
                        prefix_length=prefix,
                        broadcast=broadcast,
                    )
                )
            address = None
            netmask = None
            broadcast = None

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                flush()
                current_name = None
                continue
            if not raw_line.startswith(" "):
                flush()
                current_name = line.split(" ")[0]
                continue
            if "inet " in line:
                try:
                    _, addr, *_ = line.split()
                    address = addr
                except ValueError:
                    continue
            if "netmask" in line:
                parts = line.split()
                try:
                    netmask_index = parts.index("netmask") + 1
                    netmask = parts[netmask_index]
                except (ValueError, IndexError):
                    continue
            if "broadcast" in line:
                parts = line.split()
                try:
                    broadcast_index = parts.index("broadcast") + 1
                    broadcast = parts[broadcast_index]
                except (ValueError, IndexError):
                    continue
        flush()
        return interfaces

    def _get_interfaces_from_sysfs(self) -> List[NetworkInterface]:
        if fcntl is None:
            return []
        base_path = Path("/sys/class/net")
        if not base_path.exists():
            return []

        interfaces: List[NetworkInterface] = []
        for entry in sorted(base_path.iterdir()):
            if not entry.is_dir():
                continue
            name = entry.name
            try:
                interface = self._get_interface_via_ioctl(name)
            except OSError:
                continue
            if interface:
                interfaces.append(interface)
        return interfaces

    def _get_interface_via_ioctl(self, name: str) -> Optional[NetworkInterface]:
        if fcntl is None:
            return None
        ifname = name.encode("utf-8")[:15]
        ifreq = struct.pack("256s", ifname.ljust(256, b"\0"))

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                addr = fcntl.ioctl(sock.fileno(), 0x8915, ifreq)
            except OSError:
                return None
            address = socket.inet_ntoa(addr[20:24])

            try:
                netmask = fcntl.ioctl(sock.fileno(), 0x891b, ifreq)
                netmask_ip = socket.inet_ntoa(netmask[20:24])
                prefix_length = ipaddress.IPv4Network(f"0.0.0.0/{netmask_ip}").prefixlen
            except (OSError, ipaddress.AddressValueError, ValueError):
                prefix_length = 24

            broadcast: Optional[str] = None
            try:
                brd = fcntl.ioctl(sock.fileno(), 0x8919, ifreq)
                broadcast = socket.inet_ntoa(brd[20:24])
            except OSError:
                broadcast = None

        return NetworkInterface(name=name, address=address, prefix_length=prefix_length, broadcast=broadcast)

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
        if self._has_command("ip"):
            output = self._execute(["ip", "neigh", "show"])
            devices = self._parse_ip_neigh(output)
            if devices:
                return devices

        proc_devices = self._parse_proc_arp()
        if proc_devices:
            return proc_devices

        if self._has_command("arp"):
            return self._get_devices_from_arp()

        return []

    def _parse_ip_neigh(self, output: str) -> List[NetworkDevice]:
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

    def _parse_proc_arp(self) -> List[NetworkDevice]:
        path = Path("/proc/net/arp")
        if not path.exists():
            return []
        devices: List[NetworkDevice] = []
        try:
            with path.open("r", encoding="utf-8") as arp_table:
                next(arp_table, None)
                for line in arp_table:
                    parts = line.split()
                    if len(parts) < 6:
                        continue
                    ip_address, _, flags, mac, _, device = parts[:6]
                    state = "REACHABLE" if flags == "0x2" else "INCOMPLETE"
                    devices.append(
                        NetworkDevice(
                            ip_address=ip_address,
                            mac_address=None if mac == "00:00:00:00:00:00" else mac,
                            interface=device,
                            state=state,
                        )
                    )
        except OSError:
            return []
        return devices

    def _get_devices_from_arp(self) -> List[NetworkDevice]:
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
        if not self._has_command(command[0]):
            self._missing_commands.add(command[0])
            return False
        try:
            result = self._run(command, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            if command:
                self._missing_commands.add(command[0])
            return False
        return result.returncode == 0


# ---------------------------------------------------------------------------
# Formateadores para CLI
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Interfaz gráfica estilo "liquid glass"
# ---------------------------------------------------------------------------


class NetworkMonitorApp:
    """Aplicación gráfica inspirada en el acabado líquido de iOS."""

    def __init__(
        self,
        *,
        max_hosts: int,
        ping_count: int,
        timeout_ms: int,
        auto_scan: bool,
    ) -> None:
        self.max_hosts = max_hosts
        self.ping_count = ping_count
        self.timeout_ms = timeout_ms
        self._auto_scan = auto_scan
        self._missing_commands: set[str] = set()
        self._interfaces: List[NetworkInterface] = []
        self._devices: List[NetworkDevice] = []
        self._scan_in_progress = False

        self.root = tk.Tk()
        self.root.title("Panel de red doméstica")
        self.root.geometry("1100x720")
        self.root.minsize(920, 620)
        self.root.configure(bg="#111420")

        self._status_var = tk.StringVar(value="Listo para actualizar la red")
        self._missing_var = tk.StringVar(value="")
        self._scan_header_var = tk.StringVar(value="Escaneo de red: pendiente")
        self._scan_summary_var = tk.StringVar(value="Selecciona una interfaz y pulsa \"Escanear\".")

        self._build_background()
        self._configure_styles()
        self._build_layout()

        # Cargar datos iniciales tras montar la interfaz
        self.root.after(150, self.refresh_data)

    # Construcción de la UI ---------------------------------------------------
    def _build_background(self) -> None:
        self._background = tk.Canvas(self.root, highlightthickness=0, bd=0)
        self._background.pack(fill="both", expand=True)
        self._background.bind("<Configure>", self._on_canvas_configure)

        self._glass_container = ttk.Frame(self._background, style="Glass.TFrame")
        self._canvas_window = self._background.create_window(
            0,
            0,
            window=self._glass_container,
            anchor="center",
        )

    def _configure_styles(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        glass_color = "#1d2535"
        inner_color = "#232c3f"
        accent = "#7dd4ff"
        foreground = "#edf4ff"
        muted = "#9eb3d8"

        style.configure("Glass.TFrame", background=glass_color, padding=35)
        style.configure("Inner.TFrame", background=inner_color, padding=18)
        style.configure("Header.TLabel", background=glass_color, foreground=foreground, font=("SF Pro Display", 26, "bold"))
        style.configure("Section.TLabel", background=inner_color, foreground=foreground, font=("SF Pro Text", 14, "bold"))
        style.configure("Body.TLabel", background=glass_color, foreground=muted, font=("SF Pro Text", 12))
        style.configure("Glass.TButton", font=("SF Pro Text", 12, "bold"), padding=12, background=accent, foreground="#0a1322")
        style.map(
            "Glass.TButton",
            background=[("pressed", "#6ac8f5"), ("active", "#8ddcff")],
            foreground=[("disabled", "#1a2a42")],
        )

        style.configure(
            "Glass.Treeview",
            background=inner_color,
            fieldbackground=inner_color,
            foreground=foreground,
            rowheight=30,
            bordercolor="#31415e",
            borderwidth=0,
        )
        style.configure(
            "Glass.Treeview.Heading",
            background=inner_color,
            foreground=muted,
            font=("SF Pro Text", 12, "bold"),
            borderwidth=0,
        )
        style.map("Glass.Treeview", background=[("selected", "#355079")], foreground=[("selected", foreground)])
        style.layout("Glass.Treeview", style.layout("Treeview"))
        style.layout("Glass.Treeview.Heading", style.layout("Treeheading"))

        style.configure("Glass.Vertical.TScrollbar", background=inner_color, troughcolor=inner_color, bordercolor=inner_color)
        style.layout("Glass.Vertical.TScrollbar", style.layout("Vertical.TScrollbar"))

    def _build_layout(self) -> None:
        container = self._glass_container
        container.columnconfigure(0, weight=1)
        container.columnconfigure(1, weight=1)
        container.rowconfigure(1, weight=1)
        container.rowconfigure(2, weight=1)

        header = ttk.Label(container, text="Panel de red doméstica", style="Header.TLabel")
        header.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 20))

        controls = ttk.Frame(container, style="Glass.TFrame")
        controls.grid(row=0, column=1, sticky="e")
        controls.configure(padding=(0, 0, 0, 0))

        refresh_btn = ttk.Button(controls, text="Actualizar", style="Glass.TButton", command=self.refresh_data)
        refresh_btn.grid(row=0, column=0, padx=(0, 12))

        scan_btn = ttk.Button(controls, text="Escanear", style="Glass.TButton", command=self.start_scan)
        scan_btn.grid(row=0, column=1)

        status = ttk.Label(container, textvariable=self._status_var, style="Body.TLabel")
        status.grid(row=0, column=0, sticky="sw", pady=(0, 4))

        missing = ttk.Label(container, textvariable=self._missing_var, style="Body.TLabel")
        missing.grid(row=0, column=0, columnspan=2, sticky="se")

        interfaces_frame = ttk.Frame(container, style="Inner.TFrame")
        interfaces_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 16))
        interfaces_frame.columnconfigure(0, weight=1)
        interfaces_frame.rowconfigure(1, weight=1)

        devices_frame = ttk.Frame(container, style="Inner.TFrame")
        devices_frame.grid(row=1, column=1, sticky="nsew")
        devices_frame.columnconfigure(0, weight=1)
        devices_frame.rowconfigure(1, weight=1)

        ttk.Label(interfaces_frame, text="Interfaces de red", style="Section.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 12))
        ttk.Label(devices_frame, text="Dispositivos conocidos (ARP)", style="Section.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 12))

        self._interfaces_tree = ttk.Treeview(
            interfaces_frame,
            columns=("name", "address", "network", "broadcast"),
            show="headings",
            style="Glass.Treeview",
        )
        self._interfaces_tree.heading("name", text="Interfaz")
        self._interfaces_tree.heading("address", text="Dirección")
        self._interfaces_tree.heading("network", text="Red")
        self._interfaces_tree.heading("broadcast", text="Broadcast")
        self._interfaces_tree.column("name", width=120, anchor="center")
        self._interfaces_tree.column("address", width=150, anchor="center")
        self._interfaces_tree.column("network", width=180, anchor="center")
        self._interfaces_tree.column("broadcast", width=140, anchor="center")

        interfaces_scroll = ttk.Scrollbar(
            interfaces_frame,
            orient="vertical",
            command=self._interfaces_tree.yview,
            style="Glass.Vertical.TScrollbar",
        )
        self._interfaces_tree.configure(yscrollcommand=interfaces_scroll.set)
        self._interfaces_tree.grid(row=1, column=0, sticky="nsew")
        interfaces_scroll.grid(row=1, column=1, sticky="ns")

        self._devices_tree = ttk.Treeview(
            devices_frame,
            columns=("ip", "mac", "interface", "state"),
            show="headings",
            style="Glass.Treeview",
        )
        self._devices_tree.heading("ip", text="IP")
        self._devices_tree.heading("mac", text="MAC")
        self._devices_tree.heading("interface", text="Interfaz")
        self._devices_tree.heading("state", text="Estado")
        self._devices_tree.column("ip", width=150, anchor="center")
        self._devices_tree.column("mac", width=170, anchor="center")
        self._devices_tree.column("interface", width=110, anchor="center")
        self._devices_tree.column("state", width=100, anchor="center")

        devices_scroll = ttk.Scrollbar(
            devices_frame,
            orient="vertical",
            command=self._devices_tree.yview,
            style="Glass.Vertical.TScrollbar",
        )
        self._devices_tree.configure(yscrollcommand=devices_scroll.set)
        self._devices_tree.grid(row=1, column=0, sticky="nsew")
        devices_scroll.grid(row=1, column=1, sticky="ns")

        scan_frame = ttk.Frame(container, style="Inner.TFrame")
        scan_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(20, 0))
        scan_frame.columnconfigure(0, weight=1)
        scan_frame.rowconfigure(2, weight=1)

        ttk.Label(scan_frame, textvariable=self._scan_header_var, style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(scan_frame, textvariable=self._scan_summary_var, style="Body.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 12))

        self._scan_tree = ttk.Treeview(
            scan_frame,
            columns=("ip", "status"),
            show="headings",
            style="Glass.Treeview",
        )
        self._scan_tree.heading("ip", text="IP")
        self._scan_tree.heading("status", text="Respuesta")
        self._scan_tree.column("ip", width=160, anchor="center")
        self._scan_tree.column("status", width=160, anchor="center")

        scan_scroll = ttk.Scrollbar(
            scan_frame,
            orient="vertical",
            command=self._scan_tree.yview,
            style="Glass.Vertical.TScrollbar",
        )
        self._scan_tree.configure(yscrollcommand=scan_scroll.set)
        self._scan_tree.grid(row=2, column=0, sticky="nsew")
        scan_scroll.grid(row=2, column=1, sticky="ns")

    # Eventos de lienzo -------------------------------------------------------
    def _on_canvas_configure(self, event: tk.Event) -> None:
        width = event.width
        height = event.height
        margin = 120
        self._background.delete("gradient")
        self._draw_vertical_gradient(width, height)
        self._draw_lights(width, height)

        self._background.coords(self._canvas_window, width / 2, height / 2)
        self._background.itemconfigure(self._canvas_window, width=max(width - margin, 640), height=max(height - margin, 520))

    def _draw_vertical_gradient(self, width: int, height: int) -> None:
        base_top = (17, 26, 46)
        base_bottom = (33, 48, 78)
        steps = 80
        for i in range(steps):
            ratio = i / max(steps - 1, 1)
            r = int(base_top[0] + (base_bottom[0] - base_top[0]) * ratio)
            g = int(base_top[1] + (base_bottom[1] - base_top[1]) * ratio)
            b = int(base_top[2] + (base_bottom[2] - base_top[2]) * ratio)
            color = f"#{r:02x}{g:02x}{b:02x}"
            y1 = int(height * (i / steps))
            y2 = int(height * ((i + 1) / steps))
            self._background.create_rectangle(0, y1, width, y2, fill=color, outline="", tags="gradient")

    def _draw_lights(self, width: int, height: int) -> None:
        highlight_color = "#7dd4ff"
        glow_color = "#5a64f6"
        self._background.create_oval(
            -0.25 * width,
            -0.55 * height,
            0.75 * width,
            0.25 * height,
            fill=highlight_color,
            outline="",
            stipple="gray25",
            tags="gradient",
        )
        self._background.create_oval(
            0.35 * width,
            0.45 * height,
            1.05 * width,
            1.2 * height,
            fill=glow_color,
            outline="",
            stipple="gray50",
            tags="gradient",
        )
        self._background.lower("gradient")

    # Acciones ----------------------------------------------------------------
    def refresh_data(self) -> None:
        if self._scan_in_progress:
            self._status_var.set("Esperando a que finalice el escaneo actual...")
            return

        self._status_var.set("Actualizando información de la red...")

        def task() -> None:
            scanner = NetworkScanner()
            interfaces = scanner.get_interfaces()
            devices = scanner.get_devices()
            missing = set(scanner.missing_commands)
            self._missing_commands.update(missing)
            timestamp = datetime.now()
            self.root.after(
                0,
                lambda: self._apply_data(interfaces, devices, timestamp),
            )

        threading.Thread(target=task, daemon=True).start()

    def _apply_data(self, interfaces: List[NetworkInterface], devices: List[NetworkDevice], timestamp: datetime) -> None:
        self._interfaces = interfaces
        self._devices = devices

        self._interfaces_tree.delete(*self._interfaces_tree.get_children())
        for interface in interfaces:
            network = interface.network
            network_text = str(network) if network else "-"
            broadcast = interface.broadcast or "-"
            self._interfaces_tree.insert("", "end", values=(interface.name, interface.address, network_text, broadcast))

        self._devices_tree.delete(*self._devices_tree.get_children())
        for device in devices:
            mac = device.mac_address or "-"
            iface = device.interface or "-"
            state = device.state or "-"
            self._devices_tree.insert("", "end", values=(device.ip_address, mac, iface, state))

        if self._missing_commands:
            missing_text = ", ".join(sorted(self._missing_commands))
            self._missing_var.set(f"Comandos ausentes: {missing_text}")
        else:
            self._missing_var.set("")

        self._status_var.set(f"Última actualización: {timestamp.strftime('%H:%M:%S')}.")

        if self._auto_scan and interfaces and not self._scan_in_progress:
            self._auto_scan = False
            self.start_scan(automatic=True)

    def start_scan(self, automatic: bool = False) -> None:
        if self._scan_in_progress:
            self._status_var.set("Ya hay un escaneo en curso...")
            return

        interface = self._get_selected_interface()
        if interface is None and automatic and self._interfaces:
            interface = self._interfaces[0]
        if interface is None:
            message = "Selecciona una interfaz antes de escanear." if not automatic else "No se encontraron interfaces disponibles para el escaneo."
            messagebox.showinfo("Escaneo", message)
            return
        network = interface.network
        if network is None:
            messagebox.showinfo("Escaneo", "La interfaz seleccionada no tiene una red IPv4 válida.")
            return

        self._scan_in_progress = True
        self._status_var.set(f"Escaneando red {network}...")
        self._scan_header_var.set(f"Escaneo de red: {network} ({interface.name})")
        self._scan_summary_var.set("Realizando ping a los hosts seleccionados...")
        self._scan_tree.delete(*self._scan_tree.get_children())

        def task() -> None:
            scanner = NetworkScanner()
            results = scanner.scan_network(
                network,
                max_hosts=self.max_hosts,
                count=self.ping_count,
                timeout_ms=self.timeout_ms,
            )
            self._missing_commands.update(scanner.missing_commands)
            timestamp = datetime.now()
            online = [ip for ip, ok in results.items() if ok]
            offline = [ip for ip, ok in results.items() if not ok]
            self.root.after(
                0,
                lambda: self._apply_scan_results(results, online, offline, timestamp),
            )

        threading.Thread(target=task, daemon=True).start()

    def _apply_scan_results(
        self,
        results: Dict[str, bool],
        online: List[str],
        offline: List[str],
        timestamp: datetime,
    ) -> None:
        self._scan_tree.delete(*self._scan_tree.get_children())
        for ip, status in results.items():
            label = "Activo" if status else "Sin respuesta"
            self._scan_tree.insert("", "end", values=(ip, label))

        self._scan_summary_var.set(
            f"Activos: {len(online)} | Sin respuesta: {len(offline)} | Último escaneo: {timestamp.strftime('%H:%M:%S')}"
        )

        if self._missing_commands:
            missing_text = ", ".join(sorted(self._missing_commands))
            self._missing_var.set(f"Comandos ausentes: {missing_text}")
        else:
            self._missing_var.set("")

        self._status_var.set("Escaneo completado.")
        self._scan_in_progress = False

    def _get_selected_interface(self) -> Optional[NetworkInterface]:
        selection = self._interfaces_tree.selection()
        if not selection:
            return None
        name = self._interfaces_tree.item(selection[0], "values")[0]
        for interface in self._interfaces:
            if interface.name == name:
                return interface
        return None

    def run(self) -> None:
        self.root.mainloop()


# ---------------------------------------------------------------------------
# CLI y ejecución principal
# ---------------------------------------------------------------------------


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inspecciona la red local y muestra información de interfaces y dispositivos",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Ejemplos de uso:
              python network_monitor.py --cli           # Modo texto
              python network_monitor.py                 # Inicia la interfaz gráfica
              python network_monitor.py --scan          # Escanea automáticamente al iniciar la GUI
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
        help="Nombre de la interfaz sobre la que realizar el escaneo (solo CLI)",
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
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Usa la interfaz de línea de comandos en lugar de la ventana gráfica",
    )
    return parser.parse_args(argv)


def run_cli(args: argparse.Namespace) -> int:
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
