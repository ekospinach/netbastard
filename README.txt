NETBASTARD - Network Isolation Tool (ARP Spoofing)
===================================================
https://github.com/ekospinach/netbastard


DESCRIPTION
-----------
Netbastard is a network security testing tool that uses ARP spoofing
techniques. It detects devices on the local network and disrupts internet
access for a target device by sending forged ARP packets that impersonate
the gateway.


REQUIREMENTS
------------
1. Python 3.8+
2. Npcap or WinPcap (required by scapy for raw socket access)
   - Download: https://npcap.com
   - Must be installed with "Install in WinPcap API-compatible Mode" enabled
3. Dependencies (pip install -r requirements.txt):
   - scapy >= 2.5.0
   - colorama >= 0.4.6


INSTALLATION
------------
  pip install -r requirements.txt


ACCESS PRIVILEGES
-----------------
ARP spoofing requires Administrator privileges (Windows) or root (Linux).

EASIEST WAY (double-click, no terminal needed):
  1. Open the netbastard folder
  2. Double-click run.bat        (for GUI)
     Double-click run_cli.bat    (for CLI)
  3. Windows UAC prompt appears -> click Yes
  4. App runs as Administrator

AUTO-ELEVATE via terminal:
  1. config.json: "auto_elevate": true
  2. Run: python netbastard_gui.py
  3. Windows UAC prompt appears -> click Yes

MANUAL METHOD:
  Windows: Right-click -> Run as Administrator
  Linux:   sudo python netbastard.py


FILES INCLUDED
--------------
  netbastard.py        - CLI version (keyboard-driven menu)
  netbastard_gui.py    - GUI version (Tkinter)
  run.bat              - Double-click to run GUI as Admin
  run_cli.bat          - Double-click to run CLI as Admin
  config.json          - Application settings
  requirements.txt     - Python dependencies


USAGE - CLI (netbastard.py)
----------------------------
  python netbastard.py

  Menu:
    1  - Scan Network      : Discover all devices on the local network
    2  - List Devices      : Display scanned devices (IP, MAC, hostname)
    3  - Attack Target     : Start attacking a single target (enter number)
    4  - Stop Attack       : Stop attacking a specific target
    5  - Show Status       : Display active attack status and stats
    6  - Multi Attack      : Attack multiple targets at once (e.g. 1,3,5)
    7  - Stop All          : Stop all active attacks
    8  - Quit              : Exit (automatically restores ARP tables)


USAGE - GUI (netbastard_gui.py)
--------------------------------
  python netbastard_gui.py

  GUI:
    [Scan Network]      -> Scan the local network
    [Attack Selected]   -> Attack checked devices
    [Stop Attack]       -> Stop attacking checked devices
    [Stop All]          -> Stop all attacks

    How to select: click the leftmost column (checkbox) in the device table
    If no devices are checked, [Attack Selected] will attack ALL discovered
    devices.


CONFIGURATION (config.json)
----------------------------
  auto_elevate     : true/false  -> Auto-request admin via UAC (default: true)
  scan_method      : auto        -> Scan method (auto/scapy/api)
  spoof_interval   : 1.0         -> ARP packet send interval (seconds)
  theme            : dark        -> GUI theme (dark/light)
  scan_range       : "192.168.1.0/24" -> Network range to scan
  refresh_interval : 3           -> Status refresh interval (seconds)


HOW IT WORKS
------------
1. Scan:  Sends broadcast ARP requests to all IPs in the /24 subnet,
          recording each responding device's IP, MAC address, and hostname.

2. Attack: Continuously sends forged ARP replies to:
   - The target: telling it the attacker's MAC is the gateway
   - The gateway: telling it the attacker's MAC is the target
   As a result, all traffic between the target and the gateway flows through
   the attacker, cutting off the target's internet access.

3. Restore: When the attack stops, the ARP tables on both the target and
            gateway are restored to their correct state (genuine ARP replies).


IMPORTANT NOTES
---------------
- For security testing only on networks you own or have explicit written
  permission to test. Unauthorized use may violate applicable laws.
- ARP spoofing does not work on networks using switches with Dynamic ARP
  Inspection (DAI) or port security features.
- Some antivirus software may detect ARP spoofing as a threat.
- The target's connection will recover automatically a few seconds after
  the attack is stopped.


PROJECT STRUCTURE
-----------------
  netbastard/
  ├── netbastard.py        # CLI
  ├── netbastard_gui.py    # GUI
  ├── run.bat              # GUI launcher (auto-admin)
  ├── run_cli.bat          # CLI launcher (auto-admin)
  ├── config.json          # Settings
  └── requirements.txt     # Dependencies
