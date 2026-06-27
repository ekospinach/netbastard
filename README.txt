NETBASTARD - Network Isolation Tool (ARP Spoofing)
===================================================
https://github.com/ekospinach/netbastard


DESKRIPSI
---------
Netbastard adalah alat untuk menguji keamanan jaringan dengan teknik ARP
spoofing. Fungsinya mendeteksi perangkat dalam jaringan lokal dan memutus
koneksi internet perangkat target dengan mengirim paket ARP palsu yang
menyamar sebagai gateway.


PERSYARATAN
-----------
1. Python 3.8+
2. Npcap or WinPcap (untuk scapy raw socket)
   - Download: https://npcap.com
   - Wajib diinstal dengan opsi "Install in WinPcap API-compatible Mode"
3. Dependencies (pip install -r requirements.txt):
   - scapy >= 2.5.0
   - colorama >= 0.4.6


INSTALASI
---------
  pip install -r requirements.txt


HAK AKSES
---------
ARP spoofing membutuhkan akses Administrator (Windows) atau root (Linux).

CARA PALING MUDAH (double-click, tanpa terminal):
  1. Buka folder netbastard
  2. Double-click run.bat   (untuk GUI)
     Double-click run_cli.bat (untuk CLI)
  3. Windows UAC muncul -> klik Yes
  4. Aplikasi langsung jalan sebagai Administrator

CARA OTOMATIS via terminal:
  1. config.json: "auto_elevate": true
  2. Jalankan: python netbastard_gui.py
  3. Windows UAC muncul -> klik Yes

CARA MANUAL:
  Windows: Klik kanan -> Run as Administrator
  Linux:   sudo python netbastard.py


FILE YANG TERSEDIA
------------------
  netbastard.py        - CLI version (keyboard-driven menu)
  netbastard_gui.py    - GUI version (Tkinter)
  run.bat              - Double-click to run GUI sebagai Admin
  run_cli.bat          - Double-click to run CLI sebagai Admin
  config.json          - Pengaturan aplikasi
  requirements.txt     - Daftar dependency


CARPAKAI - CLI (netbastard.py)
-------------------------------
  python netbastard.py

  Menu:
    1  - Scan Network      : Mendeteksi semua perangkat di jaringan
    2  - List Devices      : Menampilkan daftar perangkat hasil scan
    3  - Attack Target     : Memulai serangan ke satu target (masukkan nomor)
    4  - Stop Attack       : Menghentikan serangan ke satu target
    5  - Show Status       : Menampilkan status serangan yang aktif
    6  - Multi Attack      : Serang beberapa target sekaligus (contoh: 1,3,5)
    7  - Stop All          : Hentikan semua serangan
    8  - Quit              : Keluar (otomatis restore ARP table)


CARAPAKAI - GUI (netbastard_gui.py)
------------------------------------
  python netbastard_gui.py

  GUI:
    [Scan Network]      -> Scan jaringan
    [Attack Selected]   -> Serang perangkat yang dicentang
    [Stop Attack]       -> Hentikan serangan ke perangkat yg dicentang
    [Stop All]          -> Hentikan semua serangan

    Cara mencentang: klik kolom paling kiri (kotak centang) pada tabel
    Jika tidak ada yg dicentang, [Attack Selected] akan menyerang SEMUA
    perangkat hasil scan.


KONFIGURASI (config.json)
--------------------------
  auto_elevate     : true/false  -> Otomatis minta admin via UAC (default: true)
  scan_method      : auto        -> Metode scanning (auto/scapy/api)
  spoof_interval   : 1.0         -> Interval pengiriman paket ARP (detik)
  theme            : dark        -> Tema GUI (dark/light)
  scan_range       : "192.168.1.0/24" -> Range jaringan untuk scan
  refresh_interval : 3           -> Interval refresh status (detik)


CARA KERJA
----------
1. Scan:  Mengirim ARP request broadcast ke seluruh IP /24, mencatat
          perangkat yang merespons beserta alamat MAC dan hostname.

2. Attack: Mengirim ARP reply palsu secara terus-menerus ke:
   - Target: memberitahu bahwa MAC attacker adalah gateway
   - Gateway: memberitahu bahwa MAC attacker adalah target
   Akibatnya, semua lalu lintas target ke gateway (dan sebaliknya) akan
   melalui attacker, sehingga koneksi internet target terputus.

3. Restore: Setelah serangan dihentikan, ARP table target dan gateway
            dikembalikan ke kondisi normal (ARP reply benar).


CATATAN PENTING
---------------
- Hanya untuk pengujian keamanan di jaringan milik sendiri atau yang sudah
  mendapat izin tertulis. Penggunaan tanpa izin bisa melanggar hukum.
- ARP spoofing tidak bekerja di jaringan yang menggunakan switch dengan
  fitur Dynamic ARP Inspection (DAI) atau port security.
- Beberapa antivirus mendeteksi ARP spoofing sebagai ancaman.
- Koneksi target akan pulih otomatis beberapa detik setelah serangan
  dihentikan.


STRUKTUR PROYEK
---------------
  netbastard/
  ├── netbastard.py        # CLI
  ├── netbastard_gui.py    # GUI
  ├── run.bat              # Launcher GUI (auto-admin)
  ├── run_cli.bat          # Launcher CLI (auto-admin)
  ├── config.json          # Pengaturan
  └── requirements.txt     # Dependencies
