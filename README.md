NetAuditor is an automated network security assessment tool that performs comprehensive scanning, auditing, and evidence collection for security assessments and penetration testing.

⚙️ Pipeline:

    Nmap - Port scanning and service detection
    SSH-Audit - SSH configuration and cipher analysis
    TestSSL - SSL/TLS vulnerability assessment
    Evidence Extraction - Automated vulnerability filtering
    Screenshots - Visual evidence generation with ANSI color preservation

⚙️ Features

    ✅ Automated multi-target scanning
    ✅ SSH cipher vulnerability detection
    ✅ SSL/TLS protocol and cipher analysis
    ✅ Deprecated protocol detection (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
    ✅ CBC cipher identification
    ✅ Automated evidence extraction
    ✅ Screenshot generation with color preservation
    ✅ Support for single target or batch file processing

# 🔧 Installation
Prerequisites

System Requirements:

    Linux (Ubuntu/Debian recommended)
    Python 3.7+
    Root/sudo access (for raw socket scanning)

### Step 1: Install System Dependencies


##### Update package list
```
sudo apt update
```
##### Install required tools
```
sudo apt install -y nmap python3 python3-pip
```
##### Install ssh-audit
```
sudo apt install -y ssh-audit
```
##### OR install via pip if not available
```
pip3 install ssh-audit --break-system-packages
```

##### Install testssl.sh
```
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
sudo ln -s $(pwd)/testssl.sh/testssl.sh /usr/local/bin/testssl

```
### Step 2: Install Python Dependencies
bash

##### Install Python packages
```
pip3 install python-nmap Pillow --break-system-packages
```

##### **Step 3: Fix python-nmap Library (REQUIRED)**

**The default python-nmap library doesn't include the tunnel attribute. You need to patch it manually:**
**Location of the file to modify:**


##### Find the nmap.py file location

```
python3 -c "import nmap; print(nmap.__file__)"

 Typical locations:
 /usr/local/lib/python3.x/dist-packages/nmap/nmap.py
 ~/.local/lib/python3.x/site-packages/nmap/nmap.py

```
**Edit the file:**
```
sudo nano /usr/local/lib/python3.11/dist-packages/nmap/nmap.py
```
 (adjust path based on your Python version)

Find this section (around line 460-480):
python
```
name = product = version = extrainfo = conf = cpe = ""
```

```
for dname in dport.findall("service"):
    name = dname.get("name")
    if dname.get("product"):
        product = dname.get("product")
    if dname.get("version"):
        version = dname.get("version")
    if dname.get("extrainfo"):
        extrainfo = dname.get("extrainfo")
    if dname.get("conf"):
        conf = dname.get("conf")
    for dcpe in dname.findall("cpe"):
        cpe = dcpe.text

```
Replace it with:

```
name = product = version = extrainfo = conf = cpe = tunnel = ""
```

```
for dname in dport.findall("service"):
    name = dname.get("name")
    if dname.get("product"):
        product = dname.get("product")
    if dname.get("version"):
        version = dname.get("version")
    if dname.get("extrainfo"):
        extrainfo = dname.get("extrainfo")
    if dname.get("conf"):
        conf = dname.get("conf")
    if dname.get("tunnel"):
        tunnel = dname.get("tunnel")
    for dcpe in dname.findall("cpe"):
        cpe = dcpe.text
```

Find the dictionary section (a few lines below):


```
scan_result["scan"][host][proto][port] = {
    "state": state,
    "reason": reason,
    "name": name,
    "product": product,
    "version": version,
    "extrainfo": extrainfo,
    "conf": conf,
    "cpe": cpe,
}
```

Add the tunnel field:


```
scan_result["scan"][host][proto][port] = {
    "state": state,
    "reason": reason,
    "name": name,
    "product": product,
    "version": version,
    "extrainfo": extrainfo,
    "conf": conf,
    "cpe": cpe,
    "tunnel": tunnel,
}
```


# SCAN
##### Scan a single IP
sudo python3 netauditor.py -t 192.168.1.1

##### Scan a single domain
sudo python3 netauditor.py -t example.com

Multiple Targets


##### Create a targets file
```
cat > targets.txt <<EOF
192.168.1.1
192.168.1.10
10.0.0.5
example.com
EOF
```

##### Scan all targets
```
sudo python3 netauditor.py -f targets.txt
```

##### Custom port range
```
sudo python3 netauditor.py -t 192.168.1.1 -p 1-1000
```

##### Custom nmap arguments
```
sudo python3 netauditor.py -t 192.168.1.1 -a "--min-rate 500 --max-rate 1000 -sV"
```

##### Quick scan (top 1000 ports)
```
sudo python3 netauditor.py -t 192.168.1.1 -p - -a "-sV -T4"
```


### Command-Line Arguments

| Argument      | Short | Description                                    | Default                               |
| ------------- | ----- | ---------------------------------------------- | ------------------------------------- |
| `--target`    | `-t`  | Single target to scan (IP or domain)           | None                                  |
| `--file`      | `-f`  | File containing list of targets (one per line) | None                                  |
| `--ports`     | `-p`  | Port range to scan                             | 1-65535                               |
| `--arguments` | `-a`  | Additional nmap arguments                      | `--min-rate 1100 --max-rate 2550 -sV` |

## 📁 Output Structure
```
.
├── <target>_Scans/              # Raw scan results
│   ├── nmap_scan_<target>.txt
│   ├── ssh_audit_<target>_<port>.txt
│   └── ssl_scan_<target>_<port>.txt
│
├── evidence/                    # Extracted vulnerabilities
│   └── <target>/
│       ├── ssh_vulnerable_ciphers.txt
│       ├── ssl_vulnerable_port_<port>.txt
│       └── nmap_ssh_ports.txt
│
└── screenshots/                 # Visual evidence (PNG)
    └── <target>/
        ├── ssh_vulnerable_ciphers.png
        └── ssl_vulnerable_port_<port>.png

```

# ⚠️ Important Notes
Permissions

    Nmap requires root/sudo for SYN scans and service detection
    Always run with sudo for best results

Legal Notice

 AUTHORIZATION REQUIRED: Only scan systems you own or have explicit written permission to test. Unauthorized scanning may be illegal in your jurisdiction.
Performance Tips

    Default scan of all 65535 ports takes ~3-5 minutes per target
    Use -p 1-1000 for faster scans during testing
    Adjust --min-rate and --max-rate based on network capacity


# Always run with sudo
If the environment is a virtual one use this command  or the correct one considering the path:

```
sudo /home/x/Documents/Python/python/bin/python3 /home/x/Documents/Python/NetAuditor.py -t 192.168.1.1
```




##  Example Output
```
    ███╗   ██╗███████╗████████╗
    ████╗  ██║██╔════╝╚══██╔══╝
    ██╔██╗ ██║█████╗     ██║   
    ██║╚██╗██║██╔══╝     ██║   
    ██║ ╚████║███████╗   ██║   
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   
    ╔═╗╦ ╦╔╦╗╦╔╦╗╔═╗╦═╗
    ╠═╣║ ║ ║║║ ║ ║ ║╠╦╝
    ╩ ╩╚═╝═╩╝╩ ╩ ╚═╝╩╚═

Scan Started, first target: 192.168.1.1

###### NMAP => SSHAUDIT => TESTSSL => EVIDENCE => SCREENSHOT ######
1 - Nmap scan - 3 minutes
Host: 192.168.1.1 - State: up
Port: 22     State: open   Service: ssh   Product: OpenSSH 7.4

2 - SSH Audit
SSH Audit completed for 192.168.1.1 on port 22

3 - Testssl Audit
testssl scan completed for 192.168.1.1 on port 443

4 - Taking evidence
SSH evidence extracted: evidence/192.168.1.1/ssh_vulnerable_ciphers.txt (5 lines)
   SSL evidence extracted: evidence/192.168.1.1/ssl_vulnerable_port_443.txt

5 - screenshots time!
==================================================
Generating screenshots for 192.168.1.1
==================================================
Screenshot generated: screenshots/192.168.1.1/ssh_vulnerable_ciphers.png
Screenshot generated: screenshots/192.168.1.1/ssl_vulnerable_port_443.png
```


 # Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.
📝 License

This tool is provided as-is for educational and authorized security testing purposes only.
 Credits

    Uses nmap for port scanning
    Uses ssh-audit for SSH analysis
    Uses testssl.sh for SSL/TLS testing

Happy Auditing! 


