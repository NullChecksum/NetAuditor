import sys
import subprocess
import argparse
import nmap # type: ignore
import os
from PIL import Image, ImageDraw, ImageFont
import re

nm = nmap.PortScanner()

def print_banner():
    RED = '\033[1;31m'
    YELLOW = '\033[1;33m'
    RESET = '\033[0m'
    
    banner = f"""{RED}
    ███╗   ██╗███████╗████████╗
    ████╗  ██║██╔════╝╚══██╔══╝
    ██╔██╗ ██║█████╗     ██║   
    ██║╚██╗██║██╔══╝     ██║   
    ██║ ╚████║███████╗   ██║   
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   
    {YELLOW}╔═╗╦ ╦╔╦╗╦╔╦╗╔═╗╦═╗{RESET}
    {YELLOW}╠═╣║ ║ ║║║ ║ ║ ║╠╦╝{RESET}
    {YELLOW}╩ ╩╚═╝═╩╝╩ ╩ ╚═╝╩╚═{RESET}
    
    Automated Network Security Assessment
    (yes, we will take evidence as well)
    ──────────────────────────────────────
"""
    print(banner)
# scansione target
def scanner_target(target, ports='', arguments='', output_dir='.'):
    try:
        nm.scan(target, ports, arguments=arguments) # scansioniamo tutte le porte
        output_file = f'{output_dir}/nmap_scan_{target}.txt' 
        
        with open(output_file, 'w') as f:
            f.write(f"# Nmap scan results for {target}\n") #creo anche se vuoto per evitare err. riga 432 
        for host in nm.all_hosts():
            print(f'Host: {host} - State: {nm[host].state()}')
            for proto in nm[host].all_protocols():
                print(f'Protocol: {proto}')
                ports = nm[host][proto].keys()
                for port in ports:
                    port_info = nm[host][proto][port]
                    state = port_info.get('state', 'unknown')
                    product = port_info.get('product', 'unknown')
                    service = port_info.get('name', 'unknown') #Servizio = name --##-- idioti, come fahreineit e celsius, no comment
                    version = port_info.get('version', 'unknown')
                    tunnel = port_info.get('tunnel', '')
                    print(f"Port: {port:<6} State: {state:<6} Service: {service:<16} Tunnel: {tunnel:<6} Product: {product} {version}") # print a schermo

                    with open (output_file, 'a') as f:
                        f.write(f"Port: {port:<6} State: {state:<6} Service: {service:<16} Tunnel: {tunnel:<6} Product: {product} {version} \n")

                    # Esempio output:                           
                    #Host: 127.0.0.1 - State: up
                    #Protocol: tcp
                    #Port: 5258   State: open       Product: Node.js Express framework 
    
    except Exception as e:
        print(f'Exception occurred, nmap SCAN: {e}')

# Se esiste una porta ssh, scansioniamo con ssh-audit per recuperare ciphers
def ssh_audit(target, port='', output_dir='.'):
    try:
        output_file = f'{output_dir}/ssh_audit_{target}_{port}.txt'

        with open(output_file, 'w') as f:
            f.write(f"# SSH Audit scan results for {target}\n")

        with open(output_file, 'a') as f:
            result = subprocess.run(['ssh-audit', f'-p',str(port), f'{target}'], stdout= subprocess.PIPE , stderr=subprocess.STDOUT, text=True)
            f.write(result.stdout)
    except Exception as e:
        print(f'File Exception in ssh-audit occurred: {e}')

def testssl_scan(target, port, output_dir='.'):
    try:
        output_file = f'{output_dir}/ssl_scan_{target}_{port}.txt' 

        with open(output_file, 'w') as f:
            f.write(f"# Testssl - Ciphers ssl ports scan results for {target}\n")

        with open(output_file, 'a') as f:
            result = subprocess.run(['testssl', '-q', f'{target}:{port}'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            f.write(result.stdout)
    except Exception as e:
        print(f'File Exception in testssl occurred: {e}')

def extract_ssh_ciphers(ssh_file, port, target):
    try:
        extracted = []
        with open(ssh_file, 'r') as f:
            lines = f.readlines()
        
        for line in lines:
            # Cerca i pattern SENZA .lower() perché i codici ANSI sono case-sensitive cristo
            if any(pattern in line for pattern in [
                'kex algorithm to remove',
                'mac algorithm to remove', 
                'key algorithm to remove',
                'key algorithm to change'
            ]):
                extracted.append(line)  # NON usare .strip() per preservare i colori ANSI, basta chiedo a claude per i prossimi regex e img, ssh colorato in evidenza
        
        if not extracted:
            print('No relevant SSH cipher information found. Verify at least one file.')
            return False
        
        output_dir = f'evidence/{target}'    
        os.makedirs(output_dir, exist_ok=True)
        output_file = f'{output_dir}/ssh_vulnerable_ciphers.txt'
        
        with open(output_file, 'w') as f:  
            f.write(f"################### Audit {target} {port} (SSH) ###################\n")
            f.writelines(extracted)
        
        print(f"SSH evidence extracted: {output_file} ({len(extracted)} lines)")
        return True
        
    except Exception as e:
        print(f'Exception in extract_ssh_ciphers: {e}')
        return False
    
def extract_ssl_vulnerabilities(ssl_file, target, port):
    """
    Estrae da testssl:
    1. Paragrafo protocolli SSL/TLS SE almeno uno è "offered"
    2. Cipher con CBC nel nome (con header della versione TLS)
    3. Paragrafo vulnerabilità con solo le righe "VULNERABLE"
    Mantiene i colori ANSI
    """
    try:
        with open(ssl_file, 'r') as f:
            lines = f.readlines()
        
        extracted_sections = []
        
        # ========== SEZIONE 1: Protocolli SSL/TLS ==========
        protocols_section = []
        in_protocols = False
        has_offered = False
        
        for i, line in enumerate(lines):
            if 'SSLv2' in line and ('not offered' in line or 'offered' in line):
                in_protocols = True
                protocols_section = [line]
                continue
            
            if in_protocols:
                protocols_section.append(line)
                
                # Se c'è almeno un protocollo offered (qualsiasi)
                if 'offered' in line and 'not offered' not in line:
                    has_offered = True
                
                if 'Testing cipher categories' in line:
                    break
        
        if has_offered and protocols_section:
            extracted_sections.append("########## SSL/TLS Protocols ##########\n\n")
            extracted_sections.extend(protocols_section)
            extracted_sections.append("\n")
        
        # ========== SEZIONE 2: CBC Ciphers ==========
        cbc_ciphers = []
        in_cipher_section = False
        cipher_header_lines = []
        current_tls_version = None
        
        for i, line in enumerate(lines):
            if 'Hexcode' in line and 'Cipher Suite Name' in line:
                in_cipher_section = True
                if i >= 1:
                    cipher_header_lines = [lines[i-1], line]
                continue
            
            if in_cipher_section:
                if i+1 < len(lines) and line.strip() == '' and lines[i+1].strip() == '':
                    break
                
                if '[4m' in line and ('TLS' in line or 'SSL' in line):
                    current_tls_version = line
                
                if 'CBC' in line:
                    if not cbc_ciphers:
                        cbc_ciphers.extend(cipher_header_lines)
                    
                    if current_tls_version and current_tls_version not in cbc_ciphers:
                        cbc_ciphers.append(current_tls_version)
                    
                    cbc_ciphers.append(line)
        
        if cbc_ciphers:
            extracted_sections.append("########## CBC Ciphers ##########\n")
            extracted_sections.extend(cbc_ciphers)
            extracted_sections.append("\n")
        
        # ========== SEZIONE 3: Vulnerabilità ==========
        vulnerabilities = []
        in_vuln_section = False
        processed_indices = set()
        
        for i, line in enumerate(lines):
            if i in processed_indices:
                continue
                
            if 'Testing vulnerabilities' in line:
                in_vuln_section = True
                vulnerabilities.append(line)
                continue
            
            if in_vuln_section:
                if i+1 < len(lines) and line.strip() == '' and lines[i+1].strip() == '':
                    break
                
                # Caso 1: CVE nel nome (es: BEAST) con VULNERABLE nella riga successiva
                if 'CVE-' in line and i+1 < len(lines):
                    next_line = lines[i+1]
                    if 'VULNERABLE' in next_line and 'not vulnerable' not in next_line.lower():
                        vulnerabilities.append(line)  # Nome vulnerabilità
                        vulnerabilities.append(next_line)  # Riga VULNERABLE
                        processed_indices.add(i)
                        processed_indices.add(i+1)
                        
                        # Righe indentate successive
                        j = i + 2
                        while j < len(lines):
                            indent_line = lines[j]
                            if len(indent_line) - len(indent_line.lstrip()) > 30:
                                vulnerabilities.append(indent_line)
                                processed_indices.add(j)
                                j += 1
                            else:
                                break
                        continue
                
                # Caso 2: VULNERABLE sulla stessa riga
                if 'VULNERABLE' in line and 'not vulnerable' not in line.lower():
                    vulnerabilities.append(line)
                    processed_indices.add(i)
                    
                    j = i + 1
                    while j < len(lines):
                        next_line = lines[j]
                        if len(next_line) - len(next_line.lstrip()) > 30:
                            vulnerabilities.append(next_line)
                            processed_indices.add(j)
                            j += 1
                        else:
                            break
                
                # Caso 3: Riga normale seguita da VULNERABLE indentato
                elif i+1 < len(lines):
                    next_line = lines[i+1]
                    if ('VULNERABLE' in next_line and 
                        'not vulnerable' not in next_line.lower() and
                        len(next_line) - len(next_line.lstrip()) > 30):
                        vulnerabilities.append(line)
                        processed_indices.add(i)
                        
                        j = i + 1
                        while j < len(lines):
                            next_line = lines[j]
                            if len(next_line) - len(next_line.lstrip()) > 30:
                                vulnerabilities.append(next_line)
                                processed_indices.add(j)
                                j += 1
                            else:
                                break
        
        if len(vulnerabilities) > 1:
            extracted_sections.append("########## Vulnerabilities ##########\n\n")
            extracted_sections.extend(vulnerabilities)
            extracted_sections.append("\n")
        
        # ========== Salva risultati ==========
        if not extracted_sections:
            print(f'  ○ No SSL vulnerabilities found on {target}:{port}')
            return False
        
        output_dir = f'evidence/{target}'
        os.makedirs(output_dir, exist_ok=True)
        output_file = f'{output_dir}/ssl_vulnerable_port_{port}.txt'
        
        with open(output_file, 'w') as f:
            f.write(f"################### {target}:{port} ###################\n\n")
            f.writelines(extracted_sections)
        
        print(f"  ✓ SSL evidence extracted: {output_file}")
        return True
        
    except Exception as e:
        print(f'Exception in extract_ssl_vulnerabilities: {e}')
        return False
        
def extract_nmap_evidence(nmap_file, target):
    try:
        with open(nmap_file, 'r') as file:
            lines = file.readlines()

        extracted = []
        for line in lines:
            if 'Port' in line and 'open' in line and 'service: ssh' in line.lower():
                parts = line.split()
                port = ''
                product=''
                for i, part in enumerate(parts):
                    if part == 'Port:' and i+1 < len(parts):
                        port = parts[i+1]
                    elif part == 'Product:':
                        product = ' '.join(parts[i+1:]).strip()

                # Colore ANSI verde per il prodotto ( grazie claude )
                product_colored = f"\033[1;32m{product}\033[0m" if product else "\033[1;31mUnknown\033[0m"
                
                # Formatta con evidenziazione
                formatted = f"\n{'='*70}\n"
                formatted += f"  🔹 IP: {target}\n"
                formatted += f"  🔹 PORT: {port}\n"
                formatted += f"  🔹 SERVICE: ssh\n"
                formatted += f"  🔹 PRODUCT: {product_colored}\n"
                formatted += f"{'='*70}\n"
                
                extracted.append(formatted)
        
        if not extracted:
            print(f'  ○ No SSH ports found for {target}')
            return False
        
        # Salva evidenze
        output_dir = f'evidence/{target}'
        os.makedirs(output_dir, exist_ok=True)
        output_file = f'{output_dir}/nmap_ssh_ports.txt'
        
        with open(output_file, 'w') as f:
            f.write(f"\n{'#'*70}\n")
            f.write(f"###  TARGET: {target} - SSH PORTS  ###\n")
            f.write(f"{'#'*70}\n\n")
            f.writelines(extracted)
        
        print(f"  ✓ Nmap SSH evidence extracted: {output_file} ({len(extracted)} SSH ports)")
        return True
        
    except Exception as e:
        print(f'Exception in extract_nmap_evidence: {e}')
        return False

def ansi_to_image(txt_file, output_png, width=1700, height=902):

    try:
        with open(txt_file, 'r') as f:
            lines = f.readlines()
        
        img = Image.new('RGB', (width, height), color='#1e1e1e')  # Sfondo scuro
        draw = ImageDraw.Draw(img)
        
        try:
            font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf', 16)
        except:
            font = ImageFont.load_default()
        
        # Mappa colori ANSI ( grazie claude, stiamo piangendo in polacco con sti c* di colori e spazi in x*y su img)
        ansi_colors = {
            '\033[0m': '#ffffff',      # Reset/bianco
            '\033[1;32m': '#00ff00',   # Verde brillante
            '\033[1;31m': '#ff0000',   # Rosso brillante
            '\033[1;33m': '#ffff00',   # Giallo brillante
            '\033[0;31m': '#ff6b6b',   # Rosso
            '\033[0;33m': '#ffd93d',   # Giallo
            '\033[0;36m': '#6bcfff',   # Ciano
            '\033[4m': '#ffffff',      # Sottolineato (bianco)
        }
        
        y = 20
        line_height = 20
        
        for line in lines:
            if y > height - 40:
                break
            
            # Rimuovi newline
            line = line.rstrip('\n')
            
            # Trova segmenti con colori ANSI
            segments = []
            current_color = '#ffffff'
            current_text = ''
            
            i = 0
            while i < len(line):
                # Cerca codice ANSI
                if line[i:i+2] == '\033[':
                    # Salva testo precedente
                    if current_text:
                        segments.append((current_text, current_color))
                        current_text = ''
                    
                    # Trova fine codice ANSI
                    end = line.find('m', i)
                    if end != -1:
                        ansi_code = line[i:end+1]
                        current_color = ansi_colors.get(ansi_code, '#ffffff')
                        i = end + 1
                    else:
                        i += 1
                else:
                    current_text += line[i]
                    i += 1
            
            # Aggiungi ultimo segmento
            if current_text:
                segments.append((current_text, current_color))
            
            # Disegna i segmenti
            x = 20
            for text, color in segments:
                draw.text((x, y), text, fill=color, font=font)
                # Calcola larghezza del testo per posizionare il prossimo
                bbox = draw.textbbox((x, y), text, font=font)
                x = bbox[2]
            
            y += line_height
        
        img.save(output_png, dpi=(254, 254))
        print(f"Screenshot generated: {output_png}")
        return True
        
    except Exception as e:
        print(f'Exception in ansi_to_image: {e}')
        return False

def generate_evidence_screenshots(target):
    evidence_dir = f'evidence/{target}'
    screenshot_dir = f'screenshots/{target}'
    
    if not os.path.exists(evidence_dir):
        print(f'No evidence found for {target}')
        return
    
    os.makedirs(screenshot_dir, exist_ok=True)
    
    print(f"\n{'='*50}")
    print(f"Generating screenshots for {target}")
    print(f"{'='*50}\n")
    
    # prendiamo tutti i file di evidenze al momento, direi che va bene
    for filename in os.listdir(evidence_dir):
        if filename.endswith('.txt'):
            input_file = f'{evidence_dir}/{filename}'
            output_file = f'{screenshot_dir}/{filename.replace(".txt", ".png")}'
            
            ansi_to_image(input_file, output_file,  width=1700, height=902)
    
    print(f"\n{'='*50}")
    print(f"Screenshots completed for {target}")
    print(f"{'='*50}\n")

def recap(targets):
    """
    Genera report con:
    - SSH: IP porta versione (da nmap_scan)
    - HTTP: IP porta (da nmap_scan)
    - SSL: IP:porta + vulnerabilità (da ssl_scan files)
    - TLS 1.0/1.1: IP:porta se offerti
    - CBC ciphers obsoleti
    """
    try:
        output_file = 'audit_report.txt'
        
        ssh_entries = []
        http_entries = []
        ssl_entries = []
        tls_weak_entries = []
        
        # ========== AUTO-DETECT TARGETS DA DIRECTORY *_Scans ==========
        detected_targets = []
        for item in os.listdir('.'):
            if os.path.isdir(item) and item.endswith('_Scans'):
                target = item.replace('_Scans', '')
                detected_targets.append(target)
        
        if not detected_targets:
            print('[!] No *_Scans directories found in current directory')
            return
        
        print(f'[*] Found {len(detected_targets)} targets: {detected_targets}')
        
        for target in detected_targets:
            scan_dir = f'{target}_Scans'
            
            if not os.path.exists(scan_dir):
                print(f'[!] Directory {scan_dir} not found for {target}')
                continue
            
            # ========== SSH e HTTP da nmap_scan ==========
            nmap_file = f'{scan_dir}/nmap_scan_{target}.txt'
            if os.path.exists(nmap_file):
                with open(nmap_file, 'r') as f:
                    for line in f:
                        if 'Port:' in line and 'open' in line:
                            parts = line.split()
                            port = parts[1] if len(parts) > 1 else 'unknown'
                            service = parts[5].replace('Service:', '') if len(parts) > 5 else 'unknown'
                            product = ' '.join(parts[7:]) if len(parts) > 7 else 'unknown'
                            
                            # SSH
                            if 'ssh' in service.lower():
                                ssh_entries.append(f"{target} {port} {product.strip()}")
                            
                            # HTTP
                            if 'http' in service.lower():
                                http_entries.append(f"{target} {port}")
            
            # ========== SSL vulnerabilities + TLS 1.0/1.1 ==========
            for filename in os.listdir(scan_dir):
                if filename.startswith('ssl_scan_') and filename.endswith('.txt'):
                    # Estrai porta dal nome file: ssl_scan_IP_PORT.txt
                    match = re.search(r'ssl_scan_.*_(\d+)\.txt', filename)
                    if match:
                        port = match.group(1)
                        ssl_file = f'{scan_dir}/{filename}'
                        
                        with open(ssl_file, 'r') as f:
                            lines = f.readlines()
                        
                        # Cerca vulnerabilità VULNERABLE (ignora "not vulnerable")
                        vulnerabilities = []
                        has_beast = False
                        has_sweet32 = False
                        has_poodle = False
                        has_tls10 = False
                        has_tls11 = False
                        has_sslv2 = False
                        has_sslv3 = False
                        has_cbc_obsolete = False
                        in_vuln_section = False
                        i = 0
                        
                        while i < len(lines):
                            line = lines[i]
                            clean_line = re.sub(r'\033\[[0-9;]+m', '', line).strip()
                            
                            # ===== CHECK SEZIONE PROTOCOLLI SSL/TLS =====
                            # SSLv2 e SSLv3
                            if 'SSLv2' in clean_line and 'offered' in clean_line and 'not offered' not in clean_line:
                                has_sslv2 = True
                            if 'SSLv3' in clean_line and 'offered' in clean_line and 'not offered' not in clean_line:
                                has_sslv3 = True
                            
                            # TLS 1.0 - cerchiamo "TLS 1 " (con spazio dopo) per evitare TLS 1.1, 1.2, 1.3
                            words = clean_line.split()
                            if len(words) >= 2:
                                if words[0] == 'TLS' and words[1] == '1' and 'offered' in clean_line and 'not offered' not in clean_line:
                                    has_tls10 = True
                            
                            # TLS 1.1
                            if 'TLS 1.1' in clean_line and 'offered' in clean_line and 'not offered' not in clean_line:
                                has_tls11 = True
                            
                            # ===== CHECK CBC CIPHERS OBSOLETI =====
                            if 'Obsoleted CBC ciphers' in clean_line and 'offered' in clean_line and 'not offered' not in clean_line:
                                has_cbc_obsolete = True
                                vulnerabilities.append(clean_line)
                            
                            # ===== CHECK SEZIONE VULNERABILITIES =====
                            if 'Testing vulnerabilities' in clean_line:
                                in_vuln_section = True
                                i += 1
                                continue
                            
                            if in_vuln_section:
                                # Fine sezione (doppia riga vuota)
                                if clean_line == '' and i+1 < len(lines):
                                    next_clean = re.sub(r'\033\[[0-9;]+m', '', lines[i+1]).strip()
                                    if next_clean == '':
                                        in_vuln_section = False
                                        i += 1
                                        continue
                                
                                # CASO 1: VULNERABLE sulla stessa riga
                                if 'VULNERABLE' in clean_line and 'not vulnerable' not in clean_line.lower():
                                    vulnerabilities.append(clean_line)
                                    
                                    # Check specifiche vulnerabilità
                                    if 'BEAST' in clean_line.upper():
                                        has_beast = True
                                    if 'SWEET32' in clean_line.upper():
                                        has_sweet32 = True
                                    if 'POODLE' in clean_line.upper():
                                        has_poodle = True
                                
                                # CASO 2: Nome vulnerabilità su una riga, VULNERABLE sulla successiva
                                elif i+1 < len(lines):
                                    next_line = lines[i+1]
                                    next_clean = re.sub(r'\033\[[0-9;]+m', '', next_line).strip()
                                    
                                    if 'VULNERABLE' in next_clean and 'not vulnerable' not in next_clean.lower():
                                        # Aggiungi entrambe le righe
                                        vulnerabilities.append(clean_line)
                                        vulnerabilities.append(next_clean)
                                        
                                        # Check specifiche vulnerabilità
                                        combined = clean_line + next_clean
                                        if 'BEAST' in combined.upper():
                                            has_beast = True
                                        if 'SWEET32' in combined.upper():
                                            has_sweet32 = True
                                        if 'POODLE' in combined.upper():
                                            has_poodle = True
                                        
                                        i += 1  # Salta la prossima riga
                            
                            i += 1
                        
                        # ========== Aggiungi entry SSL ==========
                        if vulnerabilities or has_tls10 or has_tls11 or has_sslv2 or has_sslv3 or has_cbc_obsolete:
                            ssl_entries.append(f"{target}:{port}")
                            
                            if vulnerabilities:
                                for vuln in vulnerabilities:
                                    ssl_entries.append(f"  {vuln}")
                                
                                # Aggiungi flag vulnerabilità specifiche
                                if has_beast:
                                    ssl_entries.append(f"  [!] BEAST vulnerability detected")
                                if has_sweet32:
                                    ssl_entries.append(f"  [!] SWEET32 vulnerability detected")
                                if has_poodle:
                                    ssl_entries.append(f"  [!] POODLE vulnerability detected")
                                if has_cbc_obsolete:
                                    ssl_entries.append(f"  [!] Obsoleted CBC ciphers detected")
                            
                            # Protocolli deboli
                            if has_sslv2 or has_sslv3 or has_tls10 or has_tls11:
                                weak_protos = []
                                if has_sslv2:
                                    weak_protos.append("SSLv2")
                                if has_sslv3:
                                    weak_protos.append("SSLv3")
                                if has_tls10:
                                    weak_protos.append("TLS 1.0")
                                if has_tls11:
                                    weak_protos.append("TLS 1.1")
                                ssl_entries.append(f"  [WEAK PROTOCOLS] {', '.join(weak_protos)} offered")
                        
                        # ========== Aggiungi entry TLS deboli ==========
                        if has_sslv2 or has_sslv3 or has_tls10 or has_tls11:
                            weak_protocols = []
                            if has_sslv2:
                                weak_protocols.append("SSLv2")
                            if has_sslv3:
                                weak_protocols.append("SSLv3")
                            if has_tls10:
                                weak_protocols.append("TLS 1.0")
                            if has_tls11:
                                weak_protocols.append("TLS 1.1")
                            tls_weak_entries.append(f"{target}:{port} - {', '.join(weak_protocols)} offered")
        
        # ========== Scrivi report ==========
        with open(output_file, 'w') as f:
            f.write("################### AUDIT REPORT ###################\n\n")
            
            # SSH
            f.write("========== SSH ==========\n")
            if ssh_entries:
                for entry in ssh_entries:
                    f.write(f"{entry}\n")
            else:
                f.write("No SSH services found\n")
            
            # HTTP
            f.write("\n========== HTTP ==========\n")
            if http_entries:
                for entry in http_entries:
                    f.write(f"{entry}\n")
            else:
                f.write("No HTTP services found\n")
            
            # SSL Vulnerabilities
            f.write("\n========== SSL VULNERABILITIES ==========\n")
            if ssl_entries:
                for entry in ssl_entries:
                    f.write(f"{entry}\n")
            else:
                f.write("No SSL vulnerabilities found\n")
            
            # TLS/SSL Weak Protocols
            f.write("\n========== WEAK SSL/TLS PROTOCOLS ==========\n")
            if tls_weak_entries:
                for entry in tls_weak_entries:
                    f.write(f"{entry}\n")
            else:
                f.write("No weak SSL/TLS protocols offered\n")
        
        print(f"\n{'='*50}")
        print(f"[✓] Report generated: {output_file}")
        print(f"{'='*50}\n")
        
    except Exception as e:
        print(f'Exception in recap(): {e}')


#Main function, sotto logica di esecuzione
def main():
    print_banner()
    parser = argparse.ArgumentParser("Automated scanner and evidence taker")
    parser.add_argument("-t","--target", help="Target to scan")
    parser.add_argument("-f","--file", help="File of targets to scan")
    parser.add_argument("-a","--arguments", help="Additional nmap arguments", default="--min-rate 1100 --max-rate 2550 -sV")
    parser.add_argument("-p","--ports", help="Ports to scan", default="1-65535")
    parser.add_argument("-m","--mode", help="mode: s=scan (default), r=recap", default="s") 


    args = parser.parse_args()
    arguments = args.arguments
    target = args.target
    ports = args.ports
    file = args.file
    mode = args.mode

    targets = []

    # ========== MODE RECAP ==========
    if mode == 'r':
        print('[*] Recap mode activated - analyzing existing scans')
        recap([])
        sys.exit(0)

    if file == None and target == None:
        print(f'A file (-f) or a target (-t) must be provided, use "-h" for help')
        sys.exit(1) 

    if file != None:
        with open(file) as f:
            lines = f.readlines()
            for line in lines:
                ips = line.strip()
                targets.append(ips)
    else:
        targets.append(target)



    for target in targets:

        output_dir = f'{target}_Scans'
        os.makedirs(output_dir, exist_ok=True)

        # recon servizi / porte aperte
        print(f'Scan Started, first target: {target}\n')
        print('###### NMAP => SSHAUDIT => TESTSSL => EVIDENCE => SCREENSHOT ######')
        print('1 - Nmap scan - 3 minutes\n')
        scanner_target(target, ports, arguments=arguments, output_dir=output_dir)

        # 2) ssh_audit(target)
        print('\n2 - SSH Audit')
        with open(f'{output_dir}/nmap_scan_{target}.txt', 'r') as f:
            lines = f.readlines()
            for line in lines:
                if 'ssh' in line.lower() and 'open' in line.lower():
                    words = line.split()
                    port = words[1]
                    ssh_audit(target, port, output_dir=output_dir)
                    print(f'SSH Audit completed for {target} on port {port}\n')

        # 3) testssl scan su ogni porta ssl trovata
        print('3 - Testssl Audit')
        ssl_ports_found = []
        with open(f'{output_dir}/nmap_scan_{target}.txt', 'r') as f:
            lines = f.readlines()
            for line in lines:
                if ('ssl' in line.lower() or 'https' in line.lower()) and 'open' in line.lower():
                    ssl_ports_found.append(line.split()[1])

        for port in ssl_ports_found:
            testssl_scan(target, port, output_dir=output_dir)
            print(f'testssl scan completed for {target} on port {port}\n')


        print('4 - Taking evidence\n')
        # 4) estrazione evidenze ssh_audit porta 22 o altre
        ssh_ports_found = []
        with open(f'{output_dir}/nmap_scan_{target}.txt', 'r') as f:
            for line in f:
                if 'ssh' in line.lower() and 'open' in line.lower():
                    ssh_ports_found.append(line.split()[1])

        for port in ssh_ports_found:
            ssh_audit_file = f'{output_dir}/ssh_audit_{target}_{port}.txt'
            if os.path.exists(ssh_audit_file):
                extract_ssh_ciphers(ssh_audit_file, port, target)
            else:
                print(f'SSH audit file {ssh_audit_file} does not exist. Skipping extraction.')    

        # 5) Estrazione evidenze testssl
        for port in ssl_ports_found:
            ssl_file = f'{output_dir}/ssl_scan_{target}_{port}.txt'
            if os.path.exists(ssl_file):
                extract_ssl_vulnerabilities(ssl_file, target, port)
            else:
                print(f'SSL scan file {ssl_file} does not exist. Skipping extraction.')

        # 6) Estrazione ssh da nmap
        nmap_file = f'{output_dir}/nmap_scan_{target}.txt'
        if os.path.exists(nmap_file):
            extract_nmap_evidence(nmap_file, target)
        else:
            print(f'Nmap file {nmap_file} does not exist. Skipping extraction.')

        print('\n5 - screenshots time!')
        # 7) Generazione screenshot evidenze
        generate_evidence_screenshots(target)

if __name__ == "__main__":
    main()
