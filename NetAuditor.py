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
    1. Paragrafo protocolli SSL/TLS SE almeno uno è "offered" (deprecated/weak)
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
        has_offered_deprecated = False
        
        for i, line in enumerate(lines):
            if 'SSLv2' in line and ('not offered' in line or 'offered' in line):
                in_protocols = True
                protocols_section = [line]
                continue
            
            if in_protocols:
                protocols_section.append(line)
                
                # se c'è almeno un protcollo offered
                if 'offered' in line and 'not offered' not in line:
                    if any(proto in line for proto in ['SSLv2', 'SSLv3', 'TLS 1 ', 'TLS 1.1']):
                        has_offered_deprecated = True
                
                if 'Testing cipher categories' in line:
                    break
        
        if has_offered_deprecated and protocols_section:
            extracted_sections.append("########## SSL/TLS Protocols (Deprecated Offered) ##########\n\n")
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




#Main function, sotto logica di esecuzione
def main():
    print_banner()
    parser = argparse.ArgumentParser("Automated scanner and evidence taker")
    parser.add_argument("-t","--target", help="Target to scan")
    parser.add_argument("-f","--file", help="File of targets to scan")
    parser.add_argument("-a","--arguments", help="Additional nmap arguments", default="--min-rate 1100 --max-rate 2550 -sV")
    parser.add_argument("-p","--ports", help="Ports to scan", default="1-65535")  # <-- OPZIONALE, cristo, scansioniamo tutto daje

    args = parser.parse_args()
    arguments = args.arguments
    target =args.target
    ports = args.ports
    file = args.file

    targets = []

    if file == None and target == None:
        print(f'A file (-f) or a target (-t) must be provided, use "-h" for help')
        sys.exit(1) 

    if file != None :
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
                    words = line.split() # ci serve una lista per la porta, il target rimane lo stesso
                    #['Port:', '22', 'State:', 'open', 'Service:ssh', 'Product:', 'OpenSSH', '8.2p1', 'Ubuntu']

                    port = words[1]
                    ssh_audit(target, port, output_dir=output_dir)
                    print(f'SSH Audit completed for {target} on port {port}\n')

        # 3) testssl scan su ogni porta ssl trovata , no default ssl ports
        print('3 - Testssl Audit')
        ssl_ports_found = []
        with open(f'{output_dir}/nmap_scan_{target}.txt', 'r') as f:
            lines = f.readlines()
            for line in lines:
                if ('ssl' in line.lower() or 'https' in line.lower()) and 'open' in line.lower():
                    ssl_ports_found.append(line.split()[1]) # porta

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
                extract_ssh_ciphers(ssh_audit_file,port, target)
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