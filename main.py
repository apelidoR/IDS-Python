from scapy.all import *
from scapy.all import sniff, IP, TCP, UDP, ICMP
import csv
from datetime import datetime
from collections import defaultdict
import time
import subprocess
import os

# Assinaturas simples baseadas em strings no payload
assinaturas = [
    "MALWARE", "ATTACK", "SQLMAP", "NMAP", "INJECTION", "SLOWLORIS", "SLOWHTTPTEST", "DIRB", "DIRBUSTER", "WFUZZ", "FEROXBUSTER",
    "GOBUSTER", "HYDRA", "JOHN", "MEDUSA", "METASPLOIT", "MSF", "MSFVENOM", "SQLI", "SQL INJECTION", "UNION SELECT", "' OR '1'='1",
    "XSS", "<SCRIPT>", "CURL", "WGET", "POC", "EXPLOIT", "RCE", "CMD=", "SHELL", "NC -E", "BASH -I", "BIN/SH", "/ETC/PASSWD",
    "/ETC/SHADOW", "NETCAT", "REVERSE SHELL", "METERPRETER", "EVILGINX", "ZPHISHER", "SETOOLKIT", "SOCIAL ENGINEERING TOOLKIT",
    "BURP", "INTRUDER", "INJECTION", "FILE INCLUSION", "LFI", "RFI", "PHPMYADMIN", "WP-ADMIN", "ADMIN LOGIN", "ROOT", "PWD",
    "CHMOD", "CHOWN", "SUDO", "SSH", "OPENVAS", "NESSUS", "MASSCAN", "ZMAP", "FLOOD", "DOS", "DDOS", "SLOW", "SLEEP(", "WAITFOR DELAY",
    "BENCHMARK(", "XP_CMDSHELL", "SYSOBJECTS", "SYS DATABASES"
]

timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
alerta_detectado = ""
load_visivel = ""

# Criar e definir os CSVs
arquivo_csv = f"{timestamp} - resultados_ids.csv"
with open(arquivo_csv, mode="w", newline="") as arquivo:
    writer = csv.writer(arquivo)
    writer.writerow(["Timestamp", "Src_IP", "Src_Port", "Dst_IP", "Dst_Port", "Flags", "Label", "Desc", "Packet_Count_src", "Packet_Count_dst"])


arquivo_csv2 = "blacklist.csv"

if not os.path.exists(arquivo_csv2):
    
    with open(arquivo_csv2, mode="w", newline="") as arquivo_blacklist:
        writer = csv.writer(arquivo_blacklist)
        writer.writerow(["Timestamp", "IP", "Desc"])

desc = ""

# Controle de ICMP Flood, SYN Flood e Port Scan
icmp_contagem = defaultdict(list)
tcp_syn_contagem = defaultdict(list)
ack_contagem = defaultdict(list)
conexoes = defaultdict(list)
ips_bloqueados = set()

# Contagem de pacotes
contagem_pacotes_src = defaultdict(int)
contagem_pacotes_dst = defaultdict(int)

# Limites de detecção
limite_icmp = 100
limite_syn = 100

def Alertas(src_ip, tempo_atual, packet, dst_port, dst_ip, src_port):
    # SYN FLOOD
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        if flags == "S":
            tcp_syn_contagem[src_ip].append(tempo_atual)
            tcp_syn_contagem[src_ip] = [t for t in tcp_syn_contagem[src_ip] if tempo_atual - t < 10]

        if flags == "A":
            ack_contagem[src_ip].append(tempo_atual)
            ack_contagem[src_ip] = [t for t in ack_contagem[src_ip] if tempo_atual - t < 10]

        if len(tcp_syn_contagem[src_ip]) - len(ack_contagem[src_ip]) > limite_syn:
            print(f"[ALERTA] Possível SYN Flood detectado de {src_ip}")
            return "SYN FLOOD"
    
    # ICMP Flood
    if packet.haslayer(ICMP):
        icmp_contagem[src_ip].append(tempo_atual)
        icmp_contagem[src_ip] = [t for t in icmp_contagem[src_ip] if tempo_atual - t < 1]

        if len(icmp_contagem[src_ip]) > limite_icmp:
            print(f"[ALERTA] ICMP Flood detectado de {src_ip}")
            return "ICMP_FLOOD"
    
    # Port Scan
    if packet.haslayer(TCP):
        flags = packet[TCP].flags

        if flags & "S":
            tcp_syn_contagem[src_ip].append(tempo_atual)
            tcp_syn_contagem[src_ip] = [t for t in tcp_syn_contagem[src_ip] if tempo_atual - t < 1]

            if len(tcp_syn_contagem[src_ip]) > limite_syn:
                print(f"[ALERTA] Varredura de portas detectada de {src_ip}")
                return "NMAP/Port_Scan"

    # DOS Slow and Low
    if packet.haslayer(Raw):
        payload = packet[Raw].load

        if payload.startswith(b'GET') or payload.startswith(b'POST'):
            if b'\r\n\r\n' not in payload:
                print("[ALERTA] Cabeçalho HTTP incompleto detectado!")
                return "DOS_SLOW_AND_LOW"
    
    # Ataque de fragmentação
    if packet.haslayer(IP) and packet[IP].flags == 1:
        return "FRAGMENTATION_ATTACK"

    # HTTPS conexão sem payload
    if packet.haslayer(TCP) and packet.haslayer(IP):
        flags = packet[TCP].flags

        if dst_port == 443:
            conexao = (src_ip, dst_ip, packet[TCP].sport, dst_port)

            if flags & "SA" and not flags & "S":
                conexoes[conexao] = {"status": "SYN enviado", "tempo": tempo_atual}

            if flags & "A":
                conexoes[conexao]["status"] = "TCP estabelecido"

            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                if payload.startswith(b'\x16\x03'):
                    conexoes[conexao]["status"] = "Handshake TLS"
                elif payload.startswith(b'\x17\x03'):
                    conexoes[conexao]["status"] = "Application Data enviado"
                    conexoes[conexao]["payload"] = True

            for conn, info in conexoes.items():
                if time.time() - info["tempo"] > 30:
                    if info.get("status") == "Handshake TLS" and not info.get("payload"):
                        print(f"[ALERTA] Conexão HTTPS sem payload detectada: {conn}")
                        return "DOS_SLOW_AND_LOW"

    return "TRAFEGO_NORMAL"
             
    


def salvar_na_blacklist(ip, descricao):
    try:
        with open(arquivo_csv2, mode="r") as arquivo:
            linhas = arquivo.readlines()
            ips_existentes = [linha.split(",")[1].strip() for linha in linhas[1:]]
    except FileNotFoundError:
        ips_existentes = []

    if ip not in ips_existentes:
        with open(arquivo_csv2, mode="a", newline="") as arquivo_blacklist:
            writer = csv.writer(arquivo_blacklist)
            writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, descricao])
            
def bloquear_ip(ip, descricao):
    if ip not in ips_bloqueados:
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            print(f"[FIREWALL] IP {ip} bloqueado com sucesso!")
            ips_bloqueados.add(ip)
            salvar_na_blacklist(ip, descricao)
        except subprocess.CalledProcessError as e:
            print(f"[ERRO] Falha ao bloquear IP {ip}: {e}")



def capturar_pacote(packet):
    alerta_detectado = ""
    load_visivel = ""
   
    if IP in packet:
        

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet.sport if (packet.haslayer(TCP) or packet.haslayer(UDP)) else "N/A"
        dst_port = packet.dport if (packet.haslayer(TCP) or packet.haslayer(UDP)) else "N/A"
        flags = packet[TCP].flags if packet.haslayer(TCP) else "Sem Flag"
        desc = ""

        if packet.haslayer(Raw) and dst_port != 443 and src_port != 443:
            load = packet[Raw].load.decode(errors="ignore").upper()

            for assinatura in assinaturas:
                if assinatura in load:
                    alerta_detectado += f"{assinatura} "

            if alerta_detectado:
                load_visivel = alerta_detectado.strip()
                alerta_detectado = alerta_detectado.strip()

        
        
        tempo_atual = time.time()
        alertas = Alertas(src_ip, tempo_atual, packet, dst_port, dst_ip, src_port)
        match alertas:
            case "SYN FLOOD" | "ICMP_FLOOD" | "NMAP/Port_Scan" | "DOS_SLOW_AND_LOW" | "FRAGMENTATION_ATTACK":
                alerta_detectado = alertas
                load_visivel = alertas

            case _:
                alerta_detectado = "TRAFEGO_NORMAL"
                load_visivel = "TRAFEGO_NORMAL"
    
        
        print("=" * 70)
        print(f"[{timestamp}]")
        print(f" packet_src {src_ip}: port_src {src_port} --> packet_dst {dst_ip}: port_dst {dst_port}")
        print(f" Flags: {flags}")
        print(f" Load: {load_visivel}")
        print(f" Quantidade de pacotes nesse fluxo_src: {contagem_pacotes_src[(src_ip, src_port)] + 1}")
        print(f" Quantidade de pacotes nesse fluxo_dst: {contagem_pacotes_dst[(dst_ip, dst_port)] + 1}")
        print("=" * 70)

        if alerta_detectado.strip() not in ["", "TRAFEGO_NORMAL"]:
            desc = f"[ALERTA] Assinaturas detectadas no tráfego de {src_ip} -> {dst_ip} : {alerta_detectado.strip()}"
            print(f"[ALERTA] Assinaturas detectadas no tráfego de {src_ip} -> {dst_ip}: {alerta_detectado.strip()}")

        if alerta_detectado in ["ICMP_FLOOD", "SYN FLOOD", "NMAP/Port_Scan", "UDP_FLOOD", assinaturas, "DOS_SLOW_AND_LOW"]:
            bloquear_ip(src_ip, desc)
        
        contagem_pacotes_src[(src_ip, src_port)] += 1
        contagem_pacotes_dst[(dst_ip, dst_port)] += 1

        with open(arquivo_csv, mode="a", newline="") as arquivo:
            writer = csv.writer(arquivo)
            writer.writerow([
                timestamp, src_ip, src_port, dst_ip, dst_port,
                flags, alerta_detectado.strip(), desc,
                contagem_pacotes_src[(src_ip, src_port)], contagem_pacotes_dst[(dst_ip, dst_port)]
            ])


print("Analisando... Pressione CTRL+C para parar.")
try:
    sniff(prn=capturar_pacote, store=0)
except KeyboardInterrupt:
    print("Finalizando Análise.")
