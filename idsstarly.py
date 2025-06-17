from scapy.all import sniff, IP, TCP, UDP, Raw
from collections import defaultdict
from datetime import datetime
import csv
import subprocess
import os
import time


class IntrusionDetectionSystem:
    def __init__(self):
        self.assinaturas = [
            "MALWARE", "ATTACK", "SQLMAP", "NMAP", "INJECTION", "SLOWLORIS", "SLOWHTTPTEST", "DIRB", "DIRBUSTER",
            "WFUZZ", "FEROXBUSTER", "GOBUSTER", "HYDRA", "JOHN", "MEDUSA", "METASPLOIT", "MSF", "MSFVENOM", "SQLI",
            "SQL INJECTION", "UNION SELECT", "' OR '1'='1", "XSS", "<SCRIPT>", "CURL", "WGET", "POC", "EXPLOIT",
            "RCE", "CMD=", "SHELL", "NC -E", "BASH -I", "BIN/SH", "/ETC/PASSWD", "/ETC/SHADOW", "NETCAT",
            "REVERSE SHELL", "METERPRETER", "EVILGINX", "ZPHISHER", "SETOOLKIT", "SOCIAL ENGINEERING TOOLKIT",
            "BURP", "INTRUDER", "INJECTION", "FILE INCLUSION", "LFI", "RFI", "PHPMYADMIN", "WP-ADMIN",
            "ADMIN LOGIN", "ROOT", "PWD", "CHMOD", "CHOWN", "SUDO", "SSH", "OPENVAS", "NESSUS", "MASSCAN", "ZMAP",
            "FLOOD", "DOS", "DDOS", "SLOW", "SLEEP(", "WAITFOR DELAY", "BENCHMARK(", "XP_CMDSHELL", "SYSOBJECTS",
            "SYS DATABASES"
        ]

        self.timestamp = datetime.now().strftime("%Y-%m-%d %H-%M-%S")
        self.diretorio_csv1 = "Dados"
        self.diretorio_csv2 = "Dados/blacklist"

        os.makedirs(self.diretorio_csv1, exist_ok=True)
        os.makedirs(self.diretorio_csv2, exist_ok=True)

        self.arquivo_csv = os.path.join(self.diretorio_csv1, f"{self.timestamp} - resultados_ids.csv")
        self.arquivo_csv2 = os.path.join(self.diretorio_csv2, "blacklist.csv")

        self._inicializar_csvs()

        # Controle
        self.icmp_contagem = defaultdict(list)
        self.udp_contagem = defaultdict(list)
        self.tcp_syn_contagem = defaultdict(list)
        self.ack_contagem = defaultdict(list)
        self.conexoes = defaultdict(list)
        self.ips_bloqueados = set()

        self.contagem_pacotes_src = defaultdict(int)
        self.contagem_pacotes_dst = defaultdict(int)

        # Limites
        self.limite_icmp = 100
        self.limite_syn = 100
        self.limite_udp = 100
        
        
        

    def _inicializar_csvs(self):
        with open(self.arquivo_csv, mode="w", newline="") as arquivo:
            writer = csv.writer(arquivo)
            writer.writerow(["Timestamp", "Src_IP", "Src_Port", "Dst_IP", "Dst_Port",
                             "Flags", "Label", "Desc", "Packet_Count_src", "Packet_Count_dst"])

        if not os.path.exists(self.arquivo_csv2):
            with open(self.arquivo_csv2, mode="w", newline="") as arquivo_blacklist:
                writer = csv.writer(arquivo_blacklist)
                writer.writerow(["Timestamp", "IP", "Desc"])

    def salvar_na_blacklist(self, ip, descricao):
        try:
            with open(self.arquivo_csv2, mode="r") as arquivo:
                linhas = arquivo.readlines()
                ips_existentes = [linha.split(",")[1].strip() for linha in linhas[1:]]
        except FileNotFoundError:
            ips_existentes = []

        if ip not in ips_existentes:
            with open(self.arquivo_csv2, mode="a", newline="") as arquivo_blacklist:
                writer = csv.writer(arquivo_blacklist)
                writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, descricao])

    def bloquear_ip(self, ip, descricao):
        if ip not in self.ips_bloqueados:
            try:
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                print(f"[FIREWALL] IP {ip} bloqueado!")
                self.ips_bloqueados.add(ip)
                self.salvar_na_blacklist(ip, descricao)
            except subprocess.CalledProcessError as e:
                print(f"[ERRO] Falha ao bloquear IP {ip}: {e}")

    def analisar_assinaturas(self, packet):
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode(errors="ignore").upper()
                for assinatura in self.assinaturas:
                    if assinatura in payload:
                        return assinatura
            except Exception:
                pass
        return None

    def detectar_ataques(self, src_ip, tempo_atual, packet):
        # SYN Flood
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            if flags == "S":
                self.tcp_syn_contagem[src_ip].append(tempo_atual)
                self.tcp_syn_contagem[src_ip] = [
                    t for t in self.tcp_syn_contagem[src_ip] if tempo_atual - t < 10
                ]
                if len(self.tcp_syn_contagem[src_ip]) > self.limite_syn:
                    return "SYN_FLOOD"

        # UDP Flood
        if packet.haslayer(UDP):
            self.udp_contagem[src_ip].append(tempo_atual)
            self.udp_contagem[src_ip] = [
                t for t in self.udp_contagem[src_ip] if tempo_atual - t < 1
            ]
            if len(self.udp_contagem[src_ip]) > self.limite_udp:
                return "UDP_FLOOD"

        # ICMP Flood (Corrigido)
        if packet.haslayer(TCP):
            self.icmp_contagem[src_ip].append(tempo_atual)
            self.icmp_contagem[src_ip] = [
                t for t in self.icmp_contagem[src_ip] if tempo_atual - t < 1
            ]
            if len(self.icmp_contagem[src_ip]) > self.limite_icmp:
                return "ICMP_FLOOD"

        return None

    def processar_pacote(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet.sport if packet.haslayer((TCP, UDP)) else "N/A"
            dst_port = packet.dport if packet.haslayer((TCP, UDP)) else "N/A"
            flags = packet[TCP].flags if packet.haslayer(TCP) else "N/A"

            tempo_atual = time.time()

            alerta_assinatura = self.analisar_assinaturas(packet)
            alerta_ataque = self.detectar_ataques(src_ip, tempo_atual, packet)

            alerta = alerta_assinatura or alerta_ataque or "TRAFEGO_NORMAL"

            desc = ""
            if alerta != "TRAFEGO_NORMAL":
                desc = f"[ALERTA] Tráfego suspeito de {src_ip} -> {dst_ip}: {alerta}"
                print(desc)

                # self.bloquear_ip(src_ip, desc)  # Descomente se quiser bloquear automaticamente

            self.contagem_pacotes_src[(src_ip, src_port)] += 1
            self.contagem_pacotes_dst[(dst_ip, dst_port)] += 1

            print("=" * 70)
            print(f"[{self.timestamp}]")
            print(f"Src {src_ip}:{src_port} --> Dst {dst_ip}:{dst_port}")
            print(f"Flags: {flags}")
            print(f"Alerta: {alerta}")
            print(f"Pacotes src: {self.contagem_pacotes_src[(src_ip, src_port)]}")
            print(f"Pacotes dst: {self.contagem_pacotes_dst[(dst_ip, dst_port)]}")
            print("=" * 70)

            with open(self.arquivo_csv, mode="a", newline="") as arquivo:
                writer = csv.writer(arquivo)
                writer.writerow([
                    self.timestamp, src_ip, src_port, dst_ip, dst_port,
                    flags, alerta, desc,
                    self.contagem_pacotes_src[(src_ip, src_port)],
                    self.contagem_pacotes_dst[(dst_ip, dst_port)]
                ])

    def iniciar_monitoramento(self, interface=None):
        print("Iniciando monitoramento... Pressione CTRL+C para parar.")
        try:
            sniff(prn=self.processar_pacote, store=0, iface=interface)
        except KeyboardInterrupt:
            print("Monitoramento finalizado.")
