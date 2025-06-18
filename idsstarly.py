from scapy.all import sniff, IP, TCP, UDP, Raw
from collections import defaultdict
from datetime import datetime
import csv
import subprocess
import os
import pandas as pd
import time


class FileManager:
    def __init__(self, diretorio_dados="Dados"):
        self.diretorio_dados = diretorio_dados
        self.diretorio_blacklist = os.path.join(diretorio_dados, "blacklist")

        os.makedirs(self.diretorio_dados, exist_ok=True)
        os.makedirs(self.diretorio_blacklist, exist_ok=True)

    def criar_log(self):
        timestamp = datetime.now().strftime("%Y-%m-%d %H-%M-%S")
        arquivo_log = os.path.join(self.diretorio_dados, f"{timestamp} - logs.csv")
        with open(arquivo_log, mode="w",newline="") as arquivo:
            writer = csv.writer(arquivo)
            writer.writerow(["Timestamp", "Src_IP", "Src_Port", "Dst_IP", "Dst_Port",
                              "Flags", "Label", "Desc", "Packet_Count_src", "Packet_Count_dst"])
        return arquivo_log
    
    
    def inicializar_blacklist(self):
        arquivo_blacklist = os.path.join(self.diretorio_blacklist, "blacklist.csv")
        if not os.path.exists(arquivo_blacklist):
            with open(arquivo_blacklist, mode="w", newline="") as arquivo:
                writer = csv.writer(arquivo)
                writer.writerow(["Timestamp", "IP", "Desc"])
        return arquivo_blacklist
    
    def salvar_blacklist(self, caminho, ip, descricao):
        try: 
            df = pd.read_csv(caminho)
            if ip not in df["IP"].values:
                with open(caminho, mode="a", newline="") as arquivo:
                    writer = csv.writer(arquivo)
                    writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, descricao])
            
        except Exception:
             with open(caminho, mode="a", newline="") as arquivo:
                writer = csv.writer(arquivo)
                writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, descricao])

    def salvar_log(self, caminho, dados):
        with open(caminho, mode="a", newline="") as arquivo:
            writer = csv.writer(arquivo)
            writer.writerow(dados)

class IntrusionDetectionSystem:
    def __init__(self, file_manager: FileManager):
        self.file_manager = file_manager

        # Assinaturas
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

        # Controle interno
        self.__icmp_contagem = defaultdict(list)
        #self.__udp_contagem = defaultdict(list)
        self.__tcp_syn_contagem = defaultdict(list)
        self.__ips_bloqueados = set()
        self.__conexoes = defaultdict(list)

        self.__contagem_pacotes_src = defaultdict(int)
        self.__contagem_pacotes_dst = defaultdict(int)

        # Limites
        self.__limite_icmp = 100
        self.__limite_syn = 100
        self.__limite_udp = 100

        # Arquivos
        self.__arquivo_log = self.file_manager.criar_log()
        self.__arquivo_blacklist = self.file_manager.inicializar_blacklist()

    # ===========================
    # Getters e Setters
    # ===========================

    def get_limite_icmp(self):
        return self.__limite_icmp

    
    def set_limite_icmp(self, valor: int):
        self.__limite_icmp = valor

    
    def get_limite_syn(self):
        return self.__limite_syn

    
    def set_limite_syn(self, valor: int):
        self.__limite_syn = valor

    
    #def get_limite_udp(self):
    #    return self.__limite_udp

    
    #def set_limite_udp(self, valor: int):
    #    self.__limite_udp = valor

    # ===========================
    # Firewall e Blacklist
    # ===========================

    def bloquear_ip(self, ip, descricao):
        if ip not in self.__ips_bloqueados:
            try:
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                print(f"[FIREWALL] IP {ip} bloqueado!")
                self.__ips_bloqueados.add(ip)
                self.file_manager.salvar_na_blacklist(self.__arquivo_blacklist, ip, descricao)
            except subprocess.CalledProcessError as e:
                print(f"[ERRO] Falha ao bloquear IP {ip}: {e}")

    # ===========================
    # Análise
    # ===========================

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

    def detectar_ataques(self, src_ip, tempo_atual, packet, dst_port, dst_ip):
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            if flags == "S":
                self.__tcp_syn_contagem[src_ip].append(tempo_atual)
                self.__tcp_syn_contagem[src_ip] = [
                    t for t in self.__tcp_syn_contagem[src_ip] if tempo_atual - t < 10
                ]
                if len(self.__tcp_syn_contagem[src_ip]) > self.__limite_syn:
                    return "SYN_FLOOD"


        if packet.haslayer(TCP):  # Corrigir para ICMP se necessário
            self.__icmp_contagem[src_ip].append(tempo_atual)
            self.__icmp_contagem[src_ip] = [
                t for t in self.__icmp_contagem[src_ip] if tempo_atual - t < 1
            ]
            if len(self.__icmp_contagem[src_ip]) > self.__limite_icmp:
                return "ICMP_FLOOD"
        # Existing DOS Slow and Low detection
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            if payload.startswith(b'GET') or payload.startswith(b'POST'):
                if b'\r\n\r\n' not in payload:
                    print("[ALERTA] Cabeçalho HTTP incompleto detectado!")
                    return "DOS_SLOW_AND_LOW"
                
        # Existing HTTPS connection without payload detection
        if packet.haslayer(TCP) and packet.haslayer(IP):
            flags = packet[TCP].flags
            if dst_port == 443:
                conexao = (src_ip, dst_ip, packet[TCP].sport, dst_port)
                if flags & "SA" and not flags & "S":
                    self.__conexoes[conexao] = {"status": "SYN enviado", "tempo": tempo_atual}
                if flags & "A":
                    self.__conexoes[conexao]["status"] = "TCP estabelecido"
                if packet.haslayer(Raw):
                    payload = bytes(packet[Raw].load)
                    if payload.startswith(b'\x16\x03'):
                        self.__conexoes[conexao]["status"] = "Handshake TLS"
                    elif payload.startswith(b'\x17\x03'):
                        self.__conexoes[conexao]["status"] = "Application Data enviado"
                        self.__conexoes[conexao]["payload"] = True
                for conn, info in self.__conexoes.items():
                    if time.time() - info["tempo"] > 30:
                        if info.get("status") == "Handshake TLS" and not info.get("payload"):
                            print(f"[ALERTA] Conexão HTTPS sem payload detectada: {conn}")
                            return "DOS_SLOW_AND_LOW"
                
        if packet.haslayer(IP) and packet[IP].flags == 1:
            return "FRAGMENTATION_ATTACK"
        
        
        return None
    
        
        

    # ===========================
    # Processamento de Pacotes
    # ===========================

    def processar_pacote(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet.sport if packet.haslayer(TCP) or  packet.haslayer(UDP) else "N/A"
            dst_port = packet.dport if packet.haslayer(TCP) or packet.haslayer(UDP) else "N/A"
            flags = packet[TCP].flags if packet.haslayer(TCP) else "N/A"

            tempo_atual = time.time()

            alerta_assinatura = self.analisar_assinaturas(packet)
            alerta_ataque = self.detectar_ataques(src_ip, tempo_atual, packet, dst_port, dst_ip)

            alerta = alerta_assinatura or alerta_ataque or "TRAFEGO_NORMAL"

            desc = ""
            if alerta != "TRAFEGO_NORMAL":
                desc = f"Assinatura detectada no tráfego de {src_ip} -> {dst_ip}: {alerta}"
                print(desc)

                # Ativar se desejar bloquear automaticamente:
                # self.bloquear_ip(src_ip, desc)

            self.__contagem_pacotes_src[(src_ip, src_port)] += 1
            self.__contagem_pacotes_dst[(dst_ip, dst_port)] += 1

            print("=" * 70)
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]")
            print(f"Src {src_ip}:{src_port} --> Dst {dst_ip}:{dst_port}")
            print(f"Flags: {flags}")
            print(f"Alerta: {alerta}")
            print(f"Pacotes src: {self.__contagem_pacotes_src[(src_ip, src_port)]}")
            print(f"Pacotes dst: {self.__contagem_pacotes_dst[(dst_ip, dst_port)]}")
            print("=" * 70)

            self.file_manager.salvar_log(self.__arquivo_log, [
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                src_ip, src_port, dst_ip, dst_port,
                flags, alerta, desc,
                self.__contagem_pacotes_src[(src_ip, src_port)],
                self.__contagem_pacotes_dst[(dst_ip, dst_port)]
            ])

    # ===========================
    # Monitoramento
    # ===========================

    def iniciar_monitoramento(self, interface: str = None):
        print("Iniciando monitoramento... Pressione CTRL+C para parar.")
        try:
            sniff(prn=self.processar_pacote, store=0, iface=interface)
        except KeyboardInterrupt:
            print("Monitoramento finalizado.")