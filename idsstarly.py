from scapy.all import sniff, IP, TCP, UDP, Raw, ICMP
from collections import defaultdict
from datetime import datetime
import csv
import subprocess
import os
import pandas as pd
import time
import mysql.connector

class DatabaseManager:
    def __init__(self, host='localhost', user='admin', password='admin', database='idsstarlyDB'):
        try:
            self.conn = mysql.connector.connect(
                host=host,
                user=user,
                password=password,
                database=database
            )
            self.cursor = self.conn.cursor()
            self.criar_tabelas()

            print("[BANCO] Conectado com sucesso!")
        except mysql.connector.Error as err:
            print(f"[ERRO] Erro na conexão com o banco: {err}")
            exit(1)  # Encerra o programa se não conectar
            
    def criar_tabelas(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp DATETIME,
                src_ip VARCHAR(50),
                src_port VARCHAR(20),
                dst_ip VARCHAR(50),
                dst_port VARCHAR(20),
                label VARCHAR(100),
                descricao TEXT,
                packet_count_src INT,
                packet_count_dst INT
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS blacklist (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp DATETIME,
                ip VARCHAR(50) UNIQUE,
                descricao TEXT
            )
        ''')
        self.conn.commit()
        
    def salvar_log(self, dados):
        query = '''
        INSERT INTO logs (
            timestamp, src_ip, src_port, dst_ip, dst_port, 
            label, descricao, packet_count_src, packet_count_dst
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    '''
        
        self.cursor.execute(query, dados)
        self.conn.commit()
        
    def salvar_na_blacklist(self, ip, descricao):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        query = '''
            INSERT IGNORE INTO blacklist (timestamp, ip, descricao)
            VALUES (%s, %s, %s)
        '''
        self.cursor.execute(query, (timestamp, ip, descricao))
        self.conn.commit()

        
    def fechar_conexao(self):
        self.conn.close()
        print("[BANCO] Conexão encerrada.")       
    
    
    def inserir_ip(self, ip):
        try:
            self.cursor.execute("SELECT ip_id FROM ips WHERE ip = %s", (ip,))
            resultado = self.cursor.fetchone()
            if resultado:
                return resultado[0]
            else:
                self.cursor.execute("INSERT INTO ips (ip) VALUES (%s)", (ip,))
                self.conn.commit()
                return self.cursor.lastrowid
        except mysql.connector.Error as err:
            print(f"[BANCO] Erro ao inserir IP: {err}")
            return None 

class IntrusionDetectionSystem:
    def __init__(self, db: DatabaseManager):
        self.db = db

        # Assinaturas
        self.assinaturas = [
            "MALWARE", "ATTACK", "SQLMAP", "NMAP", "INJECTION", "SLOWLORIS", "SLOWHTTPTEST", "CURL"]

        # Controle interno
        self.__icmp_contagem = defaultdict(list)
        #self.__udp_contagem = defaultdict(list)
        self.__tcp_syn_contagem = defaultdict(list)
        self.__ips_bloqueados = set()
        self.__conexoes = defaultdict(list)

        self.__contagem_pacotes_src = defaultdict(int)
        self.__contagem_pacotes_dst = defaultdict(int)
        self.__portScan_contagem = defaultdict(list)
        # Limites
        self.__limite_icmp = 10
        self.__limite_syn = 10
        self.__limite_udp = 100

        # Arquivos
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
        
            self.__ips_bloqueados.add(ip)
            self.db.salvar_na_blacklist(ip, descricao)
                                         
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

        if packet.haslayer(TCP):
            self.__portScan_contagem[src_ip].append((dst_port, tempo_atual))
            
            
            self.__portScan_contagem[src_ip] = [
                (porta, t) for (porta, t) in self.__portScan_contagem[src_ip] if tempo_atual - t < 10
            ]
            
            portas_unicas = set([porta for porta, _ in self.__portScan_contagem[src_ip]])
            
            if len(portas_unicas) > 20:
                return "PORT_SCAN"

        if packet.haslayer(ICMP):  # Corrigir para ICMP se necessário
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
                            return "HTTPS_SEM_PAYLOAD "
                
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
            flags = str(packet[TCP].flags) if packet.haslayer(TCP) else "N/A"

            tempo_atual = time.time()

            alerta_assinatura = self.analisar_assinaturas(packet)
            alerta_ataque = self.detectar_ataques(src_ip, tempo_atual, packet, dst_port, dst_ip)

            alerta = alerta_assinatura or alerta_ataque or "TRAFEGO_NORMAL"

            desc = ""
            if alerta != "TRAFEGO_NORMAL":
                desc = f"Assinatura detectada no tráfego de {src_ip} -> {dst_ip}: {alerta}"
                print(desc)
                alert = ["DOS_SLOW_AND_LOW", "SYN_FLOOD", "ICMP_FLOOD", "FRAGMENTATION_ATTACK", "NMAP", "PORT_SCAN"]
                if alerta in alert:
                    
                    # Ativar se desejar bloquear automaticamente:
                    self.bloquear_ip(src_ip, desc)

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
            
            
            self.db.salvar_log([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                src_ip, src_port, dst_ip, dst_port, alerta, desc,
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