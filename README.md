# IDSstarly

Sistema simples de Detecção de Intrusão (IDS) desenvolvido em Python utilizando a biblioteca Scapy para captura e análise de pacotes de rede em tempo real.

## Descrição

Este projeto implementa um IDS básico que monitora o tráfego de rede, buscando por assinaturas específicas no payload dos pacotes para detectar possíveis ameaças como malwares, ataques de injeção, scans de portas e outros comportamentos suspeitos.

## Funcionalidades

- Captura de pacotes em tempo real com Scapy
- Análise do conteúdo dos pacotes para detecção de assinaturas suspeitas
- Geração de alertas com detalhes do evento detectado (IP origem, destino, protocolo, etc.)
- Registro dos eventos detectados em arquivo CSV para posterior análise
- Implementação simples e extensível para aprendizado e uso prático

## Requisitos

- Python 3.x
- Biblioteca [Scapy](https://scapy.net/) (`pip install scapy`)

## Como usar

1. Clone o repositório:

```bash
git clone https://github.com/apelidoR/IDS-Python.git
cd IDS-Python
```
É obrigatorio que você tenha o mysql instalado 

2. Com o MySQL instalado, acesse o terminal como root
```bash
mysql -u root -p

```

3. Crie um usuário e garanta todos os privilegios
```bash

CREATE USER 'admin'@'localhost' IDENTIFIED BY 'admin';

GRANT ALL PRIVILEGES ON *.* TO 'admin'@'localhost' WITH GRANT OPTION;

FLUSH PRIVILEGES;


```
4. Crie o banco de dados
   
```bash
CREATE DATABASE idsstarlyDB;
```


5. Execute o arquivo main.py:
```bash
sudo python3 main.py
```
