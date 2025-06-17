# Idsstar

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
2. Execute o arquivo main.py:
```bash
python3 main.py
```

   
