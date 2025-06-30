# Análise de Tráfego de Rede com Scapy

Este projeto implementa uma aplicação para captura e análise de pacotes de rede, calculando estatísticas básicas sobre o tráfego capturado. A aplicação é executada dentro de um container Docker.

## Requisitos do Sistema

- **Python**: Versão 3.9 ou superior
- **Docker**: Necessário para executar o container
- **Scapy**: Biblioteca Python para captura de pacotes de rede

## Configuração Inicial

### Instalação do Python
1. Baixe e instale o Python a partir do [site oficial](https://www.python.org/).
2. Certifique-se de que o Python está incluído no PATH do sistema.

### Instalação do Docker
1. Instale o Docker Desktop a partir da [página de downloads do Docker](https://www.docker.com/products/docker-desktop).
2. Verifique a instalação executando `docker --version` no terminal.

### Instalação de Dependências
- Certifique-se de que o Python e o Docker estão funcionando.
- Instale a biblioteca Scapy executando:
  ```bash
  pip install scapy


 ### Estrutura do Projeto
capture_packets.py: Script principal para captura e análise de pacotes.
Dockerfile: Arquivo de definição para construção do container Docker.


   ### Configuração do Docker

    Dockerfile
Certifique-se de que o Dockerfile está configurado conforme abaixo:
FROM python:3.9-slim

WORKDIR /app

COPY capture_packets.py .

# Instala iproute2 para suporte adicional de rede
RUN apt-get update && apt-get install -y iproute2

RUN pip install scapy

CMD ["python", "capture_packets.py"]

   ### Execução do Projeto
Construir a Imagem Docker
No terminal, navegue até o diretório onde o Dockerfile está localizado.
Execute o comando de construção da imagem:

docker build -t packet-capture .

Executar o Container Docker

Execute o container garantindo permissões adequadas para captura de pacotes:
docker run --rm --net=host --cap-add=NET_ADMIN --cap-add=NET_RAW packet-capture

### Documentação Adicional
Interfaces de Rede
Certifique-se de que a interface de rede correta (eth0) está sendo usada dentro do container.
Arquivo de Saída
O script gera um arquivo de texto com detalhes dos pacotes capturados e as estatísticas de tráfego.

### Observações
Troubleshooting
Caso encontre problemas, verifique se as permissões do Docker estão corretamente configuradas e se o Python está sendo executado sem erros de dependência.
Contato
Para suporte, entre em contato via ext_guguenka@mercadolivre.com